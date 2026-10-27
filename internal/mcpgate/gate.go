// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package mcpgate

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/high-archytech-solutions/archytan-mcp-gate/v2/internal/tracectx"
)

// Methods the host may call that are forwarded without being gated (after
// sanitizeForServer). tools/call is gated separately; everything else
// (resources/*, prompts/*, completion/*, tasks/*, anything unknown) is
// refused, because this gate does not govern it. initialize, ping and
// logging/setLevel belong to the handshake era; server/discover and
// subscriptions/listen to 2026-07-28.
var passThroughRequests = map[string]bool{
	"initialize":       true,
	"ping":             true,
	"tools/list":       true,
	"logging/setLevel": true,
	discoverMethod:     true,
	listenMethod:       true,
}

// Capabilities stripped from the tool server's initialize result, so a
// host does not offer the agent features the gate will refuse anyway.
var strippedCapabilities = []string{"resources", "prompts", "completions"}

// MCP roots let a client tell a server which folders it may work in, and a
// server that honours them replaces its own configured scope with the
// client's list (the reference filesystem server does exactly that). Behind
// the gate the operator sets the tool server's scope when configuring its
// command, and the host must not be able to widen it: Claude Code, for one,
// sends its whole workspace. So the gate hides the host's roots capability
// from the server, answers a server's roots/list itself with an error, and
// drops the host's roots change notifications.
const (
	rootsCapability          = "roots"
	rootsListMethod          = "roots/list"
	rootsListChangedMethod   = "notifications/roots/list_changed"
	rootsUnavailableErrorMsg = "roots are not available through the Archytan gate: the operator sets this server's scope"
)

type call struct {
	id     json.RawMessage
	key    string
	raw    []byte
	name   string
	args   map[string]json.RawMessage
	ctx    context.Context
	cancel context.CancelFunc
	// traceID is the agent's trace id when its call carried a traceparent,
	// for the gate's own log lines.
	traceID string
	// modern is set when the call was made under 2026-07-28 rules, whose
	// results must name their type.
	modern bool

	mu        sync.Mutex
	forwarded bool
}

// traceNote names the agent's trace in a log line, when it sent one. The
// id has passed tracectx.Parse, so it is 32 lowercase hex characters and
// nothing else.
func (c *call) traceNote() string {
	if c.traceID == "" {
		return ""
	}
	return " otel_trace_id=" + c.traceID
}

// Gate relays one MCP session between a host and a tool server.
type Gate struct {
	cfg      *Config
	auth     Authorizer
	logf     func(format string, args ...any)
	toHost   *lineWriter
	toServer *lineWriter
	queue    *callQueue
	baseCtx  context.Context
	stop     context.CancelFunc

	mu              sync.Mutex
	inflight        map[string]*call
	pendingLists    map[string]bool
	pendingInit     map[string]bool
	pendingDiscover map[string]bool
}

// New builds a gate that writes to the host and to the tool server.
func New(cfg *Config, auth Authorizer, toHost, toServer io.Writer, logf func(string, ...any)) *Gate {
	ctx, stop := context.WithCancel(context.Background())
	return &Gate{
		cfg:             cfg,
		auth:            auth,
		logf:            logf,
		toHost:          &lineWriter{w: toHost},
		toServer:        &lineWriter{w: toServer},
		queue:           newCallQueue(),
		baseCtx:         ctx,
		stop:            stop,
		inflight:        map[string]*call{},
		pendingLists:    map[string]bool{},
		pendingInit:     map[string]bool{},
		pendingDiscover: map[string]bool{},
	}
}

// normalizeID makes an id comparable across messages: the same value with
// different whitespace is the same id.
func normalizeID(id json.RawMessage) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, id); err != nil {
		return string(id)
	}
	return buf.String()
}

// ServeHost reads host messages until EOF or error. It never blocks on the
// network: gated calls are queued for the worker.
func (g *Gate) ServeHost(r io.Reader) error {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := readLine(br, MaxMessageBytes)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		g.fromHost(line)
	}
}

// ServeServer reads tool-server messages until EOF or error.
func (g *Gate) ServeServer(r io.Reader) error {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := readLine(br, MaxMessageBytes)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		g.fromServer(line)
	}
}

// RunWorker authorizes queued calls one at a time, in arrival order, until
// Close. Order is preserved on purpose: an agent that issues two actions
// in sequence gets them executed in that sequence.
func (g *Gate) RunWorker() {
	for {
		c, ok := g.queue.pop()
		if !ok {
			return
		}
		g.handleCall(c)
	}
}

// Close stops the worker and cancels every call not yet forwarded.
func (g *Gate) Close() {
	g.stop()
	g.queue.close()
}

func (g *Gate) send(w *lineWriter, msg []byte) {
	if err := w.write(msg); err != nil {
		g.logf("write failed: %v", err)
	}
}

func (g *Gate) fromHost(line []byte) {
	if len(bytes.TrimSpace(line)) == 0 {
		return
	}
	msg, batch, err := parseMessage(line)
	if batch {
		g.send(g.toHost, errorResponse(nil, -32600, "JSON-RPC batches are not supported by the Archytan gate"))
		return
	}
	if err != nil {
		g.send(g.toHost, errorResponse(nil, -32700, "parse error"))
		return
	}
	if err := checkUnambiguous(line); err != nil {
		// A message the gate and the server could read differently is
		// refused whole: see keys.go.
		g.logf("refused a message from the host: %v", err)
		if msg.isRequest() {
			g.send(g.toHost, errorResponse(msg.ID, -32600, "the Archytan gate refuses a message readers could take two ways: keys that repeat or differ only in case, invalid UTF-8, or an unpaired surrogate escape"))
		}
		return
	}
	switch {
	case msg.isRequest():
		switch {
		case msg.Method == "tools/call":
			g.enqueueCall(msg, line)
		case passThroughRequests[msg.Method]:
			out, _, err := sanitizeForServer(line, msg.Method, true)
			if err != nil {
				// Forwarding it unchanged could hand the server the host's
				// roots, so a request the gate cannot check stops here.
				g.logf("refused %s: %v", msg.Method, err)
				text := fmt.Sprintf("%s params could not be checked by the Archytan gate", msg.Method)
				if errors.Is(err, errHostRoots) {
					text = rootsUnavailableErrorMsg
				}
				g.send(g.toHost, errorResponse(msg.ID, -32602, text))
				return
			}
			line = out
			key := normalizeID(msg.ID)
			g.mu.Lock()
			switch msg.Method {
			case "tools/list":
				g.pendingLists[key] = true
			case "initialize":
				g.pendingInit[key] = true
			case discoverMethod:
				g.pendingDiscover[key] = true
			}
			g.mu.Unlock()
			if msg.Method == "initialize" {
				out, err := stripClientRoots(line)
				if err != nil {
					// Forwarding it unchanged could hand the server the
					// host's roots, so an initialize the gate cannot read
					// does not reach the server at all.
					g.mu.Lock()
					delete(g.pendingInit, key)
					g.mu.Unlock()
					g.logf("refused initialize: its params could not be checked: %v", err)
					g.send(g.toHost, errorResponse(msg.ID, -32602, "initialize params could not be checked by the Archytan gate"))
					return
				}
				line = out
			}
			g.send(g.toServer, line)
		default:
			g.logf("refused method %q: not available through the gate", msg.Method)
			g.send(g.toHost, errorResponse(msg.ID, -32601, fmt.Sprintf("method %q is not available through the Archytan gate", msg.Method)))
		}
	case msg.isNotification():
		out, _, err := sanitizeForServer(line, msg.Method, false)
		if err != nil {
			g.logf("dropped %s from the host: its params could not be checked: %v", msg.Method, err)
			out = nil
		}
		if msg.Method == "notifications/cancelled" {
			// A cancellation still stops a call the gate holds, even one it
			// cannot relay.
			g.cancelFromHost(msg, out)
			return
		}
		if out == nil {
			return
		}
		if msg.Method == rootsListChangedMethod {
			g.logf("dropped %s from the host: roots do not pass through the gate", rootsListChangedMethod)
			return
		}
		g.send(g.toServer, out)
	case msg.isResponse():
		// The host answering a request the tool server made (sampling,
		// roots, elicitation).
		g.send(g.toServer, line)
	default:
		g.send(g.toHost, errorResponse(nil, -32600, "invalid request"))
	}
}

func (g *Gate) enqueueCall(msg *message, line []byte) {
	var params struct {
		Name      string                     `json:"name"`
		Arguments map[string]json.RawMessage `json:"arguments"`
		// Meta stays raw: trace context of any shape must not stop a
		// call that would have gone through without it. What of _meta
		// reaches the server is sanitizeForServer's business.
		Meta json.RawMessage `json:"_meta"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil || params.Name == "" {
		g.send(g.toHost, errorResponse(msg.ID, -32602, "tools/call needs params with a tool name"))
		return
	}
	line, modern, err := sanitizeForServer(line, msg.Method, true)
	if errors.Is(err, errHostRoots) {
		// Checked before authorization, so a refused retry spends nothing.
		g.logf("REFUSED tool=%q: its inputResponses answer a %s the gate never relayed", params.Name, rootsListMethod)
		g.send(g.toHost, toolRefusal(msg.ID, "Refused by Archytan Lite: "+rootsUnavailableErrorMsg, modern))
		return
	}
	if err != nil {
		g.logf("refused tools/call %q: its params could not be checked: %v", params.Name, err)
		g.send(g.toHost, errorResponse(msg.ID, -32602, "tools/call params could not be checked by the Archytan gate"))
		return
	}
	key := normalizeID(msg.ID)
	ctx, cancel := context.WithCancel(g.baseCtx)
	tp, trace := traceparentOf(params.Meta)
	c := &call{
		id:      append(json.RawMessage(nil), msg.ID...),
		key:     key,
		raw:     append([]byte(nil), line...),
		name:    params.Name,
		args:    params.Arguments,
		ctx:     withTraceparent(ctx, tp),
		cancel:  cancel,
		traceID: trace.TraceID,
		modern:  modern,
	}
	g.mu.Lock()
	if _, dup := g.inflight[key]; dup {
		g.mu.Unlock()
		cancel()
		g.send(g.toHost, errorResponse(msg.ID, -32600, "a request with this id is already in progress"))
		return
	}
	g.inflight[key] = c
	g.mu.Unlock()
	if !g.queue.push(c) {
		g.finish(c)
	}
}

// traceparentOf reads the W3C traceparent a host put in a tools/call's
// params._meta, which is where MCP carries trace context (SEP-414).
// Anything missing or malformed gives the zero values and the call goes on
// without a trace: as with the gate's own traceparent header, trace context
// never affects a decision.
func traceparentOf(meta json.RawMessage) (string, tracectx.Context) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(meta, &fields) != nil {
		return "", tracectx.Context{}
	}
	var tp string
	if json.Unmarshal(fields[tracectx.HeaderName], &tp) != nil {
		return "", tracectx.Context{}
	}
	trace, ok := tracectx.Parse(tp)
	if !ok {
		return "", tracectx.Context{}
	}
	return tp, trace
}

func (g *Gate) finish(c *call) {
	c.cancel()
	g.mu.Lock()
	if g.inflight[c.key] == c {
		delete(g.inflight, c.key)
	}
	g.mu.Unlock()
}

// cancelFromHost acts on a cancellation the moment it is read. A call not
// yet forwarded is abandoned before its capability is redeemed or, at
// worst, before it reaches the tool server; a forwarded call's
// cancellation is relayed to the server, which is the only party that can
// still stop it. A nil line is a cancellation that cannot be relayed: it
// still stops a call the gate holds.
func (g *Gate) cancelFromHost(msg *message, line []byte) {
	relay := func() {
		if line != nil {
			g.send(g.toServer, line)
		}
	}
	var params struct {
		RequestID json.RawMessage `json:"requestId"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil || len(params.RequestID) == 0 {
		relay()
		return
	}
	g.mu.Lock()
	c := g.inflight[normalizeID(params.RequestID)]
	g.mu.Unlock()
	if c == nil {
		relay()
		return
	}
	c.mu.Lock()
	c.cancel()
	forwarded := c.forwarded
	c.mu.Unlock()
	if forwarded {
		relay()
	}
}

func (g *Gate) refuse(c *call, reason string) {
	g.logf("REFUSED tool=%q%s: %s", c.name, c.traceNote(), reason)
	g.send(g.toHost, toolRefusal(c.id, "Refused by Archytan Lite: "+reason, c.modern))
}

func (g *Gate) handleCall(c *call) {
	defer g.finish(c)
	if c.ctx.Err() != nil {
		g.logf("CANCELLED tool=%q%s before authorization: nothing was spent or executed", c.name, c.traceNote())
		return
	}
	mapping, ok := g.cfg.Tools[c.name]
	if !ok {
		g.refuse(c, fmt.Sprintf("tool %q is not permitted through this gate", c.name))
		return
	}
	resourceID, err := mapping.resourceID(c.args)
	if err != nil {
		g.refuse(c, fmt.Sprintf("tool %q %v", c.name, err))
		return
	}

	grant, err := g.auth.Authorize(c.ctx, mapping.Action, g.cfg.AgentUID, mapping.ResourceType, resourceID)
	if err != nil {
		if c.ctx.Err() != nil {
			g.logf("CANCELLED tool=%q%s during authorization: nothing was spent or executed", c.name, c.traceNote())
			return
		}
		g.refuse(c, err.Error())
		return
	}
	// A cancellation that arrived while authorization was succeeding must
	// stop the call before its capability is spent.
	if c.ctx.Err() != nil {
		g.logf("CANCELLED tool=%q%s after authorization (receipt %s): capability not redeemed, nothing executed", c.name, c.traceNote(), grant.ReceiptID)
		return
	}

	if err := g.auth.Redeem(c.ctx, grant); err != nil {
		if c.ctx.Err() != nil {
			g.logf("CANCELLED tool=%q%s during redemption (receipt %s): the capability may be spent, but the call was not executed", c.name, c.traceNote(), grant.ReceiptID)
			return
		}
		g.refuse(c, err.Error())
		return
	}

	// This check and the forward happen under the call's lock, the same lock
	// cancelFromHost takes, so a cancellation lands either before this point
	// (and the call is dropped) or after it (and is relayed to the server).
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		g.logf("CANCELLED tool=%q%s after redemption (receipt %s): authorized, not executed", c.name, c.traceNote(), grant.ReceiptID)
		return
	}
	c.forwarded = true
	g.send(g.toServer, c.raw)
	c.mu.Unlock()
	g.logf("ALLOWED tool=%q action=%q receipt=%s%s: forwarded to the tool server", c.name, mapping.Action, grant.ReceiptID, c.traceNote())
}

func (g *Gate) fromServer(line []byte) {
	if len(bytes.TrimSpace(line)) == 0 {
		return
	}
	msg, batch, err := parseMessage(line)
	if batch || err != nil || !(msg.isRequest() || msg.isNotification() || msg.isResponse()) {
		g.logf("dropped a non-JSON-RPC line from the tool server's stdout: %q", preview(line))
		return
	}
	if msg.isRequest() && msg.Method == rootsListMethod {
		g.logf("answered the tool server's %s itself: roots do not pass through the gate", rootsListMethod)
		g.send(g.toServer, errorResponse(msg.ID, -32601, rootsUnavailableErrorMsg))
		return
	}
	if msg.isResponse() {
		key := normalizeID(msg.ID)
		g.mu.Lock()
		isList, isInit, isDiscover := g.pendingLists[key], g.pendingInit[key], g.pendingDiscover[key]
		delete(g.pendingLists, key)
		delete(g.pendingInit, key)
		delete(g.pendingDiscover, key)
		g.mu.Unlock()
		if asksForRoots(line) {
			// Of the requests the gate forwards, only a tools/call may be
			// answered with input requests. Its capability was spent when
			// it was forwarded, and the tool did not finish.
			g.logf("REFUSED the tool server's input_required for request %s: it asks the host for %s", key, rootsListMethod)
			g.send(g.toHost, toolRefusal(msg.ID, "Refused by Archytan Lite: "+rootsUnavailableErrorMsg, true))
			return
		}
		switch {
		case isList:
			out, err := filterToolsList(line, g.cfg)
			if err != nil {
				g.logf("could not filter tools/list: %v", err)
				g.send(g.toHost, errorResponse(msg.ID, -32603, "the tool list could not be filtered by the Archytan gate"))
				return
			}
			g.send(g.toHost, out)
			return
		case isInit, isDiscover:
			stripped, what := strippedCapabilities, "initialize"
			if isDiscover {
				stripped, what = strippedDiscoverCapabilities, discoverMethod
			}
			out, err := stripResultCapabilities(line, stripped)
			if err != nil {
				g.logf("could not adjust %s result: %v", what, err)
				g.send(g.toHost, line)
				return
			}
			g.send(g.toHost, out)
			return
		}
	}
	g.send(g.toHost, line)
}

func preview(line []byte) string {
	const n = 200
	if len(line) > n {
		return string(line[:n]) + "..."
	}
	return string(line)
}

// filterToolsList keeps only mapped tools, so the agent never sees a tool
// it could not use.
func filterToolsList(line []byte, cfg *Config) ([]byte, error) {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(line, &env); err != nil {
		return nil, err
	}
	res, ok := env["result"]
	if !ok {
		return line, nil
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(res, &result); err != nil {
		return nil, err
	}
	var tools []json.RawMessage
	if raw, ok := result["tools"]; ok {
		if err := json.Unmarshal(raw, &tools); err != nil {
			return nil, err
		}
	}
	kept := make([]json.RawMessage, 0, len(tools))
	for _, t := range tools {
		var named struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(t, &named) == nil {
			if _, ok := cfg.Tools[named.Name]; ok {
				kept = append(kept, t)
			}
		}
	}
	keptJSON, err := json.Marshal(kept)
	if err != nil {
		return nil, err
	}
	result["tools"] = keptJSON
	resJSON, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	env["result"] = resJSON
	return json.Marshal(env)
}

// stripClientRoots removes the roots capability from a host's initialize
// request, leaving everything else in it as it was. An initialize with no
// params or no capabilities is returned unchanged. Keys are matched
// without regard to case, as a server in Go would read them (keysFolding).
func stripClientRoots(line []byte) ([]byte, error) {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(line, &env); err != nil {
		return nil, err
	}
	changed := false
	for _, pk := range keysFolding(env, "params") {
		if string(env[pk]) == "null" {
			continue
		}
		var params map[string]json.RawMessage
		if err := json.Unmarshal(env[pk], &params); err != nil {
			return nil, err
		}
		paramsChanged := false
		for _, ck := range keysFolding(params, "capabilities") {
			if string(params[ck]) == "null" {
				continue
			}
			var caps map[string]json.RawMessage
			if err := json.Unmarshal(params[ck], &caps); err != nil {
				return nil, err
			}
			roots := keysFolding(caps, rootsCapability)
			if len(roots) == 0 {
				continue
			}
			for _, k := range roots {
				delete(caps, k)
			}
			capsJSON, err := json.Marshal(caps)
			if err != nil {
				return nil, err
			}
			params[ck] = capsJSON
			paramsChanged = true
		}
		if !paramsChanged {
			continue
		}
		paramsJSON, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		env[pk] = paramsJSON
		changed = true
	}
	if !changed {
		return line, nil
	}
	return json.Marshal(env)
}

// stripResultCapabilities removes the named capabilities from an initialize
// or server/discover result, so a host does not offer the agent features
// the gate will refuse anyway.
func stripResultCapabilities(line []byte, names []string) ([]byte, error) {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(line, &env); err != nil {
		return nil, err
	}
	res, ok := env["result"]
	if !ok {
		return line, nil
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(res, &result); err != nil {
		return nil, err
	}
	capsRaw, ok := result["capabilities"]
	if !ok {
		return line, nil
	}
	var caps map[string]json.RawMessage
	if err := json.Unmarshal(capsRaw, &caps); err != nil {
		return nil, err
	}
	for _, k := range names {
		delete(caps, k)
	}
	capsJSON, err := json.Marshal(caps)
	if err != nil {
		return nil, err
	}
	result["capabilities"] = capsJSON
	resJSON, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	env["result"] = resJSON
	return json.Marshal(env)
}
