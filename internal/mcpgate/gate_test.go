// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package mcpgate

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// sink collects whole lines written to it.
type sink struct {
	mu    sync.Mutex
	lines []string
}

func (s *sink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		s.lines = append(s.lines, l)
	}
	return len(p), nil
}

func (s *sink) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.lines...)
}

func (s *sink) waitFor(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := s.snapshot(); len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d line(s), have %v", n, s.snapshot())
	return nil
}

// fakeAuth lets each test decide how the gate answers.
type fakeAuth struct {
	mu          sync.Mutex
	authorizeFn func(ctx context.Context, action, uid, rtype, rid string) (Grant, error)
	redeemFn    func(ctx context.Context, g Grant) error
	authorized  []string
	redeemed    []string
}

func (f *fakeAuth) Authorize(ctx context.Context, action, uid, rtype, rid string) (Grant, error) {
	f.mu.Lock()
	f.authorized = append(f.authorized, action+" "+uid+" "+rtype+" "+rid)
	fn := f.authorizeFn
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx, action, uid, rtype, rid)
	}
	return Grant{ReceiptID: "rcpt_1", CapabilityToken: "cap", Action: action, ResourceType: rtype, ResourceID: rid}, nil
}

func (f *fakeAuth) Redeem(ctx context.Context, g Grant) error {
	f.mu.Lock()
	f.redeemed = append(f.redeemed, g.ResourceID)
	fn := f.redeemFn
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx, g)
	}
	return nil
}

func (f *fakeAuth) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.authorized), len(f.redeemed)
}

func testConfig(t *testing.T) *Config {
	t.Helper()
	cfg, err := ParseConfig([]byte(`{"version":1,"agent_uid":"agent-invoices","tools":{
	  "delete_invoice":{"action":"invoice.delete","resource_type":"invoice","resource_id_arg":"invoice_id"},
	  "read_invoice":{"action":"invoice.read","resource_type":"invoice","resource_id_arg":"invoice_id"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

type harness struct {
	g            *Gate
	host, server *sink
	auth         *fakeAuth
}

func newGateHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{host: &sink{}, server: &sink{}, auth: &fakeAuth{}}
	h.g = New(testConfig(t), h.auth, h.host, h.server, t.Logf)
	go h.g.RunWorker()
	t.Cleanup(h.g.Close)
	return h
}

func callLine(id, tool, arg string) []byte {
	return []byte(`{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":"` + tool + `","arguments":{"invoice_id":` + arg + `}}}`)
}

func decode(t *testing.T, line string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("not JSON: %q", line)
	}
	return m
}

func assertRefusal(t *testing.T, line, wantID string) {
	t.Helper()
	var m struct {
		ID     json.RawMessage `json:"id"`
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("not JSON: %q", line)
	}
	if string(m.ID) != wantID || !m.Result.IsError || len(m.Result.Content) == 0 || !strings.HasPrefix(m.Result.Content[0].Text, "Refused by Archytan Lite") {
		t.Fatalf("not a refusal for id %s: %s", wantID, line)
	}
}

func TestGate_AllowedCallIsForwardedVerbatim(t *testing.T) {
	h := newGateHarness(t)
	line := callLine(`7`, "delete_invoice", `"inv_7"`)
	h.g.fromHost(line)
	got := h.server.waitFor(t, 1)
	if got[0] != string(line) {
		t.Fatalf("forwarded bytes changed:\n got %s\nwant %s", got[0], line)
	}
	if h.auth.authorized[0] != "invoice.delete agent-invoices invoice inv_7" {
		t.Fatalf("authorized the wrong thing: %v", h.auth.authorized)
	}
	if a, r := h.auth.counts(); a != 1 || r != 1 {
		t.Fatalf("authorize/redeem counts %d/%d", a, r)
	}
	if len(h.host.snapshot()) != 0 {
		t.Fatalf("the gate answered an allowed call itself: %v", h.host.snapshot())
	}
}

func TestGate_RefusalsNeverReachTheServer(t *testing.T) {
	cases := map[string]struct {
		line          []byte
		authErr       error
		redeemErr     error
		wantAuthorize bool
	}{
		"unmapped_tool":        {line: callLine(`1`, "drop_database", `"x"`)},
		"missing_resource_arg": {line: []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_invoice","arguments":{}}}`)},
		"non_string_resource":  {line: callLine(`1`, "delete_invoice", `42`)},
		"empty_resource":       {line: callLine(`1`, "delete_invoice", `""`)},
		"gate_denied":          {line: callLine(`1`, "delete_invoice", `"inv_7"`), authErr: errors.New("the gate did not allow this action"), wantAuthorize: true},
		"redeem_refused":       {line: callLine(`1`, "delete_invoice", `"inv_7"`), redeemErr: errors.New("already spent"), wantAuthorize: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newGateHarness(t)
			h.auth.authorizeFn = func(ctx context.Context, action, uid, rtype, rid string) (Grant, error) {
				if tc.authErr != nil {
					return Grant{}, tc.authErr
				}
				return Grant{CapabilityToken: "cap", Action: action, ResourceType: rtype, ResourceID: rid}, nil
			}
			h.auth.redeemFn = func(context.Context, Grant) error { return tc.redeemErr }
			h.g.fromHost(tc.line)
			assertRefusal(t, h.host.waitFor(t, 1)[0], `1`)
			if len(h.server.snapshot()) != 0 {
				t.Fatalf("refused call reached the server: %v", h.server.snapshot())
			}
			if a, _ := h.auth.counts(); (a > 0) != tc.wantAuthorize {
				t.Fatalf("authorize called %d time(s)", a)
			}
		})
	}
}

func TestGate_UngatedMethodsAreRefused(t *testing.T) {
	for _, method := range []string{"resources/list", "resources/read", "prompts/get", "completion/complete", "something/unknown"} {
		t.Run(method, func(t *testing.T) {
			h := newGateHarness(t)
			h.g.fromHost([]byte(`{"jsonrpc":"2.0","id":"r1","method":"` + method + `","params":{}}`))
			m := decode(t, h.host.waitFor(t, 1)[0])
			if m["id"] != "r1" || m["error"] == nil {
				t.Fatalf("not an error reply: %v", m)
			}
			if len(h.server.snapshot()) != 0 {
				t.Fatal("ungated method reached the server")
			}
		})
	}
}

func TestGate_ToolsListIsFiltered(t *testing.T) {
	h := newGateHarness(t)
	h.g.fromHost([]byte(`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`))
	h.server.waitFor(t, 1)
	h.g.fromServer([]byte(`{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"delete_invoice","inputSchema":{}},{"name":"drop_database"},{"name":"read_invoice"}],"nextCursor":"c2"}}`))
	var reply struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
			NextCursor string `json:"nextCursor"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(h.host.waitFor(t, 1)[0]), &reply); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range reply.Result.Tools {
		names = append(names, tl.Name)
	}
	if strings.Join(names, ",") != "delete_invoice,read_invoice" || reply.Result.NextCursor != "c2" {
		t.Fatalf("filtered list wrong: %v cursor %q", names, reply.Result.NextCursor)
	}
}

func TestGate_InitializeStripsUngatedCapabilities(t *testing.T) {
	h := newGateHarness(t)
	h.g.fromHost([]byte(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}`))
	h.server.waitFor(t, 1)
	h.g.fromServer([]byte(`{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{},"resources":{},"prompts":{},"completions":{},"logging":{}},"serverInfo":{"name":"x"}}}`))
	m := decode(t, h.host.waitFor(t, 1)[0])
	caps := m["result"].(map[string]any)["capabilities"].(map[string]any)
	for _, gone := range []string{"resources", "prompts", "completions"} {
		if _, ok := caps[gone]; ok {
			t.Fatalf("capability %q was not stripped: %v", gone, caps)
		}
	}
	if _, ok := caps["tools"]; !ok {
		t.Fatalf("tools capability was stripped: %v", caps)
	}
}

// blockingAuth holds authorization until the call's context is cancelled.
func blockingAuth(started chan<- struct{}) func(context.Context, string, string, string, string) (Grant, error) {
	return func(ctx context.Context, action, uid, rtype, rid string) (Grant, error) {
		close(started)
		<-ctx.Done()
		return Grant{}, ctx.Err()
	}
}

// The host reader must stay responsive while the worker waits on the
// gate: a cancellation read from stdin has to act immediately.
func TestGate_CancelBeforeAuthorizationEndsIsHonoured(t *testing.T) {
	h := newGateHarness(t)
	started := make(chan struct{})
	h.auth.authorizeFn = blockingAuth(started)

	pr, pw := io.Pipe()
	go h.g.ServeHost(pr)
	_, _ = pw.Write(append(callLine(`"abc"`, "delete_invoice", `"inv_7"`), '\n'))
	<-started
	_, _ = pw.Write([]byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"abc","reason":"user"}}` + "\n"))

	time.Sleep(150 * time.Millisecond)
	if _, r := h.auth.counts(); r != 0 {
		t.Fatal("a cancelled call's capability was redeemed")
	}
	if len(h.server.snapshot()) != 0 || len(h.host.snapshot()) != 0 {
		t.Fatalf("cancelled call produced output: server=%v host=%v", h.server.snapshot(), h.host.snapshot())
	}
	_ = pw.Close()
}

func TestGate_CancelAfterRedeemBeforeForwardIsNotExecuted(t *testing.T) {
	h := newGateHarness(t)
	h.auth.redeemFn = func(ctx context.Context, g Grant) error {
		// The cancellation lands while the capability is being spent.
		h.g.fromHost([]byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":5}}`))
		return nil
	}
	h.g.fromHost(callLine(`5`, "delete_invoice", `"inv_7"`))
	time.Sleep(150 * time.Millisecond)
	if len(h.server.snapshot()) != 0 {
		t.Fatalf("a call cancelled before forwarding reached the server: %v", h.server.snapshot())
	}
}

func TestGate_CancelDuringSuccessfulAuthorizationSpendsNothing(t *testing.T) {
	h := newGateHarness(t)
	h.auth.authorizeFn = func(ctx context.Context, action, uid, rtype, rid string) (Grant, error) {
		// The gate says yes, but the host cancels while it is saying it.
		h.g.fromHost([]byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":6}}`))
		return Grant{CapabilityToken: "c", Action: action, ResourceType: rtype, ResourceID: rid}, nil
	}
	h.g.fromHost(callLine(`6`, "delete_invoice", `"inv_7"`))
	time.Sleep(150 * time.Millisecond)
	if _, r := h.auth.counts(); r != 0 {
		t.Fatal("the capability of a call cancelled during authorization was redeemed")
	}
	if len(h.server.snapshot()) != 0 || len(h.host.snapshot()) != 0 {
		t.Fatalf("cancelled call produced output: server=%v host=%v", h.server.snapshot(), h.host.snapshot())
	}
}

// An unmapped tool must be refused on its own terms, not by accident of a
// later check: here its argument name matches the zero-value mapping.
func TestGate_UnmappedToolNeverReachesAuthorization(t *testing.T) {
	h := newGateHarness(t)
	h.g.fromHost([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"drop_database","arguments":{"":"everything"}}}`))
	assertRefusal(t, h.host.waitFor(t, 1)[0], `1`)
	if a, _ := h.auth.counts(); a != 0 {
		t.Fatal("an unmapped tool reached authorization")
	}
	if len(h.server.snapshot()) != 0 {
		t.Fatal("an unmapped tool reached the server")
	}
}

// A call already forwarded but not yet cleared from the in-flight table
// must have its cancellation relayed, since only the server can stop it.
func TestGate_CancelForForwardedInflightCallIsRelayed(t *testing.T) {
	h := newGateHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	c := &call{id: json.RawMessage(`11`), key: "11", ctx: ctx, cancel: cancel, forwarded: true}
	h.g.mu.Lock()
	h.g.inflight["11"] = c
	h.g.mu.Unlock()
	line := `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":11}}`
	h.g.fromHost([]byte(line))
	if got := h.server.waitFor(t, 1); got[0] != line {
		t.Fatalf("cancellation not relayed: %v", got)
	}
	if ctx.Err() == nil {
		t.Fatal("the call's context was not cancelled")
	}
}

// A call not yet forwarded is cancelled locally and never reaches the
// server, not even as a cancellation notice.
func TestGate_CancelForUnforwardedInflightCallStaysLocal(t *testing.T) {
	h := newGateHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	c := &call{id: json.RawMessage(`12`), key: "12", ctx: ctx, cancel: cancel}
	h.g.mu.Lock()
	h.g.inflight["12"] = c
	h.g.mu.Unlock()
	h.g.fromHost([]byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":12}}`))
	time.Sleep(50 * time.Millisecond)
	if len(h.server.snapshot()) != 0 {
		t.Fatalf("an unforwarded call's cancellation reached the server: %v", h.server.snapshot())
	}
	if ctx.Err() == nil {
		t.Fatal("the call's context was not cancelled")
	}
}

func TestGate_CancelAfterForwardIsRelayed(t *testing.T) {
	h := newGateHarness(t)
	h.g.fromHost(callLine(`9`, "delete_invoice", `"inv_7"`))
	h.server.waitFor(t, 1)
	cancel := `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":9}}`
	h.g.fromHost([]byte(cancel))
	if got := h.server.waitFor(t, 2); got[1] != cancel {
		t.Fatalf("cancellation not relayed: %v", got)
	}
}

func TestGate_CallsRunInArrivalOrder(t *testing.T) {
	h := newGateHarness(t)
	h.auth.authorizeFn = func(ctx context.Context, action, uid, rtype, rid string) (Grant, error) {
		if rid == "first" {
			time.Sleep(100 * time.Millisecond)
		}
		return Grant{CapabilityToken: "c", Action: action, ResourceType: rtype, ResourceID: rid}, nil
	}
	h.g.fromHost(callLine(`1`, "delete_invoice", `"first"`))
	h.g.fromHost(callLine(`2`, "delete_invoice", `"second"`))
	got := h.server.waitFor(t, 2)
	if !strings.Contains(got[0], `"first"`) || !strings.Contains(got[1], `"second"`) {
		t.Fatalf("calls forwarded out of order: %v", got)
	}
}

func TestGate_DuplicateInflightIDIsRefused(t *testing.T) {
	h := newGateHarness(t)
	started := make(chan struct{})
	h.auth.authorizeFn = blockingAuth(started)
	h.g.fromHost(callLine(`4`, "delete_invoice", `"inv_7"`))
	<-started
	h.g.fromHost(callLine(`4`, "delete_invoice", `"inv_8"`))
	m := decode(t, h.host.waitFor(t, 1)[0])
	if m["error"] == nil {
		t.Fatalf("duplicate id accepted: %v", m)
	}
}

func TestGate_JunkFromServerIsDroppedNotFatal(t *testing.T) {
	h := newGateHarness(t)
	h.g.fromServer([]byte(`Server listening on stdio, debug=true`))
	h.g.fromServer([]byte(`{"level":"info","msg":"a JSON log line"}`))
	h.g.fromServer([]byte(`{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`))
	got := h.host.waitFor(t, 1)
	time.Sleep(50 * time.Millisecond)
	if got = h.host.snapshot(); len(got) != 1 || !strings.Contains(got[0], "list_changed") {
		t.Fatalf("junk leaked or real message lost: %v", got)
	}
}

func TestGate_HostBatchAndGarbageAreRefused(t *testing.T) {
	h := newGateHarness(t)
	h.g.fromHost([]byte(`[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_invoice","arguments":{"invoice_id":"x"}}}]`))
	h.g.fromHost([]byte(`not json`))
	got := h.host.waitFor(t, 2)
	for _, l := range got {
		if decode(t, l)["error"] == nil {
			t.Fatalf("not an error: %s", l)
		}
	}
	if len(h.server.snapshot()) != 0 {
		t.Fatal("a batch reached the server")
	}
}

func TestGate_ServerRequestsAndHostRepliesPassThrough(t *testing.T) {
	h := newGateHarness(t)
	req := `{"jsonrpc":"2.0","id":"s1","method":"sampling/createMessage","params":{}}`
	h.g.fromServer([]byte(req))
	if got := h.host.waitFor(t, 1); got[0] != req {
		t.Fatalf("server request not relayed: %v", got)
	}
	reply := `{"jsonrpc":"2.0","id":"s1","result":{"role":"assistant"}}`
	h.g.fromHost([]byte(reply))
	if got := h.server.waitFor(t, 1); got[0] != reply {
		t.Fatalf("host reply not relayed: %v", got)
	}
}

// TestGate_HostRootsNeverReachTheServer is the scope guarantee. A host that
// supports MCP roots (Claude Code sends its workspace) must not be able to
// widen the folders the operator gave the tool server: the server never
// learns the host has roots, a roots/list it sends anyway is answered by the
// gate with an error, and the host's roots change notifications are dropped.
func TestGate_HostRootsNeverReachTheServer(t *testing.T) {
	h := newGateHarness(t)
	h.g.fromHost([]byte(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{"roots":{"listChanged":true},"sampling":{}},"clientInfo":{"name":"host","version":"1"}}}`))
	fwd := decode(t, h.server.waitFor(t, 1)[0])
	params := fwd["params"].(map[string]any)
	caps := params["capabilities"].(map[string]any)
	if _, ok := caps["roots"]; ok {
		t.Fatalf("the host's roots capability reached the server: %v", caps)
	}
	if _, ok := caps["sampling"]; !ok {
		t.Fatalf("other client capabilities must pass unchanged: %v", caps)
	}
	if fwd["id"].(float64) != 0 || params["clientInfo"].(map[string]any)["name"] != "host" {
		t.Fatalf("the rest of initialize must pass unchanged: %v", fwd)
	}

	// A server that asks anyway gets an error from the gate; the host never
	// sees the request.
	h.g.fromServer([]byte(`{"jsonrpc":"2.0","id":"r1","method":"roots/list"}`))
	got := h.server.waitFor(t, 2)
	reply := decode(t, got[1])
	if reply["id"] != "r1" || reply["error"] == nil {
		t.Fatalf("roots/list must be answered with an error by the gate, got %s", got[1])
	}

	h.g.fromHost([]byte(`{"jsonrpc":"2.0","method":"notifications/roots/list_changed"}`))
	h.g.fromHost([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	got = h.server.waitFor(t, 3)
	if len(got) != 3 || !strings.Contains(got[2], "notifications/initialized") {
		t.Fatalf("a roots change must be dropped while other notifications pass: %v", got)
	}
	if lines := h.host.snapshot(); len(lines) != 0 {
		t.Fatalf("the host must see nothing of the server's roots request, got %v", lines)
	}
}

func TestGate_InitializeWithoutRootsPassesVerbatim(t *testing.T) {
	h := newGateHarness(t)
	line := `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"capabilities":{"sampling":{}}}}`
	h.g.fromHost([]byte(line))
	if got := h.server.waitFor(t, 1); got[0] != line {
		t.Fatalf("an initialize with no roots must be forwarded byte for byte, got %v", got)
	}
}

// An initialize whose params the gate cannot read could be carrying roots,
// so it does not reach the server.
func TestGate_UnreadableInitializeIsRefused(t *testing.T) {
	h := newGateHarness(t)
	h.g.fromHost([]byte(`{"jsonrpc":"2.0","id":5,"method":"initialize","params":{"capabilities":"roots"}}`))
	m := decode(t, h.host.waitFor(t, 1)[0])
	if m["id"].(float64) != 5 || m["error"] == nil {
		t.Fatalf("expected an error reply to the host, got %v", m)
	}
	if lines := h.server.snapshot(); len(lines) != 0 {
		t.Fatalf("an unreadable initialize must not reach the server, got %v", lines)
	}
}

func TestReadLine_LargeMessagesAndCap(t *testing.T) {
	big := `{"jsonrpc":"2.0","id":1,"result":{"text":"` + strings.Repeat("x", 200<<10) + `"}}`
	br := bufio.NewReaderSize(strings.NewReader(big+"\r\n"+`{"id":2}`), 4096)
	line, err := readLine(br, MaxMessageBytes)
	if err != nil || string(line) != big {
		t.Fatalf("200 KiB line not read intact: err=%v len=%d", err, len(line))
	}
	line, err = readLine(br, MaxMessageBytes)
	if err != nil || string(line) != `{"id":2}` {
		t.Fatalf("final unterminated line lost: %q %v", line, err)
	}
	if _, err := readLine(br, MaxMessageBytes); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
	over := bufio.NewReader(bytes.NewReader(append(bytes.Repeat([]byte("y"), 1024), '\n')))
	if _, err := readLine(over, 512); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("over-cap line not refused: %v", err)
	}
}
