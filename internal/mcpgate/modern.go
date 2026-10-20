// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package mcpgate

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// MCP 2026-07-28 drops the initialize handshake. A client restates its
// protocol version and capabilities in params._meta on every message,
// learns what a server offers from server/discover, and no longer takes
// requests from the server: a server that needs something from the client
// (elicitation, sampling, roots) answers a call with an input_required
// result, and the client fulfils it and retries the call with
// inputResponses. The gate holds the same lines here as it does for the
// handshake: the host's roots never reach the server, a server asking for
// them is refused, and the server advertises only what the gate relays.
const (
	discoverMethod            = "server/discover"
	listenMethod              = "subscriptions/listen"
	protocolVersionMetaKey    = "io.modelcontextprotocol/protocolVersion"
	clientCapabilitiesMetaKey = "io.modelcontextprotocol/clientCapabilities"
)

// Client capabilities removed from a message's _meta before it reaches the
// server: roots, for the reason initialize loses them, and extensions,
// because a server that takes one up (tasks, for one) can answer a call
// with something the host then has to fetch through methods the gate
// refuses.
var strippedClientCapabilities = []string{rootsCapability, "extensions"}

// Server capabilities stripped from a server/discover result: the ones
// stripped from initialize, plus the server's extensions.
var strippedDiscoverCapabilities = append(append([]string(nil), strippedCapabilities...), "extensions")

// The notification types a subscriptions/listen may ask the server for.
// Resources and prompts don't pass the gate, so neither do their changes.
var listenNotifications = []string{"toolsListChanged"}

// errHostRoots refuses a request whose inputResponses answer a roots/list.
var errHostRoots = errors.New(rootsUnavailableErrorMsg)

// keysFolding returns the keys of m equal to key under case folding, in
// order. Wherever the code below looks for a key, it takes every one of
// these: Go's encoding/json matches struct fields that way, so a server or
// host written in Go reads "Roots" as roots, while JavaScript and Python
// read keys exactly. Taking both means no reader finds what the gate
// passed over.
func keysFolding(m map[string]json.RawMessage, key string) []string {
	var keys []string
	for k := range m {
		if strings.EqualFold(k, key) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// sanitizeForServer prepares a host message for the tool server. It
// removes strippedClientCapabilities from the client capabilities in
// params._meta and narrows a subscriptions/listen to tool list changes;
// for a request it also refuses inputResponses that carry a roots listing
// (errHostRoots). Params it cannot check are an error, since forwarding
// them unchecked could hand the server what the gate removes. A message
// with nothing to remove comes back byte for byte. modern reports whether
// the message was made under 2026-07-28 rules (its _meta names a protocol
// version), so a reply the gate writes itself can follow them.
func sanitizeForServer(line []byte, method string, isRequest bool) (out []byte, modern bool, err error) {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(line, &env); err != nil {
		return nil, false, err
	}
	changed := false
	for _, pk := range keysFolding(env, "params") {
		params, paramsChanged, paramsModern, err := sanitizeParams(env[pk], method, isRequest)
		modern = modern || paramsModern
		if err != nil {
			return nil, modern, err
		}
		if paramsChanged {
			env[pk] = params
			changed = true
		}
	}
	if !changed {
		return line, modern, nil
	}
	out, err = json.Marshal(env)
	return out, modern, err
}

func sanitizeParams(raw json.RawMessage, method string, isRequest bool) (out json.RawMessage, changed, modern bool, err error) {
	if string(raw) == "null" {
		return raw, false, false, nil
	}
	var params map[string]json.RawMessage
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, false, false, fmt.Errorf("params: %w", err)
	}
	for _, mk := range keysFolding(params, "_meta") {
		meta, metaChanged, metaModern, err := sanitizeMeta(params[mk])
		modern = modern || metaModern
		if err != nil {
			return nil, false, modern, err
		}
		if metaChanged {
			params[mk] = meta
			changed = true
		}
	}
	// inputResponses and requestState are reserved on requests only; a
	// notification may use the same names for something else.
	if isRequest {
		for _, rk := range keysFolding(params, "inputResponses") {
			if err := checkInputResponses(params[rk]); err != nil {
				return nil, false, modern, err
			}
		}
	}
	if method == listenMethod && isRequest {
		for _, nk := range keysFolding(params, "notifications") {
			filter, filterChanged, err := narrowListen(params[nk])
			if err != nil {
				return nil, false, modern, err
			}
			if filterChanged {
				params[nk] = filter
				changed = true
			}
		}
	}
	if !changed {
		return raw, false, modern, nil
	}
	out, err = json.Marshal(params)
	return out, err == nil, modern, err
}

// sanitizeMeta removes strippedClientCapabilities from a _meta's client
// capabilities. A _meta that isn't an object carries no capabilities and
// is left for the server to reject; client capabilities that aren't an
// object are an error.
func sanitizeMeta(raw json.RawMessage) (out json.RawMessage, changed, modern bool, err error) {
	var meta map[string]json.RawMessage
	if json.Unmarshal(raw, &meta) != nil || meta == nil {
		return raw, false, false, nil
	}
	modern = len(keysFolding(meta, protocolVersionMetaKey)) > 0
	for _, ck := range keysFolding(meta, clientCapabilitiesMetaKey) {
		if string(meta[ck]) == "null" {
			continue
		}
		var caps map[string]json.RawMessage
		if err := json.Unmarshal(meta[ck], &caps); err != nil {
			return nil, false, modern, fmt.Errorf("client capabilities: %w", err)
		}
		removed := false
		for _, name := range strippedClientCapabilities {
			for _, k := range keysFolding(caps, name) {
				delete(caps, k)
				removed = true
			}
		}
		if !removed {
			continue
		}
		capsJSON, err := json.Marshal(caps)
		if err != nil {
			return nil, false, modern, err
		}
		meta[ck] = capsJSON
		changed = true
	}
	if !changed {
		return raw, false, modern, nil
	}
	out, err = json.Marshal(meta)
	return out, err == nil, modern, err
}

// checkInputResponses refuses a retry that answers a roots/list. The gate
// never relays one to the host, so the answer is unsolicited, and a server
// that read it would take the host's folders. An entry counts as a roots
// listing if it has a roots member, bare or inside a {method, result}
// wrapper: a roots member is how the SDKs recognise one.
func checkInputResponses(raw json.RawMessage) error {
	if string(raw) == "null" {
		return nil
	}
	var responses map[string]json.RawMessage
	if err := json.Unmarshal(raw, &responses); err != nil {
		return fmt.Errorf("inputResponses: %w", err)
	}
	for _, r := range responses {
		var resp map[string]json.RawMessage
		if json.Unmarshal(r, &resp) != nil {
			continue // an entry that isn't an object can't hold a roots listing
		}
		if len(keysFolding(resp, "roots")) > 0 {
			return errHostRoots
		}
		for _, rk := range keysFolding(resp, "result") {
			var wrapped map[string]json.RawMessage
			if json.Unmarshal(resp[rk], &wrapped) == nil && len(keysFolding(wrapped, "roots")) > 0 {
				return errHostRoots
			}
		}
	}
	return nil
}

// narrowListen keeps only the listenNotifications in a subscriptions/listen
// filter. A filter that isn't an object is an error.
func narrowListen(raw json.RawMessage) (json.RawMessage, bool, error) {
	if string(raw) == "null" {
		return raw, false, nil
	}
	var filter map[string]json.RawMessage
	if err := json.Unmarshal(raw, &filter); err != nil {
		return nil, false, fmt.Errorf("notifications: %w", err)
	}
	kept := map[string]json.RawMessage{}
	for _, name := range listenNotifications {
		for _, k := range keysFolding(filter, name) {
			kept[k] = filter[k]
		}
	}
	if len(kept) == len(filter) {
		return raw, false, nil
	}
	out, err := json.Marshal(kept)
	return out, err == nil, err
}

// asksForRoots reports whether a server's response asks the host for
// roots. Under 2026-07-28 a server does that by answering with
// input_required and a roots/list among its inputRequests, which the
// host's SDK fulfils with its folders on the retry. Every response is
// checked, whatever request it answers and whatever its resultType says,
// so no reading of it can carry a roots request past the gate;
// inputRequests the gate cannot read count as asking.
func asksForRoots(line []byte) bool {
	var env map[string]json.RawMessage
	if json.Unmarshal(line, &env) != nil {
		return false
	}
	for _, rk := range keysFolding(env, "result") {
		var res map[string]json.RawMessage
		if json.Unmarshal(env[rk], &res) != nil {
			continue
		}
		for _, ik := range keysFolding(res, "inputRequests") {
			if inputRequestsAskForRoots(res[ik]) {
				return true
			}
		}
	}
	return false
}

func inputRequestsAskForRoots(raw json.RawMessage) bool {
	if string(raw) == "null" {
		return false
	}
	var requests map[string]json.RawMessage
	if json.Unmarshal(raw, &requests) != nil {
		return true
	}
	for _, r := range requests {
		var req map[string]json.RawMessage
		if json.Unmarshal(r, &req) != nil {
			return true
		}
		methods := keysFolding(req, "method")
		if len(methods) == 0 {
			return true
		}
		for _, mk := range methods {
			var method string
			if json.Unmarshal(req[mk], &method) != nil || strings.EqualFold(method, rootsListMethod) {
				return true
			}
		}
	}
	return false
}
