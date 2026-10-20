// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package mcpgate_e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// modernParams builds 2026-07-28 request params: the given fields plus the
// _meta every request carries under that revision, from a host that
// declares roots and an extension, as hosts with a workspace do.
func modernParams(fields map[string]any) map[string]any {
	params := map[string]any{"_meta": map[string]any{
		"io.modelcontextprotocol/protocolVersion": "2026-07-28",
		"io.modelcontextprotocol/clientInfo":      map[string]any{"name": "e2e", "version": "1"},
		"io.modelcontextprotocol/clientCapabilities": map[string]any{
			"roots":       map[string]any{"listChanged": true},
			"extensions":  map[string]any{"io.modelcontextprotocol/tasks": map[string]any{}},
			"elicitation": map[string]any{},
		},
	}}
	for k, v := range fields {
		params[k] = v
	}
	return params
}

func resultOf(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	res, ok := m["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", m)
	}
	return res
}

func assertCompleteRefusal(t *testing.T, m map[string]any, wantText string) {
	t.Helper()
	res := resultOf(t, m)
	content, _ := res["content"].([]any)
	if res["isError"] != true || res["resultType"] != "complete" || len(content) == 0 {
		t.Fatalf("not a complete tool refusal: %v", res)
	}
	if text, _ := content[0].(map[string]any)["text"].(string); !strings.HasPrefix(text, "Refused by Archytan Lite") || !strings.Contains(text, wantText) {
		t.Fatalf("refusal text %q does not contain %q", text, wantText)
	}
	if _, ok := res["inputRequests"]; ok {
		t.Fatalf("the server's input requests reached the host: %v", res)
	}
}

// TestGate_ModernSessionEndToEnd runs a 2026-07-28 session through the
// real gate: no initialize, server/discover first, and a host that restates
// its roots on every request. The calls are decided by archytan-lite as in
// the handshake era, and nothing the server receives names the host's
// roots.
func TestGate_ModernSessionEndToEnd(t *testing.T) {
	e := setup(t)
	seen := filepath.Join(e.dir, "seen.log")
	s := e.startGate(t, e.liteURL, "FAKE_SERVER_SEEN_LOG="+seen)

	caps := resultOf(t, s.request("server/discover", modernParams(nil)))["capabilities"].(map[string]any)
	for _, gone := range []string{"resources", "extensions"} {
		if _, ok := caps[gone]; ok {
			t.Fatalf("the server's %s reached the host: %v", gone, caps)
		}
	}
	if _, ok := caps["tools"]; !ok {
		t.Fatalf("tools capability lost: %v", caps)
	}

	var names []string
	for _, tl := range resultOf(t, s.request("tools/list", modernParams(nil)))["tools"].([]any) {
		names = append(names, tl.(map[string]any)["name"].(string))
	}
	if strings.Join(names, ",") != "delete_invoice,read_invoice,delete_tenant" {
		t.Fatalf("agent saw tools %v", names)
	}

	call := func(name string, args map[string]any, extra map[string]any) map[string]any {
		fields := map[string]any{"name": name, "arguments": args}
		for k, v := range extra {
			fields[k] = v
		}
		return s.request("tools/call", modernParams(fields))
	}
	res := resultOf(t, call("delete_invoice", map[string]any{"invoice_id": "inv_7"}, nil))
	if res["isError"] == true || !strings.Contains(string(mustJSON(t, res)), "executed delete_invoice") {
		t.Fatalf("allowed call failed: %v", res)
	}
	assertCompleteRefusal(t, call("delete_tenant", map[string]any{"tenant_id": "t_1"}, nil), "")
	assertCompleteRefusal(t, call("drop_database", map[string]any{"invoice_id": "x"}, nil), "not permitted")
	assertCompleteRefusal(t, call("delete_invoice", map[string]any{"invoice_id": "inv_8"}, map[string]any{
		"inputResponses": map[string]any{"roots": map[string]any{"roots": []any{map[string]any{"uri": "file:///home/agent"}}}},
		"requestState":   "round-1",
	}), "roots are not available")
	if got := e.executedCalls(t); len(got) != 1 {
		t.Fatalf("want only the allowed call executed, got %v", got)
	}

	raw, err := os.ReadFile(seen)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	for _, l := range lines {
		var m struct {
			Params struct {
				Meta           map[string]json.RawMessage `json:"_meta"`
				InputResponses any                        `json:"inputResponses"`
			} `json:"params"`
		}
		var caps map[string]any
		if json.Unmarshal([]byte(l), &m) != nil || json.Unmarshal(m.Params.Meta["io.modelcontextprotocol/clientCapabilities"], &caps) != nil {
			t.Fatalf("server received a message without readable client capabilities: %q", l)
		}
		if _, ok := caps["roots"]; ok {
			t.Fatalf("the host's roots reached the server: %s", l)
		}
		if _, ok := caps["extensions"]; ok {
			t.Fatalf("the host's extensions reached the server: %s", l)
		}
		if _, ok := caps["elicitation"]; !ok {
			t.Fatalf("other client capabilities must reach the server: %s", l)
		}
		if m.Params.InputResponses != nil {
			t.Fatalf("a roots answer reached the server: %s", l)
		}
	}
	if len(lines) != 3 {
		t.Fatalf("want discover, tools/list and one tools/call at the server, got %d: %v", len(lines), lines)
	}
}

// A server that asks for roots anyway gets nothing: the host is told the
// call was refused and never sees the request its SDK would answer.
func TestGate_ModernServerAskingForRootsIsRefused(t *testing.T) {
	e := setup(t)
	s := e.startGate(t, e.liteURL, "FAKE_SERVER_ASK_ROOTS=1")
	m := s.request("tools/call", modernParams(map[string]any{"name": "delete_invoice", "arguments": map[string]any{"invoice_id": "inv_7"}}))
	assertCompleteRefusal(t, m, "roots are not available")
	if got := e.executedCalls(t); len(got) != 0 {
		t.Fatalf("the server executed a call it asked roots for: %v", got)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
