// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package mcpgate_e2e

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

// rawRequest writes one line to the gate as the host and returns the reply
// with the given id. It exists for messages json.Marshal can't produce,
// like an object with two keys that differ only in case.
func (s *session) rawRequest(id int, line string) map[string]any {
	s.t.Helper()
	if _, err := s.stdin.Write([]byte(line + "\n")); err != nil {
		s.t.Fatalf("write to gate: %v", err)
	}
	timeout := time.After(10 * time.Second)
	for {
		select {
		case l, ok := <-s.lines:
			if !ok {
				s.t.Fatal("gate closed stdout")
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(l), &m); err != nil {
				s.t.Fatalf("gate wrote non-JSON to the host: %.200q", l)
			}
			if fmt.Sprint(m["id"]) == strconv.Itoa(id) {
				return m
			}
		case <-timeout:
			s.t.Fatalf("no reply to %s", line)
		}
	}
}

// TestGate_AmbiguousKeysNeverReachTheServer puts the real gate in front of
// a tool server that reads keys exactly, as one in JavaScript or Python
// does. Each message reads one way to a case-insensitive reader and
// another way to that server; the 2.5.0 gate ran drop_database on the
// first without asking archytan-lite, and on the second spent a
// delete_invoice capability on it.
func TestGate_AmbiguousKeysNeverReachTheServer(t *testing.T) {
	e := setup(t)
	s := e.startGate(t, e.liteURL, "FAKE_SERVER_EXACT_KEYS=1")
	s.request("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "e2e"}})

	for id, line := range map[int]string{
		101: `{"jsonrpc":"2.0","id":101,"method":"tools/call","Method":"tools/list","params":{"name":"drop_database","arguments":{"invoice_id":"x"}}}`,
		102: `{"jsonrpc":"2.0","id":102,"method":"tools/call","params":{"name":"drop_database","Name":"delete_invoice","arguments":{"invoice_id":"inv_9"}}}`,
		103: `{"jsonrpc":"2.0","id":103,"method":"tools/call","params":{"name":"delete_invoice","arguments":{"invoice_id":"inv_1"},"Arguments":{"invoice_id":"inv_2"}}}`,
	} {
		m := s.rawRequest(id, line)
		e, ok := m["error"].(map[string]any)
		if !ok || !strings.Contains(fmt.Sprint(e["message"]), "repeat or differ only in case") {
			t.Fatalf("request %d not refused as ambiguous: %v", id, m)
		}
	}
	if got := e.executedCalls(t); len(got) != 0 {
		t.Fatalf("the server executed an ambiguous call: %v", got)
	}

	// The same server still runs a plain call the gate allows.
	if isErr, text := s.callTool("delete_invoice", map[string]any{"invoice_id": "inv_7"}); isErr || text != "executed delete_invoice" {
		t.Fatalf("allowed call failed: %v %q", isErr, text)
	}
	if got := e.executedCalls(t); len(got) != 1 || !strings.HasPrefix(got[0], "delete_invoice ") {
		t.Fatalf("want one delete_invoice executed, got %v", got)
	}
}
