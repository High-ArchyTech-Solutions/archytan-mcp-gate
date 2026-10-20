// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package mcpgate

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Tests for MCP 2026-07-28, where a host restates its capabilities in
// params._meta on every message and a server gets input from the host by
// answering a call with input_required.

const modernVersion = `"io.modelcontextprotocol/protocolVersion":"2026-07-28"`

// modernMeta is a 2026-07-28 _meta whose client capabilities are caps.
func modernMeta(caps string) string {
	return `{` + modernVersion + `,"io.modelcontextprotocol/clientInfo":{"name":"host","version":"1"},"io.modelcontextprotocol/clientCapabilities":` + caps + `,"traceparent":"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}`
}

// modernCallLine is a tools/call for delete_invoice made under 2026-07-28
// rules, with extra top-level params appended when given.
func modernCallLine(id, caps, extra string) []byte {
	return []byte(`{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":"delete_invoice","arguments":{"invoice_id":"inv_7"},"_meta":` + modernMeta(caps) + extra + `}}`)
}

const hostCaps = `{"roots":{"listChanged":true},"extensions":{"io.modelcontextprotocol/tasks":{}},"sampling":{},"elicitation":{"form":{}}}`

// clientCapsOf returns the client capabilities a forwarded message carried.
func clientCapsOf(t *testing.T, line string) map[string]any {
	t.Helper()
	params := decode(t, line)["params"].(map[string]any)
	meta := params["_meta"].(map[string]any)
	if meta["io.modelcontextprotocol/protocolVersion"] != "2026-07-28" || meta["traceparent"] == nil || meta["io.modelcontextprotocol/clientInfo"] == nil {
		t.Fatalf("the rest of _meta must pass unchanged: %v", meta)
	}
	return meta["io.modelcontextprotocol/clientCapabilities"].(map[string]any)
}

func assertHostCapsSanitized(t *testing.T, line string) {
	t.Helper()
	caps := clientCapsOf(t, line)
	for _, gone := range []string{"roots", "extensions"} {
		if _, ok := caps[gone]; ok {
			t.Fatalf("client capability %q reached the server: %v", gone, caps)
		}
	}
	for _, kept := range []string{"sampling", "elicitation"} {
		if _, ok := caps[kept]; !ok {
			t.Fatalf("client capability %q must pass unchanged: %v", kept, caps)
		}
	}
}

// TestModern_HostRootsNeverReachTheServer is the scope guarantee of
// TestGate_HostRootsNeverReachTheServer, for hosts that skip initialize:
// whichever message restates the host's capabilities, the server never
// learns the host has roots (or extensions).
func TestModern_HostRootsNeverReachTheServer(t *testing.T) {
	cases := map[string]string{
		"tools/list":           `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":` + modernMeta(hostCaps) + `}}`,
		"server/discover":      `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":` + modernMeta(hostCaps) + `}}`,
		"subscriptions/listen": `{"jsonrpc":"2.0","id":3,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},"_meta":` + modernMeta(hostCaps) + `}}`,
		"ping":                 `{"jsonrpc":"2.0","id":4,"method":"ping","params":{"_meta":` + modernMeta(hostCaps) + `}}`,
		"initialize":           `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"capabilities":{},"_meta":` + modernMeta(hostCaps) + `}}`,
		"notification":         `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":1,"progress":1,"_meta":` + modernMeta(hostCaps) + `}}`,
		"cancellation":         `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":99,"_meta":` + modernMeta(hostCaps) + `}}`,
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			h := newGateHarness(t)
			h.g.fromHost([]byte(line))
			assertHostCapsSanitized(t, h.server.waitFor(t, 1)[0])
		})
	}
	t.Run("tools/call", func(t *testing.T) {
		h := newGateHarness(t)
		h.g.fromHost(modernCallLine(`7`, hostCaps, ""))
		got := h.server.waitFor(t, 1)[0]
		assertHostCapsSanitized(t, got)
		params := decode(t, got)["params"].(map[string]any)
		if params["name"] != "delete_invoice" || params["arguments"].(map[string]any)["invoice_id"] != "inv_7" {
			t.Fatalf("the call itself must pass unchanged: %v", params)
		}
		if h.auth.authorized[0] != "invoice.delete agent-invoices invoice inv_7" {
			t.Fatalf("authorized the wrong thing: %v", h.auth.authorized)
		}
	})
}

// A message with nothing to strip reaches the server byte for byte.
func TestModern_MessageWithNothingToStripPassesVerbatim(t *testing.T) {
	for name, line := range map[string]string{
		"tools/call":         string(modernCallLine(`7`, `{"sampling":{}}`, "")),
		"tools/list":         `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":` + modernMeta(`{}`) + `}}`,
		"null caps":          `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/clientCapabilities":null}}}`,
		"meta not an object": `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":"opaque"}}`,
		"listen, tools only": `{"jsonrpc":"2.0","id":3,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			h := newGateHarness(t)
			h.g.fromHost([]byte(line))
			if got := h.server.waitFor(t, 1)[0]; got != line {
				t.Fatalf("forwarded bytes changed:\n got %s\nwant %s", got, line)
			}
		})
	}
}

// Client capabilities the gate cannot read could be declaring roots, so
// the message carrying them does not reach the server, and a tools/call
// carrying them spends nothing.
func TestModern_UnreadableClientCapabilitiesAreRefused(t *testing.T) {
	for _, caps := range []string{`"roots"`, `["roots"]`, `1`, `true`} {
		t.Run(caps, func(t *testing.T) {
			h := newGateHarness(t)
			h.g.fromHost(modernCallLine(`1`, caps, ""))
			h.g.fromHost([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":` + modernMeta(caps) + `}}`))
			h.g.fromHost([]byte(`{"jsonrpc":"2.0","id":3,"method":"server/discover","params":{"_meta":` + modernMeta(caps) + `}}`))
			h.g.fromHost([]byte(`{"jsonrpc":"2.0","method":"notifications/progress","params":{"_meta":` + modernMeta(caps) + `}}`))
			for _, l := range h.host.waitFor(t, 3) {
				m := decode(t, l)
				if e, ok := m["error"].(map[string]any); !ok || e["code"].(float64) != -32602 {
					t.Fatalf("not an invalid-params error: %s", l)
				}
			}
			time.Sleep(50 * time.Millisecond)
			if got := h.server.snapshot(); len(got) != 0 {
				t.Fatalf("an unreadable message reached the server: %v", got)
			}
			if a, _ := h.auth.counts(); a != 0 {
				t.Fatal("a call with unreadable capabilities reached authorization")
			}
		})
	}
	t.Run("params not an object", func(t *testing.T) {
		h := newGateHarness(t)
		h.g.fromHost([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":["roots"]}`))
		if m := decode(t, h.host.waitFor(t, 1)[0]); m["error"] == nil {
			t.Fatalf("not an error: %v", m)
		}
		if got := h.server.snapshot(); len(got) != 0 {
			t.Fatalf("unreadable params reached the server: %v", got)
		}
	})
}

// A cancellation the gate cannot relay still stops a call it holds.
func TestModern_UnrelayableCancellationStillStopsTheCall(t *testing.T) {
	h := newGateHarness(t)
	started, stopped := make(chan struct{}), make(chan struct{})
	h.auth.authorizeFn = func(ctx context.Context, action, uid, rtype, rid string) (Grant, error) {
		close(started)
		<-ctx.Done()
		close(stopped)
		return Grant{}, ctx.Err()
	}
	h.g.fromHost(modernCallLine(`"c1"`, `{}`, ""))
	<-started
	h.g.fromHost([]byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"c1","_meta":` + modernMeta(`"roots"`) + `}}`))
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("the cancellation did not stop the call")
	}
	time.Sleep(50 * time.Millisecond)
	if _, r := h.auth.counts(); r != 0 {
		t.Fatal("a cancelled call's capability was redeemed")
	}
	if got := h.server.snapshot(); len(got) != 0 {
		t.Fatalf("something reached the server: %v", got)
	}
}

// assertModernRefusal checks a refusal of a call made under 2026-07-28
// rules: a complete tool result, isError set, naming the roots rule.
func assertModernRefusal(t *testing.T, line, wantID string) {
	t.Helper()
	assertRefusal(t, line, wantID)
	result := decode(t, line)["result"].(map[string]any)
	if result["resultType"] != "complete" {
		t.Fatalf("a refusal of a 2026-07-28 call must say resultType complete: %s", line)
	}
	if !strings.Contains(line, "roots are not available through the Archytan gate") {
		t.Fatalf("the refusal must say why: %s", line)
	}
}

// TestModern_ServerAskingForRootsIsRefused covers a server that asks for
// roots anyway, through input_required. The host must never see the
// request: its SDK would answer with the host's folders on the retry.
func TestModern_ServerAskingForRootsIsRefused(t *testing.T) {
	cases := map[string]string{
		"roots only":            `{"resultType":"input_required","inputRequests":{"r":{"method":"roots/list"}}}`,
		"beside an elicitation": `{"resultType":"input_required","inputRequests":{"e":{"method":"elicitation/create","params":{"message":"ok?"}},"r":{"method":"roots/list","params":{}}},"requestState":"s1"}`,
		"no resultType":         `{"inputRequests":{"r":{"method":"roots/list"}}}`,
		"resultType complete":   `{"resultType":"complete","content":[],"inputRequests":{"r":{"method":"roots/list"}}}`,
		"inputRequests a list":  `{"resultType":"input_required","inputRequests":[{"method":"roots/list"}]}`,
		"entry not an object":   `{"resultType":"input_required","inputRequests":{"r":"roots/list"}}`,
		"entry without method":  `{"resultType":"input_required","inputRequests":{"r":{"params":{}}}}`,
		"method not a string":   `{"resultType":"input_required","inputRequests":{"r":{"method":["roots/list"]}}}`,
	}
	for name, result := range cases {
		t.Run(name, func(t *testing.T) {
			h := newGateHarness(t)
			h.g.fromHost(modernCallLine(`8`, `{}`, ""))
			h.server.waitFor(t, 1)
			h.g.fromServer([]byte(`{"jsonrpc":"2.0","id":8,"result":` + result + `}`))
			got := h.host.waitFor(t, 1)
			assertModernRefusal(t, got[0], `8`)
			if strings.Contains(got[0], "inputRequests") {
				t.Fatalf("the server's input requests reached the host: %s", got[0])
			}
		})
	}
}

// Input requests the gate lets through (elicitation, sampling) reach the
// host unchanged, so a 2026-07-28 server can still ask the user to
// confirm.
func TestModern_OtherInputRequestsPassThrough(t *testing.T) {
	h := newGateHarness(t)
	h.g.fromHost(modernCallLine(`8`, `{"elicitation":{"form":{}}}`, ""))
	h.server.waitFor(t, 1)
	reply := `{"jsonrpc":"2.0","id":8,"result":{"resultType":"input_required","inputRequests":{"confirm":{"method":"elicitation/create","params":{"message":"Delete inv_7?","requestedSchema":{"type":"object","properties":{}}}},"s":{"method":"sampling/createMessage","params":{"messages":[],"maxTokens":1}}},"requestState":"opaque"}}`
	h.g.fromServer([]byte(reply))
	if got := h.host.waitFor(t, 1)[0]; got != reply {
		t.Fatalf("input_required must reach the host unchanged:\n got %s\nwant %s", got, reply)
	}
}

// TestModern_RootsInInputResponsesAreRefused covers the other half of the
// round trip. The gate never relays a roots/list, so a retry answering one
// is unsolicited; it is refused before authorization, so it spends nothing.
func TestModern_RootsInInputResponsesAreRefused(t *testing.T) {
	for name, responses := range map[string]string{
		"bare":    `{"r":{"roots":[{"uri":"file:///home/me"}]}}`,
		"wrapped": `{"r":{"method":"roots/list","result":{"roots":[{"uri":"file:///home/me"}]}}}`,
		"empty":   `{"r":{"roots":[]}}`,
		"escaped": `{"r":{"\u0072oots":[{"uri":"file:///home/me"}]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			h := newGateHarness(t)
			h.g.fromHost(modernCallLine(`9`, `{}`, `,"inputResponses":`+responses+`,"requestState":"s1"`))
			assertModernRefusal(t, h.host.waitFor(t, 1)[0], `9`)
			time.Sleep(50 * time.Millisecond)
			if a, _ := h.auth.counts(); a != 0 {
				t.Fatal("a retry carrying roots reached authorization")
			}
			if got := h.server.snapshot(); len(got) != 0 {
				t.Fatalf("a retry carrying roots reached the server: %v", got)
			}
		})
	}
	t.Run("on a request the gate does not gate", func(t *testing.T) {
		h := newGateHarness(t)
		h.g.fromHost([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"inputResponses":{"r":{"roots":[]}}}}`))
		m := decode(t, h.host.waitFor(t, 1)[0])
		if e, ok := m["error"].(map[string]any); !ok || !strings.Contains(e["message"].(string), "roots are not available") {
			t.Fatalf("expected the roots refusal, got %v", m)
		}
		if got := h.server.snapshot(); len(got) != 0 {
			t.Fatalf("roots reached the server: %v", got)
		}
	})
	t.Run("unreadable", func(t *testing.T) {
		h := newGateHarness(t)
		h.g.fromHost(modernCallLine(`9`, `{}`, `,"inputResponses":["roots"]`))
		if m := decode(t, h.host.waitFor(t, 1)[0]); m["error"] == nil {
			t.Fatalf("not an error: %v", m)
		}
		if a, _ := h.auth.counts(); a != 0 {
			t.Fatal("unreadable inputResponses reached authorization")
		}
	})
}

// Answers to the input requests the gate relays pass, and each round of a
// multi-round-trip call is authorized and spent on its own: every round
// the gate forwards is one the server may act on.
func TestModern_RetryWithOtherAnswersIsGatedLikeAnyCall(t *testing.T) {
	h := newGateHarness(t)
	h.g.fromHost(modernCallLine(`10`, `{}`, ""))
	h.server.waitFor(t, 1)
	retry := modernCallLine(`11`, `{}`, `,"inputResponses":{"confirm":{"action":"accept","content":{"roots":"a field of the user's answer"}}},"requestState":"s1"`)
	h.g.fromHost(retry)
	if got := h.server.waitFor(t, 2)[1]; got != string(retry) {
		t.Fatalf("the retry must be forwarded unchanged:\n got %s\nwant %s", got, retry)
	}
	if a, r := h.auth.counts(); a != 2 || r != 2 {
		t.Fatalf("each round must be authorized and redeemed: %d/%d", a, r)
	}
}

// A notification may use the name inputResponses for something else; only
// requests carry answers to input requests.
func TestModern_NotificationsKeepInputResponses(t *testing.T) {
	h := newGateHarness(t)
	line := `{"jsonrpc":"2.0","method":"notifications/vendor","params":{"inputResponses":{"r":{"roots":[]}}}}`
	h.g.fromHost([]byte(line))
	if got := h.server.waitFor(t, 1)[0]; got != line {
		t.Fatalf("notification changed: %s", got)
	}
}

func TestModern_DiscoverStripsUngatedCapabilities(t *testing.T) {
	h := newGateHarness(t)
	h.g.fromHost([]byte(`{"jsonrpc":"2.0","id":"d1","method":"server/discover","params":{"_meta":` + modernMeta(`{}`) + `}}`))
	h.server.waitFor(t, 1)
	h.g.fromServer([]byte(`{"jsonrpc":"2.0","id":"d1","result":{"resultType":"complete","supportedVersions":["2026-07-28","2025-11-25"],"capabilities":{"tools":{"listChanged":true},"resources":{},"prompts":{},"completions":{},"logging":{},"extensions":{"io.modelcontextprotocol/tasks":{}}},"instructions":"x","ttlMs":0}}`))
	result := decode(t, h.host.waitFor(t, 1)[0])["result"].(map[string]any)
	caps := result["capabilities"].(map[string]any)
	for _, gone := range []string{"resources", "prompts", "completions", "extensions"} {
		if _, ok := caps[gone]; ok {
			t.Fatalf("capability %q was not stripped: %v", gone, caps)
		}
	}
	if _, ok := caps["tools"]; !ok {
		t.Fatalf("tools capability was stripped: %v", caps)
	}
	if result["resultType"] != "complete" || len(result["supportedVersions"].([]any)) != 2 || result["instructions"] != "x" {
		t.Fatalf("the rest of the result must pass unchanged: %v", result)
	}
}

// server/discover answered by a server that predates it reaches the host
// as the server sent it, so the host falls back to initialize.
func TestModern_DiscoverErrorReachesTheHost(t *testing.T) {
	h := newGateHarness(t)
	h.g.fromHost([]byte(`{"jsonrpc":"2.0","id":1,"method":"server/discover"}`))
	h.server.waitFor(t, 1)
	reply := `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`
	h.g.fromServer([]byte(reply))
	if got := h.host.waitFor(t, 1)[0]; got != reply {
		t.Fatalf("got %s", got)
	}
}

func TestModern_ListenIsNarrowedToToolChanges(t *testing.T) {
	h := newGateHarness(t)
	h.g.fromHost([]byte(`{"jsonrpc":"2.0","id":3,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true,"promptsListChanged":true,"resourcesListChanged":true,"resourceSubscriptions":["file:///etc/passwd"]}}}`))
	params := decode(t, h.server.waitFor(t, 1)[0])["params"].(map[string]any)
	filter := params["notifications"].(map[string]any)
	if len(filter) != 1 || filter["toolsListChanged"] != true {
		t.Fatalf("the listen filter must keep only tool list changes: %v", filter)
	}
	h.g.fromHost([]byte(`{"jsonrpc":"2.0","id":4,"method":"subscriptions/listen","params":{"notifications":["resourcesListChanged"]}}`))
	if m := decode(t, h.host.waitFor(t, 1)[0]); m["error"] == nil {
		t.Fatalf("an unreadable filter must be refused: %v", m)
	}
	if got := h.server.snapshot(); len(got) != 1 {
		t.Fatalf("an unreadable filter reached the server: %v", got)
	}
}

// The gate's refusals follow the rules of the call they answer: a
// 2026-07-28 client rejects a result without a resultType.
func TestModern_RefusalsNameTheirResultType(t *testing.T) {
	h := newGateHarness(t)
	h.auth.authorizeFn = func(context.Context, string, string, string, string) (Grant, error) {
		return Grant{}, errDenied
	}
	h.g.fromHost(modernCallLine(`1`, `{}`, ""))
	h.g.fromHost(callLine(`2`, "delete_invoice", `"inv_7"`))
	got := h.host.waitFor(t, 2)
	if decode(t, got[0])["result"].(map[string]any)["resultType"] != "complete" {
		t.Fatalf("a refusal of a 2026-07-28 call must say resultType complete: %s", got[0])
	}
	if _, ok := decode(t, got[1])["result"].(map[string]any)["resultType"]; ok {
		t.Fatalf("a refusal of an older call must keep its old shape: %s", got[1])
	}
	assertRefusal(t, got[0], `1`)
	assertRefusal(t, got[1], `2`)
}

var errDenied = denied("the gate did not allow this action")

type denied string

func (d denied) Error() string { return string(d) }

// The methods 2026-07-28 removed or that need a capability the gate
// strips stay refused.
func TestModern_UngatedMethodsStayRefused(t *testing.T) {
	for _, method := range []string{"tasks/get", "tasks/result", "resources/read", "prompts/get", "completion/complete"} {
		t.Run(method, func(t *testing.T) {
			h := newGateHarness(t)
			h.g.fromHost([]byte(`{"jsonrpc":"2.0","id":"m","method":"` + method + `","params":{"_meta":` + modernMeta(`{}`) + `}}`))
			var m struct {
				Error struct {
					Code int `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal([]byte(h.host.waitFor(t, 1)[0]), &m); err != nil || m.Error.Code != -32601 {
				t.Fatalf("expected method not found, got %v", h.host.snapshot())
			}
			if got := h.server.snapshot(); len(got) != 0 {
				t.Fatalf("an ungated method reached the server: %v", got)
			}
		})
	}
}

// A server or host written in Go reads JSON keys without regard to case
// ("Roots" decodes into a roots field), so every check above must hold for
// any spelling of the keys it looks at.
func TestModern_KeysAreMatchedWithoutRegardToCase(t *testing.T) {
	t.Run("client capabilities", func(t *testing.T) {
		h := newGateHarness(t)
		line := `{"jsonrpc":"2.0","id":2,"method":"tools/list","Params":{"_META":{"io.modelcontextprotocol/ClientCapabilities":{"Roots":{},"ROOTS":{},"Extensions":{},"sampling":{}}}}}`
		h.g.fromHost([]byte(line))
		got := h.server.waitFor(t, 1)[0]
		for _, gone := range []string{"Roots", "ROOTS", "Extensions"} {
			if strings.Contains(got, `"`+gone+`"`) {
				t.Fatalf("client capability %q reached the server: %s", gone, got)
			}
		}
		if !strings.Contains(got, `"sampling"`) {
			t.Fatalf("other capabilities must pass: %s", got)
		}
	})
	t.Run("roots answer", func(t *testing.T) {
		for _, responses := range []string{
			`"InputResponses":{"r":{"roots":[]}}`,
			`"inputResponses":{"r":{"Roots":[]}}`,
			`"inputResponses":{"r":{"method":"roots/list","Result":{"ROOTS":[]}}}`,
		} {
			h := newGateHarness(t)
			h.g.fromHost(modernCallLine(`9`, `{}`, `,`+responses))
			assertModernRefusal(t, h.host.waitFor(t, 1)[0], `9`)
			if a, _ := h.auth.counts(); a != 0 {
				t.Fatalf("%s reached authorization", responses)
			}
		}
	})
	t.Run("server asking", func(t *testing.T) {
		for _, reply := range []string{
			`{"jsonrpc":"2.0","id":8,"result":{"InputRequests":{"r":{"method":"roots/list"}}}}`,
			`{"jsonrpc":"2.0","id":8,"result":{"inputRequests":{"r":{"Method":"roots/list"}}}}`,
			`{"jsonrpc":"2.0","id":8,"result":{"inputRequests":{"r":{"method":"Roots/List"}}}}`,
			`{"jsonrpc":"2.0","id":8,"Result":{"resultType":"input_required","inputRequests":{"r":{"method":"roots/list"}}}}`,
			`{"jsonrpc":"2.0","id":8,"result":{"resultType":"complete","content":[]},"Result":{"inputRequests":{"r":{"method":"roots/list"}}}}`,
		} {
			h := newGateHarness(t)
			h.g.fromHost(modernCallLine(`8`, `{}`, ""))
			h.server.waitFor(t, 1)
			h.g.fromServer([]byte(reply))
			assertModernRefusal(t, h.host.waitFor(t, 1)[0], `8`)
		}
	})
	t.Run("listen filter", func(t *testing.T) {
		h := newGateHarness(t)
		h.g.fromHost([]byte(`{"jsonrpc":"2.0","id":3,"method":"subscriptions/listen","params":{"Notifications":{"ToolsListChanged":true,"ResourcesListChanged":true}}}`))
		got := h.server.waitFor(t, 1)[0]
		if strings.Contains(got, "ResourcesListChanged") || !strings.Contains(got, "ToolsListChanged") {
			t.Fatalf("the listen filter must keep only tool list changes: %s", got)
		}
	})
	t.Run("protocol version", func(t *testing.T) {
		h := newGateHarness(t)
		h.g.fromHost([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"drop_database","arguments":{},"_meta":{"io.modelcontextprotocol/ProtocolVersion":"2026-07-28"}}}`))
		if decode(t, h.host.waitFor(t, 1)[0])["result"].(map[string]any)["resultType"] != "complete" {
			t.Fatalf("a 2026-07-28 call must get a complete refusal: %v", h.host.snapshot())
		}
	})
}
