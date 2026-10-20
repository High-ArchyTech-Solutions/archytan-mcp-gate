// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package mcpgate

import (
	"strings"
	"testing"
	"time"
)

// TestGate_AmbiguousKeysAreRefused covers messages that read two ways. Each
// one is refused whole: nothing reaches the server and nothing is
// authorized, since the gate can't know which reading the server takes.
func TestGate_AmbiguousKeysAreRefused(t *testing.T) {
	cases := map[string]string{
		// Routed as an ungated tools/list by a case-insensitive reader, run
		// as tools/call by a server that reads keys exactly.
		"method and Method":       `{"jsonrpc":"2.0","id":1,"method":"tools/call","Method":"tools/list","params":{"name":"drop_database","arguments":{"invoice_id":"x"}}}`,
		"Method and method":       `{"jsonrpc":"2.0","id":1,"Method":"tools/list","method":"tools/call","params":{"name":"drop_database","arguments":{"invoice_id":"x"}}}`,
		"params and Params":       `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_invoice","arguments":{"invoice_id":"x"}},"Params":{"name":"drop_database","arguments":{}}}`,
		"name and Name":           `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"drop_database","Name":"delete_invoice","arguments":{"invoice_id":"inv_9"}}}`,
		"arguments and Arguments": `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_invoice","arguments":{"invoice_id":"inv_1"},"Arguments":{"invoice_id":"inv_2"}}}`,
		// Within arguments a model chooses the keys: a tool server in Go
		// reads Invoice_ID into an invoice_id field.
		"argument case":        `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_invoice","arguments":{"invoice_id":"inv_1","Invoice_ID":"inv_2"}}}`,
		"argument long s":      `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_invoice","arguments":{"invoice_id":"inv_1","status":"a","ſtatus":"b"}}}`,
		"argument kelvin":      `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_invoice","arguments":{"invoice_id":"inv_1","kind":"a","Kind":"b"}}}`,
		"repeated id":          `{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/call","params":{"name":"delete_invoice","arguments":{"invoice_id":"x"}}}`,
		"repeated name":        `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_invoice","name":"delete_invoice","arguments":{"invoice_id":"x"}}}`,
		"repeated argument":    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_invoice","arguments":{"invoice_id":"inv_1","invoice_id":"inv_2"}}}`,
		"escaped repeat":       `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_invoice","\u006eame":"delete_invoice","arguments":{"invoice_id":"x"}}}`,
		"escaped long s":       `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_invoice","arguments":{"invoice_id":"inv_1","status":"a","\u017ftatus":"b"}}}`,
		"escaped kelvin":       `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_invoice","arguments":{"invoice_id":"inv_1","kind":"a","\u212aind":"b"}}}`,
		"on a pass-through":    `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"cursor":"a","Cursor":"b"}}`,
		"on an ungated method": `{"jsonrpc":"2.0","id":1,"method":"resources/read","Method":"tools/list"}`,
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			h := newGateHarness(t)
			h.g.fromHost([]byte(line))
			m := decode(t, h.host.waitFor(t, 1)[0])
			e, ok := m["error"].(map[string]any)
			if !ok || e["code"].(float64) != -32600 || !strings.Contains(e["message"].(string), "repeat or differ only in case") {
				t.Fatalf("not refused as ambiguous: %v", m)
			}
			time.Sleep(50 * time.Millisecond)
			if got := h.server.snapshot(); len(got) != 0 {
				t.Fatalf("an ambiguous message reached the server: %v", got)
			}
			if a, _ := h.auth.counts(); a != 0 {
				t.Fatal("an ambiguous message reached authorization")
			}
		})
	}
}

func TestGate_AmbiguousNotificationIsDropped(t *testing.T) {
	h := newGateHarness(t)
	h.g.fromHost([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized","Method":"tools/call"}`))
	h.g.fromHost([]byte(`{"jsonrpc":"2.0","id":"s1","result":{},"Result":{"roots":[]}}`))
	time.Sleep(50 * time.Millisecond)
	if got := h.server.snapshot(); len(got) != 0 {
		t.Fatalf("an ambiguous message reached the server: %v", got)
	}
	if got := h.host.snapshot(); len(got) != 0 {
		t.Fatalf("a notification or response must not be answered: %v", got)
	}
}

// Keys that only look alike pass, and the gate looks no deeper than the
// arguments: what a tool does with a nested object is the tool's.
func TestGate_DistinctKeysPass(t *testing.T) {
	h := newGateHarness(t)
	line := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_invoice","arguments":{"invoice_id":"inv_7","invoice_id2":"x","Invoice":"y","ß":1,"ss":2,"filter":{"a":1,"A":2}}}}`
	h.g.fromHost([]byte(line))
	if got := h.server.waitFor(t, 1)[0]; got != line {
		t.Fatalf("forwarded bytes changed:\n got %s\nwant %s", got, line)
	}
}

// foldKey must agree with strings.EqualFold, which is how encoding/json
// matches keys to struct fields, including the runes outside ASCII that
// fold onto ASCII letters.
func TestFoldKey_AgreesWithEqualFold(t *testing.T) {
	runes := []string{"a", "A", "k", "K", "K", "s", "S", "ſ", "i", "I", "ı", "İ",
		"å", "Å", "Å", "σ", "ς", "Σ", "µ", "μ", "Μ", "ß", "ẞ", "ss", "_", "1"}
	for _, a := range runes {
		for _, b := range runes {
			x, y := "key_"+a, "key_"+b
			if (foldKey(x) == foldKey(y)) != strings.EqualFold(x, y) {
				t.Errorf("foldKey(%q) == foldKey(%q) is %v, EqualFold says %v", x, y, foldKey(x) == foldKey(y), strings.EqualFold(x, y))
			}
		}
	}
}

// A server in Go reads "Roots" into its roots field, so the handshake's
// roots go whatever their spelling.
func TestGate_InitializeRootsOfAnySpellingAreStripped(t *testing.T) {
	h := newGateHarness(t)
	h.g.fromHost([]byte(`{"jsonrpc":"2.0","id":0,"method":"initialize","Params":{"Capabilities":{"Roots":{"listChanged":true},"sampling":{}}}}`))
	got := h.server.waitFor(t, 1)[0]
	if strings.Contains(got, "Roots") || !strings.Contains(got, "sampling") {
		t.Fatalf("roots must go and the rest stay: %s", got)
	}
}

// Go's encoding/json turns invalid UTF-8 and unpaired surrogates into
// U+FFFD; JavaScript keeps each one distinct. A host message carrying
// either is refused, wherever it is.
func TestGate_AmbiguousTextIsRefused(t *testing.T) {
	call := func(arg string) string {
		return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_invoice","arguments":{"invoice_id":` + arg + `}}}`
	}
	cases := map[string]string{
		"lone high surrogate":        call(`"inv_\ud800"`),
		"lone low surrogate":         call(`"inv_\udfff"`),
		"upper-case hex":             call(`"inv_\uD800"`),
		"high then a letter":         call(`"inv_\ud800\u0041"`),
		"high then a raw letter":     call(`"inv_\ud800A"`),
		"high then a raw low":        call("\"inv_\\ud800\xed\xb0\x80\""),
		"high then high":             call(`"inv_\ud800\ud800"`),
		"high at the end":            call(`"\ud800"`),
		"low then high":              call(`"inv_\udc00\ud800"`),
		"in a key":                   `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_invoice","arguments":{"invoice_id":"x","k\udfff":"y"}}}`,
		"deep in an argument":        call(`"x","note":{"text":["\ud800"]}`),
		"in the tool name":           `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_invoice\ud800","arguments":{}}}`,
		"invalid UTF-8":              call("\"inv_\xe2\x82\""),
		"encoded surrogate in UTF-8": call("\"inv_\xed\xa0\x80\""),
		"overlong UTF-8":             call("\"inv_\xc0\xaf\""),
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			h := newGateHarness(t)
			h.g.fromHost([]byte(line))
			m := decode(t, h.host.waitFor(t, 1)[0])
			e, ok := m["error"].(map[string]any)
			if !ok || e["code"].(float64) != -32600 || !strings.Contains(e["message"].(string), "unpaired surrogate") {
				t.Fatalf("not refused: %v", m)
			}
			time.Sleep(50 * time.Millisecond)
			if got := h.server.snapshot(); len(got) != 0 {
				t.Fatalf("ambiguous text reached the server: %v", got)
			}
			if a, _ := h.auth.counts(); a != 0 {
				t.Fatal("ambiguous text reached authorization")
			}
		})
	}
}

// Text with one reading passes byte for byte, including escapes that only
// look like a surrogate.
func TestGate_UnambiguousTextPasses(t *testing.T) {
	for name, arg := range map[string]string{
		"pair":                    `"inv_\ud83d\ude00"`,
		"upper-case pair":         `"inv_\uD83D\uDE00"`,
		"raw emoji":               "\"inv_\U0001F600\"",
		"accented":                `"inv_\u00e9 caf` + "\u00e9" + `"`,
		"escaped backslash":       `"inv_\\ud800"`,
		"two escaped backslashes": `"inv_\\\\ud800"`,
		"quote then u":            `"inv_\"ud800"`,
		"near the surrogates":     `"inv_\ud7ff\ue000\uffff"`,
	} {
		t.Run(name, func(t *testing.T) {
			h := newGateHarness(t)
			line := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_invoice","arguments":{"invoice_id":` + arg + `}}}`
			h.g.fromHost([]byte(line))
			if got := h.server.waitFor(t, 1)[0]; got != line {
				t.Fatalf("forwarded bytes changed:\n got %s\nwant %s", got, line)
			}
		})
	}
}
