// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package tracectx

import (
	"net/http"
	"strings"
	"testing"
)

// The example from the W3C Trace Context specification.
const valid = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

func TestParse_Valid(t *testing.T) {
	c, ok := Parse(valid)
	if !ok || !c.Valid() {
		t.Fatalf("the specification's own example was refused")
	}
	if c.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" || c.ParentID != "00f067aa0ba902b7" {
		t.Fatalf("wrong ids: %+v", c)
	}
	// Any flags value is legal.
	if _, ok := Parse(valid[:53] + "00"); !ok {
		t.Fatal("unsampled flags refused")
	}
}

func TestParse_RefusesEverythingElse(t *testing.T) {
	for name, v := range map[string]string{
		"empty":                "",
		"uppercase trace id":   strings.Replace(valid, "4bf92f", "4BF92F", 1),
		"uppercase flags":      valid[:53] + "0A",
		"version 01":           "01" + valid[2:],
		"version ff":           "ff" + valid[2:],
		"all-zero trace id":    "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
		"all-zero parent id":   "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
		"one character short":  valid[:54],
		"one character long":   valid + "0",
		"trailing field":       valid + "-00",
		"wrong separator":      strings.Replace(valid, "-", "_", 1),
		"space":                strings.Replace(valid, "4bf9", "4bf ", 1),
		"leading space":        " " + valid[1:],
		"CRLF injection":       valid[:51] + "\r\n01",
		"newline in the id":    strings.Replace(valid, "4b", "\n4", 1),
		"tab":                  strings.Replace(valid, "-01", "\t01", 1),
		"non-hex letter":       strings.Replace(valid, "4bf9", "4bg9", 1),
		"non-ASCII":            strings.Replace(valid, "4b", "\xc3\xa9", 1),
		"NUL":                  strings.Replace(valid, "4b", "\x004", 1),
		"separators misplaced": "004-bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-1",
	} {
		if c, ok := Parse(v); ok || c.Valid() {
			t.Errorf("%s: %q was accepted as %+v", name, v, c)
		}
	}
}

func TestFromHeader(t *testing.T) {
	h := http.Header{}
	if FromHeader(h).Valid() {
		t.Fatal("no header produced a context")
	}
	h.Set("Traceparent", valid)
	if c := FromHeader(h); c.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("header not read: %+v", c)
	}
	// The field is not a list: two values are ambiguous, so neither is used.
	h.Add("traceparent", "00-11111111111111111111111111111111-2222222222222222-01")
	if FromHeader(h).Valid() {
		t.Fatal("two traceparent headers produced a context")
	}
	// A comma-joined pair arrives as one value and fails the layout.
	h = http.Header{}
	h.Set("traceparent", valid+","+valid)
	if FromHeader(h).Valid() {
		t.Fatal("a comma-joined pair produced a context")
	}
}

func BenchmarkParse(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, ok := Parse(valid); !ok {
			b.Fatal("refused")
		}
	}
}
