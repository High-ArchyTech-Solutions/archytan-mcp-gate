// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

// Package tracectx reads the W3C Trace Context traceparent header
// (https://www.w3.org/TR/trace-context/), so the gate's log lines can carry
// the trace of the agent that asked. It only reads: the gate starts no spans
// and sends nothing anywhere.
//
// Parsing is strict on purpose. Only version 00 is accepted, and a value the
// gate can't read exactly is ignored rather than repaired. It never affects
// a decision. Every byte is checked against the version-00 layout before any
// of it is kept, so a header carrying uppercase hex, spaces, CR or LF, or any
// other control character never reaches a log line.
package tracectx

import "net/http"

// HeaderName is the header this package reads.
const HeaderName = "traceparent"

// headerLen is the exact length of a version-00 traceparent:
// version(2) - trace-id(32) - parent-id(16) - flags(2), with three dashes.
const headerLen = 55

// Context is the part of a caller's trace context the gate records. The zero
// value means the request carried no usable traceparent.
type Context struct {
	// TraceID is 32 lowercase hex characters, never all zeros.
	TraceID string
	// ParentID is the caller's span: 16 lowercase hex characters, never all
	// zeros.
	ParentID string
}

// Valid reports whether c came from a traceparent that parsed.
func (c Context) Valid() bool { return c.TraceID != "" }

// Parse reads one traceparent value. It reports false, and returns the zero
// Context, for anything that is not a version-00 value in exactly the W3C
// layout.
func Parse(v string) (Context, bool) {
	if len(v) != headerLen {
		return Context{}, false
	}
	for i := 0; i < headerLen; i++ {
		c := v[i]
		switch i {
		case 2, 35, 52:
			if c != '-' {
				return Context{}, false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return Context{}, false
			}
		}
	}
	if v[:2] != "00" {
		return Context{}, false
	}
	traceID, parentID := v[3:35], v[36:52]
	if allZeros(traceID) || allZeros(parentID) {
		return Context{}, false
	}
	return Context{TraceID: traceID, ParentID: parentID}, true
}

// FromHeader reads the traceparent in h. A missing header, a malformed one,
// or more than one (the field is not a list) gives the zero Context.
func FromHeader(h http.Header) Context {
	vs := h.Values(HeaderName)
	if len(vs) != 1 {
		return Context{}
	}
	c, _ := Parse(vs[0])
	return c
}

func allZeros(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '0' {
			return false
		}
	}
	return true
}
