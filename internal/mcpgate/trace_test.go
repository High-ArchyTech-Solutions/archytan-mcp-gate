// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package mcpgate

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/high-archytech-solutions/archytan-mcp-gate/internal/receipt"
)

const (
	testTraceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	testTraceID     = "4bf92f3577b34da6a3ce929d0e0e4736"
)

func callWithMeta(id, tool, meta string) []byte {
	return []byte(`{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":"` + tool + `","arguments":{"invoice_id":"inv_1"},"_meta":` + meta + `}}`)
}

// traceSeen records the traceparent each authorize and redeem was given.
type traceSeen struct {
	mu  sync.Mutex
	got []string
}

func (s *traceSeen) watch(a *fakeAuth) {
	a.authorizeFn = func(ctx context.Context, action, uid, rtype, rid string) (Grant, error) {
		s.add("authorize " + traceparentFrom(ctx))
		return Grant{ReceiptID: "rcpt_1", CapabilityToken: "cap", Action: action, ResourceType: rtype, ResourceID: rid}, nil
	}
	a.redeemFn = func(ctx context.Context, g Grant) error {
		s.add("redeem " + traceparentFrom(ctx))
		return nil
	}
}

func (s *traceSeen) add(v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, v)
}

func (s *traceSeen) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.got...)
}

// logSink is a logf that keeps every line.
type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSink) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

// waitFor returns the first line starting with prefix, waiting a little
// for the worker to log it.
func (l *logSink) waitFor(t *testing.T, prefix string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		l.mu.Lock()
		for _, line := range l.lines {
			if strings.HasPrefix(line, prefix) {
				l.mu.Unlock()
				return line
			}
		}
		l.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no log line starting %q", prefix)
	return ""
}

func (l *logSink) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func newLoggedHarness(t *testing.T) (*harness, *logSink) {
	t.Helper()
	logs := &logSink{}
	h := &harness{host: &sink{}, server: &sink{}, auth: &fakeAuth{}}
	h.g = New(testConfig(t), h.auth, h.host, h.server, logs.logf)
	go h.g.RunWorker()
	t.Cleanup(h.g.Close)
	return h, logs
}

// The traceparent a tools/call carries in params._meta (SEP-414) goes with
// both requests the gate makes for that call, and the call reaches the
// tool server byte for byte, _meta included.
func TestGate_TraceparentInMetaGoesWithAuthorizeAndRedeem(t *testing.T) {
	h, logs := newLoggedHarness(t)
	seen := &traceSeen{}
	seen.watch(h.auth)
	line := callWithMeta("1", "delete_invoice", `{"traceparent":"`+testTraceparent+`","tracestate":"vendor=opaque"}`)
	h.g.fromHost(line)
	if got := h.server.waitFor(t, 1); got[0] != string(line) {
		t.Fatalf("forwarded bytes changed:\n got %s\nwant %s", got[0], line)
	}
	want := []string{"authorize " + testTraceparent, "redeem " + testTraceparent}
	if got := seen.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("trace context reached %q, want %q", got, want)
	}
	if l := logs.waitFor(t, "ALLOWED"); !strings.Contains(l, "otel_trace_id="+testTraceID) {
		t.Fatalf("the ALLOWED line should name the agent's trace: %s", l)
	}
}

// A refusal names the trace too, so the agent's span and the gate's
// refusal can be put side by side.
func TestGate_RefusalLogNamesTheTrace(t *testing.T) {
	h, logs := newLoggedHarness(t)
	h.g.fromHost(callWithMeta("2", "drop_tables", `{"traceparent":"`+testTraceparent+`"}`))
	h.host.waitFor(t, 1)
	if l := logs.waitFor(t, "REFUSED"); !strings.Contains(l, "otel_trace_id="+testTraceID) {
		t.Fatalf("the REFUSED line should name the agent's trace: %s", l)
	}
}

// Anything but a well-formed version-00 traceparent is dropped: the call
// still goes through exactly as it would have, no trace context reaches
// the gate's requests, and nothing from the bad value reaches a log line.
func TestGate_ABadTraceparentIsIgnoredAndTheCallGoesOn(t *testing.T) {
	cases := map[string]string{
		"uppercase hex":      `{"traceparent":"00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01"}`,
		"unknown version":    `{"traceparent":"01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}`,
		"zero trace id":      `{"traceparent":"00-00000000000000000000000000000000-00f067aa0ba902b7-01"}`,
		"zero parent id":     `{"traceparent":"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01"}`,
		"header injection":   `{"traceparent":"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nX-Injected: 1"}`,
		"trailing data":      `{"traceparent":"` + testTraceparent + `-extra"}`,
		"padded":             `{"traceparent":" ` + testTraceparent + `"}`,
		"not a string":       `{"traceparent":12345}`,
		"null value":         `{"traceparent":null}`,
		"a list":             `{"traceparent":["` + testTraceparent + `"]}`,
		"other key case":     `{"Traceparent":"` + testTraceparent + `"}`,
		"meta is a string":   `"` + testTraceparent + `"`,
		"meta is null":       `null`,
		"meta is an array":   `[{"traceparent":"` + testTraceparent + `"}]`,
		"empty meta":         `{}`,
		"injection, key too": `{"traceparent\r\nX-Injected":"` + testTraceparent + `"}`,
	}
	for name, meta := range cases {
		t.Run(name, func(t *testing.T) {
			h, logs := newLoggedHarness(t)
			seen := &traceSeen{}
			seen.watch(h.auth)
			line := callWithMeta("1", "delete_invoice", meta)
			h.g.fromHost(line)
			if got := h.server.waitFor(t, 1); got[0] != string(line) {
				t.Fatalf("the call must go through unchanged:\n got %s\nwant %s", got[0], line)
			}
			if got, want := seen.snapshot(), []string{"authorize ", "redeem "}; !reflect.DeepEqual(got, want) {
				t.Fatalf("no trace context should reach the gate, got %q", got)
			}
			logs.waitFor(t, "ALLOWED")
			if all := logs.all(); strings.Contains(all, "otel_trace_id") || strings.Contains(all, "X-Injected") || strings.Contains(all, "\r") {
				t.Fatalf("nothing from a bad traceparent may reach the log:\n%s", all)
			}
		})
	}
}

// traceparentOf itself keeps only a value the gate would read, and the
// trace id that goes in the log lines comes from that same parse.
func TestTraceparentOf(t *testing.T) {
	tp, trace := traceparentOf([]byte(`{"traceparent":"` + testTraceparent + `"}`))
	if tp != testTraceparent || trace.TraceID != testTraceID || trace.ParentID != "00f067aa0ba902b7" {
		t.Fatalf("traceparentOf = %q, %+v", tp, trace)
	}
	for _, meta := range []string{
		`{"traceparent":"` + strings.ToUpper(testTraceparent) + `"}`,
		`{"traceparent":"` + testTraceparent + `\r\nX-Injected: 1"}`,
		`{"traceparent":7}`,
		`"` + testTraceparent + `"`,
		``,
	} {
		if tp, trace := traceparentOf([]byte(meta)); tp != "" || trace.Valid() {
			t.Errorf("traceparentOf(%s) = %q, %+v", meta, tp, trace)
		}
	}
}

// Only a value the gate itself would read is attached, whoever asks.
func TestWithTraceparent_AttachesOnlyAValidValue(t *testing.T) {
	for _, bad := range []string{"", "garbage", strings.ToUpper(testTraceparent), testTraceparent + "\r\nX-Injected: 1"} {
		if got := traceparentFrom(withTraceparent(context.Background(), bad)); got != "" {
			t.Errorf("withTraceparent(%q) attached %q", bad, got)
		}
	}
	if got := traceparentFrom(withTraceparent(context.Background(), testTraceparent)); got != testTraceparent {
		t.Fatalf("a valid traceparent was not attached: %q", got)
	}
}

// headerLog records the traceparent header of each request a fake gate
// receives.
type headerLog struct {
	mu  sync.Mutex
	got []string
}

func (l *headerLog) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vs := r.Header.Values("traceparent")
		l.mu.Lock()
		l.got = append(l.got, fmt.Sprintf("%s %d %s", r.URL.Path, len(vs), strings.Join(vs, "|")))
		l.mu.Unlock()
		h.ServeHTTP(w, r)
	})
}

func (l *headerLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.got...)
}

// The client sends the agent's traceparent as the header the gate reads,
// on both requests, and sends no header at all without one.
func TestGateClient_SendsTheAgentsTraceparentHeader(t *testing.T) {
	for _, tc := range []struct {
		name string
		ctx  context.Context
		want string // header count and value
	}{
		{"with a trace", withTraceparent(context.Background(), testTraceparent), "1 " + testTraceparent},
		{"without", context.Background(), "0 "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeLite{decision: receipt.DecisionAllow, capability: true}
			log := &headerLog{}
			srv := httptest.NewServer(log.wrap(f.handler(t)))
			t.Cleanup(srv.Close)
			c := &GateClient{BaseURL: srv.URL, Token: "agent-token", PublicKey: testKey.Public().(ed25519.PublicKey)}
			g, err := c.Authorize(tc.ctx, "invoice.delete", "agent-invoices", "invoice", "inv_1")
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Redeem(tc.ctx, g); err != nil {
				t.Fatal(err)
			}
			want := []string{"/v1/authorize " + tc.want, "/v1/redeem " + tc.want}
			if got := log.snapshot(); !reflect.DeepEqual(got, want) {
				t.Fatalf("headers seen %q, want %q", got, want)
			}
		})
	}
}
