// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package mcpgate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/high-archytech-solutions/archytan-mcp-gate/v2/internal/receipt"
)

const holdPolicyHash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

// fakeHoldLite plays an Archytan Lite 2.9.0 gate that holds an action: a
// 202 with a signed HOLD receipt, a hold to read, and, once approved, a 200
// that resolves it. The fields at the top break one thing each.
type fakeHoldLite struct {
	// openPolls is how many reads answer "open" before the hold takes
	// finalState.
	openPolls  int
	finalState string
	expiresIn  time.Duration // default ten minutes
	collect    int           // status of the collecting authorize; default 200

	// What the 202 gets wrong.
	rawHold      string             // sent as the 202 body instead
	holdMutate   func(*holdBody)    // edits the 202 body
	holdResource string             // the HOLD receipt is minted for this resource id
	holdSigner   ed25519.PrivateKey // signs the HOLD receipt instead of testKey
	holdIdem     string             // the HOLD receipt is signed under this key instead
	holdDecision string             // the 202 receipt is validly signed with this decision instead of HOLD

	// What the collecting 200 gets wrong.
	resolveIdem     func(idem, holdID string) string // key the resolution is signed under
	resolveResource string                           // resolution is for this resource id
	resolveTenant   string                           // resolution is for this tenant
	resolveSigner   ed25519.PrivateKey
	hrResource      string // hold_receipt is for this resource id
	hrIdem          string // hold_receipt is signed under this key
	hrDecision      string // hold_receipt is minted with this decision
	otherHold       bool   // hold_receipt is another, validly signed, HOLD
	hrFlipSig       bool   // hold_receipt is the real one with its signature broken
	viewHoldID      string // the hold view names this hold instead
	resolveAction   string // resolution is for this action
	resolveType     string // resolution is for this resource type
	resolveSigned   string // resolution receipt is validly signed with this decision
	noHoldReceipt   bool
	noCapability    bool
	emptyToken      bool
	resolveDecision string // top-level decision of the collecting 200

	mu          sync.Mutex
	holds       int
	authorizes  int
	polls       int
	keys        []string
	holdReceipt receipt.Receipt
	idem        string
	state       string
	lastRedeem  map[string]string
}

type holdBody struct {
	Decision string          `json:"decision"`
	Receipt  receipt.Receipt `json:"receipt"`
	Hold     *holdInfo       `json:"hold,omitempty"`
}

type holdInfo struct {
	HoldID    string `json:"hold_id"`
	ExpiresAt string `json:"expires_at"`
}

func mintHoldTest(t *testing.T, key ed25519.PrivateKey, decision, action, rtype, rid, tenant, actor, role, caller, idem string) receipt.Receipt {
	t.Helper()
	r, err := receipt.MintV2(key, receipt.V2Fields{
		OperatorURN: "urn:test", TraceID: "trc_0011223344556677", Decision: decision,
		Action: action, ResourceType: rtype, ResourceID: rid, ResourceTenantID: tenant,
		ActorUID: actor, ActorRole: role, CallerID: caller, Mode: receipt.ModeEnforce,
		PolicySHA256: holdPolicyHash, IdempotencyKey: idem,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (f *fakeHoldLite) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer agent-token" {
			t.Errorf("missing bearer token on %s", r.URL.Path)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.URL.Path == "/v1/authorize":
			var req struct {
				Action   string            `json:"action"`
				Actor    map[string]string `json:"actor"`
				Resource map[string]string `json:"resource"`
				Idem     string            `json:"idempotency_key"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode authorize: %v", err)
				return
			}
			f.authorizes++
			f.keys = append(f.keys, req.Idem)
			if f.idem != req.Idem {
				f.newHold(t, req.Action, req.Resource["type"], req.Resource["id"], req.Actor["uid"], req.Idem)
			}
			if f.state == "open" || f.state == "" {
				f.reply(t, w, http.StatusAccepted, f.holdResponse(t))
				return
			}
			if f.state != "approved" {
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "the gate refused"})
				return
			}
			if f.collect != 0 && f.collect != http.StatusOK {
				w.WriteHeader(f.collect)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "gone"})
				return
			}
			f.reply(t, w, http.StatusOK, f.resolution(t))
		case strings.HasPrefix(r.URL.Path, "/v1/holds/"):
			f.polls++
			if f.polls > f.openPolls && f.finalState != "" {
				f.state = f.finalState
			}
			state := f.state
			if state == "" {
				state = "open"
			}
			id := strings.TrimPrefix(r.URL.Path, "/v1/holds/")
			if id != f.holdReceipt.ReceiptID {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			viewID := id
			if f.viewHoldID != "" {
				viewID = f.viewHoldID
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"hold_id": viewID, "state": state})
		case r.URL.Path == "/v1/redeem":
			_ = json.NewDecoder(r.Body).Decode(&f.lastRedeem)
			_ = json.NewEncoder(w).Encode(map[string]string{"decision": receipt.DecisionAllow})
		}
	})
}

func (f *fakeHoldLite) newHold(t *testing.T, action, rtype, rid, actor, idem string) {
	f.holds++
	f.idem = idem
	f.state = "open"
	mintRID, key, signIdem := rid, testKey, idem
	if f.holdResource != "" {
		mintRID = f.holdResource
	}
	if f.holdSigner != nil {
		key = f.holdSigner
	}
	if f.holdIdem != "" {
		signIdem = f.holdIdem
	}
	dec := receipt.DecisionHold
	if f.holdDecision != "" {
		dec = f.holdDecision
	}
	f.holdReceipt = mintHoldTest(t, key, dec, action, rtype, mintRID, "acme", actor, "billing_agent", "agent-caller", signIdem)
}

func (f *fakeHoldLite) holdResponse(t *testing.T) any {
	exp := f.expiresIn
	if exp == 0 {
		exp = 10 * time.Minute
	}
	b := holdBody{
		Decision: receipt.DecisionHold,
		Receipt:  f.holdReceipt,
		Hold:     &holdInfo{HoldID: f.holdReceipt.ReceiptID, ExpiresAt: time.Now().Add(exp).UTC().Format(time.RFC3339Nano)},
	}
	if f.holdMutate != nil {
		f.holdMutate(&b)
	}
	return b
}

func (f *fakeHoldLite) resolution(t *testing.T) any {
	h := f.holdReceipt
	rid, tenant, key := h.ResourceID, h.ResourceTenantID, testKey
	if f.resolveResource != "" {
		rid = f.resolveResource
	}
	if f.resolveTenant != "" {
		tenant = f.resolveTenant
	}
	if f.resolveSigner != nil {
		key = f.resolveSigner
	}
	signIdem := "hold:" + h.ReceiptID
	if f.resolveIdem != nil {
		signIdem = f.resolveIdem(f.idem, h.ReceiptID)
	}
	act, rtype, dec := h.Action, h.ResourceType, receipt.DecisionAllow
	if f.resolveAction != "" {
		act = f.resolveAction
	}
	if f.resolveType != "" {
		rtype = f.resolveType
	}
	if f.resolveSigned != "" {
		dec = f.resolveSigned
	}
	res := mintHoldTest(t, key, dec, act, rtype, rid, tenant, "maria", "supervisor", "approver", signIdem)

	hr := h
	switch {
	case f.hrResource != "" || f.hrIdem != "" || f.hrDecision != "":
		id, dec, idem := h.ResourceID, receipt.DecisionHold, f.idem
		if f.hrResource != "" {
			id = f.hrResource
		}
		if f.hrDecision != "" {
			dec = f.hrDecision
		}
		if f.hrIdem != "" {
			idem = f.hrIdem
		}
		hr = mintHoldTest(t, testKey, dec, h.Action, h.ResourceType, id, h.ResourceTenantID, h.ActorUID, h.ActorRole, h.CallerID, idem)
	case f.otherHold:
		hr = mintHoldTest(t, testKey, receipt.DecisionHold, h.Action, h.ResourceType, h.ResourceID, h.ResourceTenantID, h.ActorUID, h.ActorRole, h.CallerID, f.idem)
		res = mintHoldTest(t, testKey, receipt.DecisionAllow, h.Action, h.ResourceType, h.ResourceID, h.ResourceTenantID, "maria", "supervisor", "approver", "hold:"+hr.ReceiptID)
	}
	if f.hrFlipSig {
		hr.Signature = strings.Repeat("0", 128)
	}
	body := map[string]any{"decision": receipt.DecisionAllow, "receipt": res}
	if f.resolveDecision != "" {
		body["decision"] = f.resolveDecision
	}
	if !f.noHoldReceipt {
		body["hold_receipt"] = hr
	}
	if !f.noCapability {
		token := "held-cap-token"
		if f.emptyToken {
			token = ""
		}
		body["capability"] = map[string]string{"token": token, "cap_id": "cap_1"}
	}
	return body
}

func (f *fakeHoldLite) reply(t *testing.T, w http.ResponseWriter, status int, body any) {
	if status == http.StatusAccepted && f.rawHold != "" {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(f.rawHold))
		return
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (f *fakeHoldLite) client(t *testing.T, wait time.Duration) *GateClient {
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	return &GateClient{
		BaseURL: srv.URL, Token: "agent-token", PublicKey: testKey.Public().(ed25519.PublicKey),
		HoldWait: wait, holdPoll: 10 * time.Millisecond,
	}
}

func (f *fakeHoldLite) holdID() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.holdReceipt.ReceiptID
}

func authorizeHeldAction(c *GateClient) (Grant, error) {
	return c.Authorize(context.Background(), "payment.refund", "agent-payments", "payment", "pay_9")
}

// An approved hold is collected with the key the call started with, and the
// grant it yields is redeemed like any other.
func TestHold_ApprovedIsCollectedWithTheSameKey(t *testing.T) {
	f := &fakeHoldLite{openPolls: 2, finalState: "approved"}
	c := f.client(t, 5*time.Second)
	g, err := authorizeHeldAction(c)
	if err != nil {
		t.Fatalf("an approved hold was refused: %v", err)
	}
	if g.CapabilityToken != "held-cap-token" || g.Action != "payment.refund" || g.ResourceID != "pay_9" || g.ReceiptID == f.holdID() {
		t.Fatalf("grant wrong: %+v", g)
	}
	if f.holds != 1 || f.authorizes != 2 || f.keys[0] != f.keys[1] {
		t.Fatalf("holds=%d authorizes=%d keys=%v: the approval must be collected once, with the first key", f.holds, f.authorizes, f.keys)
	}
	if f.polls < 3 {
		t.Fatalf("it stopped reading the hold after %d reads, while it was open", f.polls)
	}
	if err := c.Redeem(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	if f.lastRedeem["token"] != "held-cap-token" || f.lastRedeem["resource_id"] != "pay_9" {
		t.Fatalf("redeemed the wrong scope: %v", f.lastRedeem)
	}
}

// A hold nobody can approve in time, a denial and a refused approval each
// end the call without a second authorize, and say a person was asked.
func TestHold_NotApprovedIsRefusedAndNamesTheHold(t *testing.T) {
	for state, word := range map[string]string{"denied": "denied", "expired": "expired", "refused": "no longer allows"} {
		t.Run(state, func(t *testing.T) {
			f := &fakeHoldLite{openPolls: 1, finalState: state}
			c := f.client(t, 5*time.Second)
			_, err := authorizeHeldAction(c)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), f.holdID()) || !strings.Contains(err.Error(), word) {
				t.Fatalf("message %q should name the hold and say %q", err, word)
			}
			if f.authorizes != 1 {
				t.Fatalf("collected a hold that was %s (%d authorizes)", state, f.authorizes)
			}
		})
	}
}

func TestHold_UnknownStateIsRefused(t *testing.T) {
	f := &fakeHoldLite{finalState: "dancing"}
	if _, err := authorizeHeldAction(f.client(t, 5*time.Second)); err == nil || f.authorizes != 1 {
		t.Fatalf("an unknown hold state was accepted: %v", err)
	}
}

func TestHold_TimeoutStopsWaiting(t *testing.T) {
	f := &fakeHoldLite{}
	c := f.client(t, 150*time.Millisecond)
	start := time.Now()
	_, err := authorizeHeldAction(c)
	if err == nil || !strings.Contains(err.Error(), f.holdID()) || !strings.Contains(err.Error(), "nobody answered") {
		t.Fatalf("timeout message wrong: %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("waited %v for a 150ms limit", d)
	}
	if f.authorizes != 1 {
		t.Fatalf("collected an open hold (%d authorizes)", f.authorizes)
	}
}

// The wait ends with the hold: past its expiry plus the grace, a hold that
// still reads open is not waited on for the rest of the configured maximum.
func TestHold_WaitEndsAtTheHoldsExpiry(t *testing.T) {
	f := &fakeHoldLite{expiresIn: -holdGrace - time.Second}
	c := f.client(t, time.Hour)
	start := time.Now()
	if _, err := authorizeHeldAction(c); err == nil {
		t.Fatal("accepted")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("waited %v on a hold whose expiry had passed", d)
	}
}

func TestHold_WaitDisabledRefusesAtOnce(t *testing.T) {
	f := &fakeHoldLite{finalState: "approved"}
	c := f.client(t, 0)
	_, err := authorizeHeldAction(c)
	if err == nil || !strings.Contains(err.Error(), f.holdID()) || !strings.Contains(err.Error(), "not to wait") {
		t.Fatalf("message wrong: %v", err)
	}
	if f.polls != 0 || f.authorizes != 1 {
		t.Fatalf("waited or collected: polls=%d authorizes=%d", f.polls, f.authorizes)
	}
}

func TestHold_CancelledWhileWaiting(t *testing.T) {
	f := &fakeHoldLite{}
	c := f.client(t, time.Hour)
	// Asleep between reads when the cancel arrives, so only the select ends it.
	c.holdPoll = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(60 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, err := c.Authorize(ctx, "payment.refund", "agent-payments", "payment", "pay_9")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled wait should surface the cancellation: %v", err)
	}
	if time.Since(start) > 3*time.Second || f.authorizes != 1 {
		t.Fatalf("cancel was not prompt or collected anyway (authorizes=%d)", f.authorizes)
	}
}

// A 202 is a HOLD only when every part of it checks out; anything else is a
// plain refusal and the gate never waits on it.
func TestHold_UntrustworthyHoldIsRefused(t *testing.T) {
	stranger := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, ed25519.SeedSize))
	cases := map[string]*fakeHoldLite{
		"not json":                        {rawHold: "<html>"},
		"hold id differs":                 {holdMutate: func(b *holdBody) { b.Hold.HoldID = "rcpt_other" }},
		"no hold object":                  {holdMutate: func(b *holdBody) { b.Hold = nil }},
		"no expiry":                       {holdMutate: func(b *holdBody) { b.Hold.ExpiresAt = "" }},
		"decision says ALLOW":             {holdMutate: func(b *holdBody) { b.Decision = receipt.DecisionAllow }},
		"receipt says ALLOW":              {holdMutate: func(b *holdBody) { b.Receipt.Decision = receipt.DecisionAllow }},
		"receipt validly signed as ALLOW": {holdDecision: receipt.DecisionAllow},
		"receipt for another one":         {holdResource: "pay_1"},
		"signed under a wrong key":        {holdIdem: "mcp-not-mine"},
		"signed by a stranger":            {holdSigner: stranger},
		"flipped signature":               {holdMutate: func(b *holdBody) { b.Receipt.Signature = strings.Repeat("0", 128) }},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			c := f.client(t, 5*time.Second)
			if _, err := authorizeHeldAction(c); err == nil {
				t.Fatal("accepted")
			}
			if f.polls != 0 || f.authorizes != 1 {
				t.Fatalf("went on to wait or collect: polls=%d authorizes=%d", f.polls, f.authorizes)
			}
		})
	}
}

// A 202 whose body says ALLOW is not a hold and not an allow.
func TestHold_AcceptedStatusWithAnAllowBodyIsRefused(t *testing.T) {
	f := &fakeLite{decision: receipt.DecisionAllow, capability: true, status: http.StatusAccepted}
	c := newTestClient(t, f)
	if _, err := c.Authorize(context.Background(), "invoice.delete", "agent-invoices", "invoice", "inv_7"); err == nil {
		t.Fatal("a 202 with an ALLOW body was accepted")
	}
}

// What the gate answers when asked again must prove it is the approval of
// this hold for this request, or it is refused, however approved the hold
// read.
func TestHold_ResolutionThatDoesNotCheckOutIsRefused(t *testing.T) {
	stranger := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, ed25519.SeedSize))
	cases := map[string]*fakeHoldLite{
		"signed under the call's own key":      {resolveIdem: func(idem, _ string) string { return idem }},
		"signed under another hold":            {resolveIdem: func(_, _ string) string { return "hold:rcpt_other" }},
		"signed by a stranger":                 {resolveSigner: stranger},
		"another resource":                     {resolveResource: "pay_1"},
		"another tenant":                       {resolveTenant: "globex"},
		"another action":                       {resolveAction: "invoice.read"},
		"another resource type":                {resolveType: "tenant"},
		"resolution signed as BLOCK":           {resolveSigned: receipt.DecisionBlock},
		"decision says BLOCK":                  {resolveDecision: receipt.DecisionBlock},
		"hold receipt for another request":     {hrResource: "pay_1"},
		"hold receipt under another key":       {hrIdem: "mcp-not-mine"},
		"hold receipt says ALLOW":              {hrDecision: receipt.DecisionAllow},
		"hold receipt of another hold":         {otherHold: true},
		"hold receipt with a broken signature": {hrFlipSig: true},
		"no hold receipt":                      {noHoldReceipt: true},
		"no capability":                        {noCapability: true},
		"empty capability":                     {emptyToken: true},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			f.finalState = "approved"
			c := f.client(t, 5*time.Second)
			g, err := authorizeHeldAction(c)
			if err == nil {
				t.Fatalf("accepted: %+v", g)
			}
			if !strings.Contains(err.Error(), f.holdID()) {
				t.Fatalf("message %q should name the hold", err)
			}
		})
	}
}

// An approval the gate no longer releases is refused with its reason, not
// retried under a new key.
func TestHold_CollectionRefusals(t *testing.T) {
	for status, word := range map[int]string{http.StatusGone: "can no longer be collected", http.StatusForbidden: "would not release"} {
		f := &fakeHoldLite{finalState: "approved", collect: status}
		c := f.client(t, 5*time.Second)
		_, err := authorizeHeldAction(c)
		if err == nil || !strings.Contains(err.Error(), word) || !strings.Contains(err.Error(), f.holdID()) {
			t.Fatalf("status %d: message %v", status, err)
		}
		if f.holds != 1 {
			t.Fatalf("status %d: opened %d holds", status, f.holds)
		}
	}
}

func TestParseHoldWait(t *testing.T) {
	for raw, want := range map[string]time.Duration{"": 0, " ": 0, "0": 0, "45": 45 * time.Second, " 30 ": 30 * time.Second, "3600": time.Hour} {
		got, err := ParseHoldWait(raw)
		if err != nil || got != want {
			t.Errorf("%q: got %v, %v; want %v", raw, got, err, want)
		}
	}
	for _, bad := range []string{"-1", "1.5", "45s", "abc", "3601", "99999999999"} {
		if _, err := ParseHoldWait(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// A genuine, signed receipt for something other than an ALLOW is still not
// an allow when the unsigned body calls it one: the receipt's own decision
// must say ALLOW.
func TestGateClient_RelabelledReceiptIsRefused(t *testing.T) {
	for _, decision := range []string{receipt.DecisionHold, receipt.DecisionBlock} {
		t.Run(decision, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					Action   string            `json:"action"`
					Actor    map[string]string `json:"actor"`
					Resource map[string]string `json:"resource"`
					Idem     string            `json:"idempotency_key"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				rc := mintHoldTest(t, testKey, decision, req.Action, req.Resource["type"], req.Resource["id"], "acme", req.Actor["uid"], "billing_agent", "agent-caller", req.Idem)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"decision": receipt.DecisionAllow, "receipt": rc,
					"capability": map[string]string{"token": "cap-token", "cap_id": "cap_1"},
				})
			}))
			t.Cleanup(srv.Close)
			c := &GateClient{BaseURL: srv.URL, Token: "agent-token", PublicKey: testKey.Public().(ed25519.PublicKey)}
			if g, err := c.Authorize(context.Background(), "invoice.delete", "agent-invoices", "invoice", "inv_7"); err == nil {
				t.Fatalf("a %s receipt relabelled ALLOW was accepted: %+v", decision, g)
			}
		})
	}
}

// A view of some other hold, however approved it reads, decides nothing.
func TestHold_ViewOfAnotherHoldIsRefused(t *testing.T) {
	f := &fakeHoldLite{finalState: "approved", viewHoldID: "rcpt_other"}
	if _, err := authorizeHeldAction(f.client(t, 5*time.Second)); err == nil || f.authorizes != 1 {
		t.Fatalf("a view of another hold was believed: %v (authorizes=%d)", err, f.authorizes)
	}
}
