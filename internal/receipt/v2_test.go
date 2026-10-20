// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
)

const (
	testPolicyHash  = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	testCallersHash = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752"
)

func v2Fields(idem string) V2Fields {
	return V2Fields{
		OperatorURN: "urn:x", TraceID: "trc_0011223344556677", Decision: DecisionAllow,
		Action: "invoice.delete", ResourceType: "invoice", ResourceID: "inv_7", ResourceTenantID: "acme",
		ActorUID: "agent-invoices", ActorRole: "billing_agent", CallerID: "agent-invoices",
		Mode: ModeEnforce, PolicySHA256: testPolicyHash, CallersSHA256: testCallersHash,
		IdempotencyKey: idem, OtelTraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
	}
}

// The JSON shapes are fixed: a v1 receipt exactly as v1 always was, a v2 one
// with its own fields and created_at in place of timestamp.
func TestReceiptJSON_ShapeByVersion(t *testing.T) {
	priv := testKey(t)
	v1, err := Mint(priv, "urn:x", "trc", DecisionAllow, "a", "b", "c", "d", "e", "k")
	if err != nil {
		t.Fatal(err)
	}
	v2, err := MintV2(priv, v2Fields("k"))
	if err != nil {
		t.Fatal(err)
	}
	keys := func(r Receipt) []string {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		return slices.Sorted(maps.Keys(m))
	}
	wantV1 := []string{"action", "actor_role", "actor_uid", "chain_hash", "decision", "intent_hash", "operator_urn",
		"receipt_id", "resource_id", "resource_type", "seq", "signature", "timestamp", "trace_id"}
	if got := keys(v1); !slices.Equal(got, wantV1) {
		t.Fatalf("v1 JSON shape changed:\n got %v\nwant %v", got, wantV1)
	}
	wantV2 := []string{"action", "actor_role", "actor_uid", "caller_id", "callers_sha256", "chain_hash", "created_at",
		"decision", "intent_hash", "mode", "observe_override", "operator_urn", "otel_trace_id", "policy_sha256",
		"receipt_id", "receipt_version", "resource_id", "resource_tenant_id", "resource_type", "seq", "signature",
		"trace_id"}
	if got := keys(v2); !slices.Equal(got, wantV2) {
		t.Fatalf("v2 JSON shape changed:\n got %v\nwant %v", got, wantV2)
	}
}

func TestVerifyFor_V2RefusesRelabellingAndEdits(t *testing.T) {
	priv := testKey(t)
	pub := priv.Public().(ed25519.PublicKey)
	r, err := MintV2(priv, v2Fields("idem"))
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*Receipt){
		"as v1":            func(r *Receipt) { r.Version = Version1 },
		"unknown version":  func(r *Receipt) { r.Version = 3 },
		"policy":           func(r *Receipt) { r.PolicySHA256 = testCallersHash },
		"override":         func(r *Receipt) { r.ObserveOverride = true },
		"time":             func(r *Receipt) { r.CreatedAt = r.CreatedAt.Add(1) },
		"caller":           func(r *Receipt) { r.CallerID = "x" },
		"other idempotent": nil,
	} {
		c := r
		key := "idem"
		if edit == nil {
			key = "another"
		} else {
			edit(&c)
		}
		if err := VerifyFor(c, pub, key); err == nil {
			t.Errorf("%s: an altered v2 receipt verified", name)
		}
	}
	// A v1 receipt that gained a v2 field.
	v1, err := Mint(priv, "urn:x", "trc", DecisionAllow, "a", "b", "c", "d", "e", "idem")
	if err != nil {
		t.Fatal(err)
	}
	v1.PolicySHA256 = testPolicyHash
	if err := VerifyFor(v1, pub, "idem"); !errors.Is(err, ErrReceiptIntentMismatch) {
		t.Fatalf("a v1 receipt carrying a policy hash verified: %v", err)
	}
}

// MintV2 refuses, minting nothing, when what it must record is missing or
// malformed.
func TestMintV2_RefusesIncompleteFields(t *testing.T) {
	priv := testKey(t)
	for name, edit := range map[string]func(*V2Fields){
		"no policy hash":           func(f *V2Fields) { f.PolicySHA256 = "" },
		"uppercase policy hash":    func(f *V2Fields) { f.PolicySHA256 = strings.ToUpper(testPolicyHash) },
		"short callers hash":       func(f *V2Fields) { f.CallersSHA256 = "abc" },
		"unknown mode":             func(f *V2Fields) { f.Mode = "permissive" },
		"no mode":                  func(f *V2Fields) { f.Mode = "" },
		"override in enforce mode": func(f *V2Fields) { f.ObserveOverride = true },
		"override on a BLOCK":      func(f *V2Fields) { f.Mode = ModeObserve; f.ObserveOverride = true; f.Decision = DecisionBlock },
		"reserved decision":        func(f *V2Fields) { f.Decision = DecisionEscalate },
		"malformed otel trace id":  func(f *V2Fields) { f.OtelTraceID = "not-a-trace" },
		"no caller":                func(f *V2Fields) { f.CallerID = "" },
	} {
		f := v2Fields("idem")
		edit(&f)
		if r, err := MintV2(priv, f); err == nil || r.Signature != "" {
			t.Errorf("%s: MintV2 minted %+v", name, r)
		}
	}
	// The valid edge cases mint.
	f := v2Fields("idem")
	f.Mode, f.ObserveOverride = ModeObserve, true
	f.CallersSHA256, f.OtelTraceID, f.ResourceTenantID = "", "", ""
	if _, err := MintV2(priv, f); err != nil {
		t.Fatalf("an observe override with no callers file, trace or tenant was refused: %v", err)
	}
}
