// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	acrypto "github.com/high-archytech-solutions/archytan-mcp-gate/v2/internal/crypto"
)

// vectorKeySeed is a fixed, published test seed. Ed25519 signing is
// deterministic, so the same inputs always produce the same signature and
// the vector file is reproducible byte for byte.
var vectorKeySeed = bytes.Repeat([]byte{0x42}, ed25519.SeedSize)

type intentVector struct {
	Name           string `json:"name"`
	Action         string `json:"action"`
	ResourceType   string `json:"resource_type"`
	ResourceID     string `json:"resource_id"`
	ActorUID       string `json:"actor_uid"`
	ActorRole      string `json:"actor_role"`
	Decision       string `json:"decision"`
	IdempotencyKey string `json:"idempotency_key"`
	CanonicalJSON  string `json:"canonical_json"`
	IntentHash     string `json:"intent_hash"`
	Signature      string `json:"signature"`
}

// intentVectorV2 is one v2 receipt's signed fields, with what Go produces
// for them.
type intentVectorV2 struct {
	Name             string `json:"name"`
	ReceiptID        string `json:"receipt_id"`
	OperatorURN      string `json:"operator_urn"`
	TraceID          string `json:"trace_id"`
	CreatedAt        string `json:"created_at"`
	Action           string `json:"action"`
	ResourceType     string `json:"resource_type"`
	ResourceID       string `json:"resource_id"`
	ResourceTenantID string `json:"resource_tenant_id"`
	ActorUID         string `json:"actor_uid"`
	ActorRole        string `json:"actor_role"`
	CallerID         string `json:"caller_id"`
	Decision         string `json:"decision"`
	Mode             string `json:"mode"`
	ObserveOverride  bool   `json:"observe_override"`
	PolicySHA256     string `json:"policy_sha256"`
	CallersSHA256    string `json:"callers_sha256"`
	IdempotencyKey   string `json:"idempotency_key"`
	OtelTraceID      string `json:"otel_trace_id"`
	CanonicalJSON    string `json:"canonical_json"`
	IntentHash       string `json:"intent_hash"`
	Signature        string `json:"signature"`
}

type vectorFile struct {
	Comment      string           `json:"_comment"`
	ReceiptTag   string           `json:"receipt_tag"`
	PublicKeyHex string           `json:"public_key_hex"`
	Vectors      []intentVector   `json:"vectors"`
	ReceiptTagV2 string           `json:"receipt_tag_v2"`
	VectorsV2    []intentVectorV2 `json:"vectors_v2"`
}

const (
	vecPolicyHash  = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	vecCallersHash = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752"
	vecOtelTrace   = "4bf92f3577b34da6a3ce929d0e0e4736"
)

// vectorInputsV2 covers the v2 fields with the same encoding traps as v1,
// plus a boolean, an empty optional field, and a time with nanoseconds.
func vectorInputsV2() []intentVectorV2 {
	base := intentVectorV2{
		ReceiptID: "rcpt_00112233445566778899aabbccddeeff", OperatorURN: "urn:archytan-lite:instance:vectors",
		TraceID: "trc_0011223344556677", CreatedAt: "2026-10-09T18:26:30.0109686Z", Action: "invoice.delete",
		ResourceType: "invoice", ResourceID: "inv_7", ResourceTenantID: "acme", ActorUID: "agent-invoices",
		ActorRole: "billing_agent", CallerID: "agent-invoices", Decision: DecisionAllow, Mode: ModeEnforce,
		PolicySHA256: vecPolicyHash, CallersSHA256: vecCallersHash, IdempotencyKey: "idem-1", OtelTraceID: vecOtelTrace,
	}
	with := func(name string, f func(*intentVectorV2)) intentVectorV2 {
		v := base
		v.Name = name
		f(&v)
		return v
	}
	return []intentVectorV2{
		with("plain_bound", func(v *intentVectorV2) {}),
		with("block_cross_tenant", func(v *intentVectorV2) { v.Decision = DecisionBlock; v.ResourceTenantID = "globex" }),
		with("shared_secret_no_trace", func(v *intentVectorV2) {
			v.CallerID = "shared-secret-caller"
			v.CallersSHA256 = ""
			v.OtelTraceID = ""
			v.ResourceTenantID = ""
			v.CreatedAt = "2026-10-09T18:26:30Z"
		}),
		with("observe_override", func(v *intentVectorV2) { v.Mode = ModeObserve; v.ObserveOverride = true }),
		with("observe_mode_genuine_allow", func(v *intentVectorV2) { v.Mode = ModeObserve }),
		with("html_and_separators", func(v *intentVectorV2) {
			v.ResourceID = `<script>alert("x")</script> & more`
			v.ResourceTenantID = "a&b<c>"
			v.CallerID = "caller\u2028line\u2029para"
			v.IdempotencyKey = "k<1>&2"
		}),
		with("control_backslash_non_ascii", func(v *intentVectorV2) {
			v.ResourceID = "a\x00b\x01c\tf\ng\x7fj"
			v.ResourceTenantID = "Compa\u00f1\u00eda \u65e5\u672c \U0001f642"
			v.ActorUID = `dom\user`
			v.IdempotencyKey = "\ufffd"
		}),
	}
}

// vectorInputs covers every place Go's encoding/json output differs from a
// naive JSON.stringify or json.dumps: HTML escaping, U+2028/2029, control
// characters, non-ASCII left as raw UTF-8, and backslashes.
func vectorInputs() []intentVector {
	return []intentVector{
		{Name: "plain", Action: "invoice.delete", ResourceType: "invoice", ResourceID: "inv_7", ActorUID: "agent-invoices", ActorRole: "billing_agent", Decision: DecisionAllow, IdempotencyKey: "idem-1"},
		{Name: "block", Action: "tenant.delete", ResourceType: "tenant", ResourceID: "t_99", ActorUID: "u1", ActorRole: "readonly_agent", Decision: DecisionBlock, IdempotencyKey: "idem-2"},
		{Name: "html_characters", Action: "page.publish", ResourceType: "page", ResourceID: `<script>alert("x")</script> & more`, ActorUID: "a&b", ActorRole: "editor<>", Decision: DecisionAllow, IdempotencyKey: "k<1>&2"},
		{Name: "backslashes_and_slashes", Action: "file.read", ResourceType: "file", ResourceID: `C:\Users\x\report.txt /etc/passwd`, ActorUID: `dom\user`, ActorRole: "reader", Decision: DecisionAllow, IdempotencyKey: `\\`},
		{Name: "control_characters", Action: "note.write", ResourceType: "note", ResourceID: "a\x00b\x01c\x08d\x0ce\tf\ng\rh\x1fi\x7fj", ActorUID: "u2", ActorRole: "writer", Decision: DecisionAllow, IdempotencyKey: "line1\nline2"},
		{Name: "non_ascii", Action: "cliente.actualizar", ResourceType: "cliente", ResourceID: "José Ñúñez 日本 🙂 é", ActorUID: "usuario-ñ", ActorRole: "operador", Decision: DecisionAllow, IdempotencyKey: "idem-ü"},
		{Name: "line_and_paragraph_separators", Action: "doc.edit", ResourceType: "doc", ResourceID: "x\u2028y\u2029z", ActorUID: "u3", ActorRole: "editor", Decision: DecisionAllow, IdempotencyKey: "idem-3"},
		{Name: "replacement_character", Action: "blob.read", ResourceType: "blob", ResourceID: "\ufffd", ActorUID: "u4", ActorRole: "reader", Decision: DecisionAllow, IdempotencyKey: "idem-4"},
		{Name: "empty_fields", Action: "noop", ResourceType: "", ResourceID: "", ActorUID: "", ActorRole: "", Decision: DecisionBlock, IdempotencyKey: ""},
	}
}

func buildVectorFile(t *testing.T) []byte {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(vectorKeySeed)
	pub := priv.Public().(ed25519.PublicKey)

	vf := vectorFile{
		Comment:      "Generated by internal/receipt TestIntentVectors from the Go implementation. Do not edit by hand; run `go test ./internal/receipt -run TestIntentVectors -update-vectors`. Clients must reproduce canonical_json and intent_hash exactly and accept every signature under public_key_hex.",
		ReceiptTag:   "ARCHYTAN_LITE_RECEIPT_V1:",
		PublicKeyHex: hex.EncodeToString(pub),
	}
	for _, v := range vectorInputs() {
		canonical, err := json.Marshal(intentPayload{
			Action: v.Action, ResourceType: v.ResourceType, ResourceID: v.ResourceID,
			ActorUID: v.ActorUID, ActorRole: v.ActorRole, Decision: v.Decision, IdempotencyKey: v.IdempotencyKey,
		})
		if err != nil {
			t.Fatalf("%s: marshal: %v", v.Name, err)
		}
		r, err := Mint(priv, "urn:test", "trace", v.Decision, v.Action, v.ResourceType, v.ResourceID, v.ActorUID, v.ActorRole, v.IdempotencyKey)
		if err != nil {
			t.Fatalf("%s: mint: %v", v.Name, err)
		}
		v.CanonicalJSON = string(canonical)
		v.IntentHash = r.IntentHash
		v.Signature = r.Signature
		vf.Vectors = append(vf.Vectors, v)
	}
	vf.ReceiptTagV2 = acrypto.ReceiptTagV2
	for _, v := range vectorInputsV2() {
		p := intentPayloadV2{
			ReceiptVersion: Version2, ReceiptID: v.ReceiptID, OperatorURN: v.OperatorURN, TraceID: v.TraceID,
			CreatedAt: v.CreatedAt, Action: v.Action, ResourceType: v.ResourceType, ResourceID: v.ResourceID,
			ResourceTenantID: v.ResourceTenantID, ActorUID: v.ActorUID, ActorRole: v.ActorRole, CallerID: v.CallerID,
			Decision: v.Decision, Mode: v.Mode, ObserveOverride: v.ObserveOverride, PolicySHA256: v.PolicySHA256,
			CallersSHA256: v.CallersSHA256, IdempotencyKey: v.IdempotencyKey, OtelTraceID: v.OtelTraceID,
		}
		canonical, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("%s: marshal: %v", v.Name, err)
		}
		sum, err := p.hash()
		if err != nil {
			t.Fatal(err)
		}
		sig, err := acrypto.Sign(priv, acrypto.ReceiptTagV2, sum)
		if err != nil {
			t.Fatal(err)
		}
		v.CanonicalJSON = string(canonical)
		v.IntentHash = hex.EncodeToString(sum)
		v.Signature = hex.EncodeToString(sig)

		// The same values as a Receipt must verify through VerifyFor: its
		// payload, created_at formatting included, is the vector's.
		created, err := time.Parse(time.RFC3339Nano, v.CreatedAt)
		if err != nil {
			t.Fatal(err)
		}
		r := Receipt{
			Version: Version2, ReceiptID: v.ReceiptID, OperatorURN: v.OperatorURN, TraceID: v.TraceID, CreatedAt: created,
			Action: v.Action, ResourceType: v.ResourceType, ResourceID: v.ResourceID, ResourceTenantID: v.ResourceTenantID,
			ActorUID: v.ActorUID, ActorRole: v.ActorRole, CallerID: v.CallerID, Decision: v.Decision, Mode: v.Mode,
			ObserveOverride: v.ObserveOverride, PolicySHA256: v.PolicySHA256, CallersSHA256: v.CallersSHA256,
			OtelTraceID: v.OtelTraceID, IntentHash: v.IntentHash, Signature: v.Signature,
		}
		if err := VerifyFor(r, pub, v.IdempotencyKey); err != nil {
			t.Fatalf("%s: the vector does not verify as a Receipt: %v", v.Name, err)
		}
		vf.VectorsV2 = append(vf.VectorsV2, v)
	}
	out, err := json.MarshalIndent(vf, "", "  ")
	if err != nil {
		t.Fatalf("marshal vector file: %v", err)
	}
	return append(out, '\n')
}

// TestIntentVectors keeps the cross-language test vectors in lockstep with
// the Go implementation: a stale checked-in file fails here, so a change to
// intentPayload cannot ship without the Node and Python clients being
// tested against it.
// TestIntentVectors holds this copy of the receipt format to Archytan
// Lite's. testdata/intent_vectors.json is generated by the Lite gate
// service's own receipt code and copied here unchanged; if this test fails,
// the two have drifted and the MCP gate would misjudge genuine receipts.
func TestIntentVectors(t *testing.T) {
	path := filepath.Join("testdata", "intent_vectors.json")
	want := buildVectorFile(t)
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	got = bytes.ReplaceAll(got, []byte{'\r', '\n'}, []byte{'\n'})
	if !bytes.Equal(got, want) {
		t.Fatalf("%s no longer matches this receipt code: the format has drifted from Archytan Lite's", path)
	}
}

func mintForTest(t *testing.T, priv ed25519.PrivateKey, idem string) Receipt {
	t.Helper()
	r, err := Mint(priv, "urn:test", "trace", DecisionAllow, "invoice.read", "invoice", "inv_7", "agent-1", "reader", idem)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return r
}

func TestVerifyFor_AcceptsGenuineReceipt(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(vectorKeySeed)
	r := mintForTest(t, priv, "idem-a")
	if err := VerifyFor(r, priv.Public().(ed25519.PublicKey), "idem-a"); err != nil {
		t.Fatalf("genuine receipt rejected: %v", err)
	}
}

// The attack VerifyFor exists for: a genuine signature and intent_hash
// carried over from one decision, with the visible fields rewritten to
// describe a different one.
func TestVerifyFor_RejectsRewrittenFields(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(vectorKeySeed)
	pub := priv.Public().(ed25519.PublicKey)
	cases := map[string]func(*Receipt){
		"action":        func(r *Receipt) { r.Action = "invoice.delete" },
		"resource_type": func(r *Receipt) { r.ResourceType = "tenant" },
		"resource_id":   func(r *Receipt) { r.ResourceID = "inv_99" },
		"actor_uid":     func(r *Receipt) { r.ActorUID = "someone-else" },
		"actor_role":    func(r *Receipt) { r.ActorRole = "admin" },
		"decision":      func(r *Receipt) { r.Decision = DecisionBlock },
	}
	for name, rewrite := range cases {
		t.Run(name, func(t *testing.T) {
			r := mintForTest(t, priv, "idem-b")
			rewrite(&r)
			if err := VerifyFor(r, pub, "idem-b"); !errors.Is(err, ErrReceiptIntentMismatch) {
				t.Fatalf("rewritten %s: got %v, want ErrReceiptIntentMismatch", name, err)
			}
		})
	}
}

func TestVerifyFor_RejectsWrongIdempotencyKey(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(vectorKeySeed)
	r := mintForTest(t, priv, "idem-c")
	if err := VerifyFor(r, priv.Public().(ed25519.PublicKey), "idem-other"); !errors.Is(err, ErrReceiptIntentMismatch) {
		t.Fatalf("receipt minted for another request accepted: %v", err)
	}
}

func TestVerifyFor_RejectsWrongKeyAndBadSignature(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(vectorKeySeed)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x07}, ed25519.SeedSize))
	r := mintForTest(t, priv, "idem-d")
	if err := VerifyFor(r, other.Public().(ed25519.PublicKey), "idem-d"); !errors.Is(err, ErrReceiptSignature) {
		t.Fatalf("receipt accepted under the wrong key: %v", err)
	}
	sig, _ := hex.DecodeString(r.Signature)
	sig[0] ^= 0x01
	r.Signature = hex.EncodeToString(sig)
	if err := VerifyFor(r, priv.Public().(ed25519.PublicKey), "idem-d"); !errors.Is(err, ErrReceiptSignature) {
		t.Fatalf("flipped signature accepted: %v", err)
	}
}

func TestVerifyFor_RejectsMalformedInput(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(vectorKeySeed)
	pub := priv.Public().(ed25519.PublicKey)
	good := mintForTest(t, priv, "idem-e")
	cases := map[string]func(*Receipt, *ed25519.PublicKey){
		"short_key":       func(_ *Receipt, k *ed25519.PublicKey) { *k = (*k)[:10] },
		"nonhex_hash":     func(r *Receipt, _ *ed25519.PublicKey) { r.IntentHash = "zz" },
		"short_hash":      func(r *Receipt, _ *ed25519.PublicKey) { r.IntentHash = r.IntentHash[:10] },
		"nonhex_sig":      func(r *Receipt, _ *ed25519.PublicKey) { r.Signature = "zz" },
		"short_signature": func(r *Receipt, _ *ed25519.PublicKey) { r.Signature = r.Signature[:10] },
		"empty":           func(r *Receipt, _ *ed25519.PublicKey) { r.IntentHash, r.Signature = "", "" },
	}
	for name, mangle := range cases {
		t.Run(name, func(t *testing.T) {
			r, k := good, append(ed25519.PublicKey(nil), pub...)
			mangle(&r, &k)
			if err := VerifyFor(r, k, "idem-e"); !errors.Is(err, ErrReceiptMalformed) {
				t.Fatalf("got %v, want ErrReceiptMalformed", err)
			}
		})
	}
}
