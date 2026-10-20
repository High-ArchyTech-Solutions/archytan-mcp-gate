// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	acrypto "github.com/high-archytech-solutions/archytan-mcp-gate/internal/crypto"
)

// Receipt format versions. A version 1 receipt signs what was decided about
// which action, resource and actor. Version 2 also signs what the decision
// was made under: the policy and callers files in force, the credential that
// asked, the resource's tenant, the gate's mode and whether observe mode
// overrode a refusal, the caller's W3C trace id, and the receipt's own id,
// instance, trace id and time. Every field a v2 receipt carries is covered
// by its signature except the chain position (seq, chain_hash), which the
// chain itself protects.
const (
	Version1 = 1
	Version2 = 2
)

// Gate modes recorded in a v2 receipt.
const (
	ModeEnforce = "enforce"
	ModeObserve = "observe"
)

// V2Fields is everything a v2 receipt records about one decision.
type V2Fields struct {
	OperatorURN      string
	TraceID          string
	Decision         string
	Action           string
	ResourceType     string
	ResourceID       string
	ResourceTenantID string
	ActorUID         string
	ActorRole        string
	// CallerID is the authenticated credential's id: the callers file's
	// caller_id in bound mode, a fixed shared-secret caller id otherwise.
	CallerID string
	Mode     string
	// ObserveOverride is true only when observe mode turned what would have
	// been a BLOCK into this ALLOW.
	ObserveOverride bool
	// PolicySHA256 is the hex SHA-256 of the policy file bytes the decision
	// was made against. Required.
	PolicySHA256 string
	// CallersSHA256 is the hex SHA-256 of the callers file in bound mode,
	// empty in shared-secret mode.
	CallersSHA256  string
	IdempotencyKey string
	// OtelTraceID is the caller's W3C trace id, empty when it sent none.
	OtelTraceID string
}

// intentPayloadV2 is exactly what a v2 signature covers, in this field
// order, as Go's encoding/json writes it (struct fields in declaration
// order). testdata/intent_vectors.json holds it to the Archytan Lite gate
// service's definition, which its Node and Python clients and its
// standalone receipt verifier reproduce too.
type intentPayloadV2 struct {
	ReceiptVersion   int    `json:"receipt_version"`
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
}

func (p intentPayloadV2) hash() ([]byte, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal v2 intent payload: %w", err)
	}
	sum := sha256.Sum256(b)
	return sum[:], nil
}

// formatCreatedAt is the one textual form of a receipt's time: what a v2
// signature covers, what the receipts table stores, and what the JSON forms
// carry. RFC 3339 with nanoseconds, in UTC.
func formatCreatedAt(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

var errV2Field = errors.New("receipt: invalid v2 field")

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (f V2Fields) validate() error {
	switch {
	case f.Decision != DecisionAllow && f.Decision != DecisionBlock:
		return fmt.Errorf("%w: decision %q", errV2Field, f.Decision)
	case f.Mode != ModeEnforce && f.Mode != ModeObserve:
		return fmt.Errorf("%w: mode %q", errV2Field, f.Mode)
	case f.ObserveOverride && (f.Mode != ModeObserve || f.Decision != DecisionAllow):
		return fmt.Errorf("%w: observe_override is only possible on an ALLOW in observe mode", errV2Field)
	case !isLowerHex(f.PolicySHA256, 64):
		return fmt.Errorf("%w: policy_sha256 must be a hex SHA-256, got %q", errV2Field, f.PolicySHA256)
	case f.CallersSHA256 != "" && !isLowerHex(f.CallersSHA256, 64):
		return fmt.Errorf("%w: callers_sha256 must be empty or a hex SHA-256", errV2Field)
	case f.OtelTraceID != "" && !isLowerHex(f.OtelTraceID, 32):
		return fmt.Errorf("%w: otel_trace_id must be empty or 32 hex characters", errV2Field)
	case f.CallerID == "":
		return fmt.Errorf("%w: caller_id is required", errV2Field)
	}
	return nil
}

// MintV2 mints a version 2 receipt, signed under ReceiptTagV2. It refuses,
// minting nothing, when a field it must record is missing or malformed: a
// v2 receipt without the policy it was decided under would be the gap v2
// exists to close.
func MintV2(signer crypto.Signer, f V2Fields) (Receipt, error) {
	if err := f.validate(); err != nil {
		return Receipt{}, err
	}
	id, err := randomHex("rcpt_", 16)
	if err != nil {
		return Receipt{}, err
	}
	r := Receipt{
		Version:          Version2,
		ReceiptID:        id,
		Action:           f.Action,
		ResourceType:     f.ResourceType,
		ResourceID:       f.ResourceID,
		ActorUID:         f.ActorUID,
		ActorRole:        f.ActorRole,
		Decision:         f.Decision,
		OperatorURN:      f.OperatorURN,
		IdempotencyKey:   f.IdempotencyKey,
		TraceID:          f.TraceID,
		CreatedAt:        time.Now().UTC(),
		CallerID:         f.CallerID,
		ResourceTenantID: f.ResourceTenantID,
		PolicySHA256:     f.PolicySHA256,
		CallersSHA256:    f.CallersSHA256,
		Mode:             f.Mode,
		ObserveOverride:  f.ObserveOverride,
		OtelTraceID:      f.OtelTraceID,
	}
	sum, err := r.payloadV2(f.IdempotencyKey).hash()
	if err != nil {
		return Receipt{}, err
	}
	sig, err := acrypto.Sign(signer, acrypto.ReceiptTagV2, sum)
	if err != nil {
		return Receipt{}, err
	}
	r.IntentHash = hex.EncodeToString(sum)
	r.Signature = hex.EncodeToString(sig)
	return r, nil
}

func (r Receipt) payloadV2(idempotencyKey string) intentPayloadV2 {
	return intentPayloadV2{
		ReceiptVersion:   Version2,
		ReceiptID:        r.ReceiptID,
		OperatorURN:      r.OperatorURN,
		TraceID:          r.TraceID,
		CreatedAt:        formatCreatedAt(r.CreatedAt),
		Action:           r.Action,
		ResourceType:     r.ResourceType,
		ResourceID:       r.ResourceID,
		ResourceTenantID: r.ResourceTenantID,
		ActorUID:         r.ActorUID,
		ActorRole:        r.ActorRole,
		CallerID:         r.CallerID,
		Decision:         r.Decision,
		Mode:             r.Mode,
		ObserveOverride:  r.ObserveOverride,
		PolicySHA256:     r.PolicySHA256,
		CallersSHA256:    r.CallersSHA256,
		IdempotencyKey:   idempotencyKey,
		OtelTraceID:      r.OtelTraceID,
	}
}

// hasV2Fields is the same check on a receipt as returned by the API.
func (r Receipt) hasV2Fields() bool {
	return r.CallerID != "" || r.ResourceTenantID != "" || r.PolicySHA256 != "" ||
		r.CallersSHA256 != "" || r.Mode != "" || r.ObserveOverride || r.OtelTraceID != ""
}

// version reads an unset version as 1: a v1 receipt has no version field.
func (r Receipt) version() int {
	if r.Version == 0 {
		return Version1
	}
	return r.Version
}

// receiptJSONV1 is a v1 receipt's JSON form, unchanged since v1 shipped.
type receiptJSONV1 struct {
	ReceiptID    string    `json:"receipt_id"`
	Action       string    `json:"action"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	ActorUID     string    `json:"actor_uid"`
	ActorRole    string    `json:"actor_role"`
	Decision     string    `json:"decision"`
	IntentHash   string    `json:"intent_hash"`
	Signature    string    `json:"signature"`
	OperatorURN  string    `json:"operator_urn"`
	TraceID      string    `json:"trace_id"`
	Seq          int64     `json:"seq"`
	ChainHash    string    `json:"chain_hash"`
	CreatedAt    time.Time `json:"timestamp"`
}

// receiptJSONV2 is a v2 receipt's JSON form: the signed fields in the order
// they are signed, then the signature and the chain position. The time is
// "created_at", as signed and as stored.
type receiptJSONV2 struct {
	ReceiptVersion   int    `json:"receipt_version"`
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
	OtelTraceID      string `json:"otel_trace_id"`
	IntentHash       string `json:"intent_hash"`
	Signature        string `json:"signature"`
	Seq              int64  `json:"seq"`
	ChainHash        string `json:"chain_hash"`
}

// MarshalJSON writes the receipt in its own version's shape: a v1 receipt
// exactly as v1 always has, so replaying a pre-upgrade decision returns what
// its caller first received.
func (r Receipt) MarshalJSON() ([]byte, error) {
	if r.version() == Version1 {
		return json.Marshal(receiptJSONV1{
			ReceiptID: r.ReceiptID, Action: r.Action, ResourceType: r.ResourceType, ResourceID: r.ResourceID,
			ActorUID: r.ActorUID, ActorRole: r.ActorRole, Decision: r.Decision, IntentHash: r.IntentHash,
			Signature: r.Signature, OperatorURN: r.OperatorURN, TraceID: r.TraceID, Seq: r.Seq,
			ChainHash: r.ChainHash, CreatedAt: r.CreatedAt,
		})
	}
	return json.Marshal(receiptJSONV2{
		ReceiptVersion: r.Version, ReceiptID: r.ReceiptID, OperatorURN: r.OperatorURN, TraceID: r.TraceID,
		CreatedAt: formatCreatedAt(r.CreatedAt), Action: r.Action, ResourceType: r.ResourceType,
		ResourceID: r.ResourceID, ResourceTenantID: r.ResourceTenantID, ActorUID: r.ActorUID,
		ActorRole: r.ActorRole, CallerID: r.CallerID, Decision: r.Decision, Mode: r.Mode,
		ObserveOverride: r.ObserveOverride, PolicySHA256: r.PolicySHA256, CallersSHA256: r.CallersSHA256,
		OtelTraceID: r.OtelTraceID, IntentHash: r.IntentHash, Signature: r.Signature, Seq: r.Seq,
		ChainHash: r.ChainHash,
	})
}

// UnmarshalJSON reads either version's JSON form.
func (r *Receipt) UnmarshalJSON(b []byte) error {
	var w struct {
		receiptJSONV2
		Timestamp *time.Time `json:"timestamp"`
	}
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	*r = Receipt{
		Version: w.ReceiptVersion, ReceiptID: w.ReceiptID, Action: w.Action, ResourceType: w.ResourceType,
		ResourceID: w.ResourceID, ActorUID: w.ActorUID, ActorRole: w.ActorRole, Decision: w.Decision,
		IntentHash: w.IntentHash, Signature: w.Signature, OperatorURN: w.OperatorURN, TraceID: w.TraceID,
		Seq: w.Seq, ChainHash: w.ChainHash, CallerID: w.CallerID, ResourceTenantID: w.ResourceTenantID,
		PolicySHA256: w.PolicySHA256, CallersSHA256: w.CallersSHA256, Mode: w.Mode,
		ObserveOverride: w.ObserveOverride, OtelTraceID: w.OtelTraceID,
	}
	switch {
	case w.CreatedAt != "":
		t, err := time.Parse(time.RFC3339Nano, w.CreatedAt)
		if err != nil {
			return fmt.Errorf("receipt created_at: %w", err)
		}
		r.CreatedAt = t
	case w.Timestamp != nil:
		r.CreatedAt = *w.Timestamp
	}
	return nil
}
