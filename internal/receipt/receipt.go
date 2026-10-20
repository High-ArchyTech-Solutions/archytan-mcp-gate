// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

// Package receipt mints and persists Archytan Lite's signed authorization
// decisions. A receipt is minted for both ALLOW and BLOCK outcomes, so the
// receipts table is a tamper-evident log of denials as well as grants.
package receipt

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	acrypto "github.com/high-archytech-solutions/archytan-mcp-gate/v2/internal/crypto"
)

const (
	DecisionAllow    = "ALLOW"
	DecisionBlock    = "BLOCK"
	DecisionHold     = "HOLD"     // vocabulary reserved, not wired in v1
	DecisionEscalate = "ESCALATE" // vocabulary reserved, not wired in v1
)

// Receipt is a single authorization decision: what was decided, what it
// was about, and a signature binding the two together. Its JSON form
// depends on its version (see v2.go): MarshalJSON writes a v1 receipt
// exactly as v1 always has.
type Receipt struct {
	// Version is 1 or 2; zero reads as 1, since a v1 receipt has no
	// version field.
	Version        int    `json:"receipt_version"`
	ReceiptID      string `json:"receipt_id"`
	Action         string `json:"action"`
	ResourceType   string `json:"resource_type"`
	ResourceID     string `json:"resource_id"`
	ActorUID       string `json:"actor_uid"`
	ActorRole      string `json:"actor_role"`
	Decision       string `json:"decision"`
	IntentHash     string `json:"intent_hash"`
	Signature      string `json:"signature"`
	OperatorURN    string `json:"operator_urn"`
	IdempotencyKey string `json:"-"`
	TraceID        string `json:"trace_id"`
	// Seq and ChainHash are set by Store.Insert, not Mint — chaining is a
	// property of persisted order, not of the decision itself. Zero/empty
	// on a freshly-minted, not-yet-inserted Receipt.
	Seq       int64     `json:"seq"`
	ChainHash string    `json:"chain_hash"`
	CreatedAt time.Time `json:"timestamp"`

	// Version 2 only (see V2Fields); empty on a v1 receipt.
	CallerID         string `json:"caller_id"`
	ResourceTenantID string `json:"resource_tenant_id"`
	PolicySHA256     string `json:"policy_sha256"`
	CallersSHA256    string `json:"callers_sha256"`
	Mode             string `json:"mode"`
	ObserveOverride  bool   `json:"observe_override"`
	OtelTraceID      string `json:"otel_trace_id"`
}

// intentPayload is the exact set of fields the signature covers. Field
// order is fixed by struct declaration order, which is what makes
// encoding/json's output deterministic here; full RFC 8785 JCS
// canonicalization would buy nothing at this fixed, code-defined field
// set.
//
// Decision is part of this payload deliberately, not an oversight: the
// whole point of a signed, chained receipt is that the verdict itself
// can't be altered after the fact. An intent_hash computed without
// Decision would let `UPDATE receipts SET decision = 'ALLOW' WHERE
// decision = 'BLOCK'` pass every check VerifyChain runs — the row's
// fields would still hash to its stored intent_hash, the untouched
// signature would still verify, and the untouched chain_hash would still
// recompute, because none of those three checks would have ever looked
// at decision. See TestVerifyChain_DetectsDecisionFlip for the exact
// attack this field closes.
type intentPayload struct {
	Action         string `json:"action"`
	ResourceType   string `json:"resource_type"`
	ResourceID     string `json:"resource_id"`
	ActorUID       string `json:"actor_uid"`
	ActorRole      string `json:"actor_role"`
	Decision       string `json:"decision"`
	IdempotencyKey string `json:"idempotency_key"`
}

// Mint mints a version 1 receipt: the format a gate running with
// ARCHYTAN_LITE_RECEIPT_VERSION=1 still writes. MintV2 (v2.go) is the default.
//
// Mint computes the intent hash and signs it under ReceiptTag through the
// given signer, producing a Receipt for the given decision. A signer that
// fails — a remote one being throttled, say — returns an error here, and
// no receipt is produced: an unsigned decision must never reach the
// caller or the log. Every field added after this point in
// the caller's flow (trace_id, created_at) is set on the struct here but
// is never part of the signed bytes — the signature covers action/
// resource/actor/decision/idempotency-key identity, matching what
// VerifyChain independently recomputes and checks (see store.go).
func Mint(signer crypto.Signer, operatorURN, traceID string, decision string, action, resourceType, resourceID, actorUID, actorRole, idempotencyKey string) (Receipt, error) {
	intentHash, err := IntentHash(action, resourceType, resourceID, actorUID, actorRole, decision, idempotencyKey)
	if err != nil {
		return Receipt{}, err
	}

	sig, err := acrypto.Sign(signer, acrypto.ReceiptTag, intentHash)
	if err != nil {
		return Receipt{}, err
	}

	id, err := randomHex("rcpt_", 16)
	if err != nil {
		return Receipt{}, err
	}

	return Receipt{
		Version:        Version1,
		ReceiptID:      id,
		Action:         action,
		ResourceType:   resourceType,
		ResourceID:     resourceID,
		ActorUID:       actorUID,
		ActorRole:      actorRole,
		Decision:       decision,
		IntentHash:     hex.EncodeToString(intentHash),
		Signature:      hex.EncodeToString(sig),
		OperatorURN:    operatorURN,
		IdempotencyKey: idempotencyKey,
		TraceID:        traceID,
		CreatedAt:      time.Now().UTC(),
	}, nil
}

// IntentHash is the SHA-256 digest a receipt's signature covers: Go's
// encoding/json output for intentPayload, byte for byte. It is the single
// definition used to mint and to verify a receipt. testdata/intent_vectors.json
// holds this definition to the Archytan Lite gate service's, and clients
// in other languages reproduce it from the same vectors.
func IntentHash(action, resourceType, resourceID, actorUID, actorRole, decision, idempotencyKey string) ([]byte, error) {
	payloadBytes, err := json.Marshal(intentPayload{
		Action:         action,
		ResourceType:   resourceType,
		ResourceID:     resourceID,
		ActorUID:       actorUID,
		ActorRole:      actorRole,
		Decision:       decision,
		IdempotencyKey: idempotencyKey,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal intent payload: %w", err)
	}
	sum := sha256.Sum256(payloadBytes)
	return sum[:], nil
}

// NewTraceID returns a fresh trace identifier for a request, independent
// of any decision minted for it.
func NewTraceID() (string, error) {
	return randomHex("trc_", 8)
}

func randomHex(prefix string, n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate random id: %w", err)
	}
	return prefix + hex.EncodeToString(buf), nil
}
