// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"

	acrypto "github.com/high-archytech-solutions/archytan-mcp-gate/v2/internal/crypto"
)

// Errors returned by VerifyFor, distinguished so a caller can log precisely
// what failed while still treating every one of them as a deny.
var (
	ErrReceiptMalformed      = errors.New("receipt: malformed intent_hash, signature, or public key")
	ErrReceiptIntentMismatch = errors.New("receipt: fields do not hash to intent_hash")
	ErrReceiptSignature      = errors.New("receipt: signature does not verify")
)

// VerifyFor checks that r is a genuine receipt for exactly the fields it
// carries: those fields, plus the idempotency key the caller itself sent,
// must hash to r.IntentHash, and that hash must carry a valid signature
// from pub. Checking the signature alone is not enough, because the
// signature covers intent_hash and not the fields shown beside it; a
// genuine signature could otherwise be paired with rewritten fields.
//
// Callers still compare r's fields to the request they made. VerifyFor
// proves the receipt is internally consistent and signed, not that it
// answers this particular request.
func VerifyFor(r Receipt, pub ed25519.PublicKey, idempotencyKey string) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrReceiptMalformed
	}
	claimed, err := hex.DecodeString(r.IntentHash)
	if err != nil || len(claimed) != 32 {
		return ErrReceiptMalformed
	}
	sig, err := hex.DecodeString(r.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrReceiptMalformed
	}
	var recomputed []byte
	var tag string
	switch r.version() {
	case Version1:
		// A v1 signature covers none of the v2 fields, so a v1 receipt
		// carrying any of them has been added to.
		if r.hasV2Fields() {
			return ErrReceiptIntentMismatch
		}
		recomputed, err = IntentHash(r.Action, r.ResourceType, r.ResourceID, r.ActorUID, r.ActorRole, r.Decision, idempotencyKey)
		tag = acrypto.ReceiptTag
	case Version2:
		recomputed, err = r.payloadV2(idempotencyKey).hash()
		tag = acrypto.ReceiptTagV2
	default:
		return ErrReceiptMalformed
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(recomputed, claimed) {
		return ErrReceiptIntentMismatch
	}
	if !acrypto.Verify(pub, tag, recomputed, sig) {
		return ErrReceiptSignature
	}
	return nil
}
