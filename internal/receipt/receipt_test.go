// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"crypto"
	"errors"
	acrypto "github.com/high-archytech-solutions/archytan-mcp-gate/internal/crypto"
	"io"
)

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return priv
}

func TestMint_ProducesVerifiableSignature(t *testing.T) {
	priv := testKey(t)
	pub := priv.Public().(ed25519.PublicKey)

	r, err := Mint(priv, "urn:archytan-lite:instance:test", "trc_abc", DecisionAllow,
		"business.delete", "business", "bid_1", "uid_1", "admin", "idem_1")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if r.Signature == "" || r.IntentHash == "" || r.ReceiptID == "" {
		t.Fatalf("Mint produced an incomplete receipt: %+v", r)
	}

	intentHash, err := hex.DecodeString(r.IntentHash)
	if err != nil {
		t.Fatalf("decode intent hash: %v", err)
	}
	sig, err := hex.DecodeString(r.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !acrypto.Verify(pub, acrypto.ReceiptTag, intentHash, sig) {
		t.Fatal("minted receipt's signature does not verify against the intent hash and ReceiptTag")
	}
}

func TestMint_SameInputsSameIntentHash(t *testing.T) {
	priv := testKey(t)
	r1, err := Mint(priv, "urn:x", "trc_1", DecisionAllow, "a", "b", "c", "d", "e", "idem")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := Mint(priv, "urn:x", "trc_2", DecisionAllow, "a", "b", "c", "d", "e", "idem")
	if err != nil {
		t.Fatal(err)
	}
	if r1.IntentHash != r2.IntentHash {
		t.Fatalf("same action/resource/actor/idempotency-key must hash identically, got %s vs %s", r1.IntentHash, r2.IntentHash)
	}
}

// TestMint_DifferentDecisionSameOtherFieldsDifferentHashAndSignature is the
// regression test for the bug where decision was excluded from
// intentPayload: an ALLOW and a BLOCK receipt for otherwise-identical
// inputs used to produce the same intent_hash and the same signature,
// meaning a decision could be swapped in storage without invalidating
// anything Mint or VerifyChain checked. Decision must now be part of what
// gets signed.
func TestMint_DifferentDecisionSameOtherFieldsDifferentHashAndSignature(t *testing.T) {
	priv := testKey(t)
	allow, err := Mint(priv, "urn:x", "trc_1", DecisionAllow, "a", "b", "c", "d", "e", "idem-same")
	if err != nil {
		t.Fatal(err)
	}
	block, err := Mint(priv, "urn:x", "trc_2", DecisionBlock, "a", "b", "c", "d", "e", "idem-same")
	if err != nil {
		t.Fatal(err)
	}
	if allow.IntentHash == block.IntentHash {
		t.Fatal("ALLOW and BLOCK for identical action/resource/actor/idempotency-key must NOT hash identically — decision must be bound into intent_hash")
	}
	if allow.Signature == block.Signature {
		t.Fatal("ALLOW and BLOCK for identical other fields must NOT share a signature — a shared signature would let one decision be substituted for the other undetected")
	}
}

// wrappedSigner reaches an Ed25519 key only through the crypto.Signer
// interface, standing in for a KMS-backed key, and can be told to fail.
type wrappedSigner struct {
	inner ed25519.PrivateKey
	fail  error
}

func (w wrappedSigner) Public() crypto.PublicKey { return w.inner.Public() }

func (w wrappedSigner) Sign(rnd io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	if w.fail != nil {
		return nil, w.fail
	}
	return ed25519.Sign(w.inner, msg), nil
}

// TestMint_ThroughAnExternalSigner proves a receipt minted by a signer
// that never exposes its private key is indistinguishable from one minted
// locally — same chain-verifiable signature, over the same intent.
func TestMint_ThroughAnExternalSigner(t *testing.T) {
	priv := testKey(t)
	pub := priv.Public().(ed25519.PublicKey)

	r, err := Mint(wrappedSigner{inner: priv}, "urn:x", "trc", DecisionAllow,
		"a", "t", "res", "uid", "role", "key-1")
	if err != nil {
		t.Fatalf("Mint through an external signer: %v", err)
	}

	sig, err := hex.DecodeString(r.Signature)
	if err != nil {
		t.Fatal(err)
	}
	intentHash, err := hex.DecodeString(r.IntentHash)
	if err != nil {
		t.Fatal(err)
	}
	if !acrypto.Verify(pub, acrypto.ReceiptTag, intentHash, sig) {
		t.Fatal("a receipt signed through the interface did not verify")
	}
}

// TestMint_SignerFailureProducesNoReceipt is the fail-closed property of
// the new error path. A local key cannot fail; a remote one can be
// throttled or revoked mid-request. When that happens the caller must get
// an error, never a Receipt with an empty or bogus signature that would
// go on to be persisted and break the chain permanently.
func TestMint_SignerFailureProducesNoReceipt(t *testing.T) {
	priv := testKey(t)
	signer := wrappedSigner{inner: priv, fail: errors.New("kms unavailable")}

	r, err := Mint(signer, "urn:x", "trc", DecisionAllow, "a", "t", "res", "uid", "role", "key-1")
	if err == nil {
		t.Fatal("expected a signer failure to fail the mint")
	}
	if r.ReceiptID != "" || r.Signature != "" {
		t.Fatalf("a failed mint must return a zero Receipt, got %+v", r)
	}
}
