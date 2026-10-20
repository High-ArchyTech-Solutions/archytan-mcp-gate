// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestSignVerify_RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	payload := []byte("intent-hash-bytes")
	sig, err := Sign(priv, ReceiptTag, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !Verify(pub, ReceiptTag, payload, sig) {
		t.Fatal("signature did not verify under its own tag")
	}
}

func TestVerify_RejectsCrossTagSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	payload := []byte("intent-hash-bytes")
	sig, err := Sign(priv, ReceiptTag, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if Verify(pub, ReceiptTagV2, payload, sig) {
		t.Fatal("signature made under ReceiptTag must not verify under ReceiptTagV2")
	}
}

func TestVerify_RejectsTamperedPayload(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sig, err := Sign(priv, ReceiptTag, []byte("original"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if Verify(pub, ReceiptTag, []byte("tampered"), sig) {
		t.Fatal("signature over one payload must not verify a different payload")
	}
}

// ---------------------------------------------------------------------
// crypto.Signer abstraction
// ---------------------------------------------------------------------

// remoteSigner stands in for a KMS- or HSM-backed key: it holds a real
// Ed25519 key but reaches it through the crypto.Signer interface only,
// and can be told to fail the way a throttled or unreachable remote
// service would.
type remoteSigner struct {
	inner  ed25519.PrivateKey
	fail   error
	badSig bool
	calls  int
}

func (r *remoteSigner) Public() crypto.PublicKey { return r.inner.Public() }

func (r *remoteSigner) Sign(rnd io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	r.calls++
	if r.fail != nil {
		return nil, r.fail
	}
	if r.badSig {
		return []byte("far too short to be an ed25519 signature"), nil
	}
	// Pure Ed25519 signs the message itself, and Go signals that by
	// passing crypto.Hash(0). A signer handed anything else has been
	// given a pre-hashed digest it cannot correctly sign.
	if opts.HashFunc() != crypto.Hash(0) {
		return nil, fmt.Errorf("expected crypto.Hash(0) for pure Ed25519, got %v", opts.HashFunc())
	}
	return ed25519.Sign(r.inner, msg), nil
}

// TestSign_WorksThroughAnArbitrarySigner is the point of the whole
// abstraction: a signer that never exposes its private key produces
// signatures that verify identically. If this passes, a KMS driver is a
// matter of writing one, not of changing anything that signs.
func TestSign_WorksThroughAnArbitrarySigner(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := &remoteSigner{inner: priv}
	payload := []byte("intent")

	sig, err := Sign(signer, ReceiptTag, payload)
	if err != nil {
		t.Fatalf("Sign through a remote signer: %v", err)
	}
	if signer.calls != 1 {
		t.Fatalf("signer was called %d times, want 1", signer.calls)
	}
	if !Verify(pub, ReceiptTag, payload, sig) {
		t.Fatal("a signature made through the interface did not verify against the same key")
	}
}

// TestSign_PropagatesSignerFailure covers the failure mode a local key
// simply doesn't have. A remote signer can be throttled, expired, or
// unreachable, and the caller has to learn about it — silently returning
// an unusable signature would put an unverifiable receipt in the chain
// forever.
func TestSign_PropagatesSignerFailure(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := &remoteSigner{inner: priv, fail: errors.New("kms: ThrottlingException")}

	if _, err := Sign(signer, ReceiptTag, []byte("intent")); err == nil {
		t.Fatal("expected a signer failure to be returned, not swallowed")
	} else if !strings.Contains(err.Error(), "ThrottlingException") {
		t.Fatalf("the underlying cause should survive wrapping, got %v", err)
	}
}

// TestSign_RejectsWrongSizedSignature catches a signer wired to the wrong
// algorithm at the moment it signs. Without this the gate would mint
// receipts that fail --verify-chain forever, and the operator would find
// out during an audit rather than on the first request.
func TestSign_RejectsWrongSizedSignature(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := &remoteSigner{inner: priv, badSig: true}

	if _, err := Sign(signer, ReceiptTag, []byte("intent")); err == nil {
		t.Fatal("expected a wrong-length signature to be refused")
	}
}
