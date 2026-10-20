// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

// Package crypto is the domain-separated signing Archytan Lite's receipts
// use: a signature is made over tag||payload, so a signature made under one
// tag never verifies under another. The MCP gate only verifies receipts;
// Sign is here so the tests can mint them.
package crypto

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

const (
	// ReceiptTag scopes the signature over a version 1 receipt's intent
	// hash. This is the tag a receipt's "signature" field is verified
	// against.
	ReceiptTag = "ARCHYTAN_LITE_RECEIPT_V1:"

	// ReceiptTagV2 scopes the signature over a version 2 receipt's intent
	// hash. Its own tag means a v2 signature never verifies as a v1 receipt
	// or the reverse, so a receipt can't be passed off as the other version
	// to dodge the fields only v2 signs.
	ReceiptTagV2 = "ARCHYTAN_LITE_RECEIPT_V2:"
)

// TaggedMessage builds tag||payload.
func TaggedMessage(tag string, payload []byte) []byte {
	msg := make([]byte, 0, len(tag)+len(payload))
	msg = append(msg, tag...)
	msg = append(msg, payload...)
	return msg
}

// Sign produces a domain-tagged Ed25519 signature. The whole tagged message
// goes to the signer, not a digest of it, as pure Ed25519 requires; Go
// signals that with crypto.Hash(0) as the options.
func Sign(signer crypto.Signer, tag string, payload []byte) ([]byte, error) {
	sig, err := signer.Sign(rand.Reader, TaggedMessage(tag, payload), crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("sign %s payload: %w", tag, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("sign %s payload: signer returned a %d-byte signature, want %d (is this key Ed25519?)",
			tag, len(sig), ed25519.SignatureSize)
	}
	return sig, nil
}

// Verify checks a domain-tagged Ed25519 signature. A signature produced
// under a different tag will not verify here, even with the correct key
// and the correct payload.
func Verify(pub ed25519.PublicKey, tag string, payload []byte, sig []byte) bool {
	return ed25519.Verify(pub, TaggedMessage(tag, payload), sig)
}
