// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package mcpgate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/high-archytech-solutions/archytan-mcp-gate/v2/internal/receipt"
)

var testKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))

type fakeLite struct {
	decision   string
	status     int
	capability bool
	// mutate edits the receipt after it is minted, to simulate a tampering
	// intermediary.
	mutate func(*receipt.Receipt)
	// mintResource overrides the resource the receipt is minted for.
	mintResource   string
	redeemStatus   int
	lastRedeem     map[string]string
	emptyCapToken  bool
	redeemDecision string
}

func (f *fakeLite) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/authorize":
			var req struct {
				Action   string            `json:"action"`
				Actor    map[string]string `json:"actor"`
				Resource map[string]string `json:"resource"`
				Idem     string            `json:"idempotency_key"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode authorize: %v", err)
			}
			if r.Header.Get("Authorization") != "Bearer agent-token" {
				t.Fatalf("missing bearer token")
			}
			if _, ok := req.Actor["role"]; ok {
				t.Fatalf("the gate must never assert a role")
			}
			resID := req.Resource["id"]
			if f.mintResource != "" {
				resID = f.mintResource
			}
			rc, err := receipt.Mint(testKey, "urn:test", "trace", f.decision, req.Action, req.Resource["type"], resID, req.Actor["uid"], "billing_agent", req.Idem)
			if err != nil {
				t.Fatal(err)
			}
			if f.mutate != nil {
				f.mutate(&rc)
			}
			body := map[string]any{"decision": f.decision, "receipt": rc}
			if f.capability {
				token := "cap-token"
				if f.emptyCapToken {
					token = ""
				}
				body["capability"] = map[string]string{"token": token, "cap_id": "cap_1"}
			}
			status := f.status
			if status == 0 {
				status = http.StatusOK
			}
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(body)
		case "/v1/redeem":
			_ = json.NewDecoder(r.Body).Decode(&f.lastRedeem)
			status := f.redeemStatus
			if status == 0 {
				status = http.StatusOK
			}
			decision := f.redeemDecision
			if decision == "" {
				decision = receipt.DecisionAllow
			}
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"decision": decision})
		}
	})
}

func newTestClient(t *testing.T, f *fakeLite) *GateClient {
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	return &GateClient{BaseURL: srv.URL, Token: "agent-token", PublicKey: testKey.Public().(ed25519.PublicKey)}
}

func TestGateClient_GenuineAllowWithCapability(t *testing.T) {
	f := &fakeLite{decision: receipt.DecisionAllow, capability: true}
	c := newTestClient(t, f)
	g, err := c.Authorize(context.Background(), "invoice.delete", "agent-invoices", "invoice", "inv_7")
	if err != nil {
		t.Fatalf("genuine allow refused: %v", err)
	}
	if g.CapabilityToken != "cap-token" || g.ResourceID != "inv_7" || g.ReceiptID == "" {
		t.Fatalf("grant wrong: %+v", g)
	}
	if err := c.Redeem(context.Background(), g); err != nil {
		t.Fatalf("redeem refused: %v", err)
	}
	if f.lastRedeem["action"] != "invoice.delete" || f.lastRedeem["resource_id"] != "inv_7" || f.lastRedeem["token"] != "cap-token" {
		t.Fatalf("redeemed the wrong scope: %v", f.lastRedeem)
	}
}

func TestGateClient_RefusesEverythingElse(t *testing.T) {
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	cases := map[string]*fakeLite{
		"block":             {decision: receipt.DecisionBlock, capability: true},
		"non_200":           {decision: receipt.DecisionAllow, capability: true, status: http.StatusForbidden},
		"no_capability":     {decision: receipt.DecisionAllow},
		"empty_capability":  {decision: receipt.DecisionAllow, capability: true, emptyCapToken: true},
		"rewritten_fields":  {decision: receipt.DecisionAllow, capability: true, mutate: func(r *receipt.Receipt) { r.ResourceID = "inv_7"; r.Action = "invoice.delete" }, mintResource: "inv_1"},
		"receipt_for_other": {decision: receipt.DecisionAllow, capability: true, mintResource: "inv_99"},
		"flipped_signature": {decision: receipt.DecisionAllow, capability: true, mutate: func(r *receipt.Receipt) { r.Signature = strings.Repeat("0", 128) }},
		"signed_by_stranger": {decision: receipt.DecisionAllow, capability: true, mutate: func(r *receipt.Receipt) {
			re, _ := receipt.Mint(other, r.OperatorURN, r.TraceID, r.Decision, r.Action, r.ResourceType, r.ResourceID, r.ActorUID, r.ActorRole, "")
			r.Signature = re.Signature
		}},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			c := newTestClient(t, f)
			if _, err := c.Authorize(context.Background(), "invoice.delete", "agent-invoices", "invoice", "inv_7"); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestGateClient_RedeemRefusal(t *testing.T) {
	cases := map[string]*fakeLite{
		"non_200":        {redeemStatus: http.StatusForbidden},
		"200_but_not_ok": {redeemDecision: receipt.DecisionBlock},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			c := newTestClient(t, f)
			if err := c.Redeem(context.Background(), Grant{CapabilityToken: "t", Action: "a", ResourceType: "b", ResourceID: "c"}); err == nil {
				t.Fatal("a refused redemption was treated as spent")
			}
		})
	}
}

func TestGateClient_UnreachableGate(t *testing.T) {
	c := &GateClient{BaseURL: "http://127.0.0.1:1", Token: "t", PublicKey: testKey.Public().(ed25519.PublicKey)}
	if _, err := c.Authorize(context.Background(), "a", "u", "b", "c"); err == nil {
		t.Fatal("an unreachable gate authorized")
	}
}

func TestValidateGateURL(t *testing.T) {
	for _, ok := range []string{"https://gate.example.com", "http://127.0.0.1:8421", "http://localhost:8421", "http://[::1]:8421"} {
		if err := ValidateGateURL(ok); err != nil {
			t.Errorf("%s rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://gate.example.com", "http://10.0.0.5:8421", "ftp://x", "gate.example.com", ""} {
		if err := ValidateGateURL(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
