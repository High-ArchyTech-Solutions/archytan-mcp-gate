// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package mcpgate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/high-archytech-solutions/archytan-mcp-gate/v2/internal/receipt"
	"github.com/high-archytech-solutions/archytan-mcp-gate/v2/internal/tracectx"
)

// Authorizer is what the relay needs from Archytan Lite: a verified
// decision with a capability, and redemption of that capability.
type Authorizer interface {
	Authorize(ctx context.Context, action, actorUID, resourceType, resourceID string) (Grant, error)
	Redeem(ctx context.Context, g Grant) error
}

// Grant is a verified ALLOW: the receipt that proves the decision and the
// capability that must be spent before the call is forwarded.
type Grant struct {
	ReceiptID       string
	CapabilityToken string
	Action          string
	ResourceType    string
	ResourceID      string
}

// GateClient talks to a running archytan-lite.
type GateClient struct {
	BaseURL   string
	Token     string
	PublicKey ed25519.PublicKey
	HTTP      *http.Client
	// HoldWait is the longest Authorize waits for a person to answer an
	// action Archytan Lite holds for approval. Zero, the default, doesn't
	// wait: a held action is refused at once, naming the hold.
	HoldWait time.Duration

	// holdPoll is how often a hold is read while waiting; zero means
	// defaultHoldPoll. Tests shorten it.
	holdPoll time.Duration
}

// RequestTimeout bounds each call to the gate. A slow gate is a denying
// gate.
const RequestTimeout = 3 * time.Second

const maxGateResponseBytes = 1 << 20

// ValidateGateURL refuses plain http to anything but loopback, because
// every request carries the agent's bearer credential.
func ValidateGateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("gate URL %q is not an absolute URL", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("gate URL %q uses plain http to a non-loopback host; use https, since every request carries the agent's credential", raw)
	default:
		return fmt.Errorf("gate URL %q must be http(s)", raw)
	}
}

// traceparentKey carries an agent's traceparent from its tools/call to the
// authorize and redeem requests made for that call.
type traceparentKey struct{}

// withTraceparent attaches tp to ctx when it is a traceparent the gate
// itself would read (tracectx.Parse), and returns ctx unchanged otherwise,
// so nothing else can reach a request header through it.
func withTraceparent(ctx context.Context, tp string) context.Context {
	if _, ok := tracectx.Parse(tp); !ok {
		return ctx
	}
	return context.WithValue(ctx, traceparentKey{}, tp)
}

func traceparentFrom(ctx context.Context) string {
	tp, _ := ctx.Value(traceparentKey{}).(string)
	return tp
}

func (c *GateClient) post(ctx context.Context, path string, body any, out any) (int, error) {
	return c.do(ctx, http.MethodPost, path, body, out, http.StatusOK)
}

// do makes one request to the gate and decodes the response body into out
// only when its status is one of decodeOn; any other status returns with
// out untouched, for the caller to refuse.
func (c *GateClient) do(ctx context.Context, method, path string, body any, out any, decodeOn ...int) (int, error) {
	var payload io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		payload = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, payload)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// The agent's trace, when its tools/call carried one: the gate logs it
	// beside the decision and signs its trace id into a v2 receipt.
	if tp := traceparentFrom(ctx); tp != "" {
		req.Header.Set(tracectx.HeaderName, tp)
	}
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("gate unreachable: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxGateResponseBytes))
	if err != nil {
		return resp.StatusCode, fmt.Errorf("read gate response: %w", err)
	}
	if slices.Contains(decodeOn, resp.StatusCode) {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("malformed gate response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

func newIdempotencyKey() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "mcp-" + hex.EncodeToString(b), nil
}

// authorizeRequest is what the relay asks the gate to decide, and what every
// receipt the gate returns for it must describe.
type authorizeRequest struct {
	action, actorUID, resourceType, resourceID string
}

// describes reports whether r is a receipt for exactly this request.
func (q authorizeRequest) describes(r receipt.Receipt) bool {
	return r.Action == q.action && r.ResourceType == q.resourceType && r.ResourceID == q.resourceID && r.ActorUID == q.actorUID
}

// body is the authorize request as sent. Replaying a held request sends the
// same body, with the same idempotency key, so the gate answers from the
// hold it already opened.
func (q authorizeRequest) body(idem string) map[string]any {
	return map[string]any{
		"action":          q.action,
		"actor":           map[string]string{"uid": q.actorUID},
		"resource":        map[string]string{"type": q.resourceType, "id": q.resourceID},
		"idempotency_key": idem,
	}
}

// authorizeResponse is the gate's answer to /v1/authorize: an ALLOW with a
// capability (200), a HOLD with the hold that was opened (202), or an ALLOW
// that resolves a hold, which also carries the HOLD receipt (200).
type authorizeResponse struct {
	Decision   string          `json:"decision"`
	Receipt    receipt.Receipt `json:"receipt"`
	Capability *struct {
		Token string `json:"token"`
	} `json:"capability"`
	Hold *struct {
		HoldID    string `json:"hold_id"`
		ExpiresAt string `json:"expires_at"`
	} `json:"hold"`
	HoldReceipt *receipt.Receipt `json:"hold_receipt"`
}

// Authorize asks the gate and accepts only a genuine ALLOW for exactly this
// request that carries a capability. An action the gate holds for a person's
// approval is an allow only once a person approved it and the gate's
// resolution verifies; see authorizeHeld.
func (c *GateClient) Authorize(ctx context.Context, action, actorUID, resourceType, resourceID string) (Grant, error) {
	idem, err := newIdempotencyKey()
	if err != nil {
		return Grant{}, err
	}
	q := authorizeRequest{action: action, actorUID: actorUID, resourceType: resourceType, resourceID: resourceID}
	var resp authorizeResponse
	status, err := c.do(ctx, http.MethodPost, "/v1/authorize", q.body(idem), &resp, http.StatusOK, http.StatusAccepted)
	if err != nil {
		return Grant{}, err
	}
	if status == http.StatusAccepted {
		return c.authorizeHeld(ctx, q, idem, resp)
	}
	if status != http.StatusOK || resp.Decision != receipt.DecisionAllow {
		return Grant{}, errors.New("the gate did not allow this action")
	}
	// The body's decision is not signed; the receipt's is. A genuine receipt
	// for a HOLD or a BLOCK, relabelled ALLOW in the body, verifies, so say it too.
	if resp.Receipt.Decision != receipt.DecisionAllow {
		return Grant{}, errors.New("the gate's receipt does not say ALLOW")
	}
	if err := receipt.VerifyFor(resp.Receipt, c.PublicKey, idem); err != nil {
		return Grant{}, fmt.Errorf("the gate's receipt failed verification: %w", err)
	}
	r := resp.Receipt
	if !q.describes(r) {
		return Grant{}, errors.New("the gate's receipt does not describe this request")
	}
	if resp.Capability == nil || resp.Capability.Token == "" {
		return Grant{}, errors.New("the gate issued no capability; this gate requires ARCHYTAN_LITE_CAPABILITIES=on")
	}
	return Grant{
		ReceiptID:       r.ReceiptID,
		CapabilityToken: resp.Capability.Token,
		Action:          action,
		ResourceType:    resourceType,
		ResourceID:      resourceID,
	}, nil
}

// Redeem spends the capability for exactly the action and resource it was
// granted for. Only a 200 whose decision is ALLOW counts as spent.
func (c *GateClient) Redeem(ctx context.Context, g Grant) error {
	var resp struct {
		Decision string `json:"decision"`
	}
	status, err := c.post(ctx, "/v1/redeem", map[string]string{
		"token":         g.CapabilityToken,
		"action":        g.Action,
		"resource_type": g.ResourceType,
		"resource_id":   g.ResourceID,
	}, &resp)
	if err != nil {
		return err
	}
	if status != http.StatusOK || resp.Decision != receipt.DecisionAllow {
		return errors.New("the gate refused to redeem the capability (expired, already spent, out of scope, or no longer allowed by the current policy)")
	}
	return nil
}
