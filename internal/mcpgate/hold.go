// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package mcpgate

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/high-archytech-solutions/archytan-mcp-gate/v2/internal/receipt"
)

// HoldWaitEnv names the environment variable that sets GateClient.HoldWait,
// in whole seconds.
const HoldWaitEnv = "ARCHYTAN_MCP_GATE_HOLD_WAIT_SECONDS"

// MaxHoldWait is the longest HoldWait a configuration may ask for. A hold
// can't outlive the policy's own ttl in any case.
const MaxHoldWait = time.Hour

const (
	defaultHoldPoll = 2 * time.Second
	// holdGrace is how long past a hold's expires_at the wait lasts, so that
	// a little clock skew between the gate and this process still lets the
	// gate's own answer ("expired") arrive instead of a timeout.
	holdGrace = 2 * time.Second
)

// ParseHoldWait reads the value of HoldWaitEnv: whole seconds from 0 to an
// hour, or empty for the default of 0, which doesn't wait. Anything else is
// an error, so a typo can't quietly turn waiting on or off.
func ParseHoldWait(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || time.Duration(n)*time.Second > MaxHoldWait {
		return 0, fmt.Errorf("%s must be a whole number of seconds from 0 to %d, got %q", HoldWaitEnv, int(MaxHoldWait/time.Second), raw)
	}
	return time.Duration(n) * time.Second, nil
}

// holdView is what GET /v1/holds/{id} says about a hold. Reading it mints
// nothing.
type holdView struct {
	HoldID string `json:"hold_id"`
	State  string `json:"state"`
}

// Hold states.
const (
	holdOpen     = "open"
	holdApproved = "approved"
	holdDenied   = "denied"
	holdExpired  = "expired"
	holdRefused  = "refused"
)

// authorizeHeld handles a 202: the gate has opened a hold and asks a person.
// A HOLD is never an allow. The 202 counts as a HOLD only if its receipt
// verifies with this call's own key, says HOLD, describes this request, and
// the hold's id is the receipt's id; anything else is a plain refusal.
// Then, when this gate is set to wait, it reads the hold until a person has
// answered it (or the wait ends), and asks again once, with the same key, to
// collect what the approval made.
func (c *GateClient) authorizeHeld(ctx context.Context, q authorizeRequest, idem string, resp authorizeResponse) (Grant, error) {
	h := resp.Receipt
	if resp.Decision != receipt.DecisionHold || h.Decision != receipt.DecisionHold || h.Version != receipt.Version2 {
		return Grant{}, errors.New("the gate did not allow this action")
	}
	if err := receipt.VerifyFor(h, c.PublicKey, idem); err != nil {
		return Grant{}, fmt.Errorf("the gate's hold receipt failed verification: %w", err)
	}
	if !q.describes(h) {
		return Grant{}, errors.New("the gate's hold receipt does not describe this request")
	}
	if resp.Hold == nil || resp.Hold.HoldID == "" || resp.Hold.HoldID != h.ReceiptID {
		return Grant{}, errors.New("the gate's hold does not match its hold receipt")
	}
	holdID := h.ReceiptID
	expires, err := time.Parse(time.RFC3339Nano, resp.Hold.ExpiresAt)
	if err != nil {
		return Grant{}, fmt.Errorf("the gate's hold %s has no usable expiry: %w", holdID, err)
	}

	if c.HoldWait <= 0 {
		return Grant{}, fmt.Errorf("this action is held for a person's approval as hold %s, and this gate is set not to wait for it (%s is 0)", holdID, HoldWaitEnv)
	}
	start := time.Now()
	deadline := start.Add(c.HoldWait)
	if byExpiry := expires.Add(holdGrace); byExpiry.Before(deadline) {
		deadline = byExpiry
	}
	poll := c.holdPoll
	if poll <= 0 {
		poll = defaultHoldPoll
	}

	for {
		view, err := c.readHold(ctx, holdID)
		if err != nil {
			return Grant{}, fmt.Errorf("could not read hold %s while waiting for a person to answer it: %w", holdID, err)
		}
		switch view.State {
		case holdOpen:
		case holdApproved:
			return c.collectHold(ctx, q, idem, holdID)
		case holdDenied:
			return Grant{}, fmt.Errorf("a person denied this action (hold %s)", holdID)
		case holdExpired:
			return Grant{}, fmt.Errorf("nobody answered this action before its hold expired (hold %s)", holdID)
		case holdRefused:
			return Grant{}, fmt.Errorf("a person approved this action (hold %s), but the gate refused to release it because the policy no longer allows it", holdID)
		default:
			return Grant{}, fmt.Errorf("hold %s is in a state this gate doesn't know (%q)", holdID, view.State)
		}
		left := time.Until(deadline)
		if left <= 0 {
			return Grant{}, fmt.Errorf("this action is held for a person's approval as hold %s, and nobody answered within %d seconds; the hold stays open until %s, but this call has stopped waiting", holdID, int(time.Since(start).Round(time.Second)/time.Second), expires.UTC().Format(time.RFC3339))
		}
		select {
		case <-ctx.Done():
			return Grant{}, fmt.Errorf("stopped waiting for hold %s: %w", holdID, ctx.Err())
		case <-time.After(min(poll, left)):
		}
	}
}

// readHold reads one hold. It must be the hold asked for.
func (c *GateClient) readHold(ctx context.Context, holdID string) (holdView, error) {
	var v holdView
	status, err := c.do(ctx, http.MethodGet, "/v1/holds/"+url.PathEscape(holdID), nil, &v, http.StatusOK)
	if err != nil {
		return holdView{}, err
	}
	if status != http.StatusOK {
		return holdView{}, fmt.Errorf("the gate answered %d", status)
	}
	if v.HoldID != holdID {
		return holdView{}, errors.New("the gate described a different hold")
	}
	return v, nil
}

// collectHold repeats the authorize request, exactly and with the same key,
// once a person has approved the hold, and accepts only a 200 that passes
// verifyResolution.
func (c *GateClient) collectHold(ctx context.Context, q authorizeRequest, idem, holdID string) (Grant, error) {
	var resp authorizeResponse
	status, err := c.do(ctx, http.MethodPost, "/v1/authorize", q.body(idem), &resp, http.StatusOK)
	if err != nil {
		return Grant{}, fmt.Errorf("could not collect the approval of hold %s: %w", holdID, err)
	}
	switch status {
	case http.StatusOK:
	case http.StatusGone:
		return Grant{}, fmt.Errorf("a person approved this action (hold %s), but the approval can no longer be collected: it was not collected in time, or was already; the action has to be asked for again", holdID)
	default:
		return Grant{}, fmt.Errorf("a person approved this action (hold %s), but the gate would not release it (it answered %d)", holdID, status)
	}
	g, err := c.verifyResolution(resp, q, idem, holdID)
	if err != nil {
		return Grant{}, fmt.Errorf("the gate's release of hold %s was refused: %w", holdID, err)
	}
	return g, nil
}

// verifyResolution checks a 200 that resolves a hold. The resolution
// receipt names the approver as its actor and caller, so it is not compared
// to the request; the HOLD receipt beside it is, and the resolution is tied
// to that HOLD receipt by the key it is signed under, "hold:" plus the HOLD
// receipt's id. Any mismatch refuses.
func (c *GateClient) verifyResolution(resp authorizeResponse, q authorizeRequest, idem, holdID string) (Grant, error) {
	if resp.Decision != receipt.DecisionAllow || resp.HoldReceipt == nil {
		return Grant{}, errors.New("the response is not an ALLOW that carries the hold receipt")
	}
	h, r := *resp.HoldReceipt, resp.Receipt
	if h.Decision != receipt.DecisionHold || h.Version != receipt.Version2 {
		return Grant{}, errors.New("the hold receipt is not a version 2 HOLD")
	}
	if err := receipt.VerifyFor(h, c.PublicKey, idem); err != nil {
		return Grant{}, fmt.Errorf("the hold receipt failed verification: %w", err)
	}
	if !q.describes(h) {
		return Grant{}, errors.New("the hold receipt does not describe this request")
	}
	if h.ReceiptID != holdID {
		return Grant{}, errors.New("the hold receipt is for a different hold")
	}
	if r.Decision != receipt.DecisionAllow || r.Version != receipt.Version2 {
		return Grant{}, errors.New("the resolution receipt is not a version 2 ALLOW")
	}
	if err := receipt.VerifyFor(r, c.PublicKey, "hold:"+h.ReceiptID); err != nil {
		return Grant{}, fmt.Errorf("the resolution receipt failed verification: %w", err)
	}
	if r.Action != h.Action || r.ResourceType != h.ResourceType || r.ResourceID != h.ResourceID || r.ResourceTenantID != h.ResourceTenantID {
		return Grant{}, errors.New("the resolution receipt is for a different action or resource than the hold")
	}
	if resp.Capability == nil || resp.Capability.Token == "" {
		return Grant{}, errors.New("the gate issued no capability")
	}
	return Grant{
		ReceiptID:       r.ReceiptID,
		CapabilityToken: resp.Capability.Token,
		Action:          q.action,
		ResourceType:    q.resourceType,
		ResourceID:      q.resourceID,
	}, nil
}
