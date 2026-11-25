// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package mcpgate_e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const holdGateConfig = `{"version":1,"agent_uid":"agent-invoices","tools":{
	"delete_invoice":{"action":"invoice.delete","resource_type":"invoice","resource_id_arg":"invoice_id"}}}`

// A policy whose delete waits for a supervisor. ttl_seconds 60 is the least
// the service accepts.
const holdPolicy = `{"version":2,"actions":[
	{"action":"invoice.delete","allowed_roles":["billing_agent"],"hold":{"approver_roles":["supervisor"],"ttl_seconds":60}}]}`

// Holds came with Archytan Lite 2.9.0, newer than the service these tests
// run against by default, so they run only when ARCHYTAN_LITE_HOLDS=1 says
// the service they're pointed at (ARCHYTAN_LITE_BIN) has them.
func setupHeld(t *testing.T) *env {
	t.Helper()
	if os.Getenv("ARCHYTAN_LITE_HOLDS") != "1" {
		t.Skip("set ARCHYTAN_LITE_HOLDS=1 with an ARCHYTAN_LITE_BIN of Archytan Lite 2.9.0 or later to run the hold tests")
	}
	return setupWithApprover(t, "billing_agent", "supervisor", holdPolicy, holdGateConfig)
}

// answerWhenAsked plays the person: as maria it waits for the hold to
// appear, then approves or denies it. The returned wait reports what went
// wrong, if anything, and the hold's id.
func (e *env) answerWhenAsked(t *testing.T, verb string) (wait func() (holdID string, err error)) {
	var wg sync.WaitGroup
	var holdID string
	var failure error
	wg.Add(1)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			var list struct {
				Holds []struct {
					HoldID string `json:"hold_id"`
					State  string `json:"state"`
				} `json:"holds"`
			}
			if _, err := e.maria(http.MethodGet, "/v1/holds", "", &list); err != nil {
				failure = err
				return
			}
			for _, h := range list.Holds {
				if h.State != "open" {
					continue
				}
				holdID = h.HoldID
				status, err := e.maria(http.MethodPost, "/v1/holds/"+h.HoldID+"/"+verb, `{"actor":{"uid":"maria"}}`, nil)
				if err == nil && status != http.StatusOK {
					err = fmt.Errorf("%s answered %d", verb, status)
				}
				failure = err
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		failure = fmt.Errorf("no open hold appeared")
	}()
	return func() (string, error) { wg.Wait(); return holdID, failure }
}

func (e *env) maria(method, path, body string, out any) (int, error) {
	req, err := http.NewRequest(method, e.liteURL+path, strings.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+e.approverToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

func TestHold_ApprovedCallRunsOnce(t *testing.T) {
	e := setupHeld(t)
	s := e.startGate(t, e.liteURL, "ARCHYTAN_MCP_GATE_HOLD_WAIT_SECONDS=30")
	wait := e.answerWhenAsked(t, "approve")
	isErr, text := s.callTool("delete_invoice", map[string]any{"invoice_id": "inv_7"})
	if _, err := wait(); err != nil {
		t.Fatalf("the approver: %v", err)
	}
	if isErr || text != "executed delete_invoice" {
		t.Fatalf("an approved call did not run: %v %q", isErr, text)
	}
	if got := e.executedCalls(t); len(got) != 1 {
		t.Fatalf("the approved call executed %d times: %v", len(got), got)
	}
}

func TestHold_DeniedCallNeverRuns(t *testing.T) {
	e := setupHeld(t)
	s := e.startGate(t, e.liteURL, "ARCHYTAN_MCP_GATE_HOLD_WAIT_SECONDS=30")
	wait := e.answerWhenAsked(t, "deny")
	isErr, text := s.callTool("delete_invoice", map[string]any{"invoice_id": "inv_7"})
	holdID, err := wait()
	if err != nil {
		t.Fatalf("the approver: %v", err)
	}
	if !isErr || !strings.Contains(text, "denied") || !strings.Contains(text, holdID) {
		t.Fatalf("a denied call should be refused naming its hold %s: %v %q", holdID, isErr, text)
	}
	if got := e.executedCalls(t); len(got) != 0 {
		t.Fatalf("a denied call executed: %v", got)
	}
}

// By default the gate doesn't wait: the call is refused at once and names
// the hold, which stays open for a person.
func TestHold_NoWaitByDefault(t *testing.T) {
	e := setupHeld(t)
	s := e.startGate(t, e.liteURL)
	start := time.Now()
	isErr, text := s.callTool("delete_invoice", map[string]any{"invoice_id": "inv_7"})
	if !isErr || !strings.Contains(text, "not to wait") || !strings.Contains(text, "rcpt_") {
		t.Fatalf("a held call should be refused at once, naming the hold: %v %q", isErr, text)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("a gate set not to wait took %v", time.Since(start))
	}
	if got := e.executedCalls(t); len(got) != 0 {
		t.Fatalf("a held call executed: %v", got)
	}
}
