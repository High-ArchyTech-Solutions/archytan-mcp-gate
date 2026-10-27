// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package mcpgate_e2e

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/high-archytech-solutions/archytan-mcp-gate/v2/internal/mcpgate"
)

// A role scoped by resource, reached through tools that name the resource
// with several arguments, as a code host's MCP server does with owner and
// repo. The agent may read the acme/web-* repositories and push to their
// feature/ branches, and nothing else.
const scopedRepoPolicy = `{"version":1,"actions":[
	{"action":"repo.read","grants":[{"roles":["repo_agent"],"resource_ids":["acme/web-*"]}]},
	{"action":"repo.push","grants":[{"roles":["repo_agent"],"resource_ids":["acme/web-*/feature/**"]}]}]}`

const scopedRepoGateConfig = `{"version":1,"agent_uid":"agent-invoices","tools":{
	"get_repo":{"action":"repo.read","resource_type":"repo","resource_id_args":["owner","repo"]},
	"push_files":{"action":"repo.push","resource_type":"repo_branch","resource_id_args":["owner","repo"],"resource_id_path_arg":"branch"}}}`

func TestGate_ResourceIDArgsAgainstAScopedPolicy(t *testing.T) {
	e := setupWith(t, "repo_agent", scopedRepoPolicy, scopedRepoGateConfig)
	s := e.startGate(t, e.liteURL)
	s.request("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "e2e"}})

	type call struct {
		tool string
		args map[string]any
	}
	for _, c := range []call{
		{"get_repo", map[string]any{"owner": "acme", "repo": "web-shop"}},
		{"push_files", map[string]any{"owner": "acme", "repo": "web-shop", "branch": "feature/login", "message": "m"}},
	} {
		if isErr, text := s.callTool(c.tool, c.args); isErr || text != "executed "+c.tool {
			t.Fatalf("in-scope %s %v was not executed: %v %q", c.tool, c.args, isErr, text)
		}
	}

	// The gate builds an id Archytan Lite can read, and Lite refuses it:
	// outside every grant, or, for the last two, ambiguous before any grant
	// is consulted.
	for _, c := range []call{
		{"get_repo", map[string]any{"owner": "evil", "repo": "web-shop"}},
		{"get_repo", map[string]any{"owner": "acme", "repo": "api"}},
		{"push_files", map[string]any{"owner": "acme", "repo": "web-shop", "branch": "main"}},
		{"push_files", map[string]any{"owner": "acme", "repo": "web-shop", "branch": "feature/../main"}},
		{"push_files", map[string]any{"owner": "acme", "repo": "web-shop", "branch": "feature//x"}},
	} {
		if isErr, text := s.callTool(c.tool, c.args); !isErr || !strings.Contains(text, "the gate did not allow this action") {
			t.Errorf("%s %v: want Archytan Lite's refusal, got %v %q", c.tool, c.args, isErr, text)
		}
	}

	// These the MCP gate refuses itself, before asking Lite.
	for _, c := range []struct {
		call
		want string
	}{
		{call{"push_files", map[string]any{"owner": "acme", "repo": "web-shop/feature", "branch": "x"}}, `argument "repo" to be a single name`},
		{call{"push_files", map[string]any{"owner": "acme", "repo": "web-shop"}}, `argument "branch"`},
		{call{"get_repo", map[string]any{"owner": "acme", "repo": 7}}, `argument "repo"`},
	} {
		if isErr, text := s.callTool(c.tool, c.args); !isErr || !strings.Contains(text, c.want) {
			t.Errorf("%s %v: want the MCP gate's refusal mentioning %q, got %v %q", c.tool, c.args, c.want, isErr, text)
		}
	}

	if got := e.executedCalls(t); len(got) != 2 {
		t.Fatalf("want exactly the 2 in-scope calls executed, got %d: %v", len(got), got)
	}

	// Why the gate's own refusal matters: the boundary-shifted call above,
	// repo "web-shop/feature" with branch "x", would join to
	// acme/web-shop/feature/x, and Lite, seeing only that id, allows it.
	// Only the MCP gate knows "feature" came from the repo argument.
	token, err := os.ReadFile(e.tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := hex.DecodeString(e.pubHex)
	if err != nil {
		t.Fatal(err)
	}
	direct := &mcpgate.GateClient{BaseURL: e.liteURL, Token: strings.TrimSpace(string(token)), PublicKey: ed25519.PublicKey(pub), HTTP: &http.Client{Timeout: mcpgate.RequestTimeout}}
	if _, err := direct.Authorize(context.Background(), "repo.push", "agent-invoices", "repo_branch", "acme/web-shop/feature/x"); err != nil {
		t.Fatalf("expected Lite to allow the joined id on its own, which is the case the gate's check exists for: %v", err)
	}

	e.lite.kill()
	t.Log(verifyChain(t, e.dir, e.pubHex))
}
