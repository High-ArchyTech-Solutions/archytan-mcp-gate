// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package mcpgate_e2e

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// configWithServer is mcp-gate.json with the tool server named in it.
func configWithServer(t *testing.T, command string, args ...string) string {
	t.Helper()
	server, err := json.Marshal(map[string]any{"command": command, "args": args})
	if err != nil {
		t.Fatal(err)
	}
	return `{"version":1,"agent_uid":"agent-invoices","server":` + string(server) + `,"tools":{
		"delete_invoice":{"action":"invoice.delete","resource_type":"invoice","resource_id_arg":"invoice_id"},
		"delete_tenant":{"action":"tenant.delete","resource_type":"tenant","resource_id_arg":"tenant_id"}}}`
}

// A tool server named in the config runs and is gated exactly like one
// named after "--".
func TestGate_ServerNamedInConfig(t *testing.T) {
	e := setup(t)
	path := filepath.Join(e.dir, "mcp-gate.server.json")
	write(t, path, configWithServer(t, e.serverBin))
	s := e.startGateArgs(t, e.liteURL, []string{"--config", path})

	s.request("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "e2e"}})
	var names []string
	for _, tl := range s.request("tools/list", map[string]any{})["result"].(map[string]any)["tools"].([]any) {
		names = append(names, tl.(map[string]any)["name"].(string))
	}
	if strings.Join(names, ",") != "delete_invoice,delete_tenant" {
		t.Fatalf("agent saw tools %v", names)
	}
	if isErr, text := s.callTool("delete_invoice", map[string]any{"invoice_id": "inv_7"}); isErr || text != "executed delete_invoice" {
		t.Fatalf("allowed call failed: %v %q", isErr, text)
	}
	if isErr, text := s.callTool("delete_tenant", map[string]any{"tenant_id": "t_1"}); !isErr || !strings.HasPrefix(text, "Refused by Archytan Lite") {
		t.Fatalf("disallowed role was not refused: %v %q", isErr, text)
	}
	if got := e.executedCalls(t); len(got) != 1 {
		t.Fatalf("want exactly the allowed call executed, got %v", got)
	}

	pid := s.serverPID(t)
	_ = s.stdin.Close()
	waitGone(t, pid, 10*time.Second)
}

// runGateExpectingRefusal runs the gate with args and requires it to exit
// with status code, saying want, without starting a tool server. The
// environment is complete and valid (a loopback URL nothing listens on, a
// token, a well-formed key), so a gate that got past the refusal would go
// on to start the fake server and write its pid file.
func runGateExpectingRefusal(t *testing.T, args []string, code int, want string) {
	t.Helper()
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "server.pid")
	tokenPath := filepath.Join(dir, "agent.token")
	write(t, tokenPath, strings.Repeat("ab", 32)+"\n")
	cmd := exec.Command(gateBin, args...)
	cmd.Env = append(os.Environ(),
		"ARCHYTAN_MCP_GATE_URL=http://127.0.0.1:1",
		"ARCHYTAN_MCP_GATE_CALLER_TOKEN_PATH="+tokenPath,
		"ARCHYTAN_MCP_GATE_PUBLIC_KEY_HEX="+strings.Repeat("11", 32),
		"FAKE_SERVER_PID_FILE="+pidFile,
	)
	cmd.Stdin = strings.NewReader("")
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != code {
		t.Fatalf("want exit status %d, got %v\n%s", code, err, out)
	}
	if !strings.Contains(string(out), want) {
		t.Fatalf("output doesn't say %q:\n%s", want, out)
	}
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Fatalf("a tool server was started (pid file: %v)", err)
	}
}

// Naming the tool server in the config and after "--" is two answers to
// which program runs. The gate refuses to start rather than pick one.
func TestGate_ServerNamedTwiceIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp-gate.json")
	write(t, path, configWithServer(t, serverBin))
	runGateExpectingRefusal(t, []string{"--config", path, "--", serverBin}, 2, "named twice")
}

func TestGate_NoServerNamedIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp-gate.json")
	write(t, path, `{"version":1,"agent_uid":"agent-invoices","tools":{
		"delete_invoice":{"action":"invoice.delete","resource_type":"invoice","resource_id_arg":"invoice_id"}}}`)
	runGateExpectingRefusal(t, []string{"--config", path}, 2, "no tool server")
}

// A config whose "server" appears twice reads two ways; it must not start
// either program.
func TestGate_ConfigWithTwoServersIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp-gate.json")
	first, _ := json.Marshal(serverBin)
	write(t, path, `{"version":1,"agent_uid":"agent-invoices","server":{"command":"definitely-not-a-real-program"},"server":{"command":`+string(first)+`},"tools":{
		"delete_invoice":{"action":"invoice.delete","resource_type":"invoice","resource_id_arg":"invoice_id"}}}`)
	runGateExpectingRefusal(t, []string{"--config", path}, 1, "repeat or differ only in case")
}
