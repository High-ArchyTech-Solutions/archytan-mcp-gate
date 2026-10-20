// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

// Package mcpgate_e2e drives the real archytan-mcp-gate binary between a
// scripted MCP host and a real tool-server process, with a real Archytan
// Lite gate service (credential-bound roles, capabilities on) making the
// decisions; lite_test.go says where that service comes from. Nothing here
// is mocked except the tool server, which is a deliberately untidy fixture
// (see fakeserver).
package mcpgate_e2e

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

type env struct {
	dir                string
	gateBin, serverBin string
	liteURL            string
	lite               liteService
	pubHex             string
	tokenPath          string
	callLog            string
}

// The two binaries are built once for the whole package.
var gateBin, serverBin string

// skipReason says why these tests can't run here; empty means they can.
var skipReason string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "mcpgate-e2e-bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, b := range []struct {
		out       *string
		name, pkg string
	}{
		{&gateBin, "archytan-mcp-gate", "./cmd/archytan-mcp-gate"},
		{&serverBin, "fakeserver", "./testing/mcpgate/fakeserver"},
	} {
		bin := filepath.Join(dir, b.name)
		if runtime.GOOS == "windows" {
			bin += ".exe"
		}
		cmd := exec.Command("go", "build", "-o", bin, b.pkg)
		cmd.Dir = filepath.Join("..", "..")
		cmd.Env = append(os.Environ(), "GOWORK=off")
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "build %s: %v\n%s", b.pkg, err, out)
			os.RemoveAll(dir)
			os.Exit(1)
		}
		*b.out = bin
	}
	if skipReason = pickLiteBackend(); skipReason != "" {
		fmt.Fprintln(os.Stderr, "end-to-end tests will skip:", skipReason)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func setup(t *testing.T) *env {
	t.Helper()
	if skipReason != "" {
		// CI sets this, so the tests can't pass by not running.
		if os.Getenv("ARCHYTAN_MCP_GATE_E2E_REQUIRED") == "1" {
			t.Fatal(skipReason)
		}
		t.Skip(skipReason)
	}
	e := &env{dir: t.TempDir(), gateBin: gateBin, serverBin: serverBin}
	e.pubHex = generateKey(t, e.dir)

	tokenBytes := make([]byte, 32)
	_, _ = rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)
	e.tokenPath = filepath.Join(e.dir, "agent.token")
	write(t, e.tokenPath, token+"\n")
	digest := sha256.Sum256([]byte(token))
	write(t, filepath.Join(e.dir, "callers.json"), fmt.Sprintf(
		`{"version":1,"callers":[{"caller_id":"agent-invoices","role":"billing_agent","token_sha256":%q}]}`, hex.EncodeToString(digest[:])))
	write(t, filepath.Join(e.dir, "policy.json"), `{"version":1,"actions":[
		{"action":"invoice.delete","allowed_roles":["billing_agent"]},
		{"action":"invoice.read","allowed_roles":["billing_agent"]},
		{"action":"tenant.delete","allowed_roles":["admin"]}]}`)
	write(t, filepath.Join(e.dir, "mcp-gate.json"), `{"version":1,"agent_uid":"agent-invoices","tools":{
		"delete_invoice":{"action":"invoice.delete","resource_type":"invoice","resource_id_arg":"invoice_id"},
		"read_invoice":{"action":"invoice.read","resource_type":"invoice","resource_id_arg":"invoice_id"},
		"delete_tenant":{"action":"tenant.delete","resource_type":"tenant","resource_id_arg":"tenant_id"}}}`)
	e.callLog = filepath.Join(e.dir, "calls.log")

	addr := freeAddr(t)
	e.liteURL = "http://" + addr
	e.lite = startLite(t, e.dir, addr)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(e.liteURL + "/v1/healthz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return e
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("archytan-lite never became healthy")
	return nil
}

// session is one host-side MCP connection through the gate.
type session struct {
	t       *testing.T
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	lines   chan string
	pidFile string
	nextID  int
}

func (e *env) startGate(t *testing.T, gateURL string, extraEnv ...string) *session {
	t.Helper()
	s := &session{t: t, lines: make(chan string, 64), pidFile: filepath.Join(t.TempDir(), "server.pid")}
	s.cmd = exec.Command(e.gateBin, "--config", filepath.Join(e.dir, "mcp-gate.json"), "--", e.serverBin)
	s.cmd.Env = append(os.Environ(),
		"ARCHYTAN_MCP_GATE_URL="+gateURL,
		"ARCHYTAN_MCP_GATE_CALLER_TOKEN_PATH="+e.tokenPath,
		"ARCHYTAN_MCP_GATE_PUBLIC_KEY_HEX="+e.pubHex,
		"FAKE_SERVER_PID_FILE="+s.pidFile,
		"FAKE_SERVER_CALL_LOG="+e.callLog,
	)
	s.cmd.Env = append(s.cmd.Env, extraEnv...)
	s.cmd.Stderr = testLogWriter{t}
	var err error
	if s.stdin, err = s.cmd.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	stdout, err := s.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		br := bufio.NewReaderSize(stdout, 1<<20)
		for {
			l, err := br.ReadString('\n')
			if strings.TrimSpace(l) != "" {
				s.lines <- strings.TrimSpace(l)
			}
			if err != nil {
				close(s.lines)
				return
			}
		}
	}()
	t.Cleanup(func() { _ = s.cmd.Process.Kill(); _ = s.cmd.Wait() })
	return s
}

type testLogWriter struct{ t *testing.T }

func (w testLogWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", bytes.TrimRight(p, "\n"))
	return len(p), nil
}

func (s *session) request(method string, params any) map[string]any {
	s.t.Helper()
	s.nextID++
	id := s.nextID
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if _, err := s.stdin.Write(append(body, '\n')); err != nil {
		s.t.Fatalf("write to gate: %v", err)
	}
	timeout := time.After(10 * time.Second)
	for {
		select {
		case l, ok := <-s.lines:
			if !ok {
				s.t.Fatalf("gate closed stdout waiting for reply to %s", method)
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(l), &m); err != nil {
				s.t.Fatalf("gate wrote non-JSON to the host: %.200q", l)
			}
			if fmt.Sprint(m["id"]) == strconv.Itoa(id) {
				return m
			}
		case <-timeout:
			s.t.Fatalf("no reply to %s", method)
		}
	}
}

func (s *session) callTool(name string, args map[string]any) (isError bool, text string) {
	m := s.request("tools/call", map[string]any{"name": name, "arguments": args})
	res, _ := m["result"].(map[string]any)
	if res == nil {
		s.t.Fatalf("no result: %v", m)
	}
	isError, _ = res["isError"].(bool)
	content, _ := res["content"].([]any)
	if len(content) > 0 {
		text, _ = content[0].(map[string]any)["text"].(string)
	}
	return isError, text
}

func (e *env) executedCalls(t *testing.T) []string {
	raw, err := os.ReadFile(e.callLog)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

func (s *session) serverPID(t *testing.T) int {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if raw, err := os.ReadFile(s.pidFile); err == nil && len(raw) > 0 {
			pid, err := strconv.Atoi(string(raw))
			if err == nil {
				return pid
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("tool server never wrote its pid")
	return 0
}

func waitGone(t *testing.T, pid int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("tool server pid %d is still running", pid)
}

func TestGate_EndToEnd(t *testing.T) {
	e := setup(t)
	s := e.startGate(t, e.liteURL)

	init := s.request("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "e2e"}})
	caps := init["result"].(map[string]any)["capabilities"].(map[string]any)
	if _, ok := caps["resources"]; ok {
		t.Fatalf("resources capability leaked to the host: %v", caps)
	}

	var names []string
	for _, tl := range s.request("tools/list", map[string]any{})["result"].(map[string]any)["tools"].([]any) {
		names = append(names, tl.(map[string]any)["name"].(string))
	}
	if strings.Join(names, ",") != "delete_invoice,read_invoice,delete_tenant" {
		t.Fatalf("agent saw tools %v", names)
	}

	if isErr, text := s.callTool("delete_invoice", map[string]any{"invoice_id": "inv_7"}); isErr || text != "executed delete_invoice" {
		t.Fatalf("allowed call failed: %v %q", isErr, text)
	}
	if got := e.executedCalls(t); len(got) != 1 {
		t.Fatalf("allowed call executed %d times: %v", len(got), got)
	}

	if isErr, text := s.callTool("delete_tenant", map[string]any{"tenant_id": "t_1"}); !isErr || !strings.HasPrefix(text, "Refused by Archytan Lite") {
		t.Fatalf("disallowed role was not refused: %v %q", isErr, text)
	}
	if isErr, _ := s.callTool("drop_database", map[string]any{"invoice_id": "x"}); !isErr {
		t.Fatal("an unmapped tool was not refused")
	}
	if got := e.executedCalls(t); len(got) != 1 {
		t.Fatalf("a refused call executed: %v", got)
	}

	if isErr, text := s.callTool("read_invoice", map[string]any{"invoice_id": "inv_7"}); isErr || len(text) != 200<<10 {
		t.Fatalf("large result not delivered intact: isError=%v len=%d", isErr, len(text))
	}

	if m := s.request("resources/list", map[string]any{}); m["error"] == nil {
		t.Fatalf("resources/list was not refused: %v", m)
	}

	// With the gate process gone, every call is refused and nothing runs.
	e.lite.kill()
	before := len(e.executedCalls(t))
	if isErr, _ := s.callTool("delete_invoice", map[string]any{"invoice_id": "inv_8"}); !isErr {
		t.Fatal("a call was allowed with archytan-lite down")
	}
	if got := len(e.executedCalls(t)); got != before {
		t.Fatal("a call executed with archytan-lite down")
	}

	// Host closes the session: the gate stops the tool server and exits.
	pid := s.serverPID(t)
	_ = s.stdin.Close()
	waitGone(t, pid, 10*time.Second)
}

// A proxy that relabels a genuine receipt must be caught: the receipt's
// fields no longer hash to the intent_hash the gate signed.
func TestGate_ReceiptRewritingProxyIsRefused(t *testing.T) {
	e := setup(t)
	target, _ := url.Parse(e.liteURL)
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ModifyResponse = func(resp *http.Response) error {
		if !strings.HasSuffix(resp.Request.URL.Path, "/v1/authorize") || resp.StatusCode != http.StatusOK {
			return nil
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var body map[string]any
		if json.Unmarshal(raw, &body) == nil {
			if r, ok := body["receipt"].(map[string]any); ok {
				r["actor_role"] = "admin"
			}
			raw, _ = json.Marshal(body)
		}
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		resp.ContentLength = int64(len(raw))
		resp.Header.Set("Content-Length", strconv.Itoa(len(raw)))
		return nil
	}
	front := httptest.NewServer(proxy)
	t.Cleanup(front.Close)

	s := e.startGate(t, front.URL)
	s.request("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "e2e"}})
	if isErr, text := s.callTool("delete_invoice", map[string]any{"invoice_id": "inv_7"}); !isErr || !strings.Contains(text, "verification") {
		t.Fatalf("rewritten receipt was not refused: %v %q", isErr, text)
	}
	if got := e.executedCalls(t); len(got) != 0 {
		t.Fatalf("call executed behind a rewriting proxy: %v", got)
	}
}

// Even a tool server that ignores stdin EOF is stopped when the host goes.
func TestGate_StubbornServerIsTerminated(t *testing.T) {
	e := setup(t)
	s := e.startGate(t, e.liteURL, "FAKE_SERVER_IGNORE_EOF=1")
	pid := s.serverPID(t)
	_ = s.stdin.Close()
	waitGone(t, pid, 15*time.Second)
}
