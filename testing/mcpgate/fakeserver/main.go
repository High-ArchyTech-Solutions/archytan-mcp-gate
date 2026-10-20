// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

// Command fakeserver is a deliberately untidy MCP stdio tool server for
// testing archytan-mcp-gate end to end. It prints a non-JSON banner to
// stdout, as real servers sometimes do, records every tool call it
// executes, and can return a result larger than 64 KiB. It also speaks
// MCP 2026-07-28 (server/discover, resultType on its results), and can be
// told to break that revision's rules by asking the host for roots.
//
// Environment:
//
//	FAKE_SERVER_PID_FILE   write this process's pid here on start
//	FAKE_SERVER_CALL_LOG   append one line per executed tools/call
//	FAKE_SERVER_SEEN_LOG   append every message received, as received
//	FAKE_SERVER_IGNORE_EOF if "1", keep running after stdin closes
//	FAKE_SERVER_ASK_ROOTS  if "1", answer a tools/call that carries no
//	                       inputResponses with input_required asking
//	                       for roots/list, whatever the host declared
//	FAKE_SERVER_EXACT_KEYS if "1", read the envelope and a tool call's
//	                       name and arguments with exact keys, as a
//	                       server in JavaScript or Python does (Go's
//	                       encoding/json matches struct fields without
//	                       regard to case)
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type msg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func reply(id json.RawMessage, result any) {
	out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	fmt.Println(string(out))
}

func main() {
	if p := os.Getenv("FAKE_SERVER_PID_FILE"); p != "" {
		_ = os.WriteFile(p, []byte(strconv.Itoa(os.Getpid())), 0o600)
	}
	fmt.Println("fake MCP server starting (debug output on stdout, as some servers do)")

	br := bufio.NewReaderSize(os.Stdin, 1<<20)
	for {
		line, err := br.ReadString('\n')
		if strings.TrimSpace(line) != "" {
			handle(strings.TrimSpace(line))
		}
		if err != nil {
			break
		}
	}
	if os.Getenv("FAKE_SERVER_IGNORE_EOF") == "1" {
		for {
			time.Sleep(time.Hour)
		}
	}
}

func handle(line string) {
	var m msg
	if p := os.Getenv("FAKE_SERVER_SEEN_LOG"); p != "" {
		if f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			fmt.Fprintln(f, line)
			f.Close()
		}
	}
	if json.Unmarshal([]byte(line), &m) != nil {
		return
	}
	exact := os.Getenv("FAKE_SERVER_EXACT_KEYS") == "1"
	if exact {
		var env map[string]json.RawMessage
		_ = json.Unmarshal([]byte(line), &env)
		m.ID, m.Params, m.Method = env["id"], env["params"], ""
		_ = json.Unmarshal(env["method"], &m.Method)
	}
	if len(m.ID) == 0 {
		return
	}
	switch m.Method {
	case "server/discover":
		reply(m.ID, map[string]any{
			"resultType":        "complete",
			"supportedVersions": []string{"2026-07-28"},
			"capabilities": map[string]any{
				"tools": map[string]any{}, "resources": map[string]any{},
				"extensions": map[string]any{"io.modelcontextprotocol/tasks": map[string]any{}},
			},
		})
	case "initialize":
		reply(m.ID, map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{"tools": map[string]any{}, "resources": map[string]any{}},
			"serverInfo":      map[string]any{"name": "fakeserver", "version": "0"},
		})
	case "ping":
		reply(m.ID, map[string]any{})
	case "tools/list":
		var tools []map[string]any
		for _, n := range []string{"delete_invoice", "read_invoice", "delete_tenant", "drop_database"} {
			tools = append(tools, map[string]any{"name": n, "inputSchema": map[string]any{"type": "object"}})
		}
		reply(m.ID, map[string]any{"tools": tools})
	case "tools/call":
		var p struct {
			Name           string         `json:"name"`
			Arguments      map[string]any `json:"arguments"`
			InputResponses map[string]any `json:"inputResponses"`
		}
		_ = json.Unmarshal(m.Params, &p)
		if exact {
			var params map[string]json.RawMessage
			_ = json.Unmarshal(m.Params, &params)
			p.Name, p.Arguments = "", nil
			_ = json.Unmarshal(params["name"], &p.Name)
			_ = json.Unmarshal(params["arguments"], &p.Arguments)
		}
		if os.Getenv("FAKE_SERVER_ASK_ROOTS") == "1" && p.InputResponses == nil {
			reply(m.ID, map[string]any{
				"resultType":    "input_required",
				"inputRequests": map[string]any{"roots": map[string]any{"method": "roots/list"}},
				"requestState":  "round-1",
			})
			return
		}
		if logPath := os.Getenv("FAKE_SERVER_CALL_LOG"); logPath != "" {
			f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
			if err == nil {
				fmt.Fprintf(f, "%s %v\n", p.Name, p.Arguments)
				f.Close()
			}
		}
		text := "executed " + p.Name
		if p.Name == "read_invoice" {
			text = strings.Repeat("r", 200<<10)
		}
		reply(m.ID, map[string]any{"content": []map[string]any{{"type": "text", "text": text}}})
	}
}
