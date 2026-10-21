// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package mcpgate

import (
	"strings"
	"testing"
)

const validConfig = `{"version":1,"agent_uid":"agent-invoices","tools":{
  "delete_invoice":{"action":"invoice.delete","resource_type":"invoice","resource_id_arg":"invoice_id"}}}`

func TestParseConfig_Valid(t *testing.T) {
	cfg, err := ParseConfig([]byte(validConfig))
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if cfg.AgentUID != "agent-invoices" || cfg.Tools["delete_invoice"].Action != "invoice.delete" {
		t.Fatalf("parsed wrong: %+v", cfg)
	}
}

func TestParseConfig_RejectsAnythingAmbiguous(t *testing.T) {
	cases := map[string]string{
		"unknown_field":    `{"version":1,"agent_uid":"a","tools":{"t":{"action":"x","resource_type":"y","resource_id_arg":"z"}},"allow_all":true}`,
		"unknown_tool_key": `{"version":1,"agent_uid":"a","tools":{"t":{"action":"x","resource_type":"y","resource_id_arg":"z","role":"admin"}}}`,
		"trailing_data":    validConfig + ` {}`,
		"wrong_version":    strings.Replace(validConfig, `"version":1`, `"version":2`, 1),
		"no_agent_uid":     strings.Replace(validConfig, `"agent-invoices"`, `""`, 1),
		"no_tools":         `{"version":1,"agent_uid":"a","tools":{}}`,
		"missing_action":   `{"version":1,"agent_uid":"a","tools":{"t":{"resource_type":"y","resource_id_arg":"z"}}}`,
		"missing_arg":      `{"version":1,"agent_uid":"a","tools":{"t":{"action":"x","resource_type":"y"}}}`,
		"not_json":         `not json`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConfig([]byte(raw)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestParseConfig_ServerNamedInConfig(t *testing.T) {
	cfg, err := ParseConfig([]byte(`{"version":1,"agent_uid":"a","server":{"command":"node","args":["/opt/s/index.js","--flag",""," spaced "]},"tools":{"t":{"action":"x","resource_type":"y","resource_id_arg":"z"}}}`))
	if err != nil {
		t.Fatalf("valid server rejected: %v", err)
	}
	got, err := cfg.ServerArgv(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"node", "/opt/s/index.js", "--flag", "", " spaced "}
	if strings.Join(got, "|") != strings.Join(want, "|") || len(got) != len(want) {
		t.Fatalf("argv %q, want %q: arguments must reach the server exactly as written", got, want)
	}

	bare, err := ParseConfig([]byte(`{"version":1,"agent_uid":"a","server":{"command":"/usr/local/bin/srv"},"tools":{"t":{"action":"x","resource_type":"y","resource_id_arg":"z"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := bare.ServerArgv(nil); len(got) != 1 || got[0] != "/usr/local/bin/srv" {
		t.Fatalf("argv %q", got)
	}
}

// The tool server is named in exactly one place.
func TestConfig_ServerArgv(t *testing.T) {
	inConfig := &Config{Server: &ServerCommand{Command: "srv", Args: []string{"a"}}}
	none := &Config{}
	if got, err := inConfig.ServerArgv(nil); err != nil || strings.Join(got, " ") != "srv a" {
		t.Fatalf("config only: %q %v", got, err)
	}
	if got, err := none.ServerArgv([]string{"node", "x.js"}); err != nil || strings.Join(got, " ") != "node x.js" {
		t.Fatalf("command line only: %q %v", got, err)
	}
	if _, err := inConfig.ServerArgv([]string{"node"}); err == nil || !strings.Contains(err.Error(), "named twice") {
		t.Fatalf("both places: want a refusal, got %v", err)
	}
	if _, err := none.ServerArgv(nil); err == nil {
		t.Fatal("neither place: want a refusal")
	}
}

// A server object, or the config around it, that could be read two ways,
// or that encoding/json would quietly repair, is refused.
func TestParseConfig_RejectsAmbiguousServer(t *testing.T) {
	cases := map[string]string{
		"server_unknown_field":      `{"version":1,"agent_uid":"a","server":{"command":"node","cwd":"/tmp"},"tools":{"t":{"action":"x","resource_type":"y","resource_id_arg":"z"}}}`,
		"server_no_command":         `{"version":1,"agent_uid":"a","server":{"args":["x"]},"tools":{"t":{"action":"x","resource_type":"y","resource_id_arg":"z"}}}`,
		"server_empty_command":      `{"version":1,"agent_uid":"a","server":{"command":""},"tools":{"t":{"action":"x","resource_type":"y","resource_id_arg":"z"}}}`,
		"server_blank_command":      `{"version":1,"agent_uid":"a","server":{"command":"   "},"tools":{"t":{"action":"x","resource_type":"y","resource_id_arg":"z"}}}`,
		"server_padded_command":     `{"version":1,"agent_uid":"a","server":{"command":" node"},"tools":{"t":{"action":"x","resource_type":"y","resource_id_arg":"z"}}}`,
		"server_null_command":       `{"version":1,"agent_uid":"a","server":{"command":null},"tools":{"t":{"action":"x","resource_type":"y","resource_id_arg":"z"}}}`,
		"server_null_arg":           `{"version":1,"agent_uid":"a","server":{"command":"node","args":["a",null]},"tools":{"t":{"action":"x","resource_type":"y","resource_id_arg":"z"}}}`,
		"server_number_arg":         `{"version":1,"agent_uid":"a","server":{"command":"node","args":[1]},"tools":{"t":{"action":"x","resource_type":"y","resource_id_arg":"z"}}}`,
		"server_args_not_array":     `{"version":1,"agent_uid":"a","server":{"command":"node","args":"a b"},"tools":{"t":{"action":"x","resource_type":"y","resource_id_arg":"z"}}}`,
		"server_not_object":         `{"version":1,"agent_uid":"a","server":"node index.js","tools":{"t":{"action":"x","resource_type":"y","resource_id_arg":"z"}}}`,
		"server_nul_in_command":     `{"version":1,"agent_uid":"a","server":{"command":"no\u0000de"},"tools":{"t":{"action":"x","resource_type":"y","resource_id_arg":"z"}}}`,
		"server_nul_in_arg":         `{"version":1,"agent_uid":"a","server":{"command":"node","args":["a\u0000b"]},"tools":{"t":{"action":"x","resource_type":"y","resource_id_arg":"z"}}}`,
		"server_unpaired_surrogate": `{"version":1,"agent_uid":"a","server":{"command":"node\ud800"},"tools":{"t":{"action":"x","resource_type":"y","resource_id_arg":"z"}}}`,
		"server_twice":              `{"version":1,"agent_uid":"a","server":{"command":"a"},"server":{"command":"b"},"tools":{"t":{"action":"x","resource_type":"y","resource_id_arg":"z"}}}`,
		"server_case_twin":          `{"version":1,"agent_uid":"a","server":{"command":"a"},"Server":{"command":"b"},"tools":{"t":{"action":"x","resource_type":"y","resource_id_arg":"z"}}}`,
		"command_case_twin":         `{"version":1,"agent_uid":"a","server":{"command":"a","Command":"b"},"tools":{"t":{"action":"x","resource_type":"y","resource_id_arg":"z"}}}`,
		"args_long_s_twin":          `{"version":1,"agent_uid":"a","server":{"command":"a","args":["x"],"arg\u017f":["y"]},"tools":{"t":{"action":"x","resource_type":"y","resource_id_arg":"z"}}}`,
		"tool_twice":                `{"version":1,"agent_uid":"a","tools":{"t":{"action":"x","resource_type":"y","resource_id_arg":"z"},"t":{"action":"w","resource_type":"y","resource_id_arg":"z"}}}`,
		"agent_uid_case_twin":       `{"version":1,"agent_uid":"a","Agent_UID":"b","tools":{"t":{"action":"x","resource_type":"y","resource_id_arg":"z"}}}`,
		"action_case_twin":          `{"version":1,"agent_uid":"a","tools":{"t":{"action":"x","Action":"admin.all","resource_type":"y","resource_id_arg":"z"}}}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if cfg, err := ParseConfig([]byte(raw)); err == nil {
				t.Fatalf("accepted: %+v", cfg.Server)
			}
		})
	}
}

func TestParseConfig_RejectsInvalidUTF8(t *testing.T) {
	raw := strings.Replace(validConfig, "agent-invoices", "agent-\xffinvoices", 1)
	if _, err := ParseConfig([]byte(raw)); err == nil {
		t.Fatal("accepted a config that isn't valid UTF-8")
	}
}
