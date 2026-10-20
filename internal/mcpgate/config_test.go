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
