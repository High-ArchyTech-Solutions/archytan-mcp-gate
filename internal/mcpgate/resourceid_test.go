// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package mcpgate

import (
	"encoding/json"
	"strings"
	"testing"
)

func mappingFrom(t *testing.T, tool string) ToolMapping {
	t.Helper()
	cfg, err := ParseConfig([]byte(`{"version":1,"agent_uid":"agent-repos","tools":{` + tool + `}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range cfg.Tools {
		return m
	}
	t.Fatal("no tool")
	return ToolMapping{}
}

func argsFrom(t *testing.T, raw string) map[string]json.RawMessage {
	t.Helper()
	var a map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &a); err != nil {
		t.Fatal(err)
	}
	return a
}

const repoTool = `"get_repo":{"action":"repo.read","resource_type":"repo","resource_id_args":["owner","repo"]}`
const pushTool = `"push_files":{"action":"repo.push","resource_type":"repo_branch","resource_id_args":["owner","repo"],"resource_id_path_arg":"branch"}`

func TestConfig_ResourceIDArgsRules(t *testing.T) {
	refused := map[string]struct{ tool, want string }{
		"both forms":           {`"t":{"action":"a","resource_type":"r","resource_id_arg":"id","resource_id_args":["owner"]}`, "both resource_id_arg and resource_id_args"},
		"neither form":         {`"t":{"action":"a","resource_type":"r"}`, "resource_id_arg or resource_id_args"},
		"empty list":           {`"t":{"action":"a","resource_type":"r","resource_id_args":[]}`, "resource_id_arg or resource_id_args"},
		"path arg alone":       {`"t":{"action":"a","resource_type":"r","resource_id_path_arg":"path"}`, "resource_id_arg or resource_id_args"},
		"path arg with legacy": {`"t":{"action":"a","resource_type":"r","resource_id_arg":"id","resource_id_path_arg":"path"}`, "without resource_id_args"},
		"blank name":           {`"t":{"action":"a","resource_type":"r","resource_id_args":["owner",""]}`, "empty resource argument name"},
		"null name":            {`"t":{"action":"a","resource_type":"r","resource_id_args":["owner",null]}`, "empty resource argument name"},
		"padded name":          {`"t":{"action":"a","resource_type":"r","resource_id_args":["owner"," repo"]}`, "starts or ends with space"},
		"padded path name":     {`"t":{"action":"a","resource_type":"r","resource_id_args":["owner"],"resource_id_path_arg":"branch "}`, "starts or ends with space"},
		"name twice":           {`"t":{"action":"a","resource_type":"r","resource_id_args":["owner","owner"]}`, `"owner" twice`},
		"path repeats a name":  {`"t":{"action":"a","resource_type":"r","resource_id_args":["owner","repo"],"resource_id_path_arg":"repo"}`, `"repo" twice`},
		"misspelled field":     {`"t":{"action":"a","resource_type":"r","resource_id_argz":["owner"]}`, "unknown field"},
	}
	for name, c := range refused {
		t.Run(name, func(t *testing.T) {
			_, err := ParseConfig([]byte(`{"version":1,"agent_uid":"u","tools":{` + c.tool + `}}`))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want a refusal mentioning %q, got %v", c.want, err)
			}
		})
	}
	for _, tool := range []string{repoTool, pushTool, `"t":{"action":"a","resource_type":"r","resource_id_args":["ticket"]}`} {
		if _, err := ParseConfig([]byte(`{"version":1,"agent_uid":"u","tools":{` + tool + `}}`)); err != nil {
			t.Errorf("a well-formed mapping was refused: %s: %v", tool, err)
		}
	}
}

func TestResourceID_JoinsArgumentsInConfigOrder(t *testing.T) {
	cases := []struct{ tool, args, want string }{
		{repoTool, `{"repo":"web-shop","owner":"acme","extra":"ignored"}`, "acme/web-shop"},
		{pushTool, `{"owner":"acme","repo":"web-shop","branch":"feature/login"}`, "acme/web-shop/feature/login"},
		{`"t":{"action":"a","resource_type":"r","resource_id_args":["repo","owner"]}`, `{"owner":"acme","repo":"web-shop"}`, "web-shop/acme"},
		{repoTool, `{"owner":"équipe","repo":"日本語"}`, "équipe/日本語"},
		// The single-argument form is unchanged: its value is the whole id,
		// separators and all, as it was before resource_id_args existed.
		{`"t":{"action":"a","resource_type":"r","resource_id_arg":"path"}`, `{"path":"/projects/demo/a.txt"}`, "/projects/demo/a.txt"},
	}
	for _, c := range cases {
		got, err := mappingFrom(t, c.tool).resourceID(argsFrom(t, c.args))
		if err != nil || got != c.want {
			t.Errorf("%s with %s: got %q, %v; want %q", c.tool, c.args, got, err, c.want)
		}
	}
}

// The reason resource_id_args refuses a separator: these two calls name
// different repositories, and joined without the check they would be the
// same id, so a grant written for one would admit the other.
func TestResourceID_ASeparatorCannotMoveTheBoundary(t *testing.T) {
	m := mappingFrom(t, repoTool)
	for _, args := range []string{
		`{"owner":"a/b","repo":"c"}`,
		`{"owner":"a","repo":"b/c"}`,
		`{"owner":"acme","repo":"web-shop/feature"}`,
		`{"owner":"a\\b","repo":"c"}`,
		`{"owner":"acme","repo":"web/shop"}`,
	} {
		_, err := m.resourceID(argsFrom(t, args))
		if err == nil || !strings.Contains(err.Error(), "contains a separator") {
			t.Errorf("%s: want a separator refusal, got %v", args, err)
		}
	}
}

func TestResourceID_EveryListedArgumentMustBeANonEmptyString(t *testing.T) {
	m := mappingFrom(t, pushTool)
	for _, args := range []string{
		`{"repo":"web-shop","branch":"main"}`,
		`{"owner":null,"repo":"web-shop","branch":"main"}`,
		`{"owner":"","repo":"web-shop","branch":"main"}`,
		`{"owner":42,"repo":"web-shop","branch":"main"}`,
		`{"owner":true,"repo":"web-shop","branch":"main"}`,
		`{"owner":["acme"],"repo":"web-shop","branch":"main"}`,
		`{"owner":{"name":"acme"},"repo":"web-shop","branch":"main"}`,
		// A path argument left out is refused, not dropped: a tool that
		// defaults the branch would push to one the id doesn't name.
		`{"owner":"acme","repo":"web-shop"}`,
		`{"owner":"acme","repo":"web-shop","branch":null}`,
		`{"owner":"acme","repo":"web-shop","branch":""}`,
	} {
		_, err := m.resourceID(argsFrom(t, args))
		if err == nil || !strings.Contains(err.Error(), "needs a non-empty string argument") {
			t.Errorf("%s: want a refusal, got %v", args, err)
		}
	}
}

func newGateHarnessWith(t *testing.T, tools string) *harness {
	t.Helper()
	cfg, err := ParseConfig([]byte(`{"version":1,"agent_uid":"agent-repos","tools":{` + tools + `}}`))
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{host: &sink{}, server: &sink{}, auth: &fakeAuth{}}
	h.g = New(cfg, h.auth, h.host, h.server, t.Logf)
	go h.g.RunWorker()
	t.Cleanup(h.g.Close)
	return h
}

func toolCall(id, tool, args string) []byte {
	return []byte(`{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":"` + tool + `","arguments":` + args + `}}`)
}

func TestGate_JoinedResourceIDIsWhatGetsAuthorized(t *testing.T) {
	h := newGateHarnessWith(t, pushTool)
	line := toolCall(`3`, "push_files", `{"owner":"acme","repo":"web-shop","branch":"feature/login","message":"m"}`)
	h.g.fromHost(line)
	if got := h.server.waitFor(t, 1); got[0] != string(line) {
		t.Fatalf("forwarded bytes changed:\n got %s\nwant %s", got[0], line)
	}
	if h.auth.authorized[0] != "repo.push agent-repos repo_branch acme/web-shop/feature/login" {
		t.Fatalf("authorized the wrong thing: %v", h.auth.authorized)
	}
}

// A call whose resource can't be named unambiguously is refused before
// authorization, so no capability is minted, nothing is spent, and the
// tool server never sees it.
func TestGate_UnjoinableCallsAreRefusedBeforeAuthorization(t *testing.T) {
	for name, args := range map[string]string{
		"separator in a name": `{"owner":"acme","repo":"web-shop/feature","branch":"x"}`,
		"missing path":        `{"owner":"acme","repo":"web-shop"}`,
		"number for a name":   `{"owner":7,"repo":"web-shop","branch":"x"}`,
		"escaped separator":   `{"owner":"acme/web","repo":"shop","branch":"x"}`,
		"no arguments at all": `{}`,
		"null branch":         `{"owner":"acme","repo":"web-shop","branch":null}`,
		"backslash in a name": `{"owner":"acme\\web","repo":"shop","branch":"x"}`,
		"empty name":          `{"owner":"","repo":"web-shop","branch":"x"}`,
		"array for a name":    `{"owner":["acme"],"repo":"web-shop","branch":"x"}`,
		"object for the path": `{"owner":"acme","repo":"web-shop","branch":{"name":"x"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			h := newGateHarnessWith(t, pushTool)
			h.g.fromHost(toolCall(`1`, "push_files", args))
			assertRefusal(t, h.host.waitFor(t, 1)[0], `1`)
			if len(h.server.snapshot()) != 0 {
				t.Fatalf("refused call reached the server: %v", h.server.snapshot())
			}
			if a, r := h.auth.counts(); a != 0 || r != 0 {
				t.Fatalf("authorize/redeem called %d/%d times for a call that names no single resource", a, r)
			}
		})
	}
}

// The refusal says which argument was wrong, so the operator can tell a
// misbehaving agent from a mapping that names the wrong argument.
func TestGate_RefusalNamesTheArgument(t *testing.T) {
	h := newGateHarnessWith(t, pushTool)
	h.g.fromHost(toolCall(`1`, "push_files", `{"owner":"acme","repo":"web-shop/feature","branch":"x"}`))
	line := h.host.waitFor(t, 1)[0]
	if !strings.Contains(line, `argument \"repo\"`) || !strings.Contains(line, "contains a separator") {
		t.Fatalf("refusal doesn't name the argument: %s", line)
	}
}
