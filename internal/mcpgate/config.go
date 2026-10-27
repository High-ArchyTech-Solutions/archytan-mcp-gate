// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

// Package mcpgate is an egress gate for an AI agent's tools. It sits
// between an MCP host (Claude Desktop, Claude Code, an IDE) and the MCP
// tool server the agent would otherwise talk to directly, and forwards a
// tools/call only after Archytan Lite has authorized it, the receipt has
// been fully verified, and the single-use capability has been redeemed.
//
// What it is: the only path from the agent to the tool server, provided
// the host is configured to launch the gate instead of the server. What it
// is not: an actuator guard. The tool server itself knows nothing about
// capabilities, so anything that reaches the server by another route is
// not governed by this gate. A redeemed capability records that the call
// was authorized, not that the tool then succeeded.
package mcpgate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// ToolMapping binds one MCP tool to the Lite action that governs it.
type ToolMapping struct {
	// Action is the policy.json action name, e.g. "invoice.delete".
	Action string `json:"action"`
	// ResourceType is recorded on the receipt, e.g. "invoice".
	ResourceType string `json:"resource_type"`
	// ResourceIDArg names the tool argument whose string value is the
	// resource id sent to the gate, e.g. "invoice_id".
	ResourceIDArg string `json:"resource_id_arg,omitempty"`
	// ResourceIDArgs, used instead of ResourceIDArg, names the arguments
	// whose values are joined with "/" into the resource id, for a tool
	// that names its resource with more than one, e.g. ["owner", "repo"].
	// Each value must be a single name; see resourceID.
	ResourceIDArgs []string `json:"resource_id_args,omitempty"`
	// ResourcePathArg, only with ResourceIDArgs, names one more argument
	// joined last, whose value may be a path of several segments, e.g.
	// "branch" for "feature/login".
	ResourcePathArg string `json:"resource_id_path_arg,omitempty"`
}

// ServerCommand is the tool server the gate launches, when mcp-gate.json
// names it instead of the command line. Command runs exactly as written
// (looked up on PATH when it has no directory), followed by Args, and
// inherits the gate's environment, the same as the "--" form.
type ServerCommand struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

// UnmarshalJSON decodes the server object strictly. encoding/json would
// skip a field it doesn't know and read a null argument as "", so a typo
// or a null would quietly change the command that runs.
func (s *ServerCommand) UnmarshalJSON(raw []byte) error {
	var v struct {
		Command *string   `json:"command"`
		Args    []*string `json:"args"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return fmt.Errorf("server: %w", err)
	}
	if v.Command == nil {
		return errors.New("server: command is required")
	}
	args := make([]string, len(v.Args))
	for i, a := range v.Args {
		if a == nil {
			return fmt.Errorf("server: args[%d] is null", i)
		}
		args[i] = *a
	}
	s.Command, s.Args = *v.Command, args
	return nil
}

// Config is the gate's mcp-gate.json.
type Config struct {
	Version int `json:"version"`
	// AgentUID is the actor uid sent with every authorization. The role is
	// never sent: it comes from the caller credential the gate holds.
	AgentUID string `json:"agent_uid"`
	// Server, when set, is the tool server to launch. It is named here or
	// after "--" on the command line, never both; see ServerArgv.
	Server *ServerCommand         `json:"server,omitempty"`
	Tools  map[string]ToolMapping `json:"tools"`
}

// ServerArgv returns the tool server's command line: the config's server,
// or cli, the arguments after "--". Both at once is refused rather than
// resolved by picking one, since they are two answers to which program
// the gate runs; neither is refused too.
func (c *Config) ServerArgv(cli []string) ([]string, error) {
	switch {
	case c.Server != nil && len(cli) > 0:
		return nil, errors.New("the tool server is named twice, in the config's server and after --; name it in one place")
	case c.Server != nil:
		return append([]string{c.Server.Command}, c.Server.Args...), nil
	case len(cli) > 0:
		return cli, nil
	default:
		return nil, errors.New("no tool server: name it after -- or in the config's server")
	}
}

// LoadConfig reads and strictly validates a config file. Anything unknown,
// missing, or ambiguous is an error: the gate refuses to start rather than
// guess which tools it is supposed to govern.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return ParseConfig(raw)
}

// ParseConfig validates config bytes; see LoadConfig.
func ParseConfig(raw []byte) (*Config, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse config: trailing data after the JSON object")
	}
	// The config is held to the rule host messages are: text that decodes
	// two ways, or an object whose keys repeat or differ only in case, is
	// refused rather than resolved. A second "server" would otherwise
	// quietly decide which program the gate runs.
	if err := checkText(raw); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := checkKeysEverywhere(raw, "config"); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Version != 1 {
		return nil, fmt.Errorf("config: unsupported version %d (want 1)", cfg.Version)
	}
	if strings.TrimSpace(cfg.AgentUID) == "" {
		return nil, errors.New("config: agent_uid is required")
	}
	if s := cfg.Server; s != nil {
		if strings.TrimSpace(s.Command) == "" {
			return nil, errors.New("config: server.command is empty")
		}
		if strings.TrimSpace(s.Command) != s.Command {
			return nil, fmt.Errorf("config: server.command %q starts or ends with space; write the command exactly", s.Command)
		}
		for i, part := range append([]string{s.Command}, s.Args...) {
			if strings.ContainsRune(part, 0) {
				if i == 0 {
					return nil, errors.New("config: server.command contains a NUL character")
				}
				return nil, fmt.Errorf("config: server.args[%d] contains a NUL character", i-1)
			}
		}
	}
	if len(cfg.Tools) == 0 {
		return nil, errors.New("config: tools is empty, so every call would be refused; map at least one tool")
	}
	names := make([]string, 0, len(cfg.Tools))
	for name := range cfg.Tools {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		m := cfg.Tools[name]
		if strings.TrimSpace(name) == "" {
			return nil, errors.New("config: a tool has an empty name")
		}
		if m.Action == "" || m.ResourceType == "" || (m.ResourceIDArg == "" && len(m.ResourceIDArgs) == 0) {
			return nil, fmt.Errorf("config: tool %q needs action, resource_type, and resource_id_arg or resource_id_args", name)
		}
		if err := m.checkResourceArgs(); err != nil {
			return nil, fmt.Errorf("config: tool %q %w", name, err)
		}
	}
	return &cfg, nil
}

// checkResourceArgs refuses a mapping whose resource id could be read more
// than one way: named by both forms, a path argument with nothing before
// it, or an argument name in resource_id_args or resource_id_path_arg that
// is blank, padded, or listed twice. A resource_id_arg is left as it was
// before resource_id_args existed, so no working config changes meaning.
func (m ToolMapping) checkResourceArgs() error {
	if m.ResourceIDArg != "" && len(m.ResourceIDArgs) > 0 {
		return errors.New("names its resource in both resource_id_arg and resource_id_args; use one")
	}
	if m.ResourcePathArg != "" && len(m.ResourceIDArgs) == 0 {
		return errors.New("has resource_id_path_arg without resource_id_args; for a single argument, use resource_id_arg")
	}
	names := append([]string(nil), m.ResourceIDArgs...)
	if m.ResourcePathArg != "" {
		names = append(names, m.ResourcePathArg)
	}
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		if strings.TrimSpace(n) == "" {
			return errors.New("has an empty resource argument name")
		}
		if strings.TrimSpace(n) != n {
			return fmt.Errorf("has the resource argument name %q, which starts or ends with space; write it exactly", n)
		}
		if seen[n] {
			return fmt.Errorf("lists the resource argument %q twice", n)
		}
		seen[n] = true
	}
	return nil
}
