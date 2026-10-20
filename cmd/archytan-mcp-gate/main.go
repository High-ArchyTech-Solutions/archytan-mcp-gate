// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

// Command archytan-mcp-gate is an egress gate for an AI agent's tools.
//
//	archytan-mcp-gate --config mcp-gate.json -- <tool server command> [args...]
//
// Configure your MCP host to launch this instead of the tool server. The
// gate launches the server itself, forwards everything the protocol needs,
// and lets a tools/call through only after Archytan Lite has authorized
// it, the receipt has been fully verified, and the capability redeemed.
// Unmapped tools are hidden from the agent and refused if called.
//
// Environment (all required):
//
//	ARCHYTAN_MCP_GATE_URL                 base URL of archytan-lite (https unless loopback)
//	ARCHYTAN_MCP_GATE_CALLER_TOKEN_PATH   file holding this agent's caller token (from callergen)
//	ARCHYTAN_MCP_GATE_PUBLIC_KEY_HEX      the gate's receipt-signing public key
//
// stdout carries the MCP protocol only; everything the gate says goes to
// stderr.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/high-archytech-solutions/archytan-mcp-gate/v2/internal/mcpgate"
)

const shutdownGrace = 2 * time.Second

func main() {
	os.Exit(run())
}

func run() int {
	logger := log.New(os.Stderr, "archytan-mcp-gate: ", log.LstdFlags)
	logf := func(format string, args ...any) { logger.Printf(format, args...) }

	fs := flag.NewFlagSet("archytan-mcp-gate", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to mcp-gate.json (required)")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return 2
	}
	serverArgv := fs.Args()
	if *configPath == "" || len(serverArgv) == 0 {
		logf("usage: archytan-mcp-gate --config mcp-gate.json -- <tool server command> [args...]")
		return 2
	}

	cfg, err := mcpgate.LoadConfig(*configPath)
	if err != nil {
		logf("%v", err)
		return 1
	}
	client, err := gateClientFromEnv()
	if err != nil {
		logf("%v", err)
		return 1
	}

	if err := mcpgate.EnterKillOnCloseJob(); err != nil {
		logf("refusing to start: could not bind the tool server's lifetime to the gate's: %v", err)
		return 1
	}
	cmd, serverIn, serverOut, err := mcpgate.StartServer(serverArgv)
	if err != nil {
		logf("start tool server: %v", err)
		return 1
	}
	logf("started tool server %q (pid %d); %d tool(s) gated for agent %q", serverArgv[0], cmd.Process.Pid, len(cfg.Tools), cfg.AgentUID)

	serverDone := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(serverDone)
	}()

	gate := mcpgate.New(cfg, client, os.Stdout, serverIn, logf)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		gate.RunWorker()
	}()

	serverStreamDone := make(chan struct{})
	go func() {
		if err := gate.ServeServer(serverOut); err != nil {
			logf("tool server stream: %v", err)
		}
		close(serverStreamDone)
	}()

	hostDone := make(chan struct{})
	go func() {
		if err := gate.ServeHost(os.Stdin); err != nil {
			logf("host stream: %v", err)
		}
		close(hostDone)
	}()

	select {
	case <-hostDone:
		// The host went away: stop gating, close the server's stdin, and
		// make sure it exits.
		gate.Close()
		wg.Wait()
		_ = serverIn.Close()
		mcpgate.Terminate(cmd, serverDone, shutdownGrace)
		<-serverStreamDone
	case <-serverStreamDone:
		// The server closed its stdout; it is exiting or already gone.
		gate.Close()
		wg.Wait()
		_ = serverIn.Close()
		mcpgate.Terminate(cmd, serverDone, shutdownGrace)
	}

	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return exitErr.ExitCode()
	}
	return 0
}

func gateClientFromEnv() (*mcpgate.GateClient, error) {
	url := os.Getenv("ARCHYTAN_MCP_GATE_URL")
	if url == "" {
		return nil, errors.New("ARCHYTAN_MCP_GATE_URL is required")
	}
	if err := mcpgate.ValidateGateURL(url); err != nil {
		return nil, err
	}
	tokenPath := os.Getenv("ARCHYTAN_MCP_GATE_CALLER_TOKEN_PATH")
	if tokenPath == "" {
		return nil, errors.New("ARCHYTAN_MCP_GATE_CALLER_TOKEN_PATH is required")
	}
	rawToken, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("read caller token: %w", err)
	}
	token := strings.TrimSpace(string(rawToken))
	if token == "" {
		return nil, errors.New("caller token file is empty")
	}
	keyHex := strings.TrimSpace(os.Getenv("ARCHYTAN_MCP_GATE_PUBLIC_KEY_HEX"))
	pub, err := hex.DecodeString(keyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("ARCHYTAN_MCP_GATE_PUBLIC_KEY_HEX must be the gate's 32-byte Ed25519 public key in hex")
	}
	return &mcpgate.GateClient{
		BaseURL:   url,
		Token:     token,
		PublicKey: ed25519.PublicKey(pub),
		HTTP:      &http.Client{Timeout: mcpgate.RequestTimeout},
	}, nil
}
