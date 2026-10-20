// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package mcpgate

import (
	"os"
	"syscall"
)

// EnterKillOnCloseJob is a Windows concern. Elsewhere a child whose parent
// dies sees EOF on stdin, and an MCP stdio server exits on EOF; Terminate
// covers the ones that do not. Linux's Pdeathsig is deliberately not used:
// it is tied to the creating OS thread rather than the process, which in a
// Go program can fire at the wrong time.
func EnterKillOnCloseJob() error { return nil }

func terminateSignal(p *os.Process) error { return p.Signal(syscall.SIGTERM) }
