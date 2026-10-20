// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package mcpgate_e2e

import (
	"syscall"
	"testing"
	"time"
)

const (
	processQueryLimitedInformation = 0x1000
	stillActive                    = 259
)

func processAlive(pid int) bool {
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	var code uint32
	if err := syscall.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == stillActive
}

// The case the Job Object exists for: the host kills the gate outright,
// with no chance to clean up, and the tool server must not survive it.
func TestGate_KillingTheGateKillsTheToolServer(t *testing.T) {
	e := setup(t)
	s := e.startGate(t, e.liteURL, "FAKE_SERVER_IGNORE_EOF=1")
	pid := s.serverPID(t)
	if !processAlive(pid) {
		t.Fatal("tool server not running before the kill")
	}
	if err := s.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = s.cmd.Wait()
	waitGone(t, pid, 10*time.Second)
}
