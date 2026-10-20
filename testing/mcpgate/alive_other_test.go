// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package mcpgate_e2e

import "syscall"

func processAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}
