// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package proctree

import "syscall"

const synchronize = 0x00100000

// alive reports whether pid names a running process.
func alive(pid int) bool {
	h, err := syscall.OpenProcess(synchronize, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	ev, _ := syscall.WaitForSingleObject(h, 0)
	return ev == syscall.WAIT_TIMEOUT
}
