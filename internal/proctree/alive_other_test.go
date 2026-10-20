// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package proctree

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// alive reports whether pid names a running process. On Linux a killed
// process can linger as a zombie until it is reaped, which counts as gone.
func alive(pid int) bool {
	if runtime.GOOS == "linux" {
		b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if err != nil {
			return false
		}
		// The state follows the parenthesised command name.
		s := string(b)
		i := strings.LastIndexByte(s, ')')
		return i < 0 || i+2 >= len(s) || s[i+2] != 'Z'
	}
	return syscall.Kill(pid, 0) == nil
}
