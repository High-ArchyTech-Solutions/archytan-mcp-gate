// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package proctree

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

type treeSys struct{}

// prepare makes the child the leader of a new process group, so a signal
// to the group reaches everything it spawns (unless a descendant starts a
// group of its own, which nothing short of a cgroup can prevent).
func prepare(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

func (t *Tree) contain() error { return nil }

func (t *Tree) killTree() error {
	if t.cmd.Process == nil {
		return nil
	}
	// The group id is the child's pid, since it leads the group.
	err := syscall.Kill(-t.cmd.Process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}

// closeSys does nothing on Unix. Signalling the group after a normal exit
// isn't safe: once the leader is reaped its pid, and so the group id, can
// be reused by an unrelated process.
func (t *Tree) closeSys() error { return nil }
