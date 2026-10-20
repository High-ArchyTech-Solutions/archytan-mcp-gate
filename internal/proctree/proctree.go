// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

// Package proctree starts a child process so that the whole tree of
// processes it spawns can be ended together. A plain exec.Cmd can't do
// that: killing the child leaves any grandchild it started running, still
// holding the pipes the parent is waiting on. A cloud CLI that runs a
// helper process (gcloud and az both do) would then outlive a timeout.
//
// On Unix the child leads its own process group and Kill signals the whole
// group. On Windows the child starts suspended, is placed in a job object
// before it runs a single instruction, and only then resumes; Kill
// terminates the job, and Close (closing the job's last handle) ends
// anything still running in it.
package proctree

import (
	"errors"
	"os/exec"
	"sync"
)

// Tree is one started process and everything it spawns.
type Tree struct {
	cmd *exec.Cmd

	mu     sync.Mutex
	sys    treeSys
	closed bool
}

// Start starts cmd as the root of a tree, and sets cmd.Cancel so that an
// exec.CommandContext whose context ends kills the whole tree instead of the
// child alone. cmd must not have been started. The caller must call Close
// once cmd.Wait has returned. If the tree can't be contained, the child is
// killed and an error returned: a child that might escape its own timeout is
// not run at all.
func Start(cmd *exec.Cmd) (*Tree, error) {
	if cmd == nil {
		return nil, errors.New("proctree: nil command")
	}
	t := &Tree{cmd: cmd}
	prepare(cmd)
	cmd.Cancel = t.Kill
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	t.mu.Lock()
	err := t.contain()
	t.mu.Unlock()
	if err != nil {
		_ = t.Kill()
		_ = cmd.Wait()
		_ = t.Close()
		return nil, err
	}
	return t, nil
}

// Kill ends every process in the tree. It is safe to call more than once,
// and from cmd.Cancel's goroutine.
func (t *Tree) Kill() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	return t.killTree()
}

// Close releases what Start acquired. On Windows it also ends any process
// still running in the tree, so a helper a signer left behind can't outlive
// the run.
func (t *Tree) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	return t.closeSys()
}
