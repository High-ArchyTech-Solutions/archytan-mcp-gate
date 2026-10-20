// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package proctree

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The test binary doubles as the processes under test: a "parent" that
// starts a "child" sharing its stdout, records the child's pid, and then
// either hangs or exits at once, leaving the child behind.
func TestMain(m *testing.M) {
	switch os.Getenv("PROCTREE_HELPER") {
	case "parent":
		runParent()
	case "child":
		time.Sleep(60 * time.Second)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func runParent() {
	child := exec.Command(os.Args[0], "-test.run=^$")
	child.Env = append(os.Environ(), "PROCTREE_HELPER=child")
	child.Stdout = os.Stdout
	if err := child.Start(); err != nil {
		os.Exit(3)
	}
	if err := os.WriteFile(os.Getenv("PROCTREE_PIDFILE"), []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
		os.Exit(4)
	}
	fmt.Println("started")
	if os.Getenv("PROCTREE_PARENT") == "exit" {
		os.Exit(0)
	}
	time.Sleep(60 * time.Second)
	os.Exit(0)
}

func parentCmd(ctx context.Context, t *testing.T, behaviour string) (*exec.Cmd, string) {
	t.Helper()
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "PROCTREE_HELPER=parent", "PROCTREE_PARENT="+behaviour, "PROCTREE_PIDFILE="+pidFile)
	cmd.WaitDelay = 3 * time.Second
	return cmd, pidFile
}

func childPid(t *testing.T, pidFile string) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(pidFile); err == nil && len(b) > 0 {
			pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
			if err != nil {
				t.Fatal(err)
			}
			return pid
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the parent never recorded its child's pid")
	return 0
}

func requireDead(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for alive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("grandchild %d is still running", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A timeout ends the grandchild too, and Wait returns promptly even though
// the grandchild held the stdout pipe open.
func TestCancelEndsTheWholeTree(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd, pidFile := parentCmd(ctx, t, "hang")
	var out bytes.Buffer
	cmd.Stdout = &out

	start := time.Now()
	tree, err := Start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	pid := childPid(t, pidFile)
	err = cmd.Wait()
	_ = tree.Close()
	if err == nil {
		t.Fatal("a process killed on timeout reported success")
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("Wait took %s: it waited for the grandchild", elapsed)
	}
	requireDead(t, pid)
	if !strings.Contains(out.String(), "started") {
		t.Fatalf("the parent never ran: %q", out.String())
	}
}

// On Windows, Close ends what a child that exited normally left running.
// Unix deliberately doesn't (see closeSys), so this is Windows only.
func TestCloseEndsWhatTheChildLeftBehind(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Unix doesn't signal the group after a normal exit")
	}
	cmd, pidFile := parentCmd(context.Background(), t, "exit")
	var out bytes.Buffer
	cmd.Stdout = &out
	tree, err := Start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	pid := childPid(t, pidFile)
	if err := cmd.Wait(); err != nil && !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("wait: %v", err)
	}
	if !alive(pid) {
		t.Fatal("test setup: the grandchild should still be running before Close")
	}
	if err := tree.Close(); err != nil {
		t.Fatal(err)
	}
	requireDead(t, pid)
}

func TestStartRefusesWhatCannotRun(t *testing.T) {
	cmd := exec.Command(filepath.Join(t.TempDir(), "no-such-binary"))
	if tree, err := Start(cmd); err == nil {
		_ = tree.Close()
		t.Fatal("a missing binary started")
	}
	if _, err := Start(nil); err == nil {
		t.Fatal("a nil command started")
	}
}

func TestKillAndCloseAreIdempotent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd, pidFile := parentCmd(ctx, t, "hang")
	cmd.Stdout = new(bytes.Buffer)
	tree, err := Start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	pid := childPid(t, pidFile)
	for i := 0; i < 3; i++ {
		_ = tree.Kill()
	}
	_ = cmd.Wait()
	for i := 0; i < 3; i++ {
		if err := tree.Close(); err != nil && i > 0 {
			t.Fatalf("Close %d: %v", i, err)
		}
	}
	if err := tree.Kill(); err != nil {
		t.Fatalf("Kill after Close: %v", err)
	}
	requireDead(t, pid)
}
