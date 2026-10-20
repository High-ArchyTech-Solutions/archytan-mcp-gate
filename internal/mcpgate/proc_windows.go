// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package mcpgate

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/high-archytech-solutions/archytan-mcp-gate/internal/proctree"
)

// jobHandle is deliberately never closed. It closes when this process
// exits, for any reason including being killed, and closing the last
// handle is what makes Windows kill every process in the job.
var jobHandle syscall.Handle

// EnterKillOnCloseJob places the gate itself in a job that kills every
// member when the gate exits. It must run before the tool server starts:
// a child created afterwards is born inside the job, so there is no window
// between starting the child and assigning it in which killing the gate
// would leave it running.
func EnterKillOnCloseJob() error {
	h, err := proctree.NewKillOnCloseJob()
	if err != nil {
		return err
	}
	self, err := syscall.GetCurrentProcess()
	if err != nil {
		_ = syscall.CloseHandle(h)
		return fmt.Errorf("GetCurrentProcess: %w", err)
	}
	if err := proctree.AssignProcess(h, self); err != nil {
		_ = syscall.CloseHandle(h)
		return err
	}
	jobHandle = h
	return nil
}

// terminateSignal has no Windows equivalent of SIGTERM for a console child;
// Terminate goes straight to Kill after the grace period.
func terminateSignal(*os.Process) error {
	return errors.New("no terminate signal on windows")
}
