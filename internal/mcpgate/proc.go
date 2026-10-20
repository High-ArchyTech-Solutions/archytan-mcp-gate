// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package mcpgate

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"time"
)

// StartServer launches the tool server with piped stdin and stdout. Its
// stderr is the gate's own stderr, written by the OS directly, so a chatty
// server can never fill a pipe the gate forgot to drain.
//
// The pipes are plain os.Pipe pairs rather than cmd.StdinPipe/StdoutPipe:
// cmd.Wait closes pipes it created, which would race the reader and could
// drop the server's final messages. With these, stdout reads until the
// server's side closes, independent of Wait.
func StartServer(argv []string) (*exec.Cmd, io.WriteCloser, io.ReadCloser, error) {
	if len(argv) == 0 {
		return nil, nil, nil, errors.New("no tool server command given")
	}
	childIn, parentIn, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, err
	}
	parentOut, childOut, err := os.Pipe()
	if err != nil {
		childIn.Close()
		parentIn.Close()
		return nil, nil, nil, err
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = childIn
	cmd.Stdout = childOut
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	// The child holds its own copies now; the parent must drop these ends
	// or it would never see EOF on the server's stdout.
	childIn.Close()
	childOut.Close()
	if err != nil {
		parentIn.Close()
		parentOut.Close()
		return nil, nil, nil, err
	}
	return cmd, parentIn, parentOut, nil
}

// Terminate waits for the server to exit on its own (its stdin has just
// been closed), then asks it to stop, then forces it. done is closed when
// cmd.Wait has returned.
func Terminate(cmd *exec.Cmd, done <-chan struct{}, grace time.Duration) {
	select {
	case <-done:
		return
	case <-time.After(grace):
	}
	if err := terminateSignal(cmd.Process); err == nil {
		select {
		case <-done:
			return
		case <-time.After(grace):
		}
	}
	_ = cmd.Process.Kill()
	<-done
}
