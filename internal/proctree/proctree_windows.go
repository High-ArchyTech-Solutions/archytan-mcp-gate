// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package proctree

import (
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"
)

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW         = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject  = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
	procTerminateJobObject       = kernel32.NewProc("TerminateJobObject")
	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procThread32First            = kernel32.NewProc("Thread32First")
	procThread32Next             = kernel32.NewProc("Thread32Next")
	procOpenThread               = kernel32.NewProc("OpenThread")
	procResumeThread             = kernel32.NewProc("ResumeThread")
)

const (
	jobObjectExtendedLimitInformationClass = 9
	jobObjectLimitKillOnJobClose           = 0x00002000

	createSuspended     = 0x00000004
	th32csSnapThread    = 0x00000004
	threadSuspendResume = 0x0002
	processSetQuota     = 0x0100
	processTerminate    = 0x0001
)

// Mirrors JOBOBJECT_EXTENDED_LIMIT_INFORMATION. Go's natural alignment
// matches the C layout on both 386 and amd64.
type ioCounters struct {
	ReadOperationCount, WriteOperationCount, OtherOperationCount uint64
	ReadTransferCount, WriteTransferCount, OtherTransferCount    uint64
}

type jobBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type jobExtendedLimitInformation struct {
	BasicLimitInformation jobBasicLimitInformation
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

// Mirrors THREADENTRY32.
type threadEntry32 struct {
	Size           uint32
	Usage          uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePri        int32
	DeltaPri       int32
	Flags          uint32
}

// NewKillOnCloseJob creates a job object that ends every process in it when
// its last handle closes.
func NewKillOnCloseJob() (syscall.Handle, error) {
	h, _, err := procCreateJobObjectW.Call(0, 0)
	if h == 0 {
		return 0, fmt.Errorf("CreateJobObject: %w", err)
	}
	var info jobExtendedLimitInformation
	info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose
	ok, _, err := procSetInformationJobObject.Call(h, jobObjectExtendedLimitInformationClass,
		uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	if ok == 0 {
		_ = syscall.CloseHandle(syscall.Handle(h))
		return 0, fmt.Errorf("SetInformationJobObject: %w", err)
	}
	return syscall.Handle(h), nil
}

// AssignProcess places process in job.
func AssignProcess(job, process syscall.Handle) error {
	ok, _, err := procAssignProcessToJobObject.Call(uintptr(job), uintptr(process))
	if ok == 0 {
		return fmt.Errorf("AssignProcessToJobObject: %w", err)
	}
	return nil
}

type treeSys struct{ job syscall.Handle }

// prepare creates the child suspended, so it can be placed in its job
// before it runs: there is then no window in which it could start a
// process that escapes the job.
func prepare(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= createSuspended
}

func (t *Tree) contain() error {
	job, err := NewKillOnCloseJob()
	if err != nil {
		return err
	}
	pid := uint32(t.cmd.Process.Pid)
	h, err := syscall.OpenProcess(processSetQuota|processTerminate, false, pid)
	if err != nil {
		_ = syscall.CloseHandle(job)
		return fmt.Errorf("OpenProcess: %w", err)
	}
	defer syscall.CloseHandle(h)
	if err := AssignProcess(job, h); err != nil {
		_ = syscall.CloseHandle(job)
		return err
	}
	t.sys.job = job
	return resumeProcess(pid)
}

// resumeProcess resumes the threads of a process created suspended (it has
// exactly one). Go's os/exec closes the thread handle CreateProcess returns,
// so the thread is found again through a snapshot.
func resumeProcess(pid uint32) error {
	snap, _, err := procCreateToolhelp32Snapshot.Call(th32csSnapThread, 0)
	if syscall.Handle(snap) == syscall.InvalidHandle {
		return fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer syscall.CloseHandle(syscall.Handle(snap))

	var te threadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	resumed := 0
	ok, _, _ := procThread32First.Call(snap, uintptr(unsafe.Pointer(&te)))
	for ok != 0 {
		if te.OwnerProcessID == pid {
			th, _, err := procOpenThread.Call(threadSuspendResume, 0, uintptr(te.ThreadID))
			if th == 0 {
				return fmt.Errorf("OpenThread: %w", err)
			}
			r, _, err := procResumeThread.Call(th)
			_ = syscall.CloseHandle(syscall.Handle(th))
			if uint32(r) == 0xFFFFFFFF {
				return fmt.Errorf("ResumeThread: %w", err)
			}
			resumed++
		}
		ok, _, _ = procThread32Next.Call(snap, uintptr(unsafe.Pointer(&te)))
	}
	if resumed == 0 {
		return errors.New("resume: the suspended process has no thread")
	}
	return nil
}

func (t *Tree) killTree() error {
	if t.sys.job != 0 {
		ok, _, err := procTerminateJobObject.Call(uintptr(t.sys.job), 1)
		if ok == 0 {
			return fmt.Errorf("TerminateJobObject: %w", err)
		}
		return nil
	}
	// Not yet in a job: the child is still suspended, so it has started
	// nothing that could escape.
	if t.cmd.Process != nil {
		return t.cmd.Process.Kill()
	}
	return nil
}

func (t *Tree) closeSys() error {
	if t.sys.job == 0 {
		return nil
	}
	err := syscall.CloseHandle(t.sys.job)
	t.sys.job = 0
	return err
}
