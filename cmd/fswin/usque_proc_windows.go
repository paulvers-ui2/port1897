// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// childFlags start usque with no console at all, in its own process group.
// With CREATE_NO_WINDOW it got a hidden console: a console control event
// (Ctrl+C, the console closing, a sign-out) killed it with 0xC000013A, and
// started from the service into the user's session it could fail before
// running any code with 0xC0000142, when Windows could not set that console
// up there -- the two deaths in the 2026-10-11 debug zip that left the VPN
// down. Its output still comes through the pipe.
const childFlags = windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP

// exeSuffix ends a program's file name.
const exeSuffix = ".exe"

// childAttr is how usque is started.
func childAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: childFlags}
}

// procJob is the job object usque runs in.
type procJob windows.Handle

func (j *procJob) close() {
	if *j != 0 {
		_ = windows.CloseHandle(windows.Handle(*j))
		*j = 0
	}
}

// killOnCloseJob puts pid in a job object that kills it when the last handle
// to the job closes, which happens when fswin exits for any reason.
func killOnCloseJob(pid int) (procJob, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	p, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	defer windows.CloseHandle(p)
	if err := windows.AssignProcessToJobObject(job, p); err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	return procJob(job), nil
}
