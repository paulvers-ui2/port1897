// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func cutLine(s string) (line, rest string, ok bool) { return strings.Cut(s, "\n") }
func splitColon(s string) []string                  { return strings.Split(s, ":") }

// exeSuffix ends a program's file name.
const exeSuffix = ""

// childAttr is how usque is started: in its own process group (a Ctrl+C in
// the terminal is the engine's to handle), and killed when the engine dies.
func childAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}

// procJob is nothing on Linux: childAttr's Pdeathsig kills usque with the
// engine.
type procJob struct{}

func (*procJob) close() {}

func killOnCloseJob(int) (procJob, error) { return procJob{}, nil }

// adapterBytes is what the tunnel's interface (index luid) received from
// the engine for the PC's programs (rx) and sent to it, from the kernel's
// counters.
func adapterBytes(luid uint64) (rx, tx int64, ok bool) {
	ifc, err := net.InterfaceByIndex(int(luid)) //nolint:gosec // G115: an interface index
	if err != nil {
		return 0, 0, false
	}
	read := func(name string) (int64, bool) {
		b, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/statistics/%s", ifc.Name, name)) //nolint:gosec // G304: under /sys/class/net
		if err != nil {
			return 0, false
		}
		n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		return n, err == nil
	}
	rx, ok1 := read("rx_bytes")
	tx, ok2 := read("tx_bytes")
	return rx, tx, ok1 && ok2
}
