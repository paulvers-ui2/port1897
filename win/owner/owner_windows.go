// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package owner

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

// from iprtrmib.h / tcpmib.h / udpmib.h
const (
	tcpTableOwnerPidAll = 5 // TCP_TABLE_OWNER_PID_ALL
	udpTableOwnerPid    = 1 // UDP_TABLE_OWNER_PID

	tcpRowSize = 24 // MIB_TCPROW_OWNER_PID: state, laddr, lport, raddr, rport, pid
	udpRowSize = 12 // MIB_UDPROW_OWNER_PID: laddr, lport, pid

	errInsufficientBuffer = syscall.Errno(122) // ERROR_INSUFFICIENT_BUFFER
)

var (
	ErrNotFound    = errors.New("owner: no matching socket")
	errUnsupported = errors.New("owner: only IPv4 is supported")
)

// TCP4 returns the pid owning the IPv4 TCP socket local -> remote.
func TCP4(local, remote netip.AddrPort) (uint32, error) {
	if !local.Addr().Is4() || !remote.Addr().Is4() {
		return 0, errUnsupported
	}
	buf, err := table(procGetExtendedTcpTable, tcpTableOwnerPidAll)
	if err != nil {
		return 0, err
	}
	n := int(binary.LittleEndian.Uint32(buf))
	rows := buf[4:]
	var portOnly uint32
	for i := 0; i < n && (i+1)*tcpRowSize <= len(rows); i++ {
		r := rows[i*tcpRowSize : (i+1)*tcpRowSize]
		if addrPort(r[4:8], r[8:12]) != local {
			if port(r[8:12]) == local.Port() && portOnly == 0 {
				portOnly = binary.LittleEndian.Uint32(r[20:24])
			}
			continue
		}
		if addrPort(r[12:16], r[16:20]) == remote {
			return binary.LittleEndian.Uint32(r[20:24]), nil
		}
	}
	if portOnly != 0 {
		return portOnly, nil
	}
	return 0, ErrNotFound
}

// UDP4 returns the pid owning the IPv4 UDP socket bound to local (or to the
// wildcard address on local's port).
func UDP4(local netip.AddrPort) (uint32, error) {
	if !local.Addr().Is4() {
		return 0, errUnsupported
	}
	buf, err := table(procGetExtendedUdpTable, udpTableOwnerPid)
	if err != nil {
		return 0, err
	}
	n := int(binary.LittleEndian.Uint32(buf))
	rows := buf[4:]
	var wildcard uint32
	for i := 0; i < n && (i+1)*udpRowSize <= len(rows); i++ {
		r := rows[i*udpRowSize : (i+1)*udpRowSize]
		ap := addrPort(r[0:4], r[4:8])
		if ap.Port() != local.Port() {
			continue
		}
		pid := binary.LittleEndian.Uint32(r[8:12])
		if ap.Addr() == local.Addr() {
			return pid, nil
		}
		if ap.Addr().IsUnspecified() && wildcard == 0 {
			wildcard = pid
		}
	}
	if wildcard != 0 {
		return wildcard, nil
	}
	return 0, ErrNotFound
}

// table calls GetExtendedTcpTable or GetExtendedUdpTable for AF_INET.
func table(proc *windows.LazyProc, class uintptr) ([]byte, error) {
	size := uint32(16 << 10)
	for range 4 {
		buf := make([]byte, size)
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)),
			0 /*unsorted*/, windows.AF_INET, class, 0)
		switch syscall.Errno(r) {
		case 0:
			if len(buf) < 4 {
				return nil, ErrNotFound
			}
			return buf[:size], nil
		case errInsufficientBuffer:
			size += 4 << 10 // the table may grow between calls
			continue
		default:
			return nil, syscall.Errno(r)
		}
	}
	return nil, errInsufficientBuffer
}

// addrPort decodes an IPv4 address and port as stored in MIB rows: the
// address in network order, the port in the low 16 bits, network order.
func addrPort(a, p []byte) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte(a[:4])), port(p))
}

func port(p []byte) uint16 {
	return uint16(p[0])<<8 | uint16(p[1])
}

// pathttl bounds how long a pid -> path entry is trusted; pids get reused.
const pathttl = 30 * time.Second

type pathEntry struct {
	path string
	at   time.Time
}

var (
	pathmu    sync.Mutex
	pathcache = map[uint32]pathEntry{}
)

// ExePath returns the full path of pid's executable. pid 4 is "System".
func ExePath(pid uint32) (string, error) {
	switch pid {
	case 0:
		return "", ErrNotFound
	case 4:
		return "System", nil
	}

	pathmu.Lock()
	if e, ok := pathcache[pid]; ok && time.Since(e.at) < pathttl {
		pathmu.Unlock()
		return e.path, nil
	}
	pathmu.Unlock()

	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "", err
	}
	path := windows.UTF16ToString(buf[:size])

	pathmu.Lock()
	if len(pathcache) > 4096 {
		clear(pathcache)
	}
	pathcache[pid] = pathEntry{path, time.Now()}
	pathmu.Unlock()
	return path, nil
}
