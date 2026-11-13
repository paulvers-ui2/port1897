// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build linux

// Package owner, on Linux, finds the process that owns a connection: the
// socket's uid and inode from /proc/net/{tcp,udp}{,6}, then the process of
// that user holding the inode (/proc/<pid>/fd).
package owner

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrNotFound is returned when no socket matches.
var ErrNotFound = errors.New("owner: no such socket")

type sock struct {
	uid   uint32
	inode uint64
}

// TCP4 returns the pid owning the TCP connection local -> remote.
func TCP4(local, remote netip.AddrPort) (uint32, error) {
	s, ok := find([]string{"/proc/net/tcp", "/proc/net/tcp6"}, local, remote, true)
	if !ok {
		return 0, ErrNotFound
	}
	return pidOf(s)
}

// UDP4 returns the pid owning the UDP socket bound to local, or to the
// wildcard address on local's port.
func UDP4(local netip.AddrPort) (uint32, error) {
	s, ok := find([]string{"/proc/net/udp", "/proc/net/udp6"}, local, netip.AddrPort{}, false)
	if !ok {
		return 0, ErrNotFound
	}
	return pidOf(s)
}

// ExePath returns the full path of pid's program.
func ExePath(pid uint32) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
}

// find scans socket tables for local (and remote, when exact). A wildcard
// local address on the same port matches when nothing closer does.
func find(tables []string, local, remote netip.AddrPort, exact bool) (sock, bool) {
	var loose sock
	found := false
	for _, t := range tables {
		f, err := os.Open(t) //nolint:gosec // G304: fixed /proc paths
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Scan() // header
		for sc.Scan() {
			// sl local remote st tx_queue rx_queue tr:tm->when retrnsmt uid timeout inode ...
			c := strings.Fields(sc.Text())
			if len(c) < 10 {
				continue
			}
			l, ok1 := parseAddrPort(c[1])
			r, ok2 := parseAddrPort(c[2])
			if !ok1 || !ok2 || l.Port() != local.Port() {
				continue
			}
			uid, _ := strconv.ParseUint(c[7], 10, 32)
			inode, _ := strconv.ParseUint(c[9], 10, 64)
			if inode == 0 {
				continue
			}
			s := sock{uint32(uid), inode}
			if l.Addr() == local.Addr() && (!exact || r == remote) {
				_ = f.Close()
				return s, true
			}
			if !exact && l.Addr().IsUnspecified() && !found {
				loose, found = s, true
			}
		}
		_ = f.Close()
	}
	return loose, found
}

// parseAddrPort reads /proc/net's "0100007F:1F90" and its 32-digit IPv6
// form (four host-order words); IPv4-mapped addresses come out as IPv4.
func parseAddrPort(s string) (netip.AddrPort, bool) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	b, err2 := hex.DecodeString(h)
	if err != nil || err2 != nil || (len(b) != 4 && len(b) != 16) {
		return netip.AddrPort{}, false
	}
	for i := 0; i+3 < len(b); i += 4 { // each word is in host (little-endian) order
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	a, _ := netip.AddrFromSlice(b)
	if a.Is6() && a.Unmap().Is4() {
		a = a.Unmap()
	} else if a.Is6() && a.IsUnspecified() {
		a = netip.IPv4Unspecified() // a dual-stack wildcard socket serves IPv4 too
	}
	return netip.AddrPortFrom(a, uint16(port)), true
}

var (
	mu    sync.Mutex
	pids  = map[uint64]cached{} // by socket inode
	sweep time.Time
)

type cached struct {
	pid uint32
	at  time.Time
}

// pidOf finds the process of s.uid that holds socket s.inode.
func pidOf(s sock) (uint32, error) {
	mu.Lock()
	defer mu.Unlock()
	now := time.Now()
	if c, ok := pids[s.inode]; ok && now.Sub(c.at) < time.Minute {
		return c.pid, nil
	}
	if now.Sub(sweep) > time.Minute {
		for k, c := range pids {
			if now.Sub(c.at) > time.Minute {
				delete(pids, k)
			}
		}
		sweep = now
	}
	want := "socket:[" + strconv.FormatUint(s.inode, 10) + "]"
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	for _, p := range procs {
		pid, err := strconv.ParseUint(p.Name(), 10, 32)
		if err != nil {
			continue
		}
		dir := "/proc/" + p.Name()
		if st, err := os.Stat(dir); err != nil || !ownedBy(st, s.uid) {
			continue
		}
		fds, err := os.ReadDir(dir + "/fd")
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if l, err := os.Readlink(dir + "/fd/" + fd.Name()); err == nil && l == want {
				pids[s.inode] = cached{uint32(pid), now}
				return uint32(pid), nil
			}
		}
	}
	return 0, ErrNotFound
}
