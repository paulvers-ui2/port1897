// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build dnssim && linux

package intra

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"
)

// simBacklogBlackhole listens on ip:port with a backlog of 0 and fills the
// accept queue with connections it never accepts. Linux then drops further
// SYNs without a reply, so a dial waits for its timeout exactly as through an
// adapter that swallows the traffic. Needs no root. port 0 picks one.
func simBacklogBlackhole(ip string, port int) (int, func(), error) {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is4() {
		return 0, nil, errors.New("need an IPv4 address")
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return 0, nil, err
	}
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: port, Addr: a.As4()}); err != nil {
		_ = syscall.Close(fd)
		return 0, nil, err
	}
	if err := syscall.Listen(fd, 0); err != nil {
		_ = syscall.Close(fd)
		return 0, nil, err
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		_ = syscall.Close(fd)
		return 0, nil, err
	}
	sa4, ok := sa.(*syscall.SockaddrInet4)
	if !ok {
		_ = syscall.Close(fd)
		return 0, nil, errors.New("not an IPv4 socket")
	}
	got := sa4.Port
	addr := net.JoinHostPort(ip, strconv.Itoa(got))

	var parked []net.Conn
	for i := 0; i < 4; i++ {
		if c, err := net.DialTimeout("tcp4", addr, 300*time.Millisecond); err == nil {
			parked = append(parked, c)
		}
	}
	closer := func() {
		for _, c := range parked {
			_ = c.Close()
		}
		_ = syscall.Close(fd)
	}
	// the queue must be full now: a probe must time out, not connect
	if c, err := net.DialTimeout("tcp4", addr, time.Second); err == nil {
		_ = c.Close()
		closer()
		return 0, nil, errors.New("listen backlog not full; SYNs still answered")
	}
	return got, closer, nil
}
