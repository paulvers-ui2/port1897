// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build linux

package core

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func closeFd(fd int) error {
	return syscall.Close(fd)
}

func setSockKeepAlive(fd uintptr, on bool) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, boolint(on))
}

func setSockKeepIdle(fd uintptr, secs int) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE, secs)
}

func setSockKeepIntvl(fd uintptr, secs int) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, secs)
}

func setSockKeepCnt(fd uintptr, n int) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, n)
}

func setSockUserTimeout(fd uintptr, ms int) error {
	return unix.SetsockoptInt(int(fd), unix.SOL_TCP, unix.TCP_USER_TIMEOUT, ms)
}

func setSockTTL(fd uintptr, v4 bool, ttl int) error {
	if v4 {
		// err1 := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTTL, 1)
		return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, ttl)
	}
	// err1 := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVHOPLIMIT, 1)
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, ttl)
}
