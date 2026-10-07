// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package core

import (
	"golang.org/x/sys/windows"
)

func closeFd(fd int) error {
	return windows.CloseHandle(windows.Handle(fd))
}

func setSockKeepAlive(fd uintptr, on bool) error {
	return windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_KEEPALIVE, boolint(on))
}

func setSockKeepIdle(fd uintptr, secs int) error {
	return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_TCP, windows.TCP_KEEPIDLE, secs)
}

func setSockKeepIntvl(fd uintptr, secs int) error {
	return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_TCP, windows.TCP_KEEPINTVL, secs)
}

func setSockKeepCnt(fd uintptr, n int) error {
	return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_TCP, windows.TCP_KEEPCNT, n)
}

// setSockUserTimeout sets TCP_MAXRT, the closest Windows has to Linux's
// TCP_USER_TIMEOUT; it takes whole seconds.
func setSockUserTimeout(fd uintptr, ms int) error {
	secs := max((ms+999)/1000, 1)
	return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_TCP, windows.TCP_MAXRT, secs)
}

func setSockTTL(fd uintptr, v4 bool, ttl int) error {
	if v4 {
		return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_TTL, ttl)
	}
	return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, windows.IPV6_UNICAST_HOPS, ttl)
}
