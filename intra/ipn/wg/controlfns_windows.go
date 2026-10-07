// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     SPDX-License-Identifier: MIT
//
//     Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.

//go:build windows

package wg

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// from: github.com/WireGuard/wireguard-go/blob/12269c276/conn/controlfns_windows.go
func init() {
	controlFns = append(controlFns,
		func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_RCVBUF, socketBufferSize)
				_ = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_SNDBUF, socketBufferSize)
			})
		},
	)
}
