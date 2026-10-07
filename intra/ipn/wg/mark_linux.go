// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build linux

package wg

import "golang.org/x/sys/unix"

const fwmarkIoctl = 36 /* unix.SO_MARK */

// from: github.com/WireGuard/wireguard-go/blob/1417a47c8/conn/mark_unix.go
func setSockMark(fd uintptr, mark uint32) error {
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
}
