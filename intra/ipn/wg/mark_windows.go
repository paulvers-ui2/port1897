// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package wg

// setSockMark is a no-op: Windows has no fwmark. There, the host keeps
// sockets off the tunnel through protect.Controller (Bind4/Bind6).
func setSockMark(fd uintptr, mark uint32) error {
	return nil
}
