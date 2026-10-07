// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package core

// canread on Windows does not probe the socket: Go's sockets there use
// overlapped I/O, so a non-blocking read or poll from RawConn is not
// available. The pool falls back to evicting conns by age (poolmaxidle);
// a stale conn fails on first use and callers redial.
func (a agingconn) canread() error {
	if a.sc == nil {
		return errNotSyscallConn
	}
	return nil
}
