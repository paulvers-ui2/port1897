// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build linux

package core

import (
	"fmt"
	"io"
	"syscall"

	"golang.org/x/sys/unix"
)

// github.com/go-sql-driver/mysql/blob/f20b28636/conncheck.go
// github.com/redis/go-redis/blob/cc9bcb0c0/internal/pool/conn_check.go
func (a agingconn) canread() error {
	sc := a.sc
	if sc == nil {
		return errNotSyscallConn
	}

	var checkErr error
	var ctlErr error

	if pooluseread { // stackoverflow.com/q/12741386
		ctlErr = sc.Read(func(fd uintptr) bool {
			// 0 byte reads do not work to detect readability:
			// see: go-review.googlesource.com/c/go/+/23227
			// pitfalls: github.com/redis/go-redis/issues/3137
			var buf [1]byte
			n, err := syscall.Read(int(fd), buf[:])
			switch {
			case n == 0 && err == nil:
				checkErr = io.EOF
			case n > 0:
				// conn is supposed to be idle
				checkErr = errUnexpectedRead
			case err == syscall.EAGAIN || err == syscall.EWOULDBLOCK:
				checkErr = nil
			default:
				checkErr = err
			}
			return true
		})
	} else {
		ctlErr = sc.Control(func(fd uintptr) {
			fds := []unix.PollFd{
				{Fd: int32(fd), Events: unix.POLLIN | unix.POLLERR},
			}
			n, err := unix.Poll(fds, 0)
			if err != nil {
				checkErr = fmt.Errorf("pool: poll: err: %v", err)
			}
			if n > 0 {
				checkErr = fmt.Errorf("pool: poll: sz: %d (must be 0), errno: %v",
					n, fds[0].Revents)
			}
		})
	}
	return JoinErr(ctlErr, checkErr) // may return nil
}
