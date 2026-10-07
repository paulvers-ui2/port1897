// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2019 The Outline Authors
//
//     Licensed under the Apache License, Version 2.0 (the "License");
//     you may not use this file except in compliance with the License.
//     You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
//     Unless required by applicable law or agreed to in writing, software
//     distributed under the License is distributed on an "AS IS" BASIS,
//     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//     See the License for the specific language governing permissions and
//     limitations under the License.

//go:build linux

package tunnel

import (
	"os"
	"syscall"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"golang.org/x/sys/unix"
)

// copy so golang gc may not close orig fd
func maybeDup(fd int) (int, error) {
	if fd < 0 {
		return 0, errInvalidTunFd
	}
	if settings.OwnTunFd.Load() {
		// if OwnTunFd is true, then do not dup the fd
		// as netstack owns the TUN fd and will not
		// assume ownership of the TUN fd shared with it.
		log.I("tun: assuming fd ownership %d", fd)
		return fd, nil
	}

	// ref: github.com/mdlayher/socket/blob/9c51a391b/conn.go#L309
	// fctnl(2) to dup the fd & set cloexec in one syscall
	newfd, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err == nil { // success
		return newfd, nil
	} else if err == unix.EINVAL { // fallback
		// Mirror the standard library: avoid racing a fork/exec with dup
		// so that child does not inherit socket fds unexpectedly.
		syscall.ForkLock.RLock()
		defer syscall.ForkLock.RUnlock()

		newfd, err := unix.Dup(fd)
		if err == nil {
			unix.CloseOnExec(newfd)
		}
		return newfd, err
	} // other errors?
	return 0, os.NewSyscallError("fcntl", err)
}
