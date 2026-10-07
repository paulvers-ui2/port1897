// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build linux

package protect

import "syscall"

func bindFd(fd uintptr, sa syscall.Sockaddr) error {
	return syscall.Bind(int(fd), sa)
}
