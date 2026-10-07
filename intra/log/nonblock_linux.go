// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build linux

package log

import (
	"os"
	"syscall"
)

func setNonblock(f *os.File) error {
	if f == nil {
		return nil
	}
	return syscall.SetNonblock(int(f.Fd()), true)
}
