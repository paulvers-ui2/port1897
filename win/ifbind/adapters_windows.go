// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package ifbind

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// forEachAdapter calls f with each adapter GetAdaptersAddresses reports for
// family (AF_INET, AF_INET6 or AF_UNSPEC), until f returns false.
//
// It is the one place this package reads that table. The buffer is 8-byte
// aligned, as IP_ADAPTER_ADDRESSES needs, and sized by Windows, which tells
// the size it wants when the table grew between calls. The adapters and
// their address lists point into the buffer, which stays alive while f runs;
// f must not keep any of those pointers.
func forEachAdapter(family uint32, f func(aa *windows.IpAdapterAddresses) bool) error {
	size := uint32(15 << 10)
	for range 4 {
		buf := make([]uint64, (size+7)/8)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(family, windows.GAA_FLAG_SKIP_ANYCAST, 0, first, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return err
		}
		for aa := first; aa != nil; aa = aa.Next {
			if !f(aa) {
				break
			}
		}
		runtime.KeepAlive(buf)
		return nil
	}
	return windows.ERROR_BUFFER_OVERFLOW
}
