// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import "golang.org/x/sys/windows"

// GetIfEntry2Ex came with Windows 10 1703; x/sys panics when a function is
// missing, so it is looked up first.
var procGetIfEntry2Ex = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetIfEntry2Ex")

// adapterBytes is what the adapter received (rx: from the tunnel, for the
// PC's programs) and sent, from Windows' own counters, which run live. The
// adapter is made new at each start, so they count from it.
func adapterBytes(luid uint64) (rx, tx int64, ok bool) {
	if luid == 0 || procGetIfEntry2Ex.Find() != nil {
		return 0, 0, false
	}
	row := windows.MibIfRow2{InterfaceLuid: luid}
	if windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &row) != nil {
		return 0, 0, false
	}
	return int64(row.InOctets), int64(row.OutOctets), true //nolint:gosec // G115: byte counts, far below 2^63
}
