// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dialers

import (
	"net"
	"net/netip"
	"time"
)

// Shared by split_and_desync.go (Linux) and desync_windows.go.

const desync_cache_ttl = 30 * time.Second

func asAddrPort(a net.Addr) (n netip.AddrPort) {
	if a == nil {
		return
	}
	n, _ = netip.ParseAddrPort(a.String())
	return
}
