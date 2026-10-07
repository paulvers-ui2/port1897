// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package dialers

import (
	"net"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
)

// dialWithSplitAndDesync falls back to a plain dial on Windows. The Linux
// version needs memfd, sendfile and IP_RECVERR/MSG_ERRQUEUE; a Windows port
// (see byedpi's Windows build) is left for a later phase.
func dialWithSplitAndDesync(d protect.RDialer, laddr, raddr net.Addr) (protect.Conn, error) {
	log.D("desync: unsupported on windows; plain dial to %v", raddr)
	return protect.Dial(d, laddr, raddr)
}
