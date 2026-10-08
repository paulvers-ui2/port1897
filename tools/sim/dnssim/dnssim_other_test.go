// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build dnssim && !linux

package intra

import "errors"

func simBacklogBlackhole(ip string, port int) (int, func(), error) {
	return 0, nil, errors.New("the backlog blackhole needs linux; use blackhole-testnet")
}
