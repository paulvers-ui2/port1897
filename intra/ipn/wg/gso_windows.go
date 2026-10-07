// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     SPDX-License-Identifier: MIT
//
//     Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.

//go:build windows

package wg

import "net"

// from: github.com/WireGuard/wireguard-go/blob/12269c276/conn/gso_default.go,
// features_default.go and errors_default.go: no UDP GSO/GRO off Linux.

// gsoControlSize returns the recommended buffer size for pooling UDP
// offloading control data.
var gsoControlSize = 0

// getGSOSize parses control for UDP_GRO and if found returns its GSO size data.
func getGSOSize(control []byte) (int, error) {
	return 0, nil
}

// setGSOSize sets a UDP_SEGMENT in control based on gsoSize.
func setGSOSize(control *[]byte, gsoSize uint16) {}

func supportsUDPOffload(conn *net.UDPConn) (txOffload, rxOffload bool) {
	return
}

func supportsBatchRw() bool {
	return false
}

func shouldDisableUDPGSOOnError(err error) bool {
	return false
}
