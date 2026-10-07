// Copyright (c) 2024 RethinkDNS and its authors.
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

package wg

import (
	"github.com/celzero/firestack/intra/protect"
)

// from: github.com/WireGuard/wireguard-go/blob/12269c276/conn/controlfns.go

// UDP socket read/write buffer size (7MB). The value of 7MB is chosen as it is
// the max supported by a default configuration of macOS. Some platforms will
// silently clamp the value to other maximums, such as linux clamping to
// net.core.{r,w}mem_max (see _linux.go for additional implementation that works
// around this limitation)
const socketBufferSize = 7 << 20

// controlFns is a list of functions that are called from the listen config
// that can apply socket options.
var controlFns = []protect.ControlFn{}
