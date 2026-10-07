// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2018 The gVisor Authors.
//
//     Licensed under the Apache License, Version 2.0 (the "License");
//     you may not use this file except in compliance with the License.
//     You may obtain a copy of the License at
//
//         http://www.apache.org/licenses/LICENSE-2.0
//
//     Unless required by applicable law or agreed to in writing, software
//     distributed under the License is distributed on an "AS IS" BASIS,
//     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//     See the License for the specific language governing permissions and
//     limitations under the License.

package netstack

import (
	"errors"
	"math/rand"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// Shared by the Linux (fd-based) and Windows (Wintun) endpoints.

const invalidfd int = -1

var errNeedsNewEndpoint = errors.New("ns: needs new endpoint")

// Options specify the details about the fd-based endpoint to be created.
type Options struct {
	// FDs is a set of FDs used to read/write packets.
	FDs []int

	// MTU is the mtu to use for this endpoint.
	MTU uint32

	// EthernetHeader if true, indicates that the endpoint should read/write
	// ethernet frames instead of IP packets.
	EthernetHeader bool

	// Address is the link address for this endpoint. Only used if
	// EthernetHeader is true.
	Address tcpip.LinkAddress

	// SaveRestore if true, indicates that this NIC capability set should
	// include CapabilitySaveRestore
	SaveRestore bool

	// DisconnectOk if true, indicates that this NIC capability set should
	// include CapabilityDisconnectOk.
	DisconnectOk bool

	// TXChecksumOffload if true, indicates that this endpoints capability
	// set should include CapabilityTXChecksumOffload.
	TXChecksumOffload bool

	// RXChecksumOffload if true, indicates that this endpoints capability
	// set should include CapabilityRXChecksumOffload.
	RXChecksumOffload bool

	// If MaxSyscallHeaderBytes is non-zero, it is the maximum number of bytes
	// of struct iovec, msghdr, and mmsghdr that may be passed by each host
	// system call.
	MaxSyscallHeaderBytes int
}

func rand10pc() bool {
	return rand.Intn(999999) < 99999
}

func rand1pc() bool {
	return rand.Intn(999999) < 9999
}
