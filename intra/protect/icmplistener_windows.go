// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package protect

import (
	"context"
	"net"
	"syscall"

	"github.com/celzero/firestack/intra/core"
)

// listenICMP opens a raw ICMP socket: Windows has no unprivileged
// datagram-oriented ICMP sockets like Linux's. Raw sockets need admin
// rights, which the Windows service has. network must be "udp4" or "udp6"
// (kept for parity with Linux); reads return the ICMP message without the
// IP header, and every raw ICMP socket sees every ICMP reply, so callers
// must match replies by echo id and seq.
func (ln *icmplistener) listenICMP(ctx context.Context, network, address string) (core.ICMPConn, error) {
	var rawnet string
	switch network {
	case "udp4":
		rawnet = "ip4:icmp"
	case "udp6":
		rawnet = "ip6:ipv6-icmp"
	default:
		return nil, errNoICMPL3
	}

	lc := net.ListenConfig{}
	if cfn := ln.Control; cfn != nil {
		lc.Control = func(_, addr string, c syscall.RawConn) error {
			return cfn(network, addr, c)
		}
	}
	c, err := lc.ListenPacket(ctx, rawnet, address)
	if err != nil {
		return nil, err
	}
	return &icmpConn{c}, nil
}
