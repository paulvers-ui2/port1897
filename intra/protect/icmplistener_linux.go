// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build linux

package protect

import (
	"context"
	"net"
	"os"
	"syscall"

	"github.com/celzero/firestack/intra/core"
)

// listenICMP listens for incoming ICMP packets addressed to
// address for non-privileged datagram-oriented ICMP endpoints.
// network must be "udp4" or "udp6". The endpoint allows to read,
// write a few limited ICMP messages such as echo request & reply.
//
// Examples:
//
//	listenICMP("udp4", "192.168.0.1")
//	listenICMP("udp4", "0.0.0.0")
//	listenICMP("udp6", "fe80::1%en0")
//	listenICMP("udp6", "::")
//
// from: cs.opensource.google/go/x/net/+/refs/tags/v0.28.0:icmp/listen_posix.go
func (ln *icmplistener) listenICMP(_ context.Context, network, address string) (core.ICMPConn, error) {
	var family, proto int
	switch network {
	case "udp4":
		family, proto = syscall.AF_INET, protocolICMP
	case "udp6":
		family, proto = syscall.AF_INET6, protocolIPv6ICMP
	default:
		return nil, errNoICMPL3
	}

	// todo: controller bind4, bind6
	var cerr error
	var c net.PacketConn
	s, err := syscall.Socket(family, syscall.SOCK_DGRAM, proto)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	sa, err := sockaddr(family, address)
	if err != nil {
		syscall.Close(s)
		return nil, err
	}
	if err := syscall.Bind(s, sa); err != nil {
		syscall.Close(s)
		return nil, os.NewSyscallError("bind", err)
	}
	// why? github.com/golang/go/issues/15021#issuecomment-308562480
	f := os.NewFile(uintptr(s), "datagram-oriented icmp")
	c, cerr = net.FilePacketConn(f) // expecting a *net.UDPConn
	f.Close()
	if cerr != nil {
		clos(c)
		return nil, cerr
	}
	if cfn := ln.Control; cfn != nil {
		var sc syscall.RawConn
		if sc, err = sysconn(c); err == nil {
			err = cfn(network, address, sc)
		}
		if err != nil {
			clos(c)
			return nil, err
		}
	}
	return &icmpConn{c}, nil
}
