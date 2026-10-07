// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2014 The Go Authors. All rights reserved.
//     Use of this source code is governed by a BSD-style
//     license that can be found in the LICENSE file.

package protect

import (
	"net"
	"strconv"
	"syscall"

	"github.com/celzero/firestack/intra/core"
)

const (
	protocolICMP     = 1
	protocolIPv6ICMP = 58
)

type icmplistener struct {
	Control ControlFn
}

var _ core.ICMPConn = (*icmpConn)(nil)

type icmpConn struct {
	net.PacketConn
}

func (s *icmpConn) SyscallConn() (syscall.RawConn, error) {
	return sysconn(s.PacketConn)
}


func sysconn(c net.PacketConn) (syscall.RawConn, error) {
	switch v := c.(type) {
	case *net.UDPConn:
		return v.SyscallConn()
	case *net.IPConn:
		return v.SyscallConn()
	case *net.UnixConn:
		return v.SyscallConn()
	default:
		return nil, errNoSysConn
	}
}

// from: cs.opensource.google/go/x/net/+/refs/tags/v0.28.0:icmp/helper_posix.go
// todo: do not resolve address
func sockaddr(family int, address string) (syscall.Sockaddr, error) {
	switch family {
	case syscall.AF_INET:
		a, err := net.ResolveIPAddr("ip4", address)
		if err != nil {
			return nil, err
		}
		if a == nil { // nilaway
			return nil, net.InvalidAddrError("bad ipv4 address")
		}
		if len(a.IP) == 0 {
			a.IP = net.IPv4zero
		}
		if a.IP = a.IP.To4(); a.IP == nil {
			return nil, net.InvalidAddrError("non-ipv4 address")
		}
		sa := &syscall.SockaddrInet4{}
		copy(sa.Addr[:], a.IP)
		return sa, nil
	case syscall.AF_INET6:
		a, err := net.ResolveIPAddr("ip6", address)
		if err != nil {
			return nil, err
		}
		if a == nil { // nilaway
			return nil, net.InvalidAddrError("bad ipv6 address")
		}
		if len(a.IP) == 0 {
			a.IP = net.IPv6unspecified
		}
		if a.IP.Equal(net.IPv4zero) {
			a.IP = net.IPv6unspecified
		}
		if a.IP = a.IP.To16(); a.IP == nil || a.IP.To4() != nil {
			return nil, net.InvalidAddrError("non-ipv6 address")
		}
		sa := &syscall.SockaddrInet6{ZoneId: zoneToUint32(a.Zone)}
		copy(sa.Addr[:], a.IP)
		return sa, nil
	default:
		return nil, net.InvalidAddrError("unexpected family")
	}
}

// from: cs.opensource.google/go/x/net/+/refs/tags/v0.28.0:icmp/helper_posix.go
func zoneToUint32(zone string) uint32 {
	if zone == "" {
		return 0
	}
	if ifi, err := net.InterfaceByName(zone); err == nil {
		return uint32(ifi.Index)
	}
	n, err := strconv.Atoi(zone)
	if err != nil {
		return 0
	}
	return uint32(n)
}
