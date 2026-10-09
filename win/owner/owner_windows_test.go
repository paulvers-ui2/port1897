// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package owner

import (
	"net"
	"net/netip"
	"os"
	"testing"
)

func TestTCP4FindsNewSocketsDespiteTheCopy(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	// the second connection opens after the first lookup copied the table:
	// that copy must not hide it
	for i := range 2 {
		c, err := net.Dial("tcp4", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		local := netip.MustParseAddrPort(c.LocalAddr().String())
		remote := netip.MustParseAddrPort(c.RemoteAddr().String())
		pid, err := TCP4(local, remote)
		if err != nil || pid != uint32(os.Getpid()) {
			t.Fatalf("connection %d: pid %d, %v; want %d", i, pid, err, os.Getpid())
		}
	}
}

func TestUDP4(t *testing.T) {
	bound, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Close()
	wild, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer wild.Close()
	for _, local := range []netip.AddrPort{
		netip.MustParseAddrPort(bound.LocalAddr().String()),
		// the wildcard socket, asked for by one of this PC's addresses
		netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(wild.LocalAddr().(*net.UDPAddr).Port)),
	} {
		if pid, err := UDP4(local); err != nil || pid != uint32(os.Getpid()) {
			t.Fatalf("%v: pid %d, %v; want %d", local, pid, err, os.Getpid())
		}
	}
	if _, err := UDP4(netip.MustParseAddrPort("127.0.0.1:1")); err != ErrNotFound {
		t.Fatalf("port 1: %v, want ErrNotFound", err)
	}
}

func TestLookupsIgnoreShortOrTornTables(t *testing.T) {
	local := netip.MustParseAddrPort("10.0.0.2:5000")
	remote := netip.MustParseAddrPort("1.1.1.1:443")
	// a row count larger than the rows present
	buf := make([]byte, 4+tcpRowSize/2)
	buf[0] = 200
	if pid, exact := tcpLookup(buf, local, remote); pid != 0 || exact {
		t.Fatalf("tcp: %d %v", pid, exact)
	}
	if pid := udpLookup(buf, local); pid != 0 {
		t.Fatalf("udp: %d", pid)
	}
}
