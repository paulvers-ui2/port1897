// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package owner

import (
	"encoding/binary"
	"errors"
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
	if _, err := UDP4(netip.MustParseAddrPort("127.0.0.1:1")); !errors.Is(err, ErrNotFound) {
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

// tcpRow is one MIB_TCPROW_OWNER_PID row.
func tcpRow(local, remote netip.AddrPort, pid uint32) []byte {
	r := make([]byte, tcpRowSize)
	la, ra := local.Addr().As4(), remote.Addr().As4()
	copy(r[4:8], la[:])
	binary.BigEndian.PutUint16(r[8:10], local.Port())
	copy(r[12:16], ra[:])
	binary.BigEndian.PutUint16(r[16:18], remote.Port())
	binary.LittleEndian.PutUint32(r[20:24], pid)
	return r
}

// udpRow is one MIB_UDPROW_OWNER_PID row.
func udpRow(local netip.AddrPort, pid uint32) []byte {
	r := make([]byte, udpRowSize)
	la := local.Addr().As4()
	copy(r[0:4], la[:])
	binary.BigEndian.PutUint16(r[4:6], local.Port())
	binary.LittleEndian.PutUint32(r[8:12], pid)
	return r
}

func mibTable(rows ...[]byte) []byte {
	buf := binary.LittleEndian.AppendUint32(nil, uint32(len(rows)))
	for _, r := range rows {
		buf = append(buf, r...)
	}
	return buf
}

// The engine's own sockets on the physical adapter share port numbers with
// the programs it proxies: the port-only fallback must not name the engine.
func TestFallbacksSkipSelf(t *testing.T) {
	const other = 4242
	self := selfPID
	if self == other {
		t.Skip("pid clash")
	}
	local := netip.MustParseAddrPort("10.111.222.1:50000")
	remote := netip.MustParseAddrPort("93.184.215.14:443")
	phys := netip.MustParseAddrPort("192.168.1.20:50000")
	elsewhere := netip.MustParseAddrPort("1.1.1.1:443")

	// only the engine has a socket on that port: unknown, not the engine
	if pid, exact := tcpLookup(mibTable(tcpRow(phys, elsewhere, self)), local, remote); pid != 0 || exact {
		t.Fatalf("tcp, self only: %d %v; want 0 false", pid, exact)
	}
	// the engine's row comes first: the other program's is still found
	if pid, exact := tcpLookup(mibTable(tcpRow(phys, elsewhere, self), tcpRow(phys, remote, other)), local, remote); pid != other || exact {
		t.Fatalf("tcp, self then other: %d %v; want %d false", pid, exact, other)
	}
	// an exact match is the engine's own connection, and says so
	if pid, exact := tcpLookup(mibTable(tcpRow(local, remote, self)), local, remote); pid != self || !exact {
		t.Fatalf("tcp, exact self: %d %v; want %d true", pid, exact, self)
	}

	wild := netip.MustParseAddrPort("0.0.0.0:50000")
	if pid := udpLookup(mibTable(udpRow(wild, self), udpRow(wild, other)), local); pid != other {
		t.Fatalf("udp, self then other: %d; want %d", pid, other)
	}
	if pid := udpLookup(mibTable(udpRow(wild, other), udpRow(wild, self)), local); pid != other {
		t.Fatalf("udp, other then self: %d; want %d", pid, other)
	}
	// alone on the port, the engine's wildcard socket is the engine's
	if pid := udpLookup(mibTable(udpRow(wild, self)), local); pid != self {
		t.Fatalf("udp, self only: %d; want %d", pid, self)
	}
}
