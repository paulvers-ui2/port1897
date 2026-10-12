// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"sort"
	"strings"
	"testing"
)

// lookup is the engine's asnLookup (asn_windows.go), copied so the generator
// output is checked the way fswin reads it.
func lookup(db []byte, keyLen int, ip netip.Addr) uint32 {
	ip = ip.Unmap()
	var key []byte
	if keyLen == 4 {
		a := ip.As4()
		key = a[:]
	} else {
		a := ip.As16()
		key = a[:]
	}
	size := keyLen + 4
	if len(db) < size {
		return 0
	}
	i := sort.Search(len(db)/size, func(i int) bool {
		return bytes.Compare(db[i*size:i*size+keyLen], key) > 0
	})
	if i == 0 {
		return 0
	}
	return binary.BigEndian.Uint32(db[i*size-4 : i*size])
}

func TestParse(t *testing.T) {
	const tsv = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n" +
		"1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n" +
		"2.0.0.0\t2.255.255.255\t3215\tFR\tAS3215\n" +
		"bad line\n" +
		"2001:db8::\t2001:db8::ffff\t64500\tZZ\tdoc\n" // v6, must be skipped for v4
	ranges, err := parse(strings.NewReader(tsv), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 3 {
		t.Fatalf("parsed %d v4 ranges, want 3: %+v", len(ranges), ranges)
	}
	if ranges[0].asn != 13335 || ranges[2].asn != 3215 {
		t.Errorf("ASNs = %d, %d; want 13335, 3215", ranges[0].asn, ranges[2].asn)
	}
}

func TestBuildAndLookup(t *testing.T) {
	ranges := []rng{
		{netip.MustParseAddr("2.0.0.0"), netip.MustParseAddr("2.255.255.255"), 3215},
		{netip.MustParseAddr("1.0.0.0"), netip.MustParseAddr("1.0.0.255"), 13335}, // out of order on purpose
	}
	db := build(ranges, 4)
	for ip, want := range map[string]uint32{
		"1.0.0.0":   13335,
		"1.0.0.255": 13335,
		"1.0.1.0":   0, // gap between the two ranges
		"1.255.0.0": 0,
		"2.0.0.1":   3215,
		"0.1.2.3":   0, // before the first range
		"3.0.0.0":   0, // after the last range
	} {
		if got := lookup(db, 4, netip.MustParseAddr(ip)); got != want {
			t.Errorf("lookup(%s) = %d, want %d", ip, got, want)
		}
	}
	// records must be ascending and a whole number of 8-byte records
	if len(db)%8 != 0 {
		t.Fatalf("db is %d bytes, not a whole number of 8-byte records", len(db))
	}
	for i := 8; i < len(db); i += 8 {
		if bytes.Compare(db[i-8:i-4], db[i:i+4]) >= 0 {
			t.Fatalf("record %d is not after the one before it", i/8)
		}
	}
}

func TestBuildDropsOverlap(t *testing.T) {
	ranges := []rng{
		{netip.MustParseAddr("1.0.0.0"), netip.MustParseAddr("1.0.0.255"), 100},
		{netip.MustParseAddr("1.0.0.128"), netip.MustParseAddr("1.0.0.200"), 200}, // overlaps the first
	}
	db := build(ranges, 4)
	if got := lookup(db, 4, netip.MustParseAddr("1.0.0.150")); got != 100 {
		t.Errorf("overlapping range: lookup = %d, want 100 (first range kept)", got)
	}
}
