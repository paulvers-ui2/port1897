// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"net/netip"
	"sort"
)

// IP->ASN, the same shape as the country database (geoip_windows.go): sorted
// fixed-size records of a range's first address and the 4-byte autonomous
// system number that announces it, 0 for private or unrouted ranges. Built
// in CI from iptoasn.com's public-domain data (geoip/README.md). The files
// committed to the repo may be empty in a plain source checkout, so asn
// returns 0 for every address until a release build fills them in.
var (
	//go:embed geoip/asn.v4
	asn4 []byte
	//go:embed geoip/asn.v6
	asn6 []byte
)

// asnValBytes is the width of the value stored after each range's address.
const asnValBytes = 4

// asn returns the autonomous system number that announces ip, or 0 for a
// private, unrouted or invalid address, or when no ASN data is embedded.
func asn(ip netip.Addr) uint32 {
	return asnLookup(asn4, asn6, ip)
}

// asnLookup is asn against the given tables, so a test can pass its own; it
// finds the last range that starts at or below ip, as country does.
func asnLookup(db4, db6 []byte, ip netip.Addr) uint32 {
	ip = ip.Unmap()
	var key []byte
	db := db4
	switch {
	case ip.Is4():
		a := ip.As4()
		key = a[:]
	case ip.Is6():
		a := ip.As16()
		key, db = a[:], db6
	default:
		return 0
	}
	size := len(key) + asnValBytes
	if len(db) < size {
		return 0
	}
	// the first range that starts above ip; ip is in the one before it
	i := sort.Search(len(db)/size, func(i int) bool {
		return bytes.Compare(db[i*size:i*size+len(key)], key) > 0
	})
	if i == 0 {
		return 0
	}
	return binary.BigEndian.Uint32(db[i*size-asnValBytes : i*size])
}
