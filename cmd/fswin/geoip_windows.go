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
	"net/netip"
	"sort"
	"strings"
)

// The Android app's country database (geoip/README.md; geo-IP by db-ip.com,
// CC BY 4.0): sorted fixed-size records of a range's first address and its
// two-letter country code, "ZZ" for private and unassigned ranges.
var (
	//go:embed geoip/dbip.v4
	geo4 []byte
	//go:embed geoip/dbip.v6
	geo6 []byte
)

// country returns the two-letter code of the country ip is in, or "" for a
// private, unassigned or invalid address. As the Android app's CountryMap,
// it looks for the last range that starts at or below ip.
func country(ip netip.Addr) string {
	ip = ip.Unmap()
	var key []byte
	db := geo4
	switch {
	case ip.Is4():
		a := ip.As4()
		key = a[:]
	case ip.Is6():
		a := ip.As16()
		key, db = a[:], geo6
	default:
		return ""
	}
	size := len(key) + 2
	// the first range that starts above ip; ip is in the one before it
	i := sort.Search(len(db)/size, func(i int) bool {
		return bytes.Compare(db[i*size:i*size+len(key)], key) > 0
	})
	if i == 0 {
		return ""
	}
	cc := db[i*size-2 : i*size]
	if cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' || string(cc) == "ZZ" {
		return ""
	}
	return string(cc)
}

// answerCountry is the country of the first address in a DNS answer.
func answerCountry(rdata string) string {
	for _, a := range strings.Split(rdata, ",") {
		if ip, err := netip.ParseAddr(strings.TrimSpace(a)); err == nil && !ip.IsUnspecified() {
			return country(ip)
		}
	}
	return ""
}
