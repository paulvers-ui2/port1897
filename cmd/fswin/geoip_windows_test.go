// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestCountry(t *testing.T) {
	for ip, want := range map[string]string{
		"8.8.8.8":                  "US",
		"::ffff:8.8.8.8":           "US", // IPv4 in IPv6
		"95.173.136.70":            "RU",
		"185.15.59.224":            "NL",
		"2a00:1450:4001:80b::200e": "IE",
		"192.168.1.1":              "", // private: ZZ
		"10.111.222.1":             "",
		"127.0.0.1":                "",
		"0.0.0.0":                  "",
		"255.255.255.255":          "",
		"::1":                      "",
	} {
		if got := country(netip.MustParseAddr(ip)); got != want {
			t.Errorf("country(%s) = %q, want %q", ip, got, want)
		}
	}
	if got := country(netip.Addr{}); got != "" {
		t.Errorf("country of no address = %q", got)
	}
}

// The embedded files are whole: fixed-size records in ascending order.
func TestCountryDatabase(t *testing.T) {
	for _, db := range []struct {
		name string
		data []byte
		key  int
	}{{"dbip.v4", geo4, 4}, {"dbip.v6", geo6, 16}} {
		size := db.key + 2
		if len(db.data) == 0 || len(db.data)%size != 0 {
			t.Fatalf("%s: %d bytes, not a whole number of %d-byte records", db.name, len(db.data), size)
		}
		for i := size; i < len(db.data); i += size {
			if bytes.Compare(db.data[i-size:i-size+db.key], db.data[i:i+db.key]) > 0 {
				t.Fatalf("%s: record %d is out of order", db.name, i/size)
			}
		}
	}
}

func TestAnswerCountry(t *testing.T) {
	for rdata, want := range map[string]string{
		"8.8.8.8,8.8.4.4":          "US",
		"0.0.0.0":                  "", // blocked
		"0.0.0.0,95.173.136.70":    "RU",
		"cname.example.,8.8.8.8":   "US",
		"":                         "",
		"2a00:1450:4001:80b::200e": "IE",
		"not an address":           "",
	} {
		if got := answerCountry(rdata); got != want {
			t.Errorf("answerCountry(%q) = %q, want %q", rdata, got, want)
		}
	}
}
