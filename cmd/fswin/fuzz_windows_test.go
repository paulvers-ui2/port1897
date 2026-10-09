// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"
)

// Fuzz tests: whatever arrives, the engine must not crash. `go test` runs
// the seeds below; the Simulate workflow also fuzzes each one for a while
// (go test -fuzz), and a crasher it finds lands in testdata/fuzz as a seed.

// FuzzRules feeds rule sets, as POST /api/rules and rules.json carry them,
// through compileRules and the decisions made for every connection and
// DNS lookup.
func FuzzRules(f *testing.F) {
	f.Add([]byte(`{}`), "chrome.exe", "1.2.3.4:443", "example.com", 1)
	f.Add([]byte(`{"apps":{"chrome.exe":{"mode":"block"}},"ips":[{"app":"chrome.exe","ip":"1.2.3.0/24","port":443,"action":"block"},{"ip":"*","action":"trust"},{"ip":"10.0.0.*","action":"block"}],"domains":[{"domain":"*.example.com","action":"block"},{"app":"x.exe","domain":"a.b","action":"trust"}],"universal":{"udp":true,"icmp":true,"http":true,"unknown":true,"dnsBypass":true,"newApps":true,"lockdown":true,"outgoingOnly":true},"known":["C:\\a.exe"],"dnsTypes":[1,28],"pausedUntil":1}`),
		`C:\Program Files\x.exe`, "[2001:db8::1]:53", "sub.example.com.", 28)
	f.Add([]byte(`{"ips":[{"ip":"::/0","port":-1,"action":"x"}],"domains":[{"domain":"*.","action":"block"},{"domain":"","action":"trust"}]}`), "", "0.0.0.0:0", "*", 65535)
	f.Fuzz(func(t *testing.T, raw []byte, app, dst, domain string, qtype int) {
		var rs ruleSet
		if json.Unmarshal(raw, &rs) != nil {
			return
		}
		r, err := compileRules(rs)
		if err != nil {
			return
		}
		d, err := netip.ParseAddrPort(dst)
		if err != nil {
			d = netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
		}
		now := time.Now()
		for _, p := range []int32{tcp, udp, icmp} {
			r.decide(p, app, true, d, []string{domain}, now)
			r.decide(p, app, false, d, nil, now)
		}
		r.dnsVerdict(domain, qtype, now.UnixMilli())
		r.app(app)
		r.knownApp(app)
	})
}

// FuzzCountry looks up any address in the embedded geo-IP tables, whose
// binary search reads fixed-size records.
func FuzzCountry(f *testing.F) {
	for _, s := range []string{"1.1.1.1", "0.0.0.0", "255.255.255.255", "::", "2001:db8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::ffff:8.8.8.8"} {
		a := netip.MustParseAddr(s)
		f.Add(a.AsSlice())
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		ip, ok := netip.AddrFromSlice(b)
		if !ok {
			return
		}
		if c := country(ip); c != "" && (len(c) != 2 || c[0] < 'A' || c[0] > 'Z' || c[1] < 'A' || c[1] > 'Z') {
			t.Fatalf("country(%v) = %q", ip, c)
		}
	})
}
