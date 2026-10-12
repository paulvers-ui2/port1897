// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	x "github.com/celzero/firestack/intra/backend"
)

// Addresses with a known country in the embedded tables (geoip_windows_test.go).
var (
	inUS = netip.MustParseAddrPort("8.8.8.8:443")
	inRU = netip.MustParseAddrPort("95.173.136.70:443")
	inNL = netip.MustParseAddrPort("185.15.59.224:443")
	inIE = netip.MustParseAddrPort("[2a00:1450:4001:80b::200e]:443")
	lan  = netip.MustParseAddrPort("192.168.1.10:445")
)

// Country and network blocks come first: no app mode, trust rule or pause
// lets a connection into a blocked place.
func TestGeoBlocks(t *testing.T) {
	now := time.Now()
	paused := now.Add(time.Hour).UnixMilli()
	cases := []struct {
		name      string
		rs        ruleSet
		path      string
		dst       netip.AddrPort
		wantBlock bool
		wantWhy   string
	}{
		{"a blocked country", ruleSet{Universal: universalRules{Countries: []string{"RU"}}}, `C:\a.exe`, inRU, true, "country: RU blocked"},
		{"lowercase codes count", ruleSet{Universal: universalRules{Countries: []string{" ru "}}}, `C:\a.exe`, inRU, true, "country: RU blocked"},
		{"another country", ruleSet{Universal: universalRules{Countries: []string{"RU"}}}, `C:\a.exe`, inUS, false, ""},
		{"IPv6", ruleSet{Universal: universalRules{Countries: []string{"IE"}}}, `C:\a.exe`, inIE, true, "country: IE blocked"},
		{"the LAN is never blocked", ruleSet{Universal: universalRules{Countries: []string{"US"}, CountriesAllowOnly: true}}, `C:\a.exe`, lan, false, ""},
		{"allow only: listed", ruleSet{Universal: universalRules{Countries: []string{"NL"}, CountriesAllowOnly: true}}, `C:\a.exe`, inNL, false, ""},
		{"allow only: not listed", ruleSet{Universal: universalRules{Countries: []string{"NL"}, CountriesAllowOnly: true}}, `C:\a.exe`, inUS, true, "country: US not allowed"},
		{"allow only with no countries blocks nothing", ruleSet{Universal: universalRules{CountriesAllowOnly: true}}, `C:\a.exe`, inUS, false, ""},
		{"a bypassed app", ruleSet{Universal: universalRules{Countries: []string{"RU"}}, Apps: map[string]appRule{"a.exe": {Mode: modeBypass}}}, `C:\a.exe`, inRU, true, "country: RU blocked"},
		{"an excluded app", ruleSet{Universal: universalRules{Countries: []string{"RU"}}, Apps: map[string]appRule{"a.exe": {Mode: modeExclude}}}, `C:\a.exe`, inRU, true, "country: RU blocked"},
		{"a trusted IP", ruleSet{Universal: universalRules{Countries: []string{"RU"}}, IPs: []ipRule{{IP: "95.173.136.70", Action: actTrust}}}, `C:\a.exe`, inRU, true, "country: RU blocked"},
		{"paused", ruleSet{Universal: universalRules{Countries: []string{"RU"}}, PausedUntil: paused}, `C:\a.exe`, inRU, true, "country: RU blocked"},
		{"a blocked network", ruleSet{Universal: universalRules{ASNs: []asnRule{{ASN: 15169, Name: "GOOGLE", Prefixes: []string{"8.8.8.0/24"}}}}}, `C:\a.exe`, inUS, true, "network: AS15169 GOOGLE blocked"},
		{"a network's IPv6 range", ruleSet{Universal: universalRules{ASNs: []asnRule{{ASN: 15169, Prefixes: []string{"2a00:1450::/32"}}}}}, `C:\a.exe`, inIE, true, "network: AS15169 blocked"},
		{"outside the network", ruleSet{Universal: universalRules{ASNs: []asnRule{{ASN: 15169, Prefixes: []string{"8.8.4.0/24"}}}}}, `C:\a.exe`, inUS, false, ""},
		{"an unparsable address skips them", ruleSet{Universal: universalRules{Countries: []string{"US"}, CountriesAllowOnly: true}}, `C:\a.exe`, netip.AddrPort{}, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := mustRules(t, c.rs)
			d := r.decide(tcp, c.path, true, c.dst, nil, now)
			if d.block != c.wantBlock {
				t.Errorf("block = %t (%s), want %t", d.block, d.why, c.wantBlock)
			}
			if d.why != c.wantWhy && c.wantBlock {
				t.Errorf("why = %q, want %q", d.why, c.wantWhy)
			}
		})
	}
}

// Bad entries are skipped with a warning; the good ones still apply.
func TestGeoRulesCheckInput(t *testing.T) {
	r, err := compileRules(ruleSet{Universal: universalRules{
		Countries: []string{"RU", "USA", "1A", ""},
		ASNs: []asnRule{
			{ASN: 0, Prefixes: []string{"1.0.0.0/24"}},
			{ASN: 64500, Prefixes: []string{"nope", "0.0.0.0/0", "::/0", "1.0.0.0/4", "::ffff:95.173.136.0/120"}},
		},
	}})
	if err == nil {
		t.Fatal("no warnings for bad countries and ranges")
	}
	for _, want := range []string{`"USA"`, `"1A"`, "no AS number", "nope", "0.0.0.0/0 too wide", "::/0 too wide", "1.0.0.0/4 too wide"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("warnings %q lack %q", err, want)
		}
	}
	if !r.geo.countries["RU"] || len(r.geo.countries) != 1 {
		t.Errorf("countries = %v, want RU only", r.geo.countries)
	}
	// an IPv4-in-IPv6 range counts as the IPv4 one
	if asn, ok := r.geo.asnOf(inRU.Addr()); !ok || asn != 64500 {
		t.Errorf("::ffff:95.173.136.0/120 does not cover 95.173.136.70: AS%d %t", asn, ok)
	}
	if len(r.geo.v6) != 0 {
		t.Errorf("v6 ranges = %d, want 0", len(r.geo.v6))
	}
}

// Overlapping and nested ranges are joined, so the binary search finds
// every address in any of them.
func TestASNRangesMerge(t *testing.T) {
	r := mustRules(t, ruleSet{Universal: universalRules{ASNs: []asnRule{
		{ASN: 1, Prefixes: []string{"10.0.0.0/8", "203.0.113.0/25", "203.0.113.128/25", "198.51.100.0/24"}},
		{ASN: 2, Prefixes: []string{"198.51.100.64/26", "192.0.2.0/24"}},
	}}})
	// 10/8, 192.0.2/24, 198.51.100/24 (with the /26 in it), and the two
	// halves of 203.0.113/24, which touch but do not overlap
	if len(r.geo.v4) != 5 {
		t.Errorf("v4 ranges = %d, want 5", len(r.geo.v4))
	}
	// 10/8 is private: never blocked, however it is listed
	for ip, want := range map[string]bool{
		"10.1.2.3":       false,
		"198.51.100.1":   true,
		"198.51.100.100": true,
		"198.51.100.255": true,
		"198.51.101.0":   false,
		"192.0.2.9":      true,
		"203.0.113.0":    true,
		"203.0.113.255":  true,
		"203.0.114.0":    false,
		"1.1.1.1":        false,
	} {
		if got, _ := r.geo.verdict(netip.MustParseAddr(ip)); got != want {
			t.Errorf("%s: block = %t, want %t", ip, got, want)
		}
	}
}

// DNS answers that point into a blocked place are re-answered by BlockAll,
// and the DNS log says why.
func TestGeoBlocksDNSAnswers(t *testing.T) {
	b := newTestBridge(t, "")
	if err := b.setRules(ruleSet{Universal: universalRules{Countries: []string{"RU"}}}); err != nil {
		t.Fatal(err)
	}
	smm := &x.DNSSummary{QName: "example.ru"}
	if o := b.OnUpstreamAnswer(smm, x.StrOf("95.173.136.70")); o == nil || o.TIDCSV != x.BlockAll {
		t.Fatalf("answer in RU: %+v, want BlockAll", o)
	}
	if why := b.dnsWhy.get("example.ru"); !strings.Contains(why, "country: RU blocked") {
		t.Errorf("why = %q", why)
	}
	if o := b.OnUpstreamAnswer(smm, x.StrOf("8.8.8.8,[2a00:1450:4001:80b::200e]:443")); o != nil {
		t.Errorf("answer elsewhere: %+v, want it kept", o)
	}
	// any blocked address in the answer blocks it
	if o := b.OnUpstreamAnswer(smm, x.StrOf("8.8.8.8,95.173.136.70")); o == nil || o.TIDCSV != x.BlockAll {
		t.Errorf("mixed answer: %+v, want BlockAll", o)
	}
	// blocklists answer 0.0.0.0: not a place
	if o := b.OnUpstreamAnswer(smm, x.StrOf("0.0.0.0,::")); o != nil {
		t.Errorf("unspecified answer: %+v, want it kept", o)
	}
}

// The app sends only a network's number: fswin looks its ranges up, keeps
// them on disk, applies them once they arrive, and reports them in the
// status; a failed lookup is reported too and not retried at once.
func TestASNLookup(t *testing.T) {
	asns.mu.Lock()
	dir, entries, failed, errs, fetch := asns.dir, asns.entries, asns.failed, asns.errs, asns.fetch
	t.Cleanup(func() {
		asns.mu.Lock()
		asns.dir, asns.entries, asns.failed, asns.errs, asns.busy, asns.fetch = dir, entries, failed, errs, false, fetch
		asns.mu.Unlock()
	})
	asns.entries, asns.failed, asns.errs = map[uint32]*asnEntry{}, map[uint32]time.Time{}, map[uint32]string{}
	asns.mu.Unlock()
	asns.setDir(t.TempDir())
	calls := make(chan uint32, 8)
	asns.fetch = func(_ context.Context, asn uint32) (*asnEntry, error) {
		calls <- asn
		if asn == 64502 {
			return nil, errors.New("AS64502 announces no address ranges")
		}
		return &asnEntry{Name: "EXAMPLE-NET", Prefixes: []string{"95.173.136.0/24"}, At: time.Now().UnixMilli()}, nil
	}

	b := newTestBridge(t, "")
	if err := b.setRules(ruleSet{Universal: universalRules{ASNs: []asnRule{{ASN: 64501}, {ASN: 64502}}}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if block, _ := b.rules.Load().geo.verdict(inRU.Addr()); block {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("AS64501's ranges never applied")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if d := b.decide(tcp, `C:\a.exe`, inRU, nil); d.why != "network: AS64501 EXAMPLE-NET blocked" {
		t.Errorf("why = %q", d.why)
	}
	// wait for the failed lookup too, then check the status
	for len(calls) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	st := asns.states(b.rules.Load().u.ASNs)
	if len(st) != 2 || st[0].Ranges != 1 || st[0].Name != "EXAMPLE-NET" || st[1].Ranges != 0 || st[1].Error == "" {
		t.Errorf("states = %+v", st)
	}
	// kept on disk: a fresh table reads them back
	asns.mu.Lock()
	asns.entries = map[uint32]*asnEntry{}
	asns.mu.Unlock()
	if e := asns.get(64501); e == nil || len(e.Prefixes) != 1 {
		t.Errorf("from disk: %+v", e)
	}
	// nothing due: fetched now, or failed now
	if due := asns.due([]uint32{64501, 64502}, time.Now()); len(due) != 0 {
		t.Errorf("due = %v, want none", due)
	}
	if due := asns.due([]uint32{64502}, time.Now().Add(asnRetry+time.Minute)); len(due) != 1 {
		t.Errorf("due after the retry wait = %v, want AS64502", due)
	}
}

// Rule changes close open connections into newly blocked places.
func TestGeoFlowBlocked(t *testing.T) {
	b := newTestBridge(t, "")
	if err := b.setRules(ruleSet{Universal: universalRules{Countries: []string{"RU"}}}); err != nil {
		t.Fatal(err)
	}
	m := b.Flow(tcp, -1, x.StrOf("10.111.222.2:5000"), x.StrOf("95.173.136.70:443"), nil, nil, nil, nil)
	if m.PIDCSV != x.Block {
		t.Errorf("Flow to RU = %q, want %q", m.PIDCSV, x.Block)
	}
	ev := eventsOf(b, "flow")
	if len(ev) == 0 || ev[len(ev)-1].Rule != "country: RU blocked" || ev[len(ev)-1].Country != "RU" {
		t.Errorf("events = %+v", ev)
	}
}
