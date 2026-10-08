// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/win/wfp"
)

const (
	tcp  = 6
	udp  = 17
	icmp = 1
)

func mustRules(t *testing.T, rs ruleSet) *rules {
	t.Helper()
	r, err := compileRules(rs)
	if err != nil {
		t.Fatalf("compileRules: %v", err)
	}
	return r
}

// "Allow outgoing only" lets every program connect out, even with the
// universal rules that would block it, but never overrides what the user
// chose for an app, the global IP and domain rules, Lockdown or "PC locked".
func TestOutgoingOnly(t *testing.T) {
	now := time.Now()
	web := netip.MustParseAddrPort("93.184.215.14:443")
	strict := universalRules{UDP: true, ICMP: true, HTTP: true, Unknown: true, DNSBypass: true, NewApps: true, OutgoingOnly: true}
	cases := []struct {
		name      string
		rs        ruleSet
		protocol  int32
		path      string
		dst       netip.AddrPort
		domains   []string
		wantBlock bool
		wantWhy   string
	}{
		{"a new app, every universal block on", ruleSet{Universal: strict}, tcp, `C:\new\app.exe`, web, nil, false, ruleOutgoingAllowed},
		{"an unknown program", ruleSet{Universal: strict}, tcp, "", web, nil, false, ruleOutgoingAllowed},
		{"UDP, ping and port 80", ruleSet{Universal: strict}, udp, `C:\a.exe`, netip.MustParseAddrPort("1.1.1.1:443"), nil, false, ruleOutgoingAllowed},
		{"ping", ruleSet{Universal: strict}, icmp, `C:\a.exe`, netip.MustParseAddrPort("1.1.1.1:0"), nil, false, ruleOutgoingAllowed},
		{"an app the user blocked", ruleSet{Universal: strict, Apps: map[string]appRule{"app.exe": {Mode: modeBlock}}}, tcp, `C:\x\app.exe`, web, nil, true, "app blocked"},
		{"an isolated app", ruleSet{Universal: strict, Apps: map[string]appRule{"app.exe": {Mode: modeIsolate}}}, tcp, `C:\x\app.exe`, web, nil, true, "app isolated"},
		{"a blocked domain", ruleSet{Universal: strict, Domains: []domainRule{{Domain: "ads.example", Action: actBlock}}}, tcp, `C:\a.exe`, web, []string{"ads.example"}, true, "domain rule ads.example"},
		{"a blocked IP", ruleSet{Universal: strict, IPs: []ipRule{{IP: "93.184.215.14", Action: actBlock}}}, tcp, `C:\a.exe`, web, nil, true, "IP rule 93.184.215.14"},
		{"lockdown still wins", ruleSet{Universal: universalRules{OutgoingOnly: true, Lockdown: true}}, tcp, `C:\a.exe`, web, nil, true, "universal: lockdown"},
		{"off: the universal rules apply again", ruleSet{Universal: universalRules{NewApps: true}}, tcp, `C:\new\app.exe`, web, nil, true, "universal: new app"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := mustRules(t, c.rs)
			d := r.decide(c.protocol, c.path, false, c.dst, c.domains, now)
			if d.block != c.wantBlock {
				t.Errorf("block = %t (%s), want %t", d.block, d.why, c.wantBlock)
			}
			if c.wantWhy != "" && d.why != c.wantWhy {
				t.Errorf("why = %q, want %q", d.why, c.wantWhy)
			}
		})
	}

	// "PC locked" needs the screen locked too
	r := mustRules(t, ruleSet{Universal: universalRules{OutgoingOnly: true, Locked: true}, ScreenLocked: true})
	if d := r.decide(tcp, `C:\a.exe`, false, web, nil, now); !d.block || d.why != "universal: PC locked" {
		t.Errorf("locked PC: %+v, want blocked by universal: PC locked", d)
	}
}

// Incoming connections are refused with "Allow outgoing only", except while
// protection is paused, and journaled as blocked flows.
func TestInflowWithOutgoingOnly(t *testing.T) {
	b := newTestBridge(t, "")
	src, dst := x.StrOf("203.0.113.5:4444"), x.StrOf("10.111.222.1:8080")

	if m := b.Inflow(tcp, -1, src, dst); m.PIDCSV != x.Base {
		t.Errorf("default: Inflow = %q, want %q", m.PIDCSV, x.Base)
	}

	if err := b.setRules(ruleSet{Universal: universalRules{OutgoingOnly: true}}); err != nil {
		t.Fatal(err)
	}
	flows, blocked := b.log.flows.Load(), b.log.flowsBlocked.Load()
	m := b.Inflow(tcp, -1, src, dst)
	if m.PIDCSV != x.Block {
		t.Errorf("outgoing only: Inflow = %q, want %q", m.PIDCSV, x.Block)
	}
	if b.log.flows.Load() != flows+1 || b.log.flowsBlocked.Load() != blocked+1 {
		t.Errorf("counters: flows %d -> %d, blocked %d -> %d; want +1 each", flows, b.log.flows.Load(), blocked, b.log.flowsBlocked.Load())
	}
	ev := eventsOf(b, "flow")
	if len(ev) == 0 {
		t.Fatal("no flow event for the blocked incoming connection")
	}
	e := ev[len(ev)-1]
	if !e.Blocked || e.Rule != "universal: incoming blocked" || e.Dst != "203.0.113.5:4444" || e.Proto != "tcp in" {
		t.Errorf("event = %+v; want blocked, rule universal: incoming blocked, the remote address, proto \"tcp in\"", e)
	}

	paused := time.Now().Add(time.Hour).UnixMilli()
	if err := b.setRules(ruleSet{Universal: universalRules{OutgoingOnly: true}, PausedUntil: paused}); err != nil {
		t.Fatal(err)
	}
	if m := b.Inflow(tcp, -1, src, dst); m.PIDCSV != x.Base {
		t.Errorf("paused: Inflow = %q, want %q", m.PIDCSV, x.Base)
	}
}

// The kill switch button: refused when only DNS goes through the tunnel,
// and safe to call without a Wintun adapter or when already off. (Turning it
// on for real needs admin rights; tools/sim covers that.)
func TestKillSwitchGuards(t *testing.T) {
	var none *killSwitch
	if err := none.set(true, false); !errors.Is(err, errNoKillSwitch) {
		t.Errorf("nil kill switch: set(true) = %v, want errNoKillSwitch", err)
	}
	if none.isOn() {
		t.Error("nil kill switch reports on")
	}

	dnsOnly := newKillSwitch(wfp.Options{}, false)
	if err := dnsOnly.set(true, false); !errors.Is(err, errKillNeedsFull) {
		t.Errorf("DNS-only: set(true) = %v, want errKillNeedsFull", err)
	}
	if dnsOnly.isOn() {
		t.Error("DNS-only kill switch turned on")
	}
	if err := dnsOnly.set(false, false); err != nil {
		t.Errorf("turning off a kill switch that is off: %v", err)
	}

	b := newTestBridge(t, "")
	if st := statusOf(b, options{}, time.Now(), "", "test"); st.Kill {
		t.Error("status says the kill switch is on with no kill switch")
	}
}
