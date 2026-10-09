// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"strings"
	"testing"
)

const zeroKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func wgConf(t *testing.T, mtuLine string) string {
	t.Helper()
	cfg, err := wgQuickToUAPI("[Interface]\nPrivateKey = " + zeroKey + "\nAddress = 10.2.0.2/32\n" + mtuLine +
		"\n[Peer]\nPublicKey = " + zeroKey + "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\n")
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestWgQuickMTUIsTheTunnelsPacketSize(t *testing.T) {
	// firestack keeps wgOverhead of its mtu for WireGuard: 1420 inside
	// the tunnel is 1500 on the link
	if cfg := wgConf(t, "MTU = 1420"); !strings.Contains(cfg, "mtu=1500\n") {
		t.Fatalf("MTU = 1420 gave\n%s", cfg)
	}
	if cfg := wgConf(t, ""); strings.Contains(cfg, "mtu=") {
		t.Fatalf("no MTU line gave an mtu:\n%s", cfg)
	}
}

func TestPlanMTU(t *testing.T) {
	masque := func(extra ...string) *usqueSetup { return &usqueSetup{extra: extra} }
	for _, c := range []struct {
		name          string
		link          int
		exit, cfg     string
		us            *usqueSetup
		flag          int
		wantExit, adp int
	}{
		{"direct", 1500, "", "", nil, 0, 1500, 1500},
		{"proxy over PPPoE", 1492, exitProxy, "socks5://127.0.0.1:1080", nil, 0, 1492, 1492},
		{"WireGuard, no MTU line", 1500, exitWG, wgConf(t, ""), nil, 0, 1420, 1420},
		{"WireGuard, no MTU line, PPPoE", 1492, exitWG, wgConf(t, ""), nil, 0, 1412, 1412},
		{"WireGuard MTU 1420 over PPPoE: the link wins", 1492, exitWG, wgConf(t, "MTU = 1420"), nil, 0, 1412, 1412},
		{"WireGuard MTU 1300", 1500, exitWG, wgConf(t, "MTU = 1300"), nil, 0, 1300, 1300},
		{"WireGuard on a tiny link: the adapter stays at 1280", 1300, exitWG, wgConf(t, ""), nil, 0, 1220, 1280},
		{"WARP over WireGuard", 1500, exitWarp, "private_key=00\nmtu=1360\n", nil, 0, 1280, 1280},
		{"MASQUE", 1500, exitMasque, "", masque(), 0, 1280, 1280},
		{"MASQUE -m 1350", 1500, exitMasque, "", masque("-s", "a.com", "-m", "1350"), 0, 1350, 1350},
		{"MASQUE --mtu=1400 on a 1380 link", 1380, exitMasque, "", masque("--mtu=1400"), 0, 1400, 1380},
		{"chain --exit-mtu 1300", 1500, exitChain, "", masque("-m", "1400", "--exit-mtu", "1300"), 0, 1300, 1300},
		{"set by hand", 1500, exitWG, wgConf(t, ""), nil, 1400, 1420, 1400},
	} {
		p := planMTU(c.link, "Wi-Fi", c.exit, c.cfg, c.us, c.flag)
		if p.Exit != c.wantExit || p.Adapter != c.adp || p.Link != c.link || p.Auto != (c.flag == 0) {
			t.Errorf("%s: %+v; want exit %d, adapter %d", c.name, p, c.wantExit, c.adp)
		}
		if p.Why == "" {
			t.Errorf("%s: no explanation", c.name)
		}
	}
}

func TestClampMTU(t *testing.T) {
	for in, want := range map[int]int{9000: 1500, 1500: 1500, 1492: 1492, 576: 1280} {
		if got := clampMTU(in); got != want {
			t.Errorf("clampMTU(%d) = %d, want %d", in, got, want)
		}
	}
}
