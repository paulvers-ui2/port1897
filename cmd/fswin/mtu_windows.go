// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/celzero/firestack/intra"
	"github.com/celzero/firestack/win/ifbind"
)

// MTUs, from the network this PC is on to the AuroraVPN adapter:
//
//	link     the IP MTU of the interface fswin's own traffic leaves by:
//	         Ethernet and Wi-Fi 1500, PPPoE 1492, some mobile, satellite
//	         and nested-VPN links less. firestack's WireGuard sizes its
//	         packets to fit it, so they are not fragmented or dropped.
//	exit     the largest packet the exit carries inside its tunnel.
//	adapter  the smaller of the two: programs size their UDP (QUIC, calls,
//	         games) and TCP segments to it, so their packets fit the exit
//	         instead of being dropped inside it.
//
// It used to be 1500 for the adapter and the link whatever the network and
// the exit: a WireGuard exit on a PPPoE line sent packets too big for it,
// and a 1350-byte QUIC packet did not fit WARP's 1280.
const (
	// WireGuard's overhead over IPv6 (40 IP + 8 UDP + 32 WireGuard); over
	// IPv4 it is 60. wg-quick and firestack reserve 80 either way.
	wgOverhead = 80
	// IPv6's minimum MTU: no MTU here goes below it.
	minMTU = 1280
	// internet paths carry 1500 at most, whatever a LAN's jumbo frames
	maxMTU = 1500
	// Cloudflare WARP's tunnel MTU, over WireGuard and over MASQUE
	warpMTU = 1280
)

type mtuPlan struct {
	Link    int    `json:"link"`
	Exit    int    `json:"exit"`
	Adapter int    `json:"adapter"`
	Auto    bool   `json:"auto"` // false: the adapter's was set with -mtu
	Why     string `json:"why"` // what it comes from: "Wi-Fi 1500, WireGuard 1420"
	exitWhy string // the exit's part of Why: ", WireGuard 1420"
}

// String is the plan for the log.
func (p *mtuPlan) String() string {
	how := "automatic"
	if !p.Auto {
		how = "set by hand"
	}
	return fmt.Sprintf("adapter %d (%s), from %s", p.Adapter, how, p.Why)
}

// curMTU is the plan in use, for /api/status.
var curMTU atomic.Pointer[mtuPlan]

// linkMTU is the IP MTU of the default interface other than skip (the
// AuroraVPN adapter), within [minMTU, maxMTU]; maxMTU when it is unknown.
func linkMTU(skip uint32) (int, string) {
	m, idx := ifbind.LinkMTU(skip)
	if m == 0 {
		return maxMTU, "network MTU unknown, so 1500"
	}
	name, _, _ := ifbind.Describe(idx)
	return clampMTU(int(m)), fmt.Sprintf("%s %d", name, m)
}

// parseMTU reads an MTU: 16 bits at most, as in an IP header, so it fits
// whatever it is converted to (the adapter's MTU is a uint32).
func parseMTU(v string) (int, error) {
	m, err := strconv.ParseUint(strings.TrimSpace(v), 10, 16)
	return int(m), err
}

func clampMTU(m int) int {
	return min(max(m, minMTU), maxMTU)
}

// planMTU works out the MTUs for exit exitID (with its config cfg, or usque
// setup us) over a link of MTU link. adapter > 0 is the -mtu flag.
func planMTU(link int, linkWhy, exitID, cfg string, us *usqueSetup, adapter int) mtuPlan {
	p := mtuPlan{Link: link, Exit: link, Auto: adapter <= 0}
	why := ""
	switch exitID {
	case exitWG, exitWarp:
		// firestack takes a WireGuard config's mtu as the packet size on the
		// link and keeps wgOverhead of it (see wgQuickToUAPI); without one,
		// it fits the link
		inner := link - wgOverhead
		if m := uapiMTU(cfg); m > 0 && m-wgOverhead < inner {
			inner = m - wgOverhead
		}
		p.Exit = inner // what firestack uses, even under minMTU on a tiny link
		why += fmt.Sprintf(", WireGuard %d", p.Exit)
	case exitMasque:
		p.Exit = flagInt(us, warpMTU, "-m", "--mtu")
		why += fmt.Sprintf(", WARP (MASQUE) %d", p.Exit)
	case exitChain:
		// the chain's packets leave through WARP2: its MTU is the limit
		// (usque fits WARP1 and wg0 under it)
		p.Exit = flagInt(us, warpMTU, "--exit-mtu")
		why += fmt.Sprintf(", WARP chain exit %d", p.Exit)
	}
	p.Adapter = clampMTU(adapter) // by hand: still 1280 to 1500
	if p.Auto {
		p.Adapter = clampMTU(min(p.Exit, link))
	}
	p.exitWhy = why
	p.Why = linkWhy + why
	return p
}

// uapiMTU is the mtu line of a firestack WireGuard config: 0 when there is
// none, or it is "auto".
func uapiMTU(cfg string) int {
	for line := range strings.Lines(cfg) {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "mtu="); ok {
			if m, err := parseMTU(v); err == nil && m > 0 {
				return m
			}
		}
	}
	return 0
}

// flagInt is the value of the first of names among us's extra usque flags
// ("-m 1300", "--mtu=1300"), or dflt.
func flagInt(us *usqueSetup, dflt int, names ...string) int {
	if us == nil {
		return dflt
	}
	f := us.extra
	for i, a := range f {
		for _, n := range names {
			v, ok := "", false
			if a == n && i+1 < len(f) {
				v, ok = f[i+1], true
			} else if after, found := strings.CutPrefix(a, n+"="); found {
				v, ok = after, true
			}
			if m, err := parseMTU(v); ok && err == nil && m > 0 {
				return m
			}
		}
	}
	return dflt
}

// watchLinkMTU follows the link's MTU as the PC changes networks (Wi-Fi to
// a phone's hotspot, or another VPN coming up under ours) and tells
// firestack, until done closes.
func watchLinkMTU(t intra.Tunnel, skip uint32, done <-chan struct{}) {
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return
		case <-tick.C:
		}
		m, why := linkMTU(skip)
		p := curMTU.Load()
		if p == nil || m == p.Link {
			continue
		}
		np := *p
		np.Link = m
		np.Why = why + p.exitWhy + fmt.Sprintf(" (the adapter keeps %d until protection restarts)", p.Adapter)
		curMTU.Store(&np)
		t.SetLinkMtu(m)
		fmt.Printf("fswin: network MTU now %s\n", why)
	}
}
