// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package ifbind

import (
	"net/netip"
	"time"

	"golang.org/x/sys/windows"
)

// OnLink reports whether addr (an ip or ip:port) is this machine or sits on
// a network attached to an interface other than the tunnel. Such traffic
// never takes the default route, so it cannot loop into the tunnel and
// needs no pinning; pinning it to the default interface breaks it: a
// loopback destination fails with WSAEADDRNOTAVAIL, and a host on another
// adapter (a Hyper-V switch, a second NIC) is sent out the wrong one.
func (b *Binder) OnLink(addr string) bool {
	ip, ok := parseIP(addr)
	if !ok || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	for _, p := range b.onlink() {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func parseIP(addr string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return ap.Addr().Unmap(), true
	}
	if ip, err := netip.ParseAddr(addr); err == nil {
		return ip.Unmap(), true
	}
	return netip.Addr{}, false
}

// onlink returns the on-link prefixes of the up interfaces other than the
// tunnel, refreshed at most every few seconds.
func (b *Binder) onlink() []netip.Prefix {
	b.mu.Lock()
	defer b.mu.Unlock()
	if time.Since(b.linkAt) < refresh {
		return b.links
	}
	b.links = onlinkPrefixes(b.skip)
	b.linkAt = time.Now()
	return b.links
}

// Prefixes shorter than these are not taken as on-link: an adapter that
// claims 0.0.0.0/0 would otherwise turn all pinning off.
const (
	minOnLink4 = 8
	minOnLink6 = 16
)

func onlinkPrefixes(skip uint32) (out []netip.Prefix) {
	_ = forEachAdapter(windows.AF_UNSPEC, func(aa *windows.IpAdapterAddresses) bool {
		if aa.OperStatus != windows.IfOperStatusUp || aa.IfIndex == skip || aa.Ipv6IfIndex == skip {
			return true
		}
		for u := aa.FirstUnicastAddress; u != nil; u = u.Next {
			ip, ok := netip.AddrFromSlice(u.Address.IP())
			if !ok {
				continue
			}
			ip = ip.Unmap()
			bits := int(u.OnLinkPrefixLength)
			if (ip.Is4() && bits < minOnLink4) || (ip.Is6() && bits < minOnLink6) || bits > ip.BitLen() {
				continue
			}
			out = append(out, netip.PrefixFrom(ip, bits).Masked())
		}
		return true
	})
	return out
}
