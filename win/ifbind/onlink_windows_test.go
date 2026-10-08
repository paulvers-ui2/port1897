// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package ifbind

import (
	"net"
	"net/netip"
	"testing"
)

// OnLink: loopback and link-local always; public and unspecified addresses
// never; this machine's own IPv4 addresses (on up interfaces) always.
func TestOnLink(t *testing.T) {
	b := New(0)
	for _, c := range []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:5400", true},
		{"127.0.0.1", true},
		{"[::1]:53", true},
		{"169.254.10.20:53", true},
		{"8.8.8.8:53", false},
		{"1.1.1.1", false},
		{"0.0.0.0:53", false},
		{":53", false},
		{"224.0.0.251:5353", false},
		{"dns.google:443", false},
	} {
		if got := b.OnLink(c.addr); got != c.want {
			t.Errorf("OnLink(%q) = %t, want %t", c.addr, got, c.want)
		}
	}

	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(n.IP)
			if !ok || !ip.Unmap().Is4() || ip.Unmap().IsLinkLocalUnicast() {
				continue
			}
			got := b.OnLink(netip.AddrPortFrom(ip.Unmap(), 53).String())
			t.Logf("#%d %q %s: OnLink %t", ifc.Index, ifc.Name, ip, got)
			if !got {
				t.Errorf("own address %s on %q is not on-link", ip, ifc.Name)
			}
		}
	}
}
