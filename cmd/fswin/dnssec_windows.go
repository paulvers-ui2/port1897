// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2025 RethinkDNS and its authors
//     Licensed under the Apache License, Version 2.0
//     (DnsSecGuard.kt in the Rethink / AuroraVPN Android app)

//go:build windows

package main

import (
	"net/netip"
	"strings"
)

// The DNSSEC switch, ported from the Android app's DnsSecGuard: answers that
// put a public name on a bogon address (private, loopback, link-local,
// CGNAT, TEST-NET, benchmarking, multicast, ULA, 6to4, Teredo...) are a
// classic sign of DNS poisoning, and the way DNS rebinding attacks reach
// local devices, so they are blocked. Answers without DNSSEC proof (AD bit)
// are only marked: most domains are not signed, and blocking them all, as
// the Android setting's wording suggests, would break most sites.

var bogons = func() (out []netip.Prefix) {
	for _, p := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
		"::1/128", "fe80::/10", "fc00::/7", "2001:db8::/32", "2002::/16",
		"2001::/32", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(p))
	}
	return
}()

// localSuffixes resolve to local addresses by design.
var localSuffixes = []string{
	".lan", ".local", ".internal", ".home", ".home.arpa", ".localdomain",
	".localhost", ".corp", ".intranet", ".private", ".arpa",
}

// isLocalName reports names that may legitimately answer with private
// addresses: single-label names and local or reverse-lookup zones.
func isLocalName(qname string) bool {
	n := strings.ToLower(strings.TrimSuffix(qname, "."))
	if n == "" || !strings.Contains(n, ".") {
		return true
	}
	for _, s := range localSuffixes {
		if strings.HasSuffix(n, s) {
			return true
		}
	}
	return false
}

// bogonsIn returns the bogon addresses in a csv of answer IPs. Unspecified
// addresses (0.0.0.0, ::) are how blocklists answer, not poisoning.
func bogonsIn(csv string) (out []string) {
	for _, s := range strings.Split(csv, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if ap, err := netip.ParseAddrPort(s); err == nil {
			s = ap.Addr().String()
		}
		ip, err := netip.ParseAddr(strings.Trim(s, "[]"))
		if err != nil || ip.IsUnspecified() {
			continue
		}
		ip = ip.Unmap()
		for _, p := range bogons {
			if p.Contains(ip) {
				out = append(out, ip.String())
				break
			}
		}
	}
	return
}
