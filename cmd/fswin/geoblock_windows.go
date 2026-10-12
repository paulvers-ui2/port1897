// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"bytes"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Country and network (ASN) blocks: the countries the user picked, by the
// embedded geo-IP tables (geoip_windows.go), and the address ranges each
// network they named announces (looked up by the app window, which hands
// them over with the rules). They are checked before every other rule, for
// every app, even while protection is paused, and on DNS answers too: a
// name that resolves into a blocked country or network gets no answer.

// Limits on what a rule set may carry, so a bad or hostile one cannot make
// the engine build huge tables.
const (
	maxCountries   = 300
	maxASNs        = 1000
	maxASNPrefixes = 500_000 // in all ASNs together
)

type asnRule struct {
	ASN      uint32   `json:"asn"`
	Name     string   `json:"name,omitempty"`
	Prefixes []string `json:"prefixes,omitempty"` // if empty, fswin looks them up
}

func asnNumbers(rs []asnRule) []uint32 {
	out := make([]uint32, 0, len(rs))
	for _, a := range rs {
		if a.ASN != 0 && len(a.Prefixes) == 0 {
			out = append(out, a.ASN)
		}
	}
	return out
}

// ipRange is the addresses lo..hi (inclusive) of one family; v4 uses the
// first 4 bytes.
type ipRange struct {
	lo, hi [16]byte
	asn    uint32
}

// geoBlock is compiled from a rule set; never changed once built.
type geoBlock struct {
	countries map[string]bool
	allowOnly bool      // block every country but these
	v4, v6    []ipRange // sorted, not overlapping
	names     map[uint32]string
}

// cgnat is carrier-grade NAT space: not on the internet, so never in a country.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func compileGeo(u universalRules) (g geoBlock, errs []error) {
	g.allowOnly = u.CountriesAllowOnly
	for _, c := range u.Countries {
		cc := strings.ToUpper(strings.TrimSpace(c))
		if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
			errs = append(errs, fmt.Errorf("country %q: not a two-letter code", c))
			continue
		}
		if g.countries == nil {
			g.countries = map[string]bool{}
		}
		if len(g.countries) >= maxCountries {
			errs = append(errs, fmt.Errorf("countries: more than %d", maxCountries))
			break
		}
		g.countries[cc] = true
	}
	total := 0
	for i, a := range u.ASNs {
		if i >= maxASNs {
			errs = append(errs, fmt.Errorf("networks: more than %d", maxASNs))
			break
		}
		if a.ASN == 0 {
			errs = append(errs, fmt.Errorf("network %q: no AS number", a.Name))
			continue
		}
		// the app sends only the number; fswin looks the ranges up (asn_windows.go)
		prefixes, name := a.Prefixes, a.Name
		if len(prefixes) == 0 {
			if e := asns.get(a.ASN); e != nil {
				prefixes = e.Prefixes
				if name == "" {
					name = e.Name
				}
			}
		}
		if g.names == nil {
			g.names = map[uint32]string{}
		}
		g.names[a.ASN] = cleanName(name)
		for _, s := range prefixes {
			if total >= maxASNPrefixes {
				errs = append(errs, fmt.Errorf("networks: more than %d address ranges", maxASNPrefixes))
				break
			}
			p, err := netip.ParsePrefix(strings.TrimSpace(s))
			if err != nil {
				errs = append(errs, fmt.Errorf("AS%d: %w", a.ASN, err))
				continue
			}
			if a := p.Addr(); a.Is4In6() {
				p = netip.PrefixFrom(a.Unmap(), p.Bits()-96) // invalid if under /96
			}
			p = p.Masked()
			// a range this wide is bad data, not one network
			if !p.IsValid() || (p.Addr().Is4() && p.Bits() < 8) || (p.Addr().Is6() && p.Bits() < 12) {
				errs = append(errs, fmt.Errorf("AS%d: range %s too wide", a.ASN, s))
				continue
			}
			total++
			r := rangeOf(p)
			r.asn = a.ASN
			if p.Addr().Is4() {
				g.v4 = append(g.v4, r)
			} else {
				g.v6 = append(g.v6, r)
			}
		}
	}
	g.v4 = mergeRanges(g.v4, 4)
	g.v6 = mergeRanges(g.v6, 16)
	if n := len(errs); n > 20 {
		errs = append(errs[:20], fmt.Errorf("and %d more", n-20))
	}
	return g, errs
}

// cleanName keeps a network's name short and printable, for the logs.
func cleanName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > 64 {
		s = string(r[:64])
	}
	return s
}

func rangeOf(p netip.Prefix) (r ipRange) {
	b := p.Addr().AsSlice()
	copy(r.lo[:], b)
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	copy(r.hi[:], b)
	return r
}

// mergeRanges sorts rs and joins the ones that overlap; the first one's
// network names the joined range.
func mergeRanges(rs []ipRange, n int) []ipRange {
	slices.SortFunc(rs, func(a, b ipRange) int { return bytes.Compare(a.lo[:n], b.lo[:n]) })
	out := rs[:0]
	for _, r := range rs {
		if k := len(out) - 1; k >= 0 && bytes.Compare(r.lo[:n], out[k].hi[:n]) <= 0 {
			if bytes.Compare(r.hi[:n], out[k].hi[:n]) > 0 {
				out[k].hi = r.hi
			}
			continue
		}
		out = append(out, r)
	}
	return slices.Clip(out)
}

// asnOf finds the blocked network ip is in.
func (g *geoBlock) asnOf(ip netip.Addr) (uint32, bool) {
	list, n := g.v4, 4
	if ip.Is6() {
		list, n = g.v6, 16
	}
	if len(list) == 0 {
		return 0, false
	}
	key := ip.AsSlice()
	i := sort.Search(len(list), func(i int) bool { return bytes.Compare(list[i].lo[:n], key) > 0 })
	if i == 0 || bytes.Compare(list[i-1].hi[:n], key) < 0 {
		return 0, false
	}
	return list[i-1].asn, true
}

func (g *geoBlock) empty() bool {
	return len(g.countries) == 0 && len(g.v4) == 0 && len(g.v6) == 0
}

// verdict tells whether ip is in a blocked country or network. Addresses
// on the LAN and other private ones are never blocked.
func (g *geoBlock) verdict(ip netip.Addr) (block bool, why string) {
	ip = ip.Unmap()
	if g.empty() || !ip.IsValid() || isLocalAddr(ip) || cgnat.Contains(ip) {
		return false, ""
	}
	if len(g.countries) > 0 {
		cc := country(ip)
		switch {
		case g.allowOnly && cc == "":
			return true, "country: unknown, not an allowed country"
		case g.allowOnly && !g.countries[cc]:
			return true, "country: " + cc + " not allowed"
		case !g.allowOnly && g.countries[cc]:
			return true, "country: " + cc + " blocked"
		}
	}
	if asn, ok := g.asnOf(ip); ok {
		why = "network: AS" + strconv.FormatUint(uint64(asn), 10)
		if n := g.names[asn]; n != "" {
			why += " " + n
		}
		return true, why + " blocked"
	}
	return false, ""
}

// answerVerdict blocks a DNS answer when any address in it is blocked, so
// a program never learns where a blocked place is.
func (g *geoBlock) answerVerdict(ipcsv string) (block bool, why string) {
	if g.empty() {
		return false, ""
	}
	for _, ip := range answerAddrs(ipcsv) {
		if block, why = g.verdict(ip); block {
			return true, why + " (" + ip.String() + ")"
		}
	}
	return false, ""
}
