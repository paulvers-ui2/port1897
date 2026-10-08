// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2020 RethinkDNS and its authors
//     Licensed under the Apache License, Version 2.0
//     (the firewall in BraveVPNService.kt of the Rethink Android app)

//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The firewall rules of the Android app, for Windows: a mode per app, IP and
// domain rules (for one app or all of them), the universal rules, allowed DNS
// query types and pause. The app window owns the rules; it hands fswin the
// whole set at start (-rules file) and on every change (POST /api/rules).

// App modes, as on the Android app's App info screen.
const (
	modeNone            = ""
	modeAllow           = "allow"
	modeBlock           = "block"
	modeIsolate         = "isolate"         // block all but trusted IPs and domains
	modeBypass          = "bypass"          // "Bypass DNS & Firewall"
	modeBypassUniversal = "bypassUniversal" // skip the universal rules only
	modeExclude         = "exclude"         // not firewalled, never proxied
)

// ruleOutgoingAllowed is the reason given for flows "Allow outgoing only"
// let through; the app window whitelists their programs when it sees it.
const ruleOutgoingAllowed = "universal: outgoing allowed"

// Rule actions.
const (
	actBlock = "block"
	actTrust = "trust" // allow, skipping every later rule
)

type appRule struct {
	Mode       string `json:"mode,omitempty"`
	AllowUntil int64  `json:"allowUntil,omitempty"` // unix millis: "Allow for 15 minutes"
	NoProxy    bool   `json:"noProxy,omitempty"`    // "Bypass app from all proxies"
	Route      string `json:"route,omitempty"`      // a per-app route (routes_windows.go) instead of the exit
}

type ipRule struct {
	App    string `json:"app,omitempty"` // exe name or path; "" for all apps
	IP     string `json:"ip"`            // 1.2.3.4, 1.2.3.0/24, 1.2.3.*, or * for any
	Port   int    `json:"port,omitempty"`
	Action string `json:"action"`
}

type domainRule struct {
	App    string `json:"app,omitempty"`
	Domain string `json:"domain"` // example.com, or *.example.com for it and its subdomains
	Action string `json:"action"`
}

type universalRules struct {
	UDP       bool `json:"udp"`       // block UDP except DNS (53) and NTP (123)
	ICMP      bool `json:"icmp"`      // block ping
	HTTP      bool `json:"http"`      // block TCP port 80
	Unknown   bool `json:"unknown"`   // block when the program is unknown
	DNSBypass bool `json:"dnsBypass"` // block IPs that were not looked up through the app
	NewApps   bool `json:"newApps"`   // block programs not seen before
	Locked    bool `json:"locked"`    // block everything while Windows is locked
	Lockdown  bool `json:"lockdown"`  // block all but bypassed apps and trusted IPs
	// OutgoingOnly allows every outgoing connection the rules above it do
	// not block, and blocks incoming ones; the app window then sets each
	// program it allowed to Bypass Universal, so it stays allowed.
	OutgoingOnly bool `json:"outgoingOnly"`
}

// ruleSet is the JSON the app sends.
type ruleSet struct {
	Apps         map[string]appRule `json:"apps"`
	IPs          []ipRule           `json:"ips"`
	Domains      []domainRule       `json:"domains"`
	Universal    universalRules     `json:"universal"`
	Known        []string           `json:"known"`    // programs seen before, for NewApps
	DNSTypes     []int              `json:"dnsTypes"` // allowed DNS query types; empty: all
	PausedUntil  int64              `json:"pausedUntil"`
	ScreenLocked bool               `json:"screenLocked"`
}

type cIPRule struct {
	app   string // lowercased; "" for all
	any   bool
	pfx   netip.Prefix
	port  uint16
	block bool
	text  string
}

type cDomainRule struct {
	app   string
	name  string // lowercased, no trailing dot or "*."
	wild  bool   // also matches subdomains
	block bool
	text  string
}

// rules is a ruleSet compiled for matching. It is never changed once built;
// updates swap in a new one.
type rules struct {
	src      ruleSet
	apps     map[string]appRule // lowercased exe name or full path
	ips      []cIPRule
	domains  []cDomainRule
	u        universalRules
	known    map[string]bool
	dnsTypes map[int]bool
	paused   int64
	locked   bool
}

func compileRules(rs ruleSet) (*rules, error) {
	r := &rules{
		src:      rs,
		apps:     map[string]appRule{},
		u:        rs.Universal,
		known:    map[string]bool{},
		dnsTypes: map[int]bool{},
		paused:   rs.PausedUntil,
		locked:   rs.ScreenLocked,
	}
	var errs []error
	for k, v := range rs.Apps {
		if k = strings.ToLower(strings.TrimSpace(k)); k != "" {
			r.apps[k] = v
		}
	}
	for _, k := range rs.Known {
		r.known[strings.ToLower(strings.TrimSpace(k))] = true
	}
	for _, t := range rs.DNSTypes {
		r.dnsTypes[t] = true
	}
	for _, ir := range rs.IPs {
		c, err := compileIPRule(ir)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		r.ips = append(r.ips, c)
	}
	for _, dr := range rs.Domains {
		name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(dr.Domain), "."))
		wild := strings.HasPrefix(name, "*.")
		name = strings.TrimPrefix(name, "*.")
		if name == "" || strings.ContainsAny(name, " /:*") {
			errs = append(errs, fmt.Errorf("domain rule %q: not a domain", dr.Domain))
			continue
		}
		r.domains = append(r.domains, cDomainRule{
			app:   strings.ToLower(strings.TrimSpace(dr.App)),
			name:  name,
			wild:  wild,
			block: dr.Action == actBlock,
			text:  dr.Domain,
		})
	}
	return r, errors.Join(errs...)
}

// compileIPRule accepts an address, a CIDR, octet wildcards like 10.1.*.*
// (or 10.1.*) or * for any address.
func compileIPRule(ir ipRule) (c cIPRule, err error) {
	c = cIPRule{
		app:   strings.ToLower(strings.TrimSpace(ir.App)),
		block: ir.Action == actBlock,
		text:  ir.IP,
	}
	if ir.Port < 0 || ir.Port > 65535 {
		return c, fmt.Errorf("ip rule %q: bad port %d", ir.IP, ir.Port)
	}
	c.port = uint16(ir.Port)
	s := strings.TrimSpace(ir.IP)
	if s == "" || s == "*" || s == "*.*" || s == "*.*.*.*" {
		c.any = true
		if c.port == 0 {
			return c, fmt.Errorf("ip rule: any address needs a port")
		}
		return c, nil
	}
	if strings.Contains(s, "*") {
		parts := strings.Split(s, ".")
		var fixed []string
		for _, p := range parts {
			if p == "*" {
				break
			}
			fixed = append(fixed, p)
		}
		if len(parts) > 4 || len(fixed) == 0 {
			return c, fmt.Errorf("ip rule %q: bad wildcard", ir.IP)
		}
		bits := 8 * len(fixed)
		for len(fixed) < 4 {
			fixed = append(fixed, "0")
		}
		s = strings.Join(fixed, ".") + "/" + strconv.Itoa(bits)
	}
	if strings.Contains(s, "/") {
		c.pfx, err = netip.ParsePrefix(s)
		if err == nil {
			c.pfx = c.pfx.Masked()
		}
	} else {
		var ip netip.Addr
		ip, err = netip.ParseAddr(s)
		if err == nil {
			ip = ip.Unmap()
			bits := ip.BitLen()
			if ip.IsUnspecified() {
				bits = 0 // [::]:80 or 0.0.0.0:80: any address of that family
			}
			c.pfx = netip.PrefixFrom(ip, bits)
		}
	}
	if err != nil {
		return c, fmt.Errorf("ip rule %q: %w", ir.IP, err)
	}
	return c, nil
}

func loadRulesFile(path string) (*rules, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rs ruleSet
	if err := json.Unmarshal(b, &rs); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return compileRules(rs)
}

// appKeys are the keys an app's rules may be stored under.
func appKeys(path string) (full, exe string) {
	full = strings.ToLower(path)
	exe = strings.ToLower(filepath.Base(path))
	return
}

func (r *rules) app(path string) appRule {
	if path == "" {
		return appRule{}
	}
	full, exe := appKeys(path)
	if a, ok := r.apps[full]; ok {
		return a
	}
	return r.apps[exe]
}

func (r *rules) isPaused(now int64) bool {
	return r.paused > now
}

// blocksIncoming reports whether connections coming in through the tunnel
// are refused: "Allow outgoing only", unless protection is paused.
func (r *rules) blocksIncoming(now int64) bool {
	return r.u.OutgoingOnly && !r.isPaused(now)
}

func ruleApplies(ruleApp, full, exe string) bool {
	return ruleApp == full || ruleApp == exe
}

// ipVerdict finds the first IP rule for app (or for all apps, if app is "")
// that matches dst. found is false when none does.
func (r *rules) ipVerdict(forApp bool, full, exe string, dst netip.AddrPort) (block, found bool, why string) {
	ip := dst.Addr().Unmap()
	for _, c := range r.ips {
		if forApp {
			if c.app == "" || !ruleApplies(c.app, full, exe) {
				continue
			}
		} else if c.app != "" {
			continue
		}
		if c.port != 0 && c.port != dst.Port() {
			continue
		}
		if !c.any && !c.pfx.Contains(ip) {
			continue
		}
		return c.block, true, c.text
	}
	return false, false, ""
}

func (c cDomainRule) matches(d string) bool {
	if d == c.name {
		return true
	}
	return c.wild && strings.HasSuffix(d, "."+c.name)
}

// domainVerdict is ipVerdict for domain rules; block rules win over trust
// rules when several domains match.
func (r *rules) domainVerdict(forApp bool, full, exe string, domains []string) (block, found bool, why string) {
	for _, c := range r.domains {
		if forApp {
			if c.app == "" || !ruleApplies(c.app, full, exe) {
				continue
			}
		} else if c.app != "" {
			continue
		}
		for _, d := range domains {
			if !c.matches(d) {
				continue
			}
			if c.block {
				return true, true, c.text
			}
			found, why = true, c.text
		}
	}
	return false, found, why
}

// dnsVerdict applies the rules for all apps to a DNS query: blocked query
// types and blocked domains are answered by BlockAll; trusted domains skip
// on-device blocklists.
func (r *rules) dnsVerdict(domain string, qtyp int, now int64) (block, trust bool, why string) {
	if r.isPaused(now) {
		return false, false, ""
	}
	if len(r.dnsTypes) > 0 && !r.dnsTypes[qtyp] {
		return true, false, "query type " + strconv.Itoa(qtyp) + " not allowed"
	}
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	block, found, rule := r.domainVerdict(false, "", "", []string{d})
	if !found {
		return false, false, ""
	}
	if block {
		return true, false, "domain rule " + rule
	}
	return false, true, "trusted " + rule
}

type decision struct {
	block   bool
	noProxy bool   // leave directly, not through the VPN exit
	route   string // leave through this per-app route, if loaded
	why     string // the rule that decided, for the logs
}

// decide is the Android app's firewall order: exclusions and bypasses, pause,
// the app's own IP and domain rules, isolation, the global domain and IP
// rules, the app's block, and last the universal rules.
func (r *rules) decide(protocol int32, path string, known bool, dst netip.AddrPort, domains []string, now time.Time) decision {
	ms := now.UnixMilli()
	full, exe := appKeys(path)
	a := r.app(path)
	tempAllowed := a.AllowUntil > ms

	switch a.Mode {
	case modeExclude:
		return decision{noProxy: true, why: "app excluded"}
	case modeBypass:
		return decision{noProxy: a.NoProxy, route: a.Route, why: "app bypasses DNS & firewall"}
	}
	allow := func(why string) decision { return decision{noProxy: a.NoProxy, route: a.Route, why: why} }
	blocked := func(why string) decision { return decision{block: true, why: why} }

	if r.isPaused(ms) {
		if a.Mode == modeBlock && !tempAllowed {
			return blocked("app blocked (paused)")
		}
		return allow("paused")
	}

	if path != "" {
		if block, found, rule := r.ipVerdict(true, full, exe, dst); found {
			if block {
				return blocked("app IP rule " + rule)
			}
			return allow("app trusts IP " + rule)
		}
		if block, found, rule := r.domainVerdict(true, full, exe, domains); found {
			if block {
				return blocked("app domain rule " + rule)
			}
			return allow("app trusts domain " + rule)
		}
	}
	if a.Mode == modeIsolate && !tempAllowed {
		return blocked("app isolated")
	}
	if block, found, rule := r.domainVerdict(false, "", "", domains); found {
		if block {
			return blocked("domain rule " + rule)
		}
		return allow("trusted domain " + rule)
	}
	if block, found, rule := r.ipVerdict(false, "", "", dst); found {
		if block {
			return blocked("IP rule " + rule)
		}
		return allow("trusted IP " + rule)
	}
	if a.Mode == modeBlock && !tempAllowed {
		return blocked("app blocked")
	}
	if a.Mode == modeBypassUniversal {
		return allow("app bypasses universal rules")
	}

	u := r.u
	port := dst.Port()
	switch {
	case u.Lockdown:
		return blocked("universal: lockdown")
	case u.Locked && r.locked:
		return blocked("universal: PC locked")
	case u.OutgoingOnly:
		// every program may connect out; the rules below would only block it
		return allow(ruleOutgoingAllowed)
	case u.Unknown && path == "":
		return blocked("universal: unknown app")
	case u.NewApps && path != "" && a.Mode == modeNone && !known:
		return blocked("universal: new app")
	case u.ICMP && (protocol == 1 || protocol == 58):
		return blocked("universal: ICMP")
	case u.UDP && protocol == 17 && port != 53 && port != 123:
		return blocked("universal: UDP")
	case u.HTTP && protocol == 6 && port == 80:
		return blocked("universal: HTTP (port 80)")
	case u.DNSBypass && len(domains) == 0 && !isLocalAddr(dst.Addr()):
		return blocked("universal: DNS bypassed")
	}
	return allow("")
}

// isLocalAddr reports LAN, loopback, link-local and multicast addresses,
// which never come from DNS lookups.
func isLocalAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

// knownApp reports whether a program was seen before, for "Block newly
// installed apps": listed in the app's known list or given any rule.
func (r *rules) knownApp(path string) bool {
	full, exe := appKeys(path)
	return r.known[exe] || r.known[full]
}
