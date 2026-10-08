// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/celzero/firestack/intra"
	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/win/ifbind"
)

// DNS types for -dns, as in the Android app's DNS screen.
const (
	dnsDoH      = "doh"
	dnsDoT      = "dot"
	dnsDNSCrypt = "dnscrypt"
	dnsODoH     = "odoh"
	dnsProxy    = "proxy" // plain DNS to an ip:port, like Android's "DNS Proxy"
	dnsSystem   = "system"
)

// On-device blocklist files, as the Android app names them.
const (
	blTrie     = "td.txt"
	blRank     = "rd.txt"
	blConfig   = "basicconfig.json"
	blFiletag  = "filetag.json"
	blRemoteID = "remote" // log label for the remote (RethinkDNS) filetag
)

// setupDNS adds the transports for o.dnsType and returns the transport id
// queries go to. The System transport (the physical adapter's DNS servers)
// is added whenever those servers are known: -dns system uses it, and
// -undelegated sends .lan, .internal and the like to it.
func setupDNS(t intra.Tunnel, o options, binder *ifbind.Binder) (tid, label string, err error) {
	var sys []string
	for _, ip := range binder.DNSServers() {
		sys = append(sys, ip.String())
	}
	if len(sys) > 0 {
		if err := intra.SetSystemDNS(t, x.StrOf(strings.Join(sys, ","))); err != nil {
			fmt.Printf("fswin: system dns %v: %v\n", sys, err)
		}
	}

	switch o.dnsType {
	case "", dnsDoH:
		err = intra.AddDoHTransport(t, x.StrOf(x.Preferred), x.StrOf(o.doh), x.StrOf(o.dohips))
		return x.Preferred, o.doh, err
	case dnsDoT:
		if o.dot == "" {
			return "", "", fmt.Errorf("-dns dot needs -dot")
		}
		err = intra.AddDoTTransport(t, x.StrOf(x.Preferred), x.StrOf(o.dot), x.StrOf(o.dotIPs))
		return x.Preferred, o.dot, err
	case dnsDNSCrypt:
		if o.dnscrypt == "" {
			return "", "", fmt.Errorf("-dns dnscrypt needs -dnscrypt")
		}
		// relays first: the transport routes through them once they exist
		for _, r := range splitCSV(o.dnscryptRelays) {
			if rerr := intra.AddDNSCryptRelay(t, x.StrOf(r)); rerr != nil {
				fmt.Printf("fswin: dnscrypt relay %s: %v\n", r, rerr)
			}
		}
		err = intra.AddDNSCryptTransport(t, x.StrOf(x.Preferred), x.StrOf(o.dnscrypt))
		label = "DNSCrypt"
		if o.dnscryptRelays != "" {
			label += " via relays"
		}
		return x.Preferred, label, err
	case dnsODoH:
		if o.odoh == "" {
			return "", "", fmt.Errorf("-dns odoh needs -odoh")
		}
		err = intra.AddODoHTransport(t, x.StrOf(x.Preferred), x.StrOf(o.odohRelay), x.StrOf(o.odoh), x.StrOf(o.odohIPs))
		label = "ODoH " + o.odoh
		if o.odohRelay != "" {
			label += " via " + o.odohRelay
		}
		return x.Preferred, label, err
	case dnsProxy:
		if o.dnsProxy == "" {
			return "", "", fmt.Errorf("-dns proxy needs -dns-proxy ip:port")
		}
		err = intra.AddDNSProxy(t, x.StrOf(x.Preferred), x.StrOf(o.dnsProxy))
		return x.Preferred, "DNS proxy " + o.dnsProxy, err
	case dnsSystem:
		if len(sys) == 0 {
			return "", "", fmt.Errorf("-dns system: no DNS servers found on the network adapter")
		}
		return x.System, "System DNS (" + strings.Join(sys, ", ") + ")", nil
	}
	return "", "", fmt.Errorf("-dns must be doh, dot, dnscrypt, odoh, proxy or system, not %q", o.dnsType)
}

// setupBlocklists loads the on-device blocklists in o.blocklistDir with the
// stamp of the lists to block, and the filetag that names the lists a
// RethinkDNS server blocked by. Failures are reported, not fatal: DNS still
// works without blocklists.
func setupBlocklists(t intra.Tunnel, o options) (lists bool, err error) {
	if o.blocklistDir == "" && o.filetag == "" {
		return false, nil
	}
	r, err := t.GetResolver()
	if err != nil {
		return false, err
	}
	if o.filetag != "" {
		if ferr := r.SetRdnsRemote(o.filetag); ferr != nil {
			err = errors.Join(err, fmt.Errorf("%s %s: %w", blRemoteID, o.filetag, ferr))
		}
	}
	if o.blocklistDir == "" || o.blocklistStamp == "" {
		return false, err
	}
	d := o.blocklistDir
	files := []string{filepath.Join(d, blTrie), filepath.Join(d, blRank), filepath.Join(d, blConfig), filepath.Join(d, blFiletag)}
	for _, f := range files {
		if _, serr := os.Stat(f); serr != nil {
			return false, errors.Join(err, serr)
		}
	}
	if lerr := r.SetRdnsLocal(files[0], files[1], files[2], files[3]); lerr != nil {
		return false, errors.Join(err, lerr)
	}
	local, lerr := r.GetRdnsLocal()
	if lerr != nil || local == nil {
		return false, errors.Join(err, lerr, errors.New("on-device blocklists did not load"))
	}
	if serr := local.SetStamp(x.StrOf(o.blocklistStamp)); serr != nil {
		return false, errors.Join(err, serr)
	}
	return true, err
}

func splitCSV(s string) (out []string) {
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return
}
