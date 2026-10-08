// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"fmt"
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
	dnsSystem   = "system"
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
		err = intra.AddDNSCryptTransport(t, x.StrOf(x.Preferred), x.StrOf(o.dnscrypt))
		return x.Preferred, "DNSCrypt", err
	case dnsSystem:
		if len(sys) == 0 {
			return "", "", fmt.Errorf("-dns system: no DNS servers found on the network adapter")
		}
		return x.System, "System DNS (" + strings.Join(sys, ", ") + ")", nil
	}
	return "", "", fmt.Errorf("-dns must be doh, dot, dnscrypt or system, not %q", o.dnsType)
}
