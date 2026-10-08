// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package ifbind

import (
	"math"
	"net"
	"testing"
)

// Describe names every interface that has IPv4 (it asks for AF_INET
// adapters), with the same friendly name as net.Interfaces.
func TestDescribeEachInterface(t *testing.T) {
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(ifs) == 0 {
		t.Skip("no interfaces")
	}
	named := 0
	for _, ifc := range ifs {
		name, desc, vpn := Describe(uint32(ifc.Index))
		t.Logf("#%-3d %-36q up=%-5t -> name=%q desc=%q vpn=%t",
			ifc.Index, ifc.Name, ifc.Flags&net.FlagUp != 0, name, desc, vpn)
		if name == "" {
			if desc != "" || vpn {
				t.Errorf("#%d: no name but desc=%q vpn=%t", ifc.Index, desc, vpn)
			}
			continue
		}
		named++
		if name != ifc.Name {
			t.Errorf("#%d: Describe name %q, net.Interfaces name %q", ifc.Index, name, ifc.Name)
		}
	}
	if named == 0 {
		t.Errorf("Describe named none of the %d interfaces", len(ifs))
	}
}

// An index with no interface (and 0, which fswin passes when there is no
// default route) gives nothing and does not panic.
func TestDescribeMissingIndex(t *testing.T) {
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	used := map[uint32]bool{}
	for _, ifc := range ifs {
		used[uint32(ifc.Index)] = true
	}
	missing := uint32(math.MaxUint32 - 1)
	for used[missing] {
		missing--
	}
	for _, idx := range []uint32{0, missing} {
		name, desc, vpn := Describe(idx)
		t.Logf("Describe(%d) = %q, %q, %t", idx, name, desc, vpn)
		if name != "" || desc != "" || vpn {
			t.Errorf("Describe(%d) = %q, %q, %t; want empty", idx, name, desc, vpn)
		}
	}
}

// What fswin's conflict check sees: the interface its own traffic leaves by.
func TestDescribeDefaultInterface(t *testing.T) {
	idx4, idx6 := New(0).Indexes()
	t.Logf("default interface: IPv4 #%d, IPv6 #%d", idx4, idx6)
	if idx4 == 0 {
		t.Skip("no IPv4 default route")
	}
	name, desc, vpn := Describe(idx4)
	t.Logf("Describe(#%d) = %q, %q, vpn=%t (fswin warns about another VPN: %t)", idx4, name, desc, vpn, vpn)
	if name == "" {
		t.Errorf("Describe gave no name for the default interface #%d", idx4)
	}
}
