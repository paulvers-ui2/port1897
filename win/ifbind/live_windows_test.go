// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ifbind

import (
	"net"
	"os"
	"testing"
)

// TestDescribeLive checks the other-VPN detection against this PC's real
// adapters. tools/sim/e2e-windows.ps1 runs it while fswin is up, with
// SIM_TUN naming fswin's adapter: that one must look like a VPN, and the
// interface carrying the default route must not.
func TestDescribeLive(t *testing.T) {
	if os.Getenv("SIM_LIVE") == "" {
		t.Skip("set SIM_LIVE=1 to check this PC's adapters")
	}
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	tun := os.Getenv("SIM_TUN")
	var tunIdx uint32
	for _, ifc := range ifs {
		name, desc, vpn := Describe(uint32(ifc.Index))
		t.Logf("#%d %q: Describe -> name %q, desc %q, vpn %t", ifc.Index, ifc.Name, name, desc, vpn)
		if tun != "" && ifc.Name == tun {
			tunIdx = uint32(ifc.Index)
			if !vpn {
				t.Errorf("%s is fswin's own Wintun adapter but Describe says it is not a VPN", tun)
			}
		}
	}
	if tun != "" && tunIdx == 0 {
		t.Errorf("no adapter named %q; is fswin running?", tun)
	}

	idx4, _ := New(tunIdx).Indexes()
	name, desc, vpn := Describe(idx4)
	t.Logf("default route outside the tunnel: #%d %q (%s), vpn %t", idx4, name, desc, vpn)
	if idx4 == 0 {
		t.Fatal("no IPv4 default route outside the tunnel")
	}
	if vpn {
		t.Errorf("the ordinary default-route adapter %q (%s) is reported as another VPN: a false warning", name, desc)
	}

	if n, d, v := Describe(1 << 30); n != "" || d != "" || v {
		t.Errorf("Describe(missing index) = %q, %q, %t; want empty", n, d, v)
	}
}
