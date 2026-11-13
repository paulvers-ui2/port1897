// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build linux

// Package wfp, on Linux, is the kill switch as an nftables table: while it
// is there, only the tunnel, the engine's own (marked) sockets and loopback
// may send. The table outlives the engine, so a crash leaves the PC
// blocked, not leaking; Disable (fswin -cleanup) removes it.
package wfp

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// Options configure the kill switch.
type Options struct {
	// TunLUID is unused on Linux.
	TunLUID uint64
	// TunName is the tunnel's interface: traffic leaving by it is allowed.
	TunName string
	// Mark is the firewall mark of the engine's own sockets (win/ifbind).
	Mark uint32
	// Allow is unused on Linux: usque's traffic goes through the tunnel.
	Allow []string
	// Persistent is unused on Linux: the table always outlives the engine.
	Persistent bool
	// AllowLAN lets private (RFC 1918, link-local, unique-local) and
	// multicast destinations through, for printers and file shares.
	AllowLAN bool
}

const table = "auroravpn_kill"

var ifname = regexp.MustCompile(`^[A-Za-z0-9._-]{1,15}$`).MatchString

func nft(script string) error {
	path, err := exec.LookPath("nft")
	if err != nil {
		for _, p := range []string{"/usr/sbin/nft", "/sbin/nft"} {
			if _, e := exec.LookPath(p); e == nil {
				path, err = p, nil
				break
			}
		}
	}
	if err != nil {
		return errors.New("nft not found: install the nftables package")
	}
	cmd := exec.Command(path, "-f", "-") //nolint:gosec // G204: nft, script on stdin
	cmd.Stdin = strings.NewReader(script)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft: %w: %s", err, strings.TrimSpace(out.String()))
	}
	return nil
}

// Enable turns the kill switch on, replacing its rules if it already is.
func Enable(o Options) error {
	if !ifname(o.TunName) {
		return fmt.Errorf("kill switch: bad interface name %q", o.TunName)
	}
	lan := ""
	if o.AllowLAN {
		lan = `
		ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } accept
		ip6 daddr { fe80::/10, fc00::/7, ff00::/8 } accept`
	}
	// add-then-delete makes the replace atomic whether or not it existed
	script := fmt.Sprintf(`add table inet %[1]s
delete table inet %[1]s
table inet %[1]s {
	chain kill_out {
		type filter hook output priority 0; policy drop;
		oifname "lo" accept
		oifname "%[2]s" accept
		meta mark 0x%[3]x accept
		udp sport 68 udp dport 67 accept
		ip6 daddr fe80::/10 udp sport 546 udp dport 547 accept
		icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept%[4]s
	}
	chain kill_fwd {
		type filter hook forward priority 0; policy accept;
		oifname != "%[2]s" oifname != "lo" meta mark != 0x%[3]x ct state new drop
	}
}
`, table, o.TunName, o.Mark, lan)
	if !o.AllowLAN {
		return nft(script)
	}
	// forwarded (containers, VMs) traffic may reach the LAN too
	script = strings.Replace(script, "\t\toifname != \""+o.TunName+"\" oifname != \"lo\"", lanFwd+"\t\toifname != \""+o.TunName+"\" oifname != \"lo\"", 1)
	return nft(script)
}

const lanFwd = "\t\tip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } accept\n\t\tip6 daddr { fe80::/10, fc00::/7 } accept\n"

// Disable turns the kill switch off; no error if it was not on.
func Disable() error {
	on, err := Active()
	if err != nil || !on {
		return err
	}
	return nft("delete table inet " + table + "\n")
}

// Active reports whether the kill switch is on.
func Active() (bool, error) {
	path, err := exec.LookPath("nft")
	if err != nil {
		return false, nil //nolint:nilerr // no nftables: it cannot be on
	}
	out, err := exec.Command(path, "list", "tables", "inet").CombinedOutput() //nolint:gosec // G204: nft
	if err != nil {
		return false, fmt.Errorf("nft list tables: %w: %s", err, strings.TrimSpace(string(out)))
	}
	for _, l := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(l) == "table inet "+table {
			return true, nil
		}
	}
	return false, nil
}
