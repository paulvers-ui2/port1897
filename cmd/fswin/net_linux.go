// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/celzero/firestack/win/ifbind"
	"github.com/celzero/firestack/win/wfp"
	"golang.org/x/sys/unix"
)

// Policy routing, as wg-quick does it: packets without the engine's mark
// look up a table of their own, whose only route is the tunnel; the main
// table still answers first for anything but its default route, so the
// LAN, and the tunnel's own /24, stay reachable.
const (
	routeTable   = "51897"
	prioMain     = "31897" // main table, default routes suppressed
	prioTunnel   = "31898" // everything unmarked: the tunnel
	stateDir     = "/run/auroravpn"
	resolvConf   = "/etc/resolv.conf"
	resolvBackup = stateDir + "/resolv.conf.orig"
)

// tool finds a system program: PATH under systemd or sudo may lack sbin.
func tool(name string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	for _, d := range []string{"/usr/sbin/", "/sbin/", "/usr/bin/", "/bin/"} {
		if st, err := os.Stat(d + name); err == nil && !st.IsDir() {
			return d + name, nil
		}
	}
	return "", fmt.Errorf("%s not found", name)
}

func sh(name string, args ...string) error {
	p, err := tool(name)
	if err != nil {
		return err
	}
	// nosemgrep
	out, err := exec.Command(p, args...).CombinedOutput() //nolint:gosec // G204: a system tool, plain arguments
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}

func ip(args ...string) error { return sh("ip", args...) }

// openTun makes TUN device name and returns its file descriptor. The
// device is gone when the last descriptor closes.
func openTun(name string) (int, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// configure gives the adapter its address and MTU and brings it up.
func configure(name string, mtu int) error {
	return errors.Join(
		ip("addr", "replace", ifaddr4+"/24", "dev", name),
		ip("link", "set", "dev", name, "mtu", strconv.Itoa(mtu), "up"),
	)
}

// fullTunnel sends all IPv4 to the tunnel. IPv6 is not carried: it is made
// unreachable beyond the LAN, so programs fall back to IPv4 at once and
// nothing leaves outside the tunnel.
func fullTunnel(name string) error {
	// replies to the engine's marked sockets must pass reverse-path filtering
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/all/src_valid_mark", []byte("1"), 0o644) //nolint:gosec // G306: a sysctl
	mark := fmt.Sprintf("0x%x", ifbind.Mark)
	err := errors.Join(
		ip("-4", "route", "replace", "default", "dev", name, "table", routeTable),
		ip("-4", "rule", "add", "priority", prioMain, "lookup", "main", "suppress_prefixlength", "0"),
		ip("-4", "rule", "add", "priority", prioTunnel, "not", "fwmark", mark, "lookup", routeTable),
	)
	if err != nil {
		_ = dropRouting()
		return fmt.Errorf("-full: %w", err)
	}
	// best effort: a kernel without IPv6 has nothing to leak
	if ip("-6", "route", "replace", "unreachable", "default", "table", routeTable) == nil {
		_ = ip("-6", "rule", "add", "priority", prioMain, "lookup", "main", "suppress_prefixlength", "0")
		_ = ip("-6", "rule", "add", "priority", prioTunnel, "not", "fwmark", mark, "lookup", routeTable)
	}
	return nil
}

// dropRouting removes fullTunnel's rules and routes, also those a killed
// fswin left; nil when there were none.
func dropRouting() error {
	for _, fam := range []string{"-4", "-6"} {
		for _, prio := range []string{prioMain, prioTunnel} {
			for i := 0; i < 8 && ip(fam, "rule", "del", "priority", prio) == nil; i++ {
			}
		}
		_ = ip(fam, "route", "flush", "table", routeTable)
	}
	return nil
}

// resolvedInUse reports whether programs resolve through systemd-resolved.
func resolvedInUse() bool {
	b, err := os.ReadFile(resolvConf)
	if err != nil {
		return false
	}
	if _, err := tool("resolvectl"); err != nil {
		return false
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "nameserver" && strings.HasPrefix(f[1], "127.0.0.5") {
			return true
		}
	}
	return false
}

// setSystemDNS makes every program's DNS query go to the tunnel: through
// systemd-resolved when it is in use (the tunnel's link becomes the route
// for every name), else by replacing /etc/resolv.conf, kept in
// resolvBackup until restoreDNS.
func setSystemDNS(name string) (how string, err error) {
	if resolvedInUse() {
		err := errors.Join(
			sh("resolvectl", "dns", name, fakedns4),
			sh("resolvectl", "domain", name, "~."),
			sh("resolvectl", "default-route", name, "yes"),
		)
		if err == nil {
			_ = sh("resolvectl", "flush-caches")
			return "systemd-resolved", nil
		}
		fmt.Println("fswin: systemd-resolved refused; replacing", resolvConf, "instead:", err)
		_ = sh("resolvectl", "revert", name)
	}
	orig, err := os.ReadFile(resolvConf)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil { //nolint:gosec // G301: world-readable, like /run/systemd/resolve
		return "", err
	}
	if _, err := os.Stat(resolvBackup); err != nil { // never overwrite an older backup with our own file
		if err := os.WriteFile(resolvBackup, orig, 0o644); err != nil { //nolint:gosec // G306: resolv.conf is world-readable
			return "", err
		}
	}
	conf := "# AuroraVPN: every DNS query goes to its tunnel. Restored when it stops (or: fswin -cleanup).\nnameserver " + fakedns4 + "\n"
	if err := os.WriteFile(resolvConf, []byte(conf), 0o644); err != nil { //nolint:gosec // G306: resolv.conf is world-readable
		return "", err
	}
	return resolvConf, nil
}

// restoreDNS undoes setSystemDNS, also for a killed fswin.
func restoreDNS(name string, loud bool) {
	if _, err := os.Stat("/sys/class/net/" + name); err == nil && resolvedInUse() {
		_ = sh("resolvectl", "revert", name)
	}
	orig, err := os.ReadFile(resolvBackup)
	if err != nil {
		return
	}
	if err := os.WriteFile(resolvConf, orig, 0o644); err != nil { //nolint:gosec // G306: resolv.conf is world-readable
		if loud {
			fmt.Fprintln(os.Stderr, "fswin: restore", resolvConf, "(its copy is in", resolvBackup+"):", err)
		}
		return
	}
	_ = os.Remove(resolvBackup)
}

// cleanup removes what a killed fswin left behind.
func cleanup(name string) error {
	restoreDNS(name, true)
	return errors.Join(dropRouting(), wfp.Disable())
}
