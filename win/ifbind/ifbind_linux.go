// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build linux

// Package ifbind, on Linux, keeps the engine's own sockets out of the
// tunnel with a firewall mark: policy routing sends every packet without
// the mark to the tunnel (cmd/fswin/main_linux.go), and marked ones by the
// main table, to the network.
package ifbind

import (
	"bufio"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Mark is the firewall mark on the engine's own sockets.
const Mark = 0x1897

// ErrNoDefault is returned when no default route exists outside the tunnel.
var ErrNoDefault = errors.New("ifbind: no default route outside the tunnel")

// Binder marks sockets. tun is the tunnel's interface index, never chosen
// as the network's.
type Binder struct{ tun uint32 }

// New returns a Binder that keeps sockets off interface tunIndex.
func New(tunIndex uint32) *Binder { return &Binder{tun: tunIndex} }

// Bind4 marks an IPv4 socket; ErrNoDefault if no network carries IPv4.
func (b *Binder) Bind4(fd uintptr) error {
	if idx, _ := b.Indexes(); idx == 0 {
		return ErrNoDefault
	}
	return mark(fd)
}

// Bind6 marks an IPv6 socket; ErrNoDefault if no network carries IPv6.
func (b *Binder) Bind6(fd uintptr) error {
	if _, idx := b.Indexes(); idx == 0 {
		return ErrNoDefault
	}
	return mark(fd)
}

// Protect marks a socket of either family.
func (b *Binder) Protect(fd uintptr) error { return mark(fd) }

// OnLink is always false: a marked socket reaches on-link addresses too.
func (b *Binder) OnLink(string) bool { return false }

func mark(fd uintptr) error {
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, Mark) //nolint:gosec // G115: a file descriptor
}

// Indexes returns the interfaces of the IPv4 and IPv6 default routes
// outside the tunnel; 0 for none.
func (b *Binder) Indexes() (idx4, idx6 uint32) {
	return default4(b.tun), default6(b.tun)
}

// default4 reads the main table's IPv4 default routes (/proc/net/route) and
// returns the interface of the one with the lowest metric, other than skip.
func default4(skip uint32) uint32 {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return 0
	}
	defer f.Close()
	best, bestMetric := uint32(0), uint64(1<<63)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// Iface Destination Gateway Flags RefCnt Use Metric Mask ...
		c := strings.Fields(sc.Text())
		if len(c) < 8 || c[1] != "00000000" || c[7] != "00000000" {
			continue
		}
		flags, _ := strconv.ParseUint(c[3], 16, 32)
		metric, _ := strconv.ParseUint(c[6], 10, 64)
		idx := indexOf(c[0])
		if flags&unix.RTF_UP == 0 || idx == 0 || idx == skip || metric >= bestMetric {
			continue
		}
		best, bestMetric = idx, metric
	}
	return best
}

// default6 is default4 for IPv6 (/proc/net/ipv6_route).
func default6(skip uint32) uint32 {
	f, err := os.Open("/proc/net/ipv6_route")
	if err != nil {
		return 0
	}
	defer f.Close()
	best, bestMetric := uint32(0), uint64(1<<63)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// dst dstlen src srclen nexthop metric refcnt use flags iface
		c := strings.Fields(sc.Text())
		if len(c) < 10 || c[1] != "00" || strings.Trim(c[0], "0") != "" {
			continue
		}
		metric, _ := strconv.ParseUint(c[5], 16, 64)
		flags, _ := strconv.ParseUint(c[8], 16, 32)
		idx := indexOf(c[9])
		if flags&unix.RTF_UP == 0 || flags&unix.RTF_REJECT != 0 || idx == 0 || idx == skip || c[9] == "lo" || metric >= bestMetric {
			continue
		}
		best, bestMetric = idx, metric
	}
	return best
}

func indexOf(name string) uint32 {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return 0
	}
	return uint32(ifc.Index) //nolint:gosec // G115: an interface index
}

// DNSServers returns the network's own DNS servers: systemd-resolved's
// upstream ones when it runs, else those of /etc/resolv.conf; never a
// loopback stub, nor the tunnel's.
func (b *Binder) DNSServers() []netip.Addr {
	var out []netip.Addr
	for _, p := range []string{"/run/systemd/resolve/resolv.conf", "/run/auroravpn/resolv.conf.orig", "/etc/resolv.conf"} {
		f, err := os.Open(p) //nolint:gosec // G304: fixed paths
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			c := strings.Fields(sc.Text())
			if len(c) < 2 || c[0] != "nameserver" {
				continue
			}
			a, err := netip.ParseAddr(strings.Split(c[1], "%")[0])
			if err != nil || a.IsLoopback() || a.IsUnspecified() || tunnelNet.Contains(a) {
				continue
			}
			out = append(out, a.Unmap())
		}
		_ = f.Close()
		if len(out) > 0 {
			break
		}
	}
	return out
}

// tunnelNet is the tunnel's own network (cmd/fswin: ifaddr4, fakedns4).
var tunnelNet = netip.MustParsePrefix("10.111.222.0/24")

// Describe names interface idx; vpn says it is a tunnel of another VPN.
func Describe(idx uint32) (name, desc string, vpn bool) {
	ifc, err := net.InterfaceByIndex(int(idx))
	if err != nil {
		return "", "", false
	}
	name = ifc.Name
	sys := filepath.Join("/sys/class/net", name)
	if _, err := os.Stat(filepath.Join(sys, "tun_flags")); err == nil {
		return name, "TUN/TAP device", true
	}
	if b, err := os.ReadFile(filepath.Join(sys, "uevent")); err == nil { //nolint:gosec // G304: under /sys/class/net
		for _, l := range strings.Split(string(b), "\n") {
			if t, ok := strings.CutPrefix(l, "DEVTYPE="); ok {
				return name, t, t == "wireguard" || t == "ppp"
			}
		}
	}
	if _, err := os.Stat(filepath.Join(sys, "wireless")); err == nil {
		return name, "wlan", false
	}
	return name, "ethernet", false
}

// LinkMTU returns the IP MTU of the IPv4 default interface other than skip,
// and that interface's index; 0, 0 when there is none.
func LinkMTU(skip uint32) (mtu, idx uint32) {
	idx = default4(skip)
	if idx == 0 {
		return 0, 0
	}
	ifc, err := net.InterfaceByIndex(int(idx))
	if err != nil {
		return 0, 0
	}
	return uint32(ifc.MTU), idx //nolint:gosec // G115: an MTU
}
