// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package ifbind

import (
	"errors"
	"math"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// from ws2ipdef.h; not in x/sys/windows.
const (
	ipUnicastIf   = 31 // IP_UNICAST_IF; index in network byte order
	ipv6UnicastIf = 31 // IPV6_UNICAST_IF; index in host byte order
)

// refresh is how long a looked-up default interface is reused.
const refresh = 5 * time.Second

// ErrNoDefault means no default route exists outside the tunnel.
var ErrNoDefault = errors.New("ifbind: no default route outside the tunnel")

// Binder pins sockets to the interface that carries the default route,
// ignoring the tunnel's own interface. Safe for concurrent use.
type Binder struct {
	skip uint32 // tunnel interface index

	mu   sync.Mutex
	idx4 uint32
	idx6 uint32
	at   time.Time

	links  []netip.Prefix // on-link prefixes of the other interfaces (onlink_windows.go)
	linkAt time.Time
}

// New returns a Binder that never picks interface tunIndex.
func New(tunIndex uint32) *Binder {
	return &Binder{skip: tunIndex}
}

// Bind4 makes fd send IPv4 traffic out of the default physical interface.
func (b *Binder) Bind4(fd uintptr) error {
	idx4, _ := b.indexes()
	if idx4 == 0 {
		return ErrNoDefault
	}
	return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIf, int(htonl(idx4)))
}

// Bind6 makes fd send IPv6 traffic out of the default physical interface.
func (b *Binder) Bind6(fd uintptr) error {
	_, idx6 := b.indexes()
	if idx6 == 0 {
		return ErrNoDefault
	}
	return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, ipv6UnicastIf, int(idx6))
}

// Protect binds fd for whichever families it supports.
func (b *Binder) Protect(fd uintptr) error {
	err4 := b.Bind4(fd)
	err6 := b.Bind6(fd)
	if err4 != nil && err6 != nil {
		return errors.Join(err4, err6)
	}
	return nil
}

// Indexes reports the current IPv4 and IPv6 default interface indexes
// (0 if none).
func (b *Binder) Indexes() (idx4, idx6 uint32) {
	return b.indexes()
}

func (b *Binder) indexes() (uint32, uint32) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if time.Since(b.at) < refresh {
		return b.idx4, b.idx6
	}
	b.idx4, _ = defaultIndex(windows.AF_INET, b.skip)
	b.idx6, _ = defaultIndex(windows.AF_INET6, b.skip)
	b.at = time.Now()
	return b.idx4, b.idx6
}

// defaultIndex returns the interface of the cheapest default route
// (route metric + interface metric) on an up interface other than skip.
func defaultIndex(family uint16, skip uint32) (uint32, error) {
	metrics, err := ifaceMetrics(family)
	if err != nil {
		return 0, err
	}
	var tab *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(family, &tab); err != nil {
		return 0, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(tab))

	best, bestm := uint32(0), uint64(math.MaxUint64)
	for _, r := range tab.Rows() {
		if r.DestinationPrefix.PrefixLength != 0 || r.InterfaceIndex == skip {
			continue
		}
		im, up := metrics[r.InterfaceIndex]
		if !up {
			continue
		}
		if m := uint64(r.Metric) + uint64(im); m < bestm {
			best, bestm = r.InterfaceIndex, m
		}
	}
	if best == 0 {
		return 0, ErrNoDefault
	}
	return best, nil
}

// ifaceMetrics maps the index of every up interface to its metric.
func ifaceMetrics(family uint16) (map[uint32]uint32, error) {
	size := uint32(15 << 10)
	var buf []byte
	for range 4 {
		buf = make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(uint32(family), windows.GAA_FLAG_SKIP_ANYCAST, 0, aa, &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return nil, err
		}
		buf = nil
	}
	if buf == nil {
		return nil, windows.ERROR_BUFFER_OVERFLOW
	}

	out := make(map[uint32]uint32)
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		if aa.OperStatus != windows.IfOperStatusUp {
			continue
		}
		if family == windows.AF_INET6 {
			out[aa.Ipv6IfIndex] = aa.Ipv6Metric
		} else {
			out[aa.IfIndex] = aa.Ipv4Metric
		}
	}
	return out, nil
}

func htonl(v uint32) uint32 {
	return v<<24 | (v&0xff00)<<8 | (v>>8)&0xff00 | v>>24
}

// DNSServers returns the IPv4 DNS servers of the default interface outside
// the tunnel: the "System DNS" that Windows would use without us.
func (b *Binder) DNSServers() []netip.Addr {
	idx4, _ := b.indexes()
	if idx4 == 0 {
		return nil
	}
	size := uint32(15 << 10)
	var buf []byte
	for range 4 {
		buf = make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_INET, windows.GAA_FLAG_SKIP_ANYCAST, 0, aa, &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return nil
		}
		buf = nil
	}
	if buf == nil {
		return nil
	}
	var out []netip.Addr
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		if aa.IfIndex != idx4 {
			continue
		}
		for d := aa.FirstDnsServerAddress; d != nil; d = d.Next {
			if ip, ok := netip.AddrFromSlice(d.Address.IP()); ok && ip.Unmap().Is4() {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}

// from ipifcons.h.
const (
	ifTypePropVirtual = 53
	ifTypeTunnel      = 131
)

// Describe names interface idx and reports whether it looks like another
// VPN's tunnel (a virtual adapter rather than Wi-Fi or Ethernet). Firestack
// traffic sent through such an adapter depends on that VPN, which usually
// also claims all routes and all DNS, as Proton VPN does.
func Describe(idx uint32) (name, desc string, vpn bool) {
	size := uint32(15 << 10)
	var buf []byte
	for range 4 {
		buf = make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_INET, windows.GAA_FLAG_SKIP_ANYCAST, 0, aa, &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return "", "", false
		}
		buf = nil
	}
	if buf == nil {
		return "", "", false
	}
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		if aa.IfIndex != idx {
			continue
		}
		name = windows.UTF16PtrToString(aa.FriendlyName)
		desc = windows.UTF16PtrToString(aa.Description)
		d := strings.ToLower(desc)
		vpn = aa.IfType == ifTypePropVirtual || aa.IfType == ifTypeTunnel ||
			strings.Contains(d, "vpn") || strings.Contains(d, "tunnel") ||
			strings.Contains(d, "wireguard") || strings.Contains(d, "wintun") || strings.Contains(d, "tap-")
		return name, desc, vpn
	}
	return "", "", false
}
