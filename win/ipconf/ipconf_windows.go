// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package ipconf

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The calls netsh makes, from netioapi.h; x/sys has the row types but not
// these functions. All take a pointer to a row (or a GUID: 16 bytes go by
// reference on amd64).
var (
	iphlpapi                            = windows.NewLazySystemDLL("iphlpapi.dll")
	procInitializeUnicastIpAddressEntry = iphlpapi.NewProc("InitializeUnicastIpAddressEntry")
	procCreateUnicastIpAddressEntry     = iphlpapi.NewProc("CreateUnicastIpAddressEntry")
	procInitializeIpForwardEntry        = iphlpapi.NewProc("InitializeIpForwardEntry")
	procCreateIpForwardEntry2           = iphlpapi.NewProc("CreateIpForwardEntry2")
	procSetIpInterfaceEntry             = iphlpapi.NewProc("SetIpInterfaceEntry")
	procConvertInterfaceLuidToGuid      = iphlpapi.NewProc("ConvertInterfaceLuidToGuid")
	// Windows 10 2004 and later
	procSetInterfaceDnsSettings = iphlpapi.NewProc("SetInterfaceDnsSettings")
)

// ErrNoDNSAPI is SetDNS on a Windows without SetInterfaceDnsSettings.
var ErrNoDNSAPI = errors.New("ipconf: SetInterfaceDnsSettings needs Windows 10 2004 or later")

const ipDadStatePreferred = 4 // NL_DAD_STATE IpDadStatePreferred

func call(p *windows.LazyProc, args ...uintptr) error {
	if err := p.Find(); err != nil {
		return err
	}
	r, _, _ := syscall.SyscallN(p.Addr(), args...)
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

func sockaddr4(p unsafe.Pointer, a netip.Addr) {
	s := (*windows.RawSockaddrInet4)(p)
	s.Family = windows.AF_INET
	s.Addr = a.As4()
}

// SetAddress gives the adapter luid the IPv4 address p, as netsh's
// "set address source=static": 10.111.222.1/24.
func SetAddress(luid uint64, p netip.Prefix) error {
	if !p.Addr().Is4() {
		return fmt.Errorf("ipconf: %v is not IPv4", p)
	}
	var row windows.MibUnicastIpAddressRow
	if err := procInitializeUnicastIpAddressEntry.Find(); err != nil {
		return err
	}
	_, _, _ = syscall.SyscallN(procInitializeUnicastIpAddressEntry.Addr(), uintptr(unsafe.Pointer(&row))) //nolint:gosec // G103: a netioapi row; returns nothing
	row.InterfaceLuid = luid
	sockaddr4(unsafe.Pointer(&row.Address), p.Addr()) //nolint:gosec // G103: a netioapi row
	row.OnLinkPrefixLength = uint8(p.Bits()) //nolint:gosec // G115: 0..32
	row.DadState = ipDadStatePreferred
	err := call(procCreateUnicastIpAddressEntry, uintptr(unsafe.Pointer(&row))) //nolint:gosec // G103: a netioapi row
	if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("ipconf: address %v: %w", p, err)
	}
	return nil
}

// SetMetric gives the adapter's IPv4 side a fixed metric, as netsh's
// "set interface metric=": the lowest wins Windows' DNS and route choices.
func SetMetric(luid uint64, metric uint32) error {
	row := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: luid}
	if err := windows.GetIpInterfaceEntry(&row); err != nil {
		return fmt.Errorf("ipconf: interface: %w", err)
	}
	row.UseAutomaticMetric = 0
	row.Metric = metric
	row.SitePrefixLength = 0 // SetIpInterfaceEntry refuses anything else for IPv4
	if err := call(procSetIpInterfaceEntry, uintptr(unsafe.Pointer(&row))); err != nil { //nolint:gosec // G103: a netioapi row
		return fmt.Errorf("ipconf: metric: %w", err)
	}
	return nil
}

// AddRoute sends dst to the adapter, on link (no next hop), as netsh's
// "add route nexthop=0.0.0.0 store=active": the route goes with the adapter.
func AddRoute(luid uint64, dst netip.Prefix, metric uint32) error {
	if !dst.Addr().Is4() {
		return fmt.Errorf("ipconf: %v is not IPv4", dst)
	}
	var row windows.MibIpForwardRow2
	if err := procInitializeIpForwardEntry.Find(); err != nil {
		return err
	}
	_, _, _ = syscall.SyscallN(procInitializeIpForwardEntry.Addr(), uintptr(unsafe.Pointer(&row))) //nolint:gosec // G103: a netioapi row; returns nothing
	row.InterfaceLuid = luid
	sockaddr4(unsafe.Pointer(&row.DestinationPrefix.Prefix), dst.Masked().Addr()) //nolint:gosec // G103: a netioapi row
	row.DestinationPrefix.PrefixLength = uint8(dst.Bits()) //nolint:gosec // G115: 0..32
	sockaddr4(unsafe.Pointer(&row.NextHop), netip.IPv4Unspecified()) //nolint:gosec // G103: a netioapi row
	row.Metric = metric
	err := call(procCreateIpForwardEntry2, uintptr(unsafe.Pointer(&row))) //nolint:gosec // G103: a netioapi row
	if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("ipconf: route %v: %w", dst, err)
	}
	return nil
}

// DNS_INTERFACE_SETTINGS (netioapi.h), version 1.
type dnsInterfaceSettings struct {
	Version             uint32
	Flags               uint64
	Domain              *uint16
	NameServer          *uint16
	SearchList          *uint16
	RegistrationEnabled uint32
	RegisterAdapterName uint32
	EnableLLMNR         uint32
	QueryAdapterName    uint32
	ProfileNameServer   *uint16
}

const (
	dnsSettingNameServer          = 0x0002
	dnsSettingRegistrationEnabled = 0x0008
	dnsSettingRegisterAdapterName = 0x0010
)

// SetDNS points the adapter's IPv4 DNS at server and keeps the PC from
// registering its name through it, as netsh's "set dnsservers
// register=none". ErrNoDNSAPI on a Windows too old for it.
func SetDNS(luid uint64, server netip.Addr) error {
	if procSetInterfaceDnsSettings.Find() != nil {
		return ErrNoDNSAPI
	}
	var guid windows.GUID
	if err := call(procConvertInterfaceLuidToGuid, uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&guid))); err != nil { //nolint:gosec // G103: a netioapi row
		return fmt.Errorf("ipconf: interface guid: %w", err)
	}
	ns, err := windows.UTF16PtrFromString(server.String())
	if err != nil {
		return err
	}
	s := dnsInterfaceSettings{
		Version:    1,
		Flags:      dnsSettingNameServer | dnsSettingRegistrationEnabled | dnsSettingRegisterAdapterName,
		NameServer: ns, // RegistrationEnabled and RegisterAdapterName stay 0: off
	}
	err = call(procSetInterfaceDnsSettings, uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(&s))) //nolint:gosec // G103: a netioapi row
	runtime.KeepAlive(ns)
	if err != nil {
		return fmt.Errorf("ipconf: dns: %w", err)
	}
	return nil
}
