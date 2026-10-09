// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     SPDX-License-Identifier: MIT
//
//     Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.

//go:build windows

package wfp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// wfpObjectInstaller and baseObjects come from wireguard-windows' blocker.go.
type wfpObjectInstaller func(uintptr) error

type baseObjects struct {
	provider windows.GUID
	filters  windows.GUID
}

// Options for Enable.
type Options struct {
	// TunLUID is the tunnel adapter, through which everything may pass.
	TunLUID uint64
	// Allow lists more programs (full paths) that may connect directly,
	// besides the calling process; e.g. usque.exe.
	Allow []string
	// Persistent keeps the block in place if this process dies, until
	// Disable runs (from a later start or "fswin -cleanup").
	Persistent bool
	// AllowLAN lets private, link-local and multicast addresses through,
	// so printers, file shares and casting keep working.
	AllowLAN bool
}

// Fixed keys, so a later process can find and remove what a crashed one
// left behind. Filters get filterKeyBase with their index in the last bytes.
var (
	providerKey   = windows.GUID{Data1: 0x6b1c2a47, Data2: 0x5f2e, Data3: 0x4c8f, Data4: [8]byte{0x9a, 0x51, 0x18, 0x97, 0xa0, 0xc0, 0xf0, 0x01}}
	sublayerKey   = windows.GUID{Data1: 0x6b1c2a47, Data2: 0x5f2e, Data3: 0x4c8f, Data4: [8]byte{0x9a, 0x51, 0x18, 0x97, 0xa0, 0xc0, 0xf0, 0x02}}
	filterKeyBase = windows.GUID{Data1: 0x6b1c2a47, Data2: 0x5f2e, Data3: 0x4c8f, Data4: [8]byte{0x9a, 0x51, 0x18, 0x97, 0xa0, 0xc1, 0x00, 0x00}}
)

const (
	maxFilters = 160

	cFWPM_PROVIDER_FLAG_PERSISTENT = 0x00000001

	// from fwpmu.h
	fwpErrFilterNotFound   = 0x80320003
	fwpErrProviderNotFound = 0x80320005
	fwpErrSublayerNotFound = 0x80320007
)

var (
	procFwpmFilterDeleteByKey0   = modfwpuclnt.NewProc("FwpmFilterDeleteByKey0")
	procFwpmSubLayerDeleteByKey0 = modfwpuclnt.NewProc("FwpmSubLayerDeleteByKey0")
	procFwpmProviderDeleteByKey0 = modfwpuclnt.NewProc("FwpmProviderDeleteByKey0")
	procFwpmProviderGetByKey0    = modfwpuclnt.NewProc("FwpmProviderGetByKey0")
)

var errTooManyFilters = errors.New("wfp: too many filters")

var (
	mu        sync.Mutex
	dynamic   uintptr // open dynamic session, if any
	persisted bool    // filters being added are persistent
	seq       int     // index of the next filter key
)

func filterKey(i int) windows.GUID {
	k := filterKeyBase
	k.Data4[6] = byte(i >> 8)
	k.Data4[7] = byte(i)
	return k
}

// fwpmFilterAdd0 gives every filter the rules add a known key, and makes it
// persistent when asked; rules.go calls this instead of the raw API.
func fwpmFilterAdd0(engine uintptr, filter *wtFwpmFilter0, sd uintptr, id *uint64) error {
	if seq >= maxFilters {
		return errTooManyFilters
	}
	filter.filterKey = filterKey(seq)
	seq++
	if persisted {
		filter.flags |= cFWPM_FILTER_FLAG_PERSISTENT
	}
	return fwpmFilterAdd0Raw(engine, filter, sd, id)
}

// Enable blocks all traffic except through the tunnel, by this process, by
// the programs in o.Allow, and loopback, DHCP and IPv6 neighbour discovery.
// It first removes any rules left by an earlier run.
func Enable(o Options) error {
	mu.Lock()
	defer mu.Unlock()
	if err := disableLocked(); err != nil {
		return err
	}

	flags := wtFwpmSessionFlagsValue(0)
	if !o.Persistent {
		flags = cFWPM_SESSION_FLAG_DYNAMIC
	}
	session, err := openSession(flags)
	if err != nil {
		return err
	}
	persisted, seq = o.Persistent, 0

	err = runTransaction(session, func(session uintptr) error {
		bo, err := addBaseObjects(session, o.Persistent)
		if err != nil {
			return err
		}
		if err := permitWireGuardService(session, bo, 15); err != nil {
			return err
		}
		for _, p := range o.Allow {
			if err := permitApp(session, bo, 15, p); err != nil {
				return fmt.Errorf("allow %s: %w", p, err)
			}
		}
		if err := permitLoopback(session, bo, 13); err != nil {
			return err
		}
		if o.AllowLAN {
			if err := permitLAN(session, bo, 13); err != nil {
				return fmt.Errorf("allow LAN: %w", err)
			}
		}
		if err := permitTunInterface(session, bo, 12, o.TunLUID); err != nil {
			return err
		}
		if err := permitDHCPIPv4(session, bo, 12); err != nil {
			return err
		}
		if err := permitDHCPIPv6(session, bo, 12); err != nil {
			return err
		}
		if err := permitNdp(session, bo, 12); err != nil {
			return err
		}
		return blockAll(session, bo, 0)
	})
	if err != nil {
		fwpmEngineClose0(session)
		return fmt.Errorf("wfp: enable: %w", err)
	}
	if o.Persistent {
		fwpmEngineClose0(session) // persistent objects outlive the session
	} else {
		dynamic = session // closing it removes everything
	}
	return nil
}

// Disable removes the kill switch, including rules left by a crashed run.
func Disable() error {
	mu.Lock()
	defer mu.Unlock()
	return disableLocked()
}

func disableLocked() error {
	if dynamic != 0 {
		fwpmEngineClose0(dynamic)
		dynamic = 0
	}
	session, err := openSession(0)
	if err != nil {
		return err
	}
	defer fwpmEngineClose0(session)
	return runTransaction(session, func(session uintptr) error {
		for i := range maxFilters {
			k := filterKey(i)
			if r := callByKey(procFwpmFilterDeleteByKey0, session, &k); r != 0 && r != fwpErrFilterNotFound {
				return fmt.Errorf("wfp: delete filter %d: 0x%08x", i, r)
			}
		}
		if r := callByKey(procFwpmSubLayerDeleteByKey0, session, &sublayerKey); r != 0 && r != fwpErrSublayerNotFound {
			return fmt.Errorf("wfp: delete sublayer: 0x%08x", r)
		}
		if r := callByKey(procFwpmProviderDeleteByKey0, session, &providerKey); r != 0 && r != fwpErrProviderNotFound {
			return fmt.Errorf("wfp: delete provider: 0x%08x", r)
		}
		return nil
	})
}

// Active reports whether kill-switch rules are installed (for example left
// behind by a run that crashed).
func Active() (bool, error) {
	session, err := openSession(0)
	if err != nil {
		return false, err
	}
	defer fwpmEngineClose0(session)
	var p unsafe.Pointer
	r, _, _ := syscall.SyscallN(procFwpmProviderGetByKey0.Addr(), session,
		uintptr(unsafe.Pointer(&providerKey)), uintptr(unsafe.Pointer(&p)))
	switch uint32(r) {
	case 0:
		fwpmFreeMemory0(unsafe.Pointer(&p))
		return true, nil
	case fwpErrProviderNotFound:
		return false, nil
	}
	return false, fmt.Errorf("wfp: get provider: 0x%08x", uint32(r))
}

func callByKey(p *windows.LazyProc, session uintptr, key *windows.GUID) uint32 {
	r, _, _ := syscall.SyscallN(p.Addr(), session, uintptr(unsafe.Pointer(key)))
	return uint32(r)
}

func openSession(flags wtFwpmSessionFlagsValue) (uintptr, error) {
	dd, err := createWtFwpmDisplayData0("AuroraVPN", "AuroraVPN kill switch session")
	if err != nil {
		return 0, err
	}
	s := wtFwpmSession0{
		displayData:          *dd,
		flags:                flags,
		txnWaitTimeoutInMSec: windows.INFINITE,
	}
	h := uintptr(0)
	if err := fwpmEngineOpen0(nil, cRPC_C_AUTHN_WINNT, nil, &s, unsafe.Pointer(&h)); err != nil {
		return 0, fmt.Errorf("wfp: open engine (run as admin?): %w", err)
	}
	return h, nil
}

// addBaseObjects registers our provider and sublayer under the fixed keys.
func addBaseObjects(session uintptr, persistent bool) (*baseObjects, error) {
	bo := &baseObjects{provider: providerKey, filters: sublayerKey}

	dd, err := createWtFwpmDisplayData0("AuroraVPN", "AuroraVPN kill switch")
	if err != nil {
		return nil, err
	}
	provider := wtFwpmProvider0{providerKey: bo.provider, displayData: *dd}
	if persistent {
		provider.flags = cFWPM_PROVIDER_FLAG_PERSISTENT
	}
	if err := fwpmProviderAdd0(session, &provider, 0); err != nil {
		return nil, fmt.Errorf("add provider: %w", err)
	}

	dd, err = createWtFwpmDisplayData0("AuroraVPN filters", "Permit the tunnel and the engine, block the rest")
	if err != nil {
		return nil, err
	}
	sublayer := wtFwpmSublayer0{
		subLayerKey: bo.filters,
		displayData: *dd,
		providerKey: &bo.provider,
		weight:      ^uint16(0),
	}
	if persistent {
		sublayer.flags = cFWPM_SUBLAYER_FLAG_PERSISTENT
	}
	if err := fwpmSubLayerAdd0(session, &sublayer, 0); err != nil {
		return nil, fmt.Errorf("add sublayer: %w", err)
	}
	return bo, nil
}

// permitApp lets the program at path connect and accept directly, like
// permitWireGuardService does for the calling process.
func permitApp(session uintptr, bo *baseObjects, weight uint8, path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	var appID *wtFwpByteBlob
	if err := fwpmGetAppIdFromFileName0(p, unsafe.Pointer(&appID)); err != nil {
		return err
	}
	defer fwpmFreeMemory0(unsafe.Pointer(&appID))

	cond := wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_ALE_APP_ID,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_BYTE_BLOB_TYPE,
			value: uintptr(unsafe.Pointer(appID)),
		},
	}
	filter := wtFwpmFilter0{
		providerKey:         &bo.provider,
		subLayerKey:         bo.filters,
		weight:              filterWeight(weight),
		flags:               cFWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
		numFilterConditions: 1,
		filterCondition:     &cond,
		action:              wtFwpmAction0{_type: cFWP_ACTION_PERMIT},
	}
	for _, layer := range []windows.GUID{
		cFWPM_LAYER_ALE_AUTH_CONNECT_V4, cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
		cFWPM_LAYER_ALE_AUTH_CONNECT_V6, cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
	} {
		dd, err := createWtFwpmDisplayData0("Permit "+path, "")
		if err != nil {
			return err
		}
		filter.displayData = *dd
		filter.layerKey = layer
		id := uint64(0)
		if err := fwpmFilterAdd0(session, &filter, 0, &id); err != nil {
			return err
		}
	}
	return nil
}

var (
	lan4 = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("255.255.255.255/32"),
	}
	lan6 = []netip.Prefix{
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("ff00::/8"),
	}
)

// permitLAN lets traffic to and from the lan4 and lan6 ranges through.
// Conditions on the same field are ORed, so one filter per layer covers all.
func permitLAN(session uintptr, bo *baseObjects, weight uint8) error {
	v4 := make([]wtFwpV4AddrAndMask, len(lan4))
	c4 := make([]wtFwpmFilterCondition0, len(lan4))
	for i, p := range lan4 {
		a := p.Addr().As4()
		v4[i] = wtFwpV4AddrAndMask{
			addr: binary.BigEndian.Uint32(a[:]), // WFP wants host order
			mask: ^uint32(0) << (32 - p.Bits()),
		}
		c4[i] = wtFwpmFilterCondition0{
			fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_V4_ADDR_MASK,
				value: uintptr(unsafe.Pointer(&v4[i])),
			},
		}
	}
	v6 := make([]wtFwpV6AddrAndMask, len(lan6))
	c6 := make([]wtFwpmFilterCondition0, len(lan6))
	for i, p := range lan6 {
		v6[i] = wtFwpV6AddrAndMask{addr: p.Addr().As16(), prefixLength: uint8(p.Bits())}
		c6[i] = wtFwpmFilterCondition0{
			fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_V6_ADDR_MASK,
				value: uintptr(unsafe.Pointer(&v6[i])),
			},
		}
	}

	add := func(name string, layer windows.GUID, conds []wtFwpmFilterCondition0) error {
		dd, err := createWtFwpmDisplayData0(name, "")
		if err != nil {
			return err
		}
		filter := wtFwpmFilter0{
			displayData:         *dd,
			providerKey:         &bo.provider,
			layerKey:            layer,
			subLayerKey:         bo.filters,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(conds)),
			filterCondition:     &conds[0],
			action:              wtFwpmAction0{_type: cFWP_ACTION_PERMIT},
		}
		id := uint64(0)
		return fwpmFilterAdd0(session, &filter, 0, &id)
	}
	err := errors.Join(
		add("Permit LAN (IPv4 out)", cFWPM_LAYER_ALE_AUTH_CONNECT_V4, c4),
		add("Permit LAN (IPv4 in)", cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, c4),
		add("Permit LAN (IPv6 out)", cFWPM_LAYER_ALE_AUTH_CONNECT_V6, c6),
		add("Permit LAN (IPv6 in)", cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, c6),
	)
	runtime.KeepAlive(v4)
	runtime.KeepAlive(v6)
	return err
}
