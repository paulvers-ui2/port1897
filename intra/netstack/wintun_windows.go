// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package netstack

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Windows has no tun fd. The host creates a Wintun adapter (for example with
// tun.CreateTUN from golang.zx2c4.com/wireguard/tun) and hands it over with
// RegisterTun. The returned id then stands in for the tun fd everywhere the
// Android build passes one: NewEndpoint, Swap, and tunnel.NewGTunnel.

const (
	// maxPacketSize is the largest packet Wintun hands out.
	maxPacketSize = 0xffff
	// waitttl is how long Attach(nil) waits for the read loop to exit.
	waitttl = 5 * time.Second
)

var errNoSuchTun = errors.New("ns: no registered tun for id")

var (
	tunmu   sync.Mutex
	tuns    = map[int]tun.Device{}
	nexttun = 100 // ids look nothing like fds 0, 1, 2
)

// RegisterTun hands dev over to netstack and returns the id to pass in place
// of a tun fd. Netstack owns dev from here on and closes it when done.
func RegisterTun(dev tun.Device) int {
	tunmu.Lock()
	defer tunmu.Unlock()
	id := nexttun
	nexttun++
	tuns[id] = dev
	return id
}

// takeTun removes the device for id from the registry and returns it.
func takeTun(id int) (tun.Device, bool) {
	tunmu.Lock()
	defer tunmu.Unlock()
	dev, ok := tuns[id]
	delete(tuns, id)
	return dev, ok && dev != nil
}

// closeDev closes the tun device registered under id, if it was never taken.
func closeDev(id int) {
	if dev, ok := takeTun(id); ok {
		_ = dev.Close()
	}
}

// wdev is a Wintun device and its counters; the Windows analogue of fds.
type wdev struct {
	id     int
	dev    tun.Device
	once   sync.Once
	closed atomic.Bool

	since     atomic.Int64 // unix millis
	death     atomic.Int64 // unix millis
	read      atomic.Int64 // bytes
	written   atomic.Int64 // bytes
	lastRead  atomic.Int64 // unix millis
	lastWrite atomic.Int64 // unix millis
}

var invalidDev = &wdev{id: invalidfd}

func newWdev(id int) (*wdev, error) {
	dev, ok := takeTun(id)
	if !ok {
		return nil, fmt.Errorf("%w: %d", errNoSuchTun, id)
	}
	w := &wdev{id: id, dev: dev}
	w.since.Store(time.Now().UnixMilli())
	return w, nil
}

func (w *wdev) ok() bool {
	return w != nil && w.dev != nil && !w.closed.Load()
}

func (w *wdev) tun() int {
	if !w.ok() {
		return invalidfd
	}
	return w.id
}

// stop closes the device once; a blocked Read then returns an error.
func (w *wdev) stop() {
	if w == nil || w.dev == nil {
		return
	}
	w.once.Do(func() {
		w.closed.Store(true)
		now := time.Now().UnixMilli()
		w.death.Store(now)
		err := w.dev.Close()
		logeif(err)("ns: wintun(%d): stop: age(%s); err? %v",
			w.id, core.FmtMillis(now-w.since.Load()), err)
	})
}

func (w *wdev) String() string {
	return fmt.Sprintf("%d", w.tun())
}

// wendpoint is a stack.LinkEndpoint backed by a Wintun adapter.
type wendpoint struct {
	sync.RWMutex

	dev  *core.Volatile[*wdev]
	mtu  atomic.Uint32
	caps stack.LinkEndpointCapabilities
	addr tcpip.LinkAddress

	// dispatcher is the nic this endpoint is attached to; protected by mu.
	dispatcher stack.NetworkDispatcher
	// mgr spreads inbound packets over processors.
	mgr atomic.Pointer[supervisor]

	// wg tracks running read loops.
	wg core.RollingWaitGroup
}

var _ stack.InjectableLinkEndpoint = (*wendpoint)(nil)
var _ SeamlessEndpoint = (*wendpoint)(nil)

// newFdbasedInjectableEndpoint keeps the Linux name so seamless.go is shared;
// opts.FDs holds the RegisterTun id.
func newFdbasedInjectableEndpoint(opts *Options) (SeamlessEndpoint, error) {
	if len(opts.FDs) != 1 {
		return nil, fmt.Errorf("len(opts.FDs) = %d, expected 1", len(opts.FDs))
	}
	if opts.EthernetHeader {
		return nil, errors.New("ns: wintun: ethernet header not supported")
	}

	caps := stack.LinkEndpointCapabilities(0)
	if opts.RXChecksumOffload {
		caps |= stack.CapabilityRXChecksumOffload
	}
	if opts.TXChecksumOffload {
		caps |= stack.CapabilityTXChecksumOffload
	}
	if opts.SaveRestore {
		caps |= stack.CapabilitySaveRestore
	}

	e := &wendpoint{
		dev:  core.NewVolatile(invalidDev),
		caps: caps,
		addr: opts.Address,
	}
	e.SetMTU(opts.MTU)

	if err := e.swap(opts.FDs[0], true); err != nil {
		return nil, err
	}
	return e, nil
}

// Swap implements FdSwapper.
func (e *wendpoint) Swap(id, mtu int) error {
	e.SetMTU(uint32(mtu))
	return e.swap(id, false)
}

func (e *wendpoint) swap(id int, force bool) error {
	e.Lock()
	defer e.Unlock()

	prev := e.dev.Load()
	if !force && !prev.ok() {
		return errNeedsNewEndpoint
	}

	w, err := newWdev(id)
	if err != nil {
		return log.EE("ns: wintun(%d): swap: %v", id, err)
	}

	e.dev.Store(w)
	if m := e.mgr.Load(); m == nil {
		m = newSupervisor(e, id)
		m.start()
		e.mgr.Store(m)
	} else {
		m.note(id) // diagnostics only
	}
	prev.stop() // its read loop, if any, exits

	if e.dispatcher != nil {
		go e.readLoop(w)
	}
	log.I("ns: wintun(%s => %d): swap; attached? %t", prev, id, e.dispatcher != nil)
	return nil
}

// Dispose implements FdSwapper.
func (e *wendpoint) Dispose() error {
	e.Lock()
	defer e.Unlock()

	prev := e.dev.Swap(invalidDev)
	prev.stop()
	log.I("ns: wintun(%s): dispose", prev)
	return nil
}

// Stat implements FdSwapper.
func (e *wendpoint) Stat() (zz EpStat) {
	w := e.dev.Load()
	if w == nil || w.dev == nil {
		return
	}
	t := time.Now()
	if death := w.death.Load(); death > 0 {
		t = time.UnixMilli(death)
	}
	return EpStat{
		Fd:        w.id,
		Alive:     !w.closed.Load(),
		Age:       core.FmtPeriod(t.Sub(time.UnixMilli(w.since.Load()))),
		Read:      core.FmtBytes(uint64(w.read.Load())),
		Written:   core.FmtBytes(uint64(w.written.Load())),
		LastRead:  core.FmtUnixMillisAsPeriod(w.lastRead.Load()),
		LastWrite: core.FmtUnixMillisAsPeriod(w.lastWrite.Load()),
	}
}

// Attach implements stack.LinkEndpoint.
func (e *wendpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.Lock()
	defer e.Unlock()

	w := e.dev.Load()

	if dispatcher == nil {
		if e.dispatcher == nil {
			return
		}
		if m := e.mgr.Swap(nil); m != nil {
			core.Gx("ns.w.stop", m.stop)
		}
		w.stop()
		done := core.Await(func() { e.wg.Wait() }, waitttl)
		e.dispatcher = nil
		e.dev.Store(invalidDev)
		logei(!done)("ns: wintun(%s): detached; read loop done? %t", w, done)
		return
	}

	first := e.dispatcher == nil
	e.dispatcher = dispatcher
	if !first {
		log.W("ns: wintun(%s): attach: switch to new dispatcher", w)
		return
	}
	if !w.ok() {
		log.W("ns: wintun(%s): attach: no device yet", w)
		return
	}
	if e.mgr.Load() == nil {
		m := newSupervisor(e, w.id)
		m.start()
		e.mgr.Store(m)
	}
	go e.readLoop(w)
	log.I("ns: wintun(%s): attach: read loop started", w)
}

// readLoop moves packets from the adapter into netstack until w is closed.
func (e *wendpoint) readLoop(w *wdev) {
	defer core.Recover(core.Exit11, "ns.wintun.read")

	e.wg.Add(1)
	defer e.wg.Done()
	defer w.stop()

	n := max(w.dev.BatchSize(), 1)
	bufs := make([][]byte, n)
	for i := range bufs {
		bufs[i] = make([]byte, maxPacketSize)
	}
	sizes := make([]int, n)

	for {
		count, err := w.dev.Read(bufs, sizes, 0)
		if err != nil {
			if errors.Is(err, tun.ErrTooManySegments) {
				continue
			}
			logei(!w.closed.Load())("ns: wintun(%d): read loop exit; err: %v", w.id, err)
			return
		}
		w.lastRead.Store(time.Now().UnixMilli())

		m := e.mgr.Load()
		if m == nil {
			continue // detaching; drop
		}

		for i := 0; i < count; i++ {
			sz := sizes[i]
			if sz <= 0 {
				continue
			}
			w.read.Add(int64(sz))
			// netstack keeps the payload; bufs[i] is reused next read.
			b := make([]byte, sz)
			copy(b, bufs[i][:sz])
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(b),
			})
			m.queuePacket(pkt, false)
			pkt.DecRef()
		}
		m.wakeReady()
	}
}

// IsAttached implements stack.LinkEndpoint.
func (e *wendpoint) IsAttached() bool {
	e.RLock()
	defer e.RUnlock()
	return e.dispatcher != nil
}

// MTU implements stack.LinkEndpoint.
func (e *wendpoint) MTU() uint32 { return e.mtu.Load() }

// SetMTU implements stack.LinkEndpoint.
func (e *wendpoint) SetMTU(mtu uint32) { e.mtu.Store(mtu) }

// Capabilities implements stack.LinkEndpoint.
func (e *wendpoint) Capabilities() stack.LinkEndpointCapabilities { return e.caps }

// MaxHeaderLength implements stack.LinkEndpoint; Wintun carries bare IP.
func (e *wendpoint) MaxHeaderLength() uint16 { return 0 }

// LinkAddress implements stack.LinkEndpoint.
func (e *wendpoint) LinkAddress() tcpip.LinkAddress {
	e.RLock()
	defer e.RUnlock()
	return e.addr
}

// SetLinkAddress implements stack.LinkEndpoint.
func (e *wendpoint) SetLinkAddress(addr tcpip.LinkAddress) {
	e.Lock()
	defer e.Unlock()
	e.addr = addr
}

// Wait implements stack.LinkEndpoint.
func (e *wendpoint) Wait() { e.wg.Wait() }

// ARPHardwareType implements stack.LinkEndpoint.
func (e *wendpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }

// AddHeader implements stack.LinkEndpoint.
func (e *wendpoint) AddHeader(*stack.PacketBuffer) {}

// ParseHeader implements stack.LinkEndpoint.
func (e *wendpoint) ParseHeader(pkt *stack.PacketBuffer) bool { return pkt != nil }

// WritePackets implements stack.LinkEndpoint; it writes netstack's outbound
// packets to the adapter.
func (e *wendpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	total := pkts.Len()
	if total == 0 {
		return 0, nil
	}
	w := e.dev.Load()
	if !w.ok() {
		log.E("ns: wintun(-1): WritePackets: no device (pkts: %d)", total)
		return 0, &tcpip.ErrNoSuchFile{}
	}

	bufs := make([][]byte, 0, total)
	var sz int64
	for _, pkt := range pkts.AsSlice() {
		b := make([]byte, 0, pkt.Size())
		for _, v := range pkt.AsSlices() {
			b = append(b, v...)
		}
		bufs = append(bufs, b)
		sz += int64(len(b))
	}

	n, err := w.dev.Write(bufs, 0)
	w.lastWrite.Store(time.Now().UnixMilli())
	if n == len(bufs) {
		w.written.Add(sz)
	}
	if err != nil {
		log.W("ns: wintun(%d): WritePackets: sent(%d)/total(%d); err: %v", w.id, n, total, err)
		return n, &tcpip.ErrClosedForSend{}
	}
	if settings.Debug {
		log.VV("ns: wintun(%d): WritePackets: written(%d)/total(%d)", w.id, n, total)
	}
	return n, nil
}

// InjectInbound implements stack.InjectableLinkEndpoint.
func (e *wendpoint) InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	e.RLock()
	d := e.dispatcher
	e.RUnlock()
	if d != nil && pkt != nil {
		d.DeliverNetworkPacket(protocol, pkt)
	} else {
		log.W("ns: wintun: inject-inbound %d pkt?(%t) dropped: not attached", protocol, pkt != nil)
	}
}

// InjectOutbound implements stack.InjectableLinkEndpoint.
func (e *wendpoint) InjectOutbound(dest tcpip.Address, packet *buffer.View) tcpip.Error {
	w := e.dev.Load()
	if !w.ok() {
		log.E("ns: wintun(-1): inject-outbound to dst(%v): no device", dest)
		return &tcpip.ErrUnknownDevice{}
	}
	b := packet.AsSlice()
	if _, err := w.dev.Write([][]byte{b}, 0); err != nil {
		log.W("ns: wintun(%d): inject-outbound to dst(%v): err: %v", w.id, dest, err)
		return &tcpip.ErrClosedForSend{}
	}
	w.written.Add(int64(len(b)))
	w.lastWrite.Store(time.Now().UnixMilli())
	return nil
}

// Close implements stack.LinkEndpoint.
func (e *wendpoint) Close() {
	log.W("ns: wintun(%s): Close!", e.dev.Load())
	e.Attach(nil)
}

// SetOnCloseAction implements stack.LinkEndpoint.
func (*wendpoint) SetOnCloseAction(func()) {}
