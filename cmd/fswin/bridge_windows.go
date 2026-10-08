// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/celzero/firestack/intra"
	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/win/ifbind"
	"github.com/celzero/firestack/win/owner"
	"golang.org/x/sys/windows"
)

const unknownUID = -1

// apps hands out a stable numeric id per program path, which firestack
// expects in place of an Android app uid. Ids start at 10000 like Android's.
type apps struct {
	mu     sync.Mutex
	byPath map[string]int32 // lowercased path -> uid
	byUID  map[int32]string // uid -> path as reported
	next   int32
}

func newApps() *apps {
	return &apps{byPath: map[string]int32{}, byUID: map[int32]string{}, next: 10000}
}

func (a *apps) uid(path string) int32 {
	key := strings.ToLower(path)
	a.mu.Lock()
	defer a.mu.Unlock()
	if u, ok := a.byPath[key]; ok {
		return u
	}
	u := a.next
	a.next++
	a.byPath[key] = u
	a.byUID[u] = path
	return u
}

func (a *apps) path(uid int32) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.byUID[uid]
}

// bridge answers firestack's callbacks: it finds which program owns each
// flow, blocks the programs listed in -block, sends DNS to the Preferred
// (DoH) transport, and prints what it sees.
type bridge struct {
	start   time.Time
	cid     atomic.Int64
	binder  *ifbind.Binder
	apps    *apps
	blocked []string // lowercased exe names or full paths
	selfpid uint32
	selfuid int32
	exit    atomic.Value // string: proxy id for allowed flows and DNS
}

var _ intra.Bridge = (*bridge)(nil)

func newBridge(binder *ifbind.Binder, blockcsv string) *bridge {
	b := &bridge{
		start:   time.Now(),
		binder:  binder,
		apps:    newApps(),
		selfpid: windows.GetCurrentProcessId(),
	}
	self, err := os.Executable()
	if err != nil {
		self = "fswin.exe"
	}
	b.selfuid = b.apps.uid(self)
	for _, s := range strings.Split(blockcsv, ",") {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			b.blocked = append(b.blocked, s)
		}
	}
	return b
}

// setExit sends allowed flows and DNS queries through proxy id.
func (b *bridge) setExit(id string) {
	b.exit.Store(id)
}

// exitID is the proxy that allowed traffic leaves through; Base is direct.
func (b *bridge) exitID() string {
	if id, ok := b.exit.Load().(string); ok && id != "" {
		return id
	}
	return x.Base
}

func (b *bridge) blockedList() string {
	return strings.Join(b.blocked, ", ")
}

func (b *bridge) isBlocked(path string) bool {
	if path == "" {
		return false
	}
	p := strings.ToLower(path)
	return slices.Contains(b.blocked, p) || slices.Contains(b.blocked, filepath.Base(p))
}

func (b *bridge) logf(format string, args ...any) {
	fmt.Printf("%8.3fs "+format+"\n", append([]any{time.Since(b.start).Seconds()}, args...)...)
}

// appName is the exe name for uid, or "?" if the owner is unknown.
func (b *bridge) appName(uid int32) string {
	if p := b.apps.path(uid); p != "" {
		return filepath.Base(p)
	}
	return "?"
}

func proto(p int32) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	}
	return strconv.Itoa(int(p))
}

var errNoOwner = errors.New("fswin: no owner lookup for protocol")

// ownerPID finds the process behind a flow from the Windows side: src is the
// program's local address (on the tunnel adapter), dst the remote.
func ownerPID(protocol int32, src, dst string) (uint32, error) {
	s, err := netip.ParseAddrPort(src)
	if err != nil {
		return 0, err
	}
	switch protocol {
	case 6:
		d, err := netip.ParseAddrPort(dst)
		if err != nil {
			return 0, err
		}
		return owner.TCP4(s, d)
	case 17:
		return owner.UDP4(s)
	}
	return 0, errNoOwner
}

// SocketListener

func (b *bridge) Preflow(protocol, uid int32, src, dst *x.Gostr) *intra.PreMark {
	pid, err := ownerPID(protocol, src.V(), dst.V())
	if err != nil {
		return &intra.PreMark{UID: strconv.Itoa(unknownUID)}
	}
	if pid == b.selfpid {
		// our own socket should have been bound out of the tunnel
		return &intra.PreMark{UID: strconv.Itoa(int(b.selfuid)), IsUidSelf: true}
	}
	path, err := owner.ExePath(pid)
	if err != nil {
		path = "pid" + strconv.FormatUint(uint64(pid), 10)
	}
	return &intra.PreMark{UID: strconv.Itoa(int(b.apps.uid(path)))}
}

func (b *bridge) Flow(protocol, uid int32, src, dst, origdsts, domains, probableDomains, blocklists *x.Gostr) *intra.Mark {
	cid := strconv.FormatInt(b.cid.Add(1), 10)
	pid := b.exitID()
	verdict := ""
	if b.isBlocked(b.apps.path(uid)) {
		pid = x.Block
		verdict = " BLOCKED"
	}
	b.logf("flow  #%s %s %s %s -> %s [%s]%s",
		cid, proto(protocol), b.appName(uid), src.V(), dst.V(), domains.V(), verdict)
	return &intra.Mark{PIDCSV: pid, CID: cid, UID: strconv.Itoa(int(uid))}
}

func (b *bridge) Inflow(protocol, uid int32, src, dst *x.Gostr) *intra.Mark {
	cid := strconv.FormatInt(b.cid.Add(1), 10)
	b.logf("inflow #%s %s %s -> %s", cid, proto(protocol), src.V(), dst.V())
	return &intra.Mark{PIDCSV: x.Base, CID: cid, UID: strconv.Itoa(int(uid))}
}

func (b *bridge) PostFlow(m *intra.Mark) {}

func (b *bridge) OnSocketClosed(s *intra.SocketSummary) {
	if s == nil {
		return
	}
	b.logf("close #%s %s -> %s via %s rx %d tx %d %dms %s",
		s.ID, s.Proto, s.Target, s.PID, s.Rx, s.Tx, s.Duration, s.Msg)
}

// DNSListener

func (b *bridge) OnQuery(uid, domain *x.Gostr, qtyp int) *x.DNSOpts {
	return &x.DNSOpts{TIDCSV: x.Preferred, PIDCSV: b.exitID()}
}

func (b *bridge) OnUpstreamAnswer(smm *x.DNSSummary, unmodifiedipcsv *x.Gostr) *x.DNSOpts {
	return nil // keep the answer
}

func (b *bridge) OnResponse(s *x.DNSSummary) {
	if s == nil {
		return
	}
	b.logf("dns   %s (type %d) -> %s via %s %.0fms status %d %s",
		s.QName, s.QType, s.RData, s.ID, s.Latency*1000, s.Status, s.Msg)
}

func (b *bridge) OnDNSAdded(id *x.Gostr)   { b.logf("dns transport added: %s", id.V()) }
func (b *bridge) OnDNSRemoved(id *x.Gostr) { b.logf("dns transport removed: %s", id.V()) }
func (b *bridge) OnDNSStopped()            { b.logf("dns stopped") }

// ServerListener: fswin runs no local proxy servers; refuse anything.

func (b *bridge) SvcRoute(sid, pid, network, sipport, dipport string) *x.Tab {
	return &x.Tab{CID: sid, Block: true}
}

func (b *bridge) OnSvcComplete(*x.ServerSummary) {}

// ProxyListener

func (b *bridge) OnProxyAdded(id *x.Gostr)   { b.logf("proxy added: %s", id.V()) }
func (b *bridge) OnProxyRemoved(id *x.Gostr) { b.logf("proxy removed: %s", id.V()) }
func (b *bridge) OnProxyStopped(id *x.Gostr) { b.logf("proxy stopped: %s", id.V()) }
func (b *bridge) OnProxiesStopped()          { b.logf("proxies stopped") }

// Controller: firestack's own sockets go out of the physical default
// interface (IP_UNICAST_IF), so in -full mode they do not loop back into the
// tunnel. The Windows stand-in for Android's VpnService.protect.

func (b *bridge) Bind4(who, addrport string, fd int) {
	if err := b.binder.Bind4(uintptr(fd)); err != nil {
		b.logf("bind4 %s %s: %v", who, addrport, err)
	}
}

func (b *bridge) Bind6(who, addrport string, fd int) {
	// IPv4-only networks have no IPv6 default route; nothing to pin to.
	if err := b.binder.Bind6(uintptr(fd)); err != nil && !errors.Is(err, ifbind.ErrNoDefault) {
		b.logf("bind6 %s %s: %v", who, addrport, err)
	}
}

func (b *bridge) Protect(who string, fd int) {
	if err := b.binder.Protect(uintptr(fd)); err != nil {
		b.logf("protect %s: %v", who, err)
	}
}

// Console: Go logs already go to stderr.

func (b *bridge) Log(level int32, msg *x.Gostr) { fmt.Fprintln(os.Stderr, msg.V()) }
func (b *bridge) LogFD(readAfterDup int) bool   { return false }
func (b *bridge) CrashFD(readUntilEOF int) bool { return false }
