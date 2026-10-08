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
	"github.com/miekg/dns"
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
// flow, applies the firewall rules (rules_windows.go), sends DNS to the
// chosen transport, and records what it sees.
type bridge struct {
	start  time.Time
	cid    atomic.Int64
	binder *ifbind.Binder
	apps   *apps
	rulemu sync.Mutex // serializes rule updates
	rules  atomic.Pointer[rules]
	conns  *connTable
	closer atomic.Value // func(cidcsv string) string: the tunnel's CloseConns
	dnsWhy *whyCache    // why recent queries were answered by BlockAll
	log    *journal
	bypass atomic.Value // string: lowercased exe path let straight out (usque)
	dnsTID atomic.Value // string: transport DNS queries go to

	routes atomic.Pointer[map[string]string] // per-app routes that loaded: id -> name
	tun    atomic.Value                      // intra.Tunnel, for proxy stats

	dnsDirect bool // never send DNS through the exit
	dnsCache  bool // "DNS booster": answer repeat lookups from the cache
	dnssec    bool // block bogus (bogon) answers, as DnsSecGuard does
	selfpid   uint32
	selfuid   int32
	exit      atomic.Value // string: proxy id for allowed flows and DNS
}

var _ intra.Bridge = (*bridge)(nil)

func newBridge(binder *ifbind.Binder, initial *rules, blockcsv string) *bridge {
	b := &bridge{
		start:   time.Now(),
		binder:  binder,
		apps:    newApps(),
		conns:   newConnTable(),
		dnsWhy:  newWhyCache(),
		selfpid: windows.GetCurrentProcessId(),
		log:     newJournal(),
	}
	if initial == nil {
		initial, _ = compileRules(ruleSet{})
	}
	b.rules.Store(initial)
	self, err := os.Executable()
	if err != nil {
		self = "fswin.exe"
	}
	b.selfuid = b.apps.uid(self)
	for _, s := range strings.Split(blockcsv, ",") {
		b.setBlocked(s, true)
	}
	return b
}

// setBypass lets the program at path connect directly, never through the
// exit: usque's own connections to Cloudflare would otherwise loop into it.
func (b *bridge) setBypass(path string) {
	b.bypass.Store(strings.ToLower(path))
}

func (b *bridge) isBypass(path string) bool {
	p, ok := b.bypass.Load().(string)
	return ok && p != "" && strings.EqualFold(p, path)
}

// setDNS sends DNS queries to transport tid (Preferred or System).
func (b *bridge) setDNS(tid string) {
	b.dnsTID.Store(tid)
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

// setRules swaps in a new rule set and closes the open connections it now
// blocks. Rules that do not parse are skipped and reported in err.
func (b *bridge) setRules(rs ruleSet) error {
	r, err := compileRules(rs)
	b.rulemu.Lock()
	b.rules.Store(r)
	b.rulemu.Unlock()
	b.enforce()
	return err
}

// setBlocked blocks or unblocks app, an exe name or a full path, keeping
// its other settings.
func (b *bridge) setBlocked(app string, block bool) {
	app = strings.ToLower(strings.TrimSpace(app))
	if app == "" {
		return
	}
	b.rulemu.Lock()
	rs := b.rules.Load().src
	apps := make(map[string]appRule, len(rs.Apps)+1)
	for k, v := range rs.Apps {
		apps[strings.ToLower(k)] = v
	}
	a := apps[app]
	if block {
		a.Mode = modeBlock
	} else if a.Mode == modeBlock {
		a.Mode = modeNone
	}
	a.AllowUntil = 0
	if a == (appRule{}) {
		delete(apps, app)
	} else {
		apps[app] = a
	}
	rs.Apps = apps
	r, _ := compileRules(rs)
	b.rules.Store(r)
	b.rulemu.Unlock()
	b.enforce()
}

// blockedApps lists the blocked exe names and paths, sorted.
func (b *bridge) blockedApps() []string {
	r := b.rules.Load()
	out := make([]string, 0, len(r.apps))
	for k, a := range r.apps {
		if a.Mode == modeBlock {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

func (b *bridge) blockedList() string {
	return strings.Join(b.blockedApps(), ", ")
}

// decide applies the rules to a flow from the program at path.
func (b *bridge) decide(protocol int32, path string, dst netip.AddrPort, domains []string) decision {
	if b.isBypass(path) {
		return decision{noProxy: true, why: "usque"}
	}
	r := b.rules.Load()
	return r.decide(protocol, path, r.knownApp(path), dst, domains, time.Now())
}

// enforce closes the open connections the current rules block, as the
// Android app does when a rule changes.
func (b *bridge) enforce() {
	var cids []string
	for cid, c := range b.conns.all() {
		if d := b.decide(c.proto, b.apps.path(c.uid), c.dst, c.domains); d.block {
			cids = append(cids, cid)
		}
	}
	b.closeConns(cids)
}

// closeApp closes the open connections of app (exe name or path), or all
// of them if app is "".
func (b *bridge) closeApp(app string) int {
	app = strings.ToLower(strings.TrimSpace(app))
	var cids []string
	for cid, c := range b.conns.all() {
		full, exe := appKeys(b.apps.path(c.uid))
		if app == "" || app == full || app == exe {
			cids = append(cids, cid)
		}
	}
	b.closeConns(cids)
	return len(cids)
}

func (b *bridge) closeConns(cids []string) {
	if len(cids) == 0 {
		return
	}
	if f, ok := b.closer.Load().(func(string) string); ok && f != nil {
		closed := f(strings.Join(cids, ","))
		b.logf("closed %d connections: %s", len(cids), closed)
	}
}

// splitDomains turns firestack's domain csvs into a lowercased list,
// preferring the domains looked up by this app over probable ones.
func splitDomains(domains, probable string) (out []string) {
	csv := domains
	if strings.TrimSpace(csv) == "" {
		csv = probable
	}
	for _, d := range strings.Split(csv, ",") {
		if d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), ".")); d != "" {
			out = append(out, d)
		}
	}
	return
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
	switch dst.V() {
	case fakedns4 + ":53":
		// a query to our DNS address: firestack answers it only when marked
		// Base, whatever the exit, and it shows in the DNS log, not as a flow
		return &intra.Mark{PIDCSV: x.Base, CID: cid, UID: strconv.Itoa(int(uid))}
	case fakedns4 + ":853":
		// DNS over TLS to our address, which we do not serve; as the Android
		// app does, refuse it so Windows falls back to plain DNS on :53
		return &intra.Mark{PIDCSV: x.Block, CID: cid, UID: strconv.Itoa(int(uid))}
	}
	path := b.apps.path(uid)
	dap, _ := netip.ParseAddrPort(dst.V()) // zero if unparsable: IP rules then skip it
	doms := splitDomains(domains.V(), probableDomains.V())
	d := b.decide(protocol, path, dap, doms)
	pid := b.exitID()
	verdict := ""
	if d.block {
		pid = x.Block
		verdict = " BLOCKED"
	} else if d.noProxy {
		pid = x.Base
	} else if d.route != "" && b.routeName(d.route) != "" {
		pid = d.route
	}
	app := b.appName(uid)
	via := exitName(pid)
	if n := b.routeName(pid); n != "" {
		via = n
	}
	b.logf("flow  #%s %s %s %s -> %s [%s]%s %s",
		cid, proto(protocol), app, src.V(), dst.V(), strings.Join(doms, ","), verdict, d.why)
	domain := ""
	if len(doms) > 0 {
		domain = doms[0]
	}
	b.log.flows.Add(1)
	if d.block {
		b.log.flowsBlocked.Add(1)
	} else {
		b.conns.add(cid, liveConn{uid: uid, proto: protocol, dst: dap, domains: doms, app: app, at: time.Now().UnixMilli()})
	}
	b.log.add(event{Kind: "flow", App: app, Proto: proto(protocol), Dst: dst.V(),
		Domain: domain, Via: via, Blocked: d.block, Rule: d.why, CID: cid})
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
	b.conns.remove(s.ID)
	b.log.rx.Add(s.Rx)
	b.log.tx.Add(s.Tx)
	app := "?"
	if u, err := strconv.ParseInt(s.UID, 10, 32); err == nil {
		app = b.appName(int32(u))
	}
	b.log.add(event{Kind: "close", App: app, Proto: s.Proto, Dst: s.Target,
		Via: exitName(s.PID), Rx: s.Rx, Tx: s.Tx, DurMs: s.Duration, CID: s.ID})
}

// DNSListener

func (b *bridge) OnQuery(uid, domain *x.Gostr, qtyp int) *x.DNSOpts {
	tid, _ := b.dnsTID.Load().(string)
	if tid == "" {
		tid = x.Preferred
	}
	if b.dnsCache && tid != x.BlockAll && !strings.HasPrefix(tid, x.CT) {
		tid = x.CT + tid // as the Android app does for its DNS booster
	}
	pid := b.exitID()
	if b.dnsDirect {
		pid = x.Base
	}
	block, trust, why := b.rules.Load().dnsVerdict(domain.V(), qtyp, time.Now().UnixMilli())
	if block {
		b.dnsWhy.put(domain.V(), why)
		b.log.dnsBlocked.Add(1)
		return &x.DNSOpts{TIDCSV: x.BlockAll, PIDCSV: x.Base}
	}
	return &x.DNSOpts{TIDCSV: tid, PIDCSV: pid, NOBLOCK: trust}
}

// OnUpstreamAnswer blocks bogus answers when the DNSSEC switch is on: a
// public name answered with a bogon address is re-answered by BlockAll.
func (b *bridge) OnUpstreamAnswer(smm *x.DNSSummary, unmodifiedipcsv *x.Gostr) *x.DNSOpts {
	if !b.dnssec || smm == nil || isLocalName(smm.QName) {
		return nil // keep the answer
	}
	bad := bogonsIn(unmodifiedipcsv.V())
	if len(bad) == 0 {
		return nil
	}
	b.log.dnsBogus.Add(1)
	b.dnsWhy.put(smm.QName, "DNSSEC: bogus answer "+strings.Join(bad, ","))
	b.logf("dnssec: %s answered with bogus %v via %s (AD %t); blocked", smm.QName, bad, smm.ID, smm.AD)
	return &x.DNSOpts{TIDCSV: x.BlockAll, PIDCSV: x.Base}
}

func (b *bridge) OnResponse(s *x.DNSSummary) {
	if s == nil {
		return
	}
	b.logf("dns   %s (type %d) -> %s via %s (%s) %.0fms status %d rcode %d %s",
		s.QName, s.QType, s.RData, s.ID, s.Server, s.Latency*1000, s.Status, s.RCode, s.Msg)
	ms := int64(s.Latency * 1000)
	b.log.dnsQueries.Add(1)
	failure := ""
	if s.Status != x.Complete {
		b.log.dnsFailed.Add(1)
		failure = dnsFailure(s)
	} else if badRcode(s) {
		// answered, but with an error such as SERVFAIL or REFUSED
		b.log.dnsFailed.Add(1)
		failure = fmt.Sprintf("%s answered %s", dnsServer(s), dns.RcodeToString[s.RCode])
	} else {
		b.log.dnsLastMs.Store(ms)
		b.log.dnsTotalMs.Add(ms)
	}
	why := ""
	if strings.HasSuffix(s.ID, x.BlockAll) {
		why = b.dnsWhy.get(s.QName)
	}
	if why == "" && s.Blocklists != "" {
		why = "blocklists: " + s.Blocklists
	}
	app := ""
	if u, err := strconv.ParseInt(s.UID, 10, 32); err == nil {
		app = b.appName(int32(u)) // who asked; "?" if unknown
	}
	b.log.add(event{Kind: "dns", App: app, Domain: strings.TrimSuffix(s.QName, "."), Answer: s.RData,
		Via: s.ID, LatencyMs: ms, Blocked: why != "" || (s.Status == x.Complete && isUnspecifiedAnswer(s.RData)),
		Secure: s.AD, Cached: s.Cached, Rule: why, QType: s.QType, Error: failure})
}

// dnsFailure says why a query got no answer, from firestack's summary, in
// words a user can act on: a timeout means the server was never reached.
func dnsFailure(s *x.DNSSummary) string {
	why := dnsFailureMsg(s)
	switch {
	case strings.Contains(why, "timeout"):
		return fmt.Sprintf("no reply from %s in %.0f s (%s)", dnsServer(s), s.Latency, why)
	case strings.HasPrefix(why, "http-status: "):
		return fmt.Sprintf("%s answered HTTP %s", dnsServer(s), strings.TrimPrefix(why, "http-status: "))
	}
	return why
}

// badRcode reports an upstream answer that is an error. NXDOMAIN is a
// real answer, and blocked names are answered by BlockAll on purpose.
func badRcode(s *x.DNSSummary) bool {
	return s.RCode != dns.RcodeSuccess && s.RCode != dns.RcodeNameError && !strings.HasSuffix(s.ID, x.BlockAll)
}

func dnsServer(s *x.DNSSummary) string {
	if s.Server != "" {
		return s.Server
	}
	return "the DNS server"
}

func dnsFailureMsg(s *x.DNSSummary) string {
	if s.Msg != "" {
		return s.Msg
	}
	switch s.Status {
	case x.SendFailed:
		return "could not send the query to the DNS server"
	case x.NoResponse:
		return "the DNS server did not answer"
	case x.BadQuery:
		return "bad query"
	case x.BadResponse:
		return "bad answer from the DNS server"
	case x.TransportError:
		return "could not reach the DNS server"
	case x.ClientError:
		return "DNS client error"
	case x.InternalError:
		return "internal error"
	case x.Paused:
		return "DNS is paused"
	case x.DEnd:
		return "DNS stopped"
	}
	return fmt.Sprintf("status %d", s.Status)
}

// isUnspecifiedAnswer reports answers of 0.0.0.0 / ::, which is how
// blocklists answer blocked names.
func isUnspecifiedAnswer(rdata string) bool {
	if rdata == "" {
		return false
	}
	for _, a := range strings.Split(rdata, ",") {
		ip, err := netip.ParseAddr(strings.TrimSpace(a))
		if err != nil || !ip.IsUnspecified() {
			return false
		}
	}
	return true
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
