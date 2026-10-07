// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

// fswin runs firestack on a Wintun adapter in DNS-only mode and logs every
// DNS query and connection it sees. It is a Phase 1 test tool, not the app:
// only DNS is routed into the tunnel; all other traffic is untouched.
// IPv4 only for now: the adapter gets no IPv6 address or DNS server.
//
// Run from an elevated prompt, with wintun.dll (from www.wintun.net) next to
// fswin.exe:
//
//	fswin.exe -doh https://cloudflare-dns.com/dns-query -doh-ips 1.1.1.1,1.0.0.1
//
// Press Ctrl+C to stop; the adapter is removed on exit.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/celzero/firestack/intra"
	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/netstack"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	ifaddr4  = "10.111.222.1"
	fakedns4 = "10.111.222.3"
)

func main() {
	name := flag.String("name", "port1897", "Wintun adapter name")
	mtu := flag.Int("mtu", 1500, "adapter MTU")
	doh := flag.String("doh", "https://cloudflare-dns.com/dns-query", "DoH server URL")
	dohips := flag.String("doh-ips", "1.1.1.1,1.0.0.1", "comma-separated IPs of the DoH server")
	setdns := flag.Bool("set-dns", true, "point the adapter's DNS at the tunnel and give it the lowest metric")
	golog := flag.Int("log", 3, "firestack log level: 0 very verbose ... 5 errors, 8 none")
	flag.Parse()

	if err := run(*name, *mtu, *doh, *dohips, *setdns, int32(*golog)); err != nil {
		fmt.Fprintln(os.Stderr, "fswin:", err)
		os.Exit(1)
	}
}

func run(name string, mtu int, doh, dohips string, setdns bool, golog int32) error {
	intra.LogLevel(golog, 8 /*no console logs; Go logs go to stderr*/)

	tun.WintunTunnelType = "port1897"
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return fmt.Errorf("create wintun adapter (run as admin, wintun.dll next to the exe?): %w", err)
	}
	if n, err := dev.Name(); err == nil {
		name = n
	}
	// netstack owns dev from here and closes it (removing the adapter) on Disconnect.
	id := netstack.RegisterTun(dev)

	if err := configure(name, setdns); err != nil {
		_ = dev.Close()
		return err
	}

	ipports := withPort(dohips, "443")
	dtr, err := intra.NewDefaultDNS(x.StrOf(x.DOH), x.StrOf(doh), x.StrOf(ipports))
	if err != nil {
		_ = dev.Close()
		return fmt.Errorf("default dns: %w", err)
	}

	b := &bridge{start: time.Now()}
	t, err := intra.Connect(id, mtu, mtu, ifaddr4+"/24", fakedns4, dtr, b)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer t.Disconnect()

	if err := intra.AddDoHTransport(t, x.StrOf(x.Preferred), x.StrOf(doh), x.StrOf(dohips)); err != nil {
		return fmt.Errorf("add doh %s: %w", doh, err)
	}

	fmt.Printf("fswin: up on %q; DNS %s -> %s. Ctrl+C to stop.\n", name, fakedns4, doh)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
	fmt.Println("fswin: stopping")
	return nil
}

// configure gives the adapter its IPv4 address and, if setdns, makes Windows
// send DNS to the tunnel. Windows may still query other adapters' DNS servers
// (including over IPv6) in parallel; the app will need NRPT and firewall
// rules to stop that.
func configure(name string, setdns bool) error {
	cmds := [][]string{
		{"interface", "ipv4", "set", "address", "name=" + name, "source=static", "address=" + ifaddr4, "mask=255.255.255.0"},
	}
	if setdns {
		cmds = append(cmds,
			[]string{"interface", "ipv4", "set", "dnsservers", "name=" + name, "source=static", "address=" + fakedns4, "register=none", "validate=no"},
			[]string{"interface", "ipv4", "set", "interface", "interface=" + name, "metric=1"},
		)
	}
	for _, args := range cmds {
		out, err := exec.Command("netsh", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("netsh %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// withPort turns "1.1.1.1,2606:4700::1111" into "1.1.1.1:443,[2606:4700::1111]:443".
func withPort(csv, port string) string {
	var out []string
	for _, ip := range strings.Split(csv, ",") {
		if ip = strings.TrimSpace(ip); ip != "" {
			out = append(out, net.JoinHostPort(ip, port))
		}
	}
	return strings.Join(out, ",")
}

// bridge answers firestack's callbacks: it allows everything, sends DNS to
// the Preferred (DoH) transport, and prints what it sees.
type bridge struct {
	start time.Time
	cid   atomic.Int64
}

var _ intra.Bridge = (*bridge)(nil)

func (b *bridge) logf(format string, args ...any) {
	fmt.Printf("%8.3fs "+format+"\n", append([]any{time.Since(b.start).Seconds()}, args...)...)
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

// SocketListener

func (b *bridge) Preflow(protocol, uid int32, src, dst *x.Gostr) *intra.PreMark {
	// TODO(phase 2): find the owning process (GetExtendedTcpTable/UdpTable).
	return &intra.PreMark{UID: "-1"}
}

func (b *bridge) Flow(protocol, uid int32, src, dst, origdsts, domains, probableDomains, blocklists *x.Gostr) *intra.Mark {
	cid := strconv.FormatInt(b.cid.Add(1), 10)
	b.logf("flow  #%s %s %s -> %s domains[%s] blocklists[%s]",
		cid, proto(protocol), src.V(), dst.V(), domains.V(), blocklists.V())
	return &intra.Mark{PIDCSV: x.Base, CID: cid, UID: strconv.Itoa(int(uid))}
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
	return &x.DNSOpts{TIDCSV: x.Preferred, PIDCSV: x.Base}
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

// Controller: in DNS-only mode the default route stays on the physical
// network, so firestack's own sockets need no binding. Full-tunnel mode will
// bind them to the physical interface with IP_UNICAST_IF / IPV6_UNICAST_IF.

func (b *bridge) Bind4(who, addrport string, fd int) {}
func (b *bridge) Bind6(who, addrport string, fd int) {}
func (b *bridge) Protect(who string, fd int)         {}

// Console: Go logs already go to stderr.

func (b *bridge) Log(level int32, msg *x.Gostr) { fmt.Fprintln(os.Stderr, msg.V()) }
func (b *bridge) LogFD(readAfterDup int) bool   { return false }
func (b *bridge) CrashFD(readUntilEOF int) bool { return false }
