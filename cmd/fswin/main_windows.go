// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

// fswin runs firestack on a Wintun adapter and logs every DNS query and
// connection it sees, with the program that made it. It is a test tool, not
// the app. By default only DNS goes through the tunnel; with -full, all IPv4
// traffic does, and -block can block programs by exe name.
// IPv4 only for now: the adapter gets no IPv6 address or DNS server.
//
// Run from an elevated prompt, with wintun.dll (from www.wintun.net) next to
// fswin.exe:
//
//	fswin.exe
//	fswin.exe -full -nrpt -block msedge.exe,notepad.exe
//
// Press Ctrl+C to stop; the adapter, its routes and the NRPT rule are removed
// on exit. If fswin is killed instead, run fswin -cleanup to restore DNS.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/celzero/firestack/intra"
	x "github.com/celzero/firestack/intra/backend"
	flog "github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/netstack"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/win/dnspolicy"
	"github.com/celzero/firestack/win/ifbind"
	"github.com/celzero/firestack/win/ipconf"
	"github.com/celzero/firestack/win/wfp"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

func main() {
	var o options
	var golog int
	defineFlags(&o, &golog)
	showVersion := flag.Bool("version", false, "print the build and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("fswin", version)
		return
	}
	o.golog = int32(golog)

	if o.service != "" {
		if err := serviceMain(o.service, o.serviceApp); err != nil {
			fmt.Fprintln(os.Stderr, "fswin: -service:", err)
			os.Exit(1)
		}
		return
	}

	// the app's files are opened with the user's rights (asuser_windows.go):
	// those of the user who asked the service, or else fswin's own, lowered
	var tok *userToken
	var err error
	if o.userToken != 0 {
		tok, err = newUserTokenFrom(windows.Token(o.userToken))
	} else {
		tok, err = newUserToken()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fswin:", err)
		os.Exit(1)
	}
	asUser.Store(tok)

	if o.logFile != "" {
		if err := redirectOutput(o.logFile); err != nil {
			fmt.Fprintln(os.Stderr, "fswin: -logfile:", err)
			os.Exit(1)
		}
	}

	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "fswin:", err)
		os.Exit(1)
	}
	stopStep("stopped")
}

func run(o options) error {
	began := time.Now() // for the "up in" line
	// AuroraVPN Service asks the engine it started to stop with an event
	serviceStop := make(chan struct{})
	if o.stopHandle != 0 {
		go func() {
			if ev, err := windows.WaitForSingleObject(windows.Handle(o.stopHandle), windows.INFINITE); err == nil && ev == windows.WAIT_OBJECT_0 {
				close(serviceStop)
			}
		}()
	}
	if !validAdapterName(o.name) {
		return fmt.Errorf("-name %q: up to 64 letters, digits, spaces, dots, dashes or underscores", o.name)
	}
	if o.cleanup {
		errDNS := dnspolicy.Remove()
		errKill := wfp.Disable()
		if err := errors.Join(errDNS, errKill); err != nil {
			return err
		}
		fmt.Println("fswin: removed fswin's NRPT rule and kill switch, if any")
		return nil
	}

	intra.LogLevel(o.golog, 8 /*no console logs; Go logs go to stderr*/)

	// fail before changing anything on the PC (adapter, routes, DNS rules,
	// firewall) if the app could not reach us anyway
	if o.api != "" {
		if err := apiPreflight(o.api, o.tokenFile); err != nil {
			return fmt.Errorf("api: %w", err)
		}
	}

	// all traffic in the tunnel needs a network outside it from the start
	if o.full || o.kill || o.wg != "" || o.warp || o.proxy != "" || o.masque || o.chain != "" {
		if !waitForNetwork(networkWait, serviceStop) {
			select {
			case <-serviceStop:
				fmt.Println("fswin: stopping (requested by AuroraVPN Service)")
				return nil
			default: // the -full check below says why it cannot start
			}
		}
	}

	// prepare the exit first: WARP registers over the normal network
	exitID, exitCfg, us, err := prepareExit(o)
	if err != nil {
		return err
	}
	// before the adapter exists, the default route is still the network's
	link, linkWhy := linkMTU(0)
	plan := planMTU(link, linkWhy, exitID, exitCfg, us, o.mtu)
	curMTU.Store(&plan)
	if us != nil {
		us.link = plan.Link // usque's QUIC packets fit the network (usqueDefaults)
	}
	fmt.Printf("fswin: MTU: %s\n", &plan)
	var uq *usque // started once all traffic goes to the tunnel
	defer func() { uq.stop() }()
	if exitID != "" || o.kill {
		o.full = true // a VPN exit and the kill switch need all traffic in the tunnel
	}

	if o.block != "" && !o.full {
		fmt.Println("fswin: -block needs -full: without it only DNS goes through the tunnel, and DNS is answered for every app")
	}

	tun.WintunTunnelType = "AuroraVPN"
	dev, err := tun.CreateTUN(o.name, plan.Adapter)
	if err != nil {
		return fmt.Errorf("create wintun adapter (run as admin, wintun.dll next to the exe?): %w", err)
	}
	startStep(began, "adapter created")
	name := o.name
	if n, err := dev.Name(); err == nil {
		name = n
	}
	// netstack owns dev from here and closes it (removing the adapter) on
	// Disconnect; closing it again waits for that (stopTunnel), and is how a
	// start that fails half way removes it.
	id := netstack.RegisterTun(dev)
	defer func() { _ = dev.Close() }()

	var luid uint64 // the adapter, for ipconf's calls
	if nt, ok := dev.(*tun.NativeTun); ok {
		luid = nt.LUID()
	}
	// The NRPT rule goes in before the adapter gets its DNS server: Windows'
	// DNS Client reloads its settings, NRPT rules among them, when that
	// changes. Written after, it was not in force (Simulate, PRs #26, #28).
	nrptSet := false // until stopTunnel drops it
	if o.nrpt {
		if err := dnspolicy.Add(netip.MustParseAddr(fakedns4)); err != nil {
			return err
		}
		nrptSet = true
		defer func() {
			if !nrptSet {
				return
			}
			if err := dnspolicy.Remove(); err != nil {
				fmt.Fprintln(os.Stderr, "fswin: remove NRPT rule (run fswin -cleanup):", err)
			}
		}()
		startStep(began, "NRPT rule set")
	}
	if err := configure(name, luid, o.setdns); err != nil {
		_ = dev.Close()
		return err
	}
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		_ = dev.Close()
		return fmt.Errorf("find adapter %s: %w", name, err)
	}
	binder := ifbind.New(uint32(ifc.Index))
	// this PC and its attached networks never take the default route; pinning
	// them to it would break DNS servers like Tor's on 127.0.0.1
	protect.SkipBind = binder.OnLink
	phys4, _ := binder.Indexes()
	if o.full && phys4 == 0 {
		_ = dev.Close()
		return errors.New("-full: no IPv4 default route outside the tunnel to send firestack's own traffic over")
	}
	startStep(began, "adapter configured")

	// The kill switch (on now for -killswitch, or later from the app's
	// button) goes on before fswin opens a connection of its own: turning it
	// on re-checks every open connection, and Windows cut fswin's own, DNS
	// among them, although the rules let fswin through.
	var kill *killSwitch
	if nt, ok := dev.(*tun.NativeTun); ok {
		var allow []string
		if us != nil {
			allow = append(allow, us.exe)
		}
		kill = newKillSwitch(wfp.Options{TunLUID: nt.LUID(), Allow: allow, Persistent: true, AllowLAN: o.allowLAN}, o.full)
	}
	defer func() {
		if kill.isOn() {
			if err := wfp.Disable(); err != nil {
				fmt.Fprintln(os.Stderr, "fswin: remove kill switch (run fswin -cleanup):", err)
			}
		}
	}()
	killMode := ""
	if o.kill {
		// without the kill switch protection still runs, rather than not at
		// all; the status carries the error and the app shows it
		if err := kill.set(true, o.allowLAN); err != nil {
			fmt.Println("fswin: warning: -killswitch: not on:", err)
			killMode = "; kill switch FAILED"
		} else {
			killMode = "; kill switch on"
		}
		startStep(began, "kill switch set")
	} else if cleared, err := kill.clearLeftover(); err != nil {
		fmt.Println("fswin: warning: a kill switch left by an earlier run may still block:", err)
	} else if cleared {
		fmt.Println("fswin: removed the kill switch an earlier run left on")
	}

	fbURL, fbIPs := o.fallbackDoH, o.fallbackIPs
	if fbURL == "" {
		fbURL, fbIPs = o.doh, o.dohips
	}
	dtr, err := intra.NewDefaultDNS(x.StrOf(x.DOH), x.StrOf(fbURL), x.StrOf(withPort(fbIPs, "443")))
	if err != nil {
		_ = dev.Close()
		return fmt.Errorf("default dns: %w", err)
	}
	intra.UndelegatedDomains(o.undelegated)
	intra.DefaultDNSAsFallback(o.dnsFallback)

	var initial *rules
	if o.rulesFile != "" {
		// blocked networks' ranges are kept next to the rules (asn_windows.go)
		asns.setDir(filepath.Join(filepath.Dir(o.rulesFile), "asn"))
		r, err := loadRulesFile(o.rulesFile)
		if r == nil {
			return fmt.Errorf("-rules: %w", err)
		}
		if err != nil {
			fmt.Println("fswin: -rules: skipped:", err)
		}
		initial = r
	}
	b := newBridge(binder, initial, o.block)
	b.kill = kill
	b.luid = luid
	b.dnsDirect = o.dnsDirect
	b.dnsCache = o.dnsCache
	b.dnssec = o.dnssec
	if us != nil {
		b.setBypass(us.exe) // its own connections to Cloudflare
	}
	// allowed flows and DNS go to the exit from the first packet: until it is
	// added, firestack holds a new flow 3 s for it and fails a query, rather
	// than letting either out direct
	if exitID != "" {
		b.setExit(exitID)
	}
	// fakedns must be ip:port; a bare ip is rejected and DNS goes unrecognized.
	t, err := intra.Connect(id, plan.Link, plan.Adapter, ifaddr4+"/24", fakedns4+":53", dtr, b)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	// after the API, the supervisor and usque (deferred later, so done first)
	defer stopTunnel(t, dev, luid, o.setdns, kill, &nrptSet)
	mtuDone := make(chan struct{})
	defer close(mtuDone) // before Disconnect
	go watchLinkMTU(t, uint32(ifc.Index), mtuDone)
	b.closer.Store(func(csv string) string { return t.CloseConns(csv) })
	b.tun.Store(t)
	// blocked networks are looked up once the tunnel is up, then checked
	// hourly: a week-old list is refreshed, a failed lookup tried again
	asnDone := make(chan struct{})
	defer close(asnDone)
	go func() {
		for {
			asns.refresh(asnNumbers(b.rules.Load().src.Universal.ASNs), b.recompile)
			select {
			case <-asnDone:
				return
			case <-time.After(time.Hour):
			}
		}
	}()
	if err := setDialer(o); err != nil {
		return err
	}
	intra.Transparency(o.eim, o.eim)
	if o.pcapFile != "" {
		// the app's file, opened with the user's rights; a capture starts
		// with its own header
		err := asUser.Load().do(func() error {
			_ = os.Remove(o.pcapFile)
			return t.SetPcap(o.pcapFile)
		})
		if err != nil {
			fmt.Println("fswin: -pcap:", err)
		} else {
			fmt.Println("fswin: capturing packets to", o.pcapFile)
		}
	}

	tid, dnsLabel, err := setupDNS(t, o, binder)
	if err != nil {
		return fmt.Errorf("dns: %w", err)
	}
	b.setDNS(tid)
	lists, err := setupBlocklists(t, o)
	if err != nil {
		fmt.Println("fswin: blocklists:", err)
	}
	if lists {
		dnsLabel += " + on-device blocklists"
	}
	startStep(began, "tunnel and DNS ready")

	if o.routesFile != "" {
		r, err := loadRoutes(t, o.routesFile)
		if err != nil {
			fmt.Println("fswin: routes:", err)
		}
		b.setRoutes(r)
		if len(r) > 0 {
			o.full = true // routes only see traffic in the tunnel
			kill.setFull(true)
		}
	}

	physName, physDesc, _ := ifbind.Describe(phys4)
	fmt.Printf("fswin: firestack's own traffic leaves via interface #%d %s (%s)\n", phys4, physName, physDesc)
	o.conflicts = append(o.conflicts, findConflicts(phys4)...)
	b.setConflicts(o.conflicts)
	for _, c := range o.conflicts {
		fmt.Printf("fswin: warning: %s; disconnect that VPN\n", c)
	}

	// The NRPT rule's backup (dnspolicy.Nudge), here as up to 0.2.22. Started
	// right after the rule, before the adapter had its address and the kill
	// switch was on, the time from the adapter's creation to the DNS setup
	// went from 3-4 s to 6.5 and 19.6 s (0.2.24 logs); ipconfig /registerdns
	// also renews every adapter's DHCP lease, the new one's among them.
	if nrptSet {
		n, err := dnspolicy.Nudge()
		if err != nil {
			fmt.Println("fswin: warning: the NRPT rule is set, but Windows may apply it late:", err)
		}
		go n.Wait(-1)
	}

	mode := "DNS only"
	if o.full {
		// routes go once the tunnel can carry traffic; they vanish with the adapter
		if err := fullTunnel(name, luid); err != nil {
			return err
		}
		mode = fmt.Sprintf("all IPv4; firestack's own traffic leaves via interface #%d", phys4)
	}
	// the exit comes once all traffic goes to the tunnel (see startUsque)
	if us != nil {
		if uq, err = startUsque(*us); err != nil {
			return err
		}
		exitCfg = uq.url
		startStep(began, "usque listening")
	}
	if exitID != "" {
		pxs, err := t.GetProxies()
		if err != nil {
			return fmt.Errorf("proxies: %w", err)
		}
		if _, err := pxs.AddProxy(x.StrOf(exitID), x.StrOf(exitCfg)); err != nil {
			return fmt.Errorf("add exit %s: %w", exitID, err)
		}
		if uq != nil {
			// keeps usque up: a restart within a second when it dies, and
			// when it lives on with no traffic (supervise_windows.go)
			sup := supervise(*us, uq, uint32(ifc.Index), func(url string) error {
				_, err := pxs.AddProxy(x.StrOf(exitID), x.StrOf(url))
				return err
			})
			curSup.Store(sup)
			defer func() {
				sup.stop() // before uq.stop above
				stopStep("usque stopped")
			}()
		}
	}
	mode += killMode
	if exitID != "" {
		mode += "; exit: " + exitName(exitID)
	}
	fmt.Printf("fswin %s: up on %q in %d ms (%s); DNS %s:53 -> %s. Ctrl+C to stop.\n", version, name, time.Since(began).Milliseconds(), mode, fakedns4, dnsLabel)
	if blocked := b.blockedList(); blocked != "" {
		fmt.Printf("fswin: blocking %s\n", blocked)
	}

	apiStop := make(chan struct{})
	if o.api != "" {
		started := time.Now()
		var once sync.Once
		srv, err := serveAPI(o.api, o.tokenFile, b,
			func() apiStatus { return statusOf(b, o, started, exitID, dnsLabel) },
			func() { once.Do(func() { close(apiStop) }) })
		if err != nil {
			return fmt.Errorf("api: %w", err)
		}
		defer srv.Close()
		fmt.Printf("fswin: control API on %s\n", o.api)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	// adapter byte counters show whether Windows sends anything our way
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			fmt.Println("fswin: stopping")
			stopAt = time.Now()
			return nil
		case <-apiStop:
			fmt.Println("fswin: stopping (requested by the app)")
			stopAt = time.Now()
			return nil
		case <-serviceStop:
			fmt.Println("fswin: stopping (requested by AuroraVPN Service)")
			stopAt = time.Now()
			return nil
		case <-tick.C:
			if st, err := t.Stat(); err == nil && st != nil {
				b.logf("tun   %s", st.TUNSt.EpStats)
			}
			// a VPN connected after the start (Proton VPN, 2026-10-10)
			// broke ours with nothing in the status to say why
			idx, _ := binder.Indexes()
			for _, c := range b.setConflicts(findConflicts(idx)) {
				fmt.Printf("fswin: warning: %s; disconnect that VPN\n", c)
			}
		}
	}
}

// findConflicts lists other VPNs that break ours: one whose NRPT rule claims
// all DNS races ours for every query, and firestack's own traffic leaving
// through another VPN's adapter (phys4) may never get answers.
func findConflicts(phys4 uint32) []string {
	out := []string{}
	if others, err := dnspolicy.Others(); err == nil {
		for _, r := range others {
			out = append(out, "another VPN sends all DNS elsewhere: "+r)
		}
	}
	if name, desc, vpn := ifbind.Describe(phys4); vpn {
		out = append(out, fmt.Sprintf("internet traffic leaves through another VPN's adapter: %s (%s)", name, desc))
	}
	return out
}

// stopTunnel is the stop once the API, the supervisor and usque are gone,
// in an order that lets nothing out of the tunnel while it is up and waits
// on nothing it need not:
//
//  1. The NRPT rule: its registry key goes, then the adapter's DNS server,
//     which makes the DNS Client reload its settings, the rule among them
//     (as the start relies on). ipconfig /registerdns, the backup, runs on
//     by itself; waiting up to 5 s for it held every stop up ("NRPT rule
//     removed after 7249 ms").
//  2. The tunnel, then the adapter and its routes: Disconnect only begins
//     that; closing the device again waits until the adapter is gone.
//  3. The kill switch last: until the adapter is gone nothing leaves outside
//     it, and a stop cut short (the service ends an engine still running
//     after 15 s) leaves the PC blocked rather than open, until -cleanup or
//     the next start.
//  4. The DNS cache is emptied once more, of answers from the tunnel.
func stopTunnel(t intra.Tunnel, dev tun.Device, luid uint64, setdns bool, kill *killSwitch, nrptSet *bool) {
	var nudge *dnspolicy.Nudging
	if *nrptSet {
		var err error
		nudge, err = dnspolicy.Drop()
		*nrptSet = false
		if err != nil {
			fmt.Fprintln(os.Stderr, "fswin: stop: NRPT rule (if DNS fails, run fswin -cleanup):", err)
		}
		if luid != 0 && setdns {
			if err := ipconf.ClearDNS(luid); err != nil {
				fmt.Fprintln(os.Stderr, "fswin: clear the adapter's DNS server:", err)
			}
		}
		stopStep("NRPT rule removed")
	}
	t.Disconnect()
	_ = dev.Close()
	stopStep("tunnel and adapter removed")
	if kill.isOn() {
		if err := kill.set(false, false); err != nil {
			fmt.Fprintln(os.Stderr, "fswin: remove kill switch (run fswin -cleanup):", err)
		}
		stopStep("kill switch removed")
	}
	if nudge != nil {
		nudge.Wait(0)
	}
}

// configure gives the adapter its IPv4 address and, if setdns, makes Windows
// send DNS to the tunnel. Windows may still query other adapters' DNS servers
// (including over IPv6) in parallel; the NRPT rule (-nrpt) stops that.
//
// It calls IP Helper directly (win/ipconf), in a few milliseconds; netsh, a
// program started per setting (about 0.2 s each), is the fallback.
func configure(name string, luid uint64, setdns bool) error {
	if luid != 0 {
		err := ipconf.SetAddress(luid, netip.PrefixFrom(netip.MustParseAddr(ifaddr4), 24))
		if err == nil && setdns {
			err = errors.Join(ipconf.SetDNS(luid, netip.MustParseAddr(fakedns4)), ipconf.SetMetric(luid, 1))
		}
		if err == nil {
			return nil
		}
		fmt.Println("fswin: configuring the adapter directly failed; using netsh:", err)
	}
	cmds := [][]string{
		{"interface", "ipv4", "set", "address", "name=" + name, "source=static", "address=" + ifaddr4, "mask=255.255.255.0"},
	}
	if setdns {
		cmds = append(cmds,
			[]string{"interface", "ipv4", "set", "dnsservers", "name=" + name, "source=static", "address=" + fakedns4, "register=none", "validate=no"},
			[]string{"interface", "ipv4", "set", "interface", "interface=" + name, "metric=1"},
		)
	}
	return netsh(cmds)
}

// fullTunnel sends all IPv4 traffic to the adapter with two /1 routes, which
// beat any 0.0.0.0/0 default route without replacing it. Directly through IP
// Helper (win/ipconf); netsh is the fallback.
func fullTunnel(name string, luid uint64) error {
	if luid != 0 {
		err := errors.Join(
			ipconf.AddRoute(luid, netip.MustParsePrefix("0.0.0.0/1"), 0),
			ipconf.AddRoute(luid, netip.MustParsePrefix("128.0.0.0/1"), 0),
		)
		if err == nil {
			return nil
		}
		fmt.Println("fswin: adding the routes directly failed; using netsh:", err)
	}
	return netsh([][]string{
		{"interface", "ipv4", "add", "route", "prefix=0.0.0.0/1", "interface=" + name, "nexthop=0.0.0.0", "metric=0", "store=active"},
		{"interface", "ipv4", "add", "route", "prefix=128.0.0.0/1", "interface=" + name, "nexthop=0.0.0.0", "metric=0", "store=active"},
	})
}

// systemTool is a program in System32, never one found through PATH, which
// the user's environment sets.
func systemTool(name string) string {
	if dir, err := windows.GetSystemDirectory(); err == nil {
		return filepath.Join(dir, name)
	}
	return name
}

func netsh(cmds [][]string) error {
	for _, args := range cmds {
		// netsh from System32, with plain arguments
		out, err := exec.Command(systemTool("netsh.exe"), args...).CombinedOutput() //nolint:gosec // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
		if err != nil {
			return fmt.Errorf("netsh %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// redirectOutput sends stdout, stderr and the standard logger to path, for
// when the app window starts fswin without a console. The log is the app's
// file: it is opened with the user's rights.
func redirectOutput(path string) error {
	var f *os.File
	err := asUser.Load().do(func() (err error) {
		f, err = os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		return err
	})
	if err != nil {
		return err
	}
	os.Stdout, os.Stderr = f, f
	w := &cappedLog{f: f, path: filepath.Clean(path), limit: logLimit}
	log.SetOutput(w)
	flog.SetOutput(w) // firestack's own logs, which say why a DNS query or dial failed
	_ = windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, windows.Handle(f.Fd()))
	_ = windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(f.Fd()))
	return nil
}
