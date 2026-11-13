// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build linux

// fswin on Linux: the same engine, on a kernel TUN device.
//
//	sudo fswin -full            all IPv4 through the tunnel
//	sudo fswin -cleanup         undo what a killed fswin left behind
//
// What Windows does with Wintun, IP Helper, NRPT and WFP is done here with
// /dev/net/tun, ip(8) policy routing on a firewall mark (win/ifbind),
// systemd-resolved or /etc/resolv.conf, and nftables (win/wfp).
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/celzero/firestack/intra"
	x "github.com/celzero/firestack/intra/backend"
	flog "github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/win/ifbind"
	"github.com/celzero/firestack/win/wfp"
	"golang.org/x/sys/unix"
)

// validAdapterName keeps -name to what the kernel takes as an interface name.
var validAdapterName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,14}$`).MatchString

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
	o.golog = int32(golog) //nolint:gosec // G115: a log level
	if o.service != "" {
		// AuroraVPN Service, run by systemd (auroravpn.service)
		if os.Geteuid() != 0 {
			fmt.Fprintln(os.Stderr, "fswin: -service needs root: systemd runs it (auroravpn.service)")
			os.Exit(1)
		}
		if err := serviceMain(o.service, o.serviceApp); err != nil {
			fmt.Fprintln(os.Stderr, "fswin:", err)
			os.Exit(1)
		}
		return
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "fswin: needs root: it makes a TUN device, routes and firewall rules (run it with sudo)")
		os.Exit(1)
	}
	// the app's files are opened with the user's rights (asuser_linux.go)
	var tok *userToken
	var err error
	if o.userToken != 0 {
		tok, err = newUserTokenFrom(o.userToken)
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
	began := time.Now()
	if !validAdapterName(o.name) {
		return fmt.Errorf("-name %q: up to 15 letters, digits, dots, dashes or underscores", o.name)
	}
	if o.cleanup {
		if err := cleanup(o.name); err != nil {
			return err
		}
		fmt.Println("fswin: removed fswin's DNS setting, routing rules and kill switch, if any")
		return nil
	}
	// a stop asked for during the start is not lost
	stop := make(chan os.Signal, 2)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	stopping := make(chan struct{})
	var stopOnce sync.Once
	asked := "" // who asked to stop
	askStop := func(who string) { stopOnce.Do(func() { asked = who; close(stopping) }) }
	go func() {
		<-stop
		askStop("")
	}()

	intra.LogLevel(o.golog, 8 /*no console logs; Go logs go to stderr*/)

	// fail before changing anything on the PC if the app could not reach us
	if o.api != "" {
		if err := apiPreflight(o.api, o.tokenFile); err != nil {
			return fmt.Errorf("api: %w", err)
		}
	}
	// what a killed fswin left would break this start (a second default
	// rule, a resolv.conf pointing at a tunnel that is gone)
	_ = dropRouting()
	restoreDNS(o.name, false)

	if o.full || o.kill || o.wg != "" || o.warp || o.proxy != "" || o.masque || o.chain != "" {
		if !waitForNetwork(networkWait, stopping) {
			select {
			case <-stopping:
				fmt.Println("fswin: stopping")
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
	link, linkWhy := linkMTU(0)
	plan := planMTU(link, linkWhy, exitID, exitCfg, us, o.mtu)
	curMTU.Store(&plan)
	if us != nil {
		us.link = plan.Link
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

	fd, err := openTun(o.name)
	if err != nil {
		return fmt.Errorf("create TUN device %s (is the tun module loaded?): %w", o.name, err)
	}
	// the tunnel works on its own copy of fd; the device lives until both close
	defer func() { _ = unix.Close(fd) }()
	startStep(began, "adapter created")
	name := o.name
	if err := configure(name, plan.Adapter); err != nil {
		return err
	}
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("find adapter %s: %w", name, err)
	}
	tunIndex := uint32(ifc.Index) //nolint:gosec // G115: an interface index
	binder := ifbind.New(tunIndex)
	phys4, _ := binder.Indexes()
	if o.full && phys4 == 0 {
		return errors.New("-full: no IPv4 default route outside the tunnel to send firestack's own traffic over")
	}
	startStep(began, "adapter configured")

	kill := newKillSwitch(wfp.Options{TunName: name, Mark: ifbind.Mark, AllowLAN: o.allowLAN}, o.full)
	killMode := ""
	if o.kill {
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
		return fmt.Errorf("default dns: %w", err)
	}
	intra.UndelegatedDomains(o.undelegated)
	intra.DefaultDNSAsFallback(o.dnsFallback)

	var initial *rules
	if o.rulesFile != "" {
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
	b.luid = uint64(tunIndex) // adapterBytes reads the interface's counters by it
	b.dnsDirect = o.dnsDirect
	b.dnsCache = o.dnsCache
	b.dnssec = o.dnssec
	if us != nil {
		b.setBypass(us.exe) // its own connections to Cloudflare
	}
	if exitID != "" {
		b.setExit(exitID)
	}
	t, err := intra.Connect(fd, plan.Link, plan.Adapter, ifaddr4+"/24", fakedns4+":53", dtr, b)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	dnsSet := false
	defer func() {
		if dnsSet {
			restoreDNS(name, true)
			stopStep("DNS restored")
		}
		_ = dropRouting()
		t.Disconnect()
		stopStep("tunnel and adapter removed")
		if kill.isOn() {
			if err := kill.set(false, false); err != nil {
				fmt.Fprintln(os.Stderr, "fswin: remove kill switch (run fswin -cleanup):", err)
			}
			stopStep("kill switch removed")
		}
	}()
	mtuDone := make(chan struct{})
	defer close(mtuDone) // before Disconnect
	go watchLinkMTU(t, tunIndex, mtuDone)
	b.closer.Store(func(csv string) string { return t.CloseConns(csv) })
	b.tun.Store(t)
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

	// the system's DNS goes to the tunnel last, once it answers
	if o.setdns || o.nrpt {
		how, err := setSystemDNS(name)
		if err != nil {
			return fmt.Errorf("system DNS: %w", err)
		}
		dnsSet = true
		fmt.Println("fswin: system DNS set through", how)
	}

	mode := "DNS only"
	if o.full {
		if err := fullTunnel(name); err != nil {
			return err
		}
		mode = fmt.Sprintf("all IPv4; firestack's own traffic leaves via interface #%d", phys4)
	}
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
		if uq != nil && us != nil {
			sup := supervise(*us, uq, tunIndex, func(url string) error {
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

	if o.api != "" {
		started := time.Now()
		srv, err := serveAPI(o.api, o.tokenFile, b,
			func() apiStatus { return statusOf(b, o, started, exitID, dnsLabel) },
			func() { askStop(" (requested by the app)") })
		if err != nil {
			return fmt.Errorf("api: %w", err)
		}
		defer srv.Close()
		fmt.Printf("fswin: control API on %s\n", o.api)
	}

	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-stopping:
			fmt.Println("fswin: stopping" + asked)
			stopAt = time.Now()
			return nil
		case <-tick.C:
			if st, err := t.Stat(); err == nil && st != nil {
				b.logf("tun   %s", st.TUNSt.EpStats)
			}
			idx, _ := binder.Indexes()
			for _, c := range b.setConflicts(findConflicts(idx)) {
				fmt.Printf("fswin: warning: %s; disconnect that VPN\n", c)
			}
		}
	}
}

// findConflicts lists what breaks the tunnel: another VPN's interface
// carrying the default route.
func findConflicts(phys4 uint32) []string {
	out := []string{}
	if name, desc, vpn := ifbind.Describe(phys4); vpn {
		out = append(out, fmt.Sprintf("internet traffic leaves through another VPN's adapter: %s (%s)", name, desc))
	}
	return out
}

// redirectOutput sends stdout, stderr and the loggers to path, the app's
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
	w := &cappedLog{f: f, path: filepath.Clean(path), limit: logLimit}
	log.SetOutput(w)
	flog.SetOutput(w)
	fd := int(f.Fd()) //nolint:gosec // G115: a file descriptor
	if err := errors.Join(unix.Dup2(fd, 1), unix.Dup2(fd, 2)); err != nil {
		return err
	}
	return nil
}
