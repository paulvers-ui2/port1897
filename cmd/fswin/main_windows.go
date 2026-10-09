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
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/win/dnspolicy"
	"github.com/celzero/firestack/win/ifbind"
	"github.com/celzero/firestack/win/wfp"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

// version is set at build time: -ldflags "-X main.version=<commit>".
var version = "dev"

const (
	ifaddr4  = "10.111.222.1"
	fakedns4 = "10.111.222.3"
)

type options struct {
	name      string
	mtu       int
	doh       string
	dohips    string
	setdns    bool
	full      bool
	nrpt      bool
	cleanup   bool
	kill      bool
	conflicts []string // other VPNs that compete with ours, found at start
	block     string
	wg        string
	warp      bool
	proxy     string
	masque    bool
	chain     string
	usqueExe  string
	usqueDir  string
	warpFile  string
	api       string
	tokenFile string
	logFile   string
	golog     int32

	dnsType     string // doh, dot, dnscrypt or system
	dot         string
	dotIPs      string
	dnscrypt    string
	dnsDirect   bool
	dnsCache    bool
	dnssec      bool
	undelegated bool
	dnsFallback bool
	fallbackDoH string
	fallbackIPs string
	usqueFlags  string
	allowLAN    bool

	dnscryptRelays string // csv of relay stamps for -dns dnscrypt
	odoh           string // ODoH target for -dns odoh
	odohRelay      string // ODoH relay (proxy) URL; direct if empty
	odohIPs        string
	dnsProxy       string // ip:port for -dns proxy
	blocklistDir   string // on-device blocklists (td.txt, rd.txt, basicconfig.json, filetag.json)
	blocklistStamp string // which of them to block, as a RethinkDNS stamp
	filetag        string // filetag.json naming the lists a RethinkDNS server blocks by

	rulesFile    string
	routesFile   string // per-app WireGuard and proxy routes
	pcapFile     string // packet capture
	dialStrategy string // anti-censorship: never, auto, split-tcp, split-tls
	dialRetry    string // never, split (retry with split), plain (retry as-is)
	dialTimeout  int    // seconds; 0 for the default
	keepAlive    bool   // shorter TCP keep alive
	eim          bool   // UDP endpoint-independent mapping and filtering
}

func main() {
	var o options
	var golog int
	flag.StringVar(&o.name, "name", "AuroraVPN", "Wintun adapter name")
	flag.IntVar(&o.mtu, "mtu", 1500, "adapter MTU")
	flag.StringVar(&o.doh, "doh", "https://cloudflare-dns.com/dns-query", "DoH server URL")
	flag.StringVar(&o.dohips, "doh-ips", "1.1.1.1,1.0.0.1", "comma-separated IPs of the DoH server")
	flag.BoolVar(&o.setdns, "set-dns", true, "point the adapter's DNS at the tunnel and give it the lowest metric")
	flag.BoolVar(&o.full, "full", false, "route all IPv4 traffic through the tunnel, not just DNS")
	flag.BoolVar(&o.nrpt, "nrpt", false, "send every DNS query to the tunnel with an NRPT rule, whatever other adapters use; removed on exit")
	flag.BoolVar(&o.kill, "killswitch", false, "block all traffic outside the tunnel, and keep blocking if fswin crashes until it starts again or -cleanup runs (implies -full)")
	flag.BoolVar(&o.cleanup, "cleanup", false, "remove fswin's NRPT rule (left behind if fswin was killed) and exit")
	flag.StringVar(&o.block, "block", "", "comma-separated programs to block (exe names like chrome.exe, or full paths); needs -full")
	flag.StringVar(&o.wg, "wg", "", "send all traffic through the WireGuard server in this wg-quick .conf file (implies -full)")
	flag.BoolVar(&o.warp, "warp", false, "send all traffic through free Cloudflare WARP; registers on first use and saves fswin-warp.json next to fswin.exe (implies -full)")
	flag.StringVar(&o.proxy, "proxy", "", "send all traffic through this proxy: socks5://[user:pass@]host:port or http://... (implies -full)")
	flag.IntVar(&golog, "log", 3, "firestack log level: 0 very verbose ... 5 errors, 8 none")
	flag.BoolVar(&o.masque, "masque", false, "send all traffic through free Cloudflare WARP over MASQUE (HTTP/3, falls back to HTTP/2), using usque (implies -full)")
	flag.StringVar(&o.chain, "chain", "", "send all traffic through WARP2 -> this WireGuard server -> WARP1, using usque chain; value is a wg-quick .conf (implies -full)")
	flag.StringVar(&o.usqueExe, "usque", "", "path to usque.exe (default: next to fswin.exe)")
	flag.StringVar(&o.usqueDir, "usque-dir", "", "where -masque and -chain keep their WARP identities (default: next to fswin.exe)")
	flag.StringVar(&o.warpFile, "warp-file", "", "where -warp keeps its account (default: fswin-warp.json next to fswin.exe)")
	flag.StringVar(&o.api, "api", "", "serve the control API for the app window on this loopback address, e.g. 127.0.0.1:47897")
	flag.StringVar(&o.tokenFile, "token-file", "", "file holding the secret every -api request must present")
	flag.StringVar(&o.logFile, "logfile", "", "write output to this file instead of the console")
	flag.StringVar(&o.dnsType, "dns", dnsDoH, "DNS type: doh, dot, dnscrypt, odoh (Oblivious DoH), proxy (plain DNS to -dns-proxy) or system (the network adapter's own DNS servers)")
	flag.StringVar(&o.dot, "dot", "", "DNS-over-TLS server for -dns dot, e.g. tls://dns.adguard-dns.com")
	flag.StringVar(&o.dotIPs, "dot-ips", "", "comma-separated IPs of the -dot server (optional)")
	flag.StringVar(&o.dnscrypt, "dnscrypt", "", "DNSCrypt server stamp (sdns://...) for -dns dnscrypt")
	flag.BoolVar(&o.dnsDirect, "dns-direct", false, "never send DNS through the VPN exit")
	flag.BoolVar(&o.dnsCache, "dns-cache", false, "DNS booster: answer repeat lookups from the cache")
	flag.BoolVar(&o.dnssec, "dnssec", false, "block DNS answers that put public names on bogus (bogon) addresses, a sign of poisoning")
	flag.BoolVar(&o.undelegated, "undelegated", false, "use System DNS for undelegated domains like .lan and .internal")
	flag.BoolVar(&o.dnsFallback, "dns-fallback", false, "use the fallback DNS when the chosen DNS fails")
	flag.StringVar(&o.fallbackDoH, "fallback-doh", "", "fallback (bootstrap) DoH server URL (default: -doh)")
	flag.StringVar(&o.fallbackIPs, "fallback-ips", "", "comma-separated IPs of -fallback-doh (default: -doh-ips)")
	flag.StringVar(&o.usqueFlags, "usque-flags", "", "extra usque flags for -masque or -chain, space-separated; core flags (-b -p -u -w -c --wg --exit-config) are refused")
	flag.BoolVar(&o.allowLAN, "allow-lan", false, "with -killswitch, let private and link-local addresses (printers, shares) through")
	flag.StringVar(&o.dnscryptRelays, "dnscrypt-relays", "", "comma-separated DNSCrypt relay stamps (sdns://...) for -dns dnscrypt, to hide your IP from the resolver")
	flag.StringVar(&o.odoh, "odoh", "", "Oblivious DoH target for -dns odoh, e.g. https://odoh.cloudflare-dns.com/dns-query")
	flag.StringVar(&o.odohRelay, "odoh-relay", "", "Oblivious DoH relay (proxy) URL; without one, queries go to the target directly")
	flag.StringVar(&o.odohIPs, "odoh-ips", "", "comma-separated IPs of the ODoH relay or target (optional)")
	flag.StringVar(&o.dnsProxy, "dns-proxy", "", "plain DNS server ip:port for -dns proxy, e.g. 9.9.9.9:53 or a local DNS forwarder like 127.0.0.1:5400")
	flag.StringVar(&o.blocklistDir, "blocklists", "", "folder with the on-device RethinkDNS blocklists (td.txt, rd.txt, basicconfig.json, filetag.json)")
	flag.StringVar(&o.blocklistStamp, "blocklist-stamp", "", "RethinkDNS stamp of the on-device blocklists to block, e.g. 1-...")
	flag.StringVar(&o.filetag, "filetag", "", "filetag.json, to name the blocklists a RethinkDNS server blocked a domain by")
	flag.StringVar(&o.pcapFile, "pcap", "", "write a packet capture of the tunnel to this .pcap file (replaced at start)")
	flag.StringVar(&o.routesFile, "routes", "", "per-app routes (JSON list of {id, name, kind: wg|proxy, file|url}): extra WireGuard tunnels or proxies that apps with a route rule use instead of the exit")
	flag.StringVar(&o.rulesFile, "rules", "", "firewall rules (JSON, as the app writes them) to start with; the app updates them through -api")
	flag.StringVar(&o.dialStrategy, "dial-strategy", dialNever, "anti-censorship: never (connect as-is), auto, split-tcp (split the first TCP segment) or split-tls (fragment the TLS ClientHello)")
	flag.StringVar(&o.dialRetry, "dial-retry", "", "when a connection fails: never, split (retry with the split) or plain (retry as-is); default: never for -dial-strategy never, else plain")
	flag.IntVar(&o.dialTimeout, "dial-timeout", 0, "idle timeout for TCP and UDP sockets, in seconds; 0 for firestack's default")
	flag.BoolVar(&o.keepAlive, "tcp-keepalive", false, "shorter TCP keep alive: quickly close TCP sockets with no recent activity")
	flag.BoolVar(&o.eim, "eim", false, "endpoint-independent mapping and filtering for UDP (fixed port for all destinations; helps games and calls)")
	showVersion := flag.Bool("version", false, "print the build and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("fswin", version)
		return
	}
	o.golog = int32(golog)

	// the app's files are opened with the user's rights (asuser_windows.go)
	tok, err := newUserToken()
	if err != nil {
		fmt.Fprintln(os.Stderr, "fswin:", err)
		os.Exit(1)
	}
	asUser = tok

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
}

func run(o options) error {
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

	// prepare the exit first: WARP registers over the normal network
	exitID, exitCfg, us, err := prepareExit(o)
	if err != nil {
		return err
	}
	var uq *usque // started once all traffic goes to the tunnel
	defer func() { uq.stop() }()
	if exitID != "" || o.kill {
		o.full = true // a VPN exit and the kill switch need all traffic in the tunnel
	}

	if o.block != "" && !o.full {
		fmt.Println("fswin: -block needs -full: without it only DNS goes through the tunnel, and DNS is answered for every app")
	}

	tun.WintunTunnelType = "AuroraVPN"
	dev, err := tun.CreateTUN(o.name, o.mtu)
	if err != nil {
		return fmt.Errorf("create wintun adapter (run as admin, wintun.dll next to the exe?): %w", err)
	}
	name := o.name
	if n, err := dev.Name(); err == nil {
		name = n
	}
	// netstack owns dev from here and closes it (removing the adapter) on Disconnect.
	id := netstack.RegisterTun(dev)

	if err := configure(name, o.setdns); err != nil {
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
	t, err := intra.Connect(id, o.mtu, o.mtu, ifaddr4+"/24", fakedns4+":53", dtr, b)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer t.Disconnect()
	b.closer.Store(func(csv string) string { return t.CloseConns(csv) })
	b.tun.Store(t)
	if err := setDialer(o); err != nil {
		return err
	}
	intra.Transparency(o.eim, o.eim)
	if o.pcapFile != "" {
		// the app's file, opened with the user's rights; a capture starts
		// with its own header
		err := asUser.do(func() error {
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

	// Another VPN that claims all DNS or all traffic breaks ours: its NRPT
	// rule races ours for every query, and firestack's own traffic leaves
	// through that VPN's adapter, where it may never get answers.
	if others, err := dnspolicy.Others(); err == nil {
		for _, r := range others {
			o.conflicts = append(o.conflicts, "another VPN sends all DNS elsewhere: "+r)
		}
	}
	physName, physDesc, physVPN := ifbind.Describe(phys4)
	fmt.Printf("fswin: firestack's own traffic leaves via interface #%d %s (%s)\n", phys4, physName, physDesc)
	if physVPN {
		o.conflicts = append(o.conflicts, fmt.Sprintf("internet traffic leaves through another VPN's adapter: %s (%s)", physName, physDesc))
	}
	for _, c := range o.conflicts {
		fmt.Printf("fswin: warning: %s; disconnect that VPN\n", c)
	}

	if o.nrpt {
		if err := dnspolicy.Add(netip.MustParseAddr(fakedns4)); err != nil {
			return err
		}
		defer func() {
			if err := dnspolicy.Remove(); err != nil {
				fmt.Fprintln(os.Stderr, "fswin: remove NRPT rule (run fswin -cleanup):", err)
			}
		}()
	}

	mode := "DNS only"
	if o.full {
		// routes go once the tunnel can carry traffic; they vanish with the adapter
		if err := fullTunnel(name); err != nil {
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
	}
	if exitID != "" {
		pxs, err := t.GetProxies()
		if err != nil {
			return fmt.Errorf("proxies: %w", err)
		}
		if _, err := pxs.AddProxy(x.StrOf(exitID), x.StrOf(exitCfg)); err != nil {
			return fmt.Errorf("add exit %s: %w", exitID, err)
		}
	}
	mode += killMode
	if exitID != "" {
		mode += "; exit: " + exitName(exitID)
	}
	fmt.Printf("fswin %s: up on %q (%s); DNS %s:53 -> %s. Ctrl+C to stop.\n", version, name, mode, fakedns4, dnsLabel)
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
			return nil
		case <-apiStop:
			fmt.Println("fswin: stopping (requested by the app)")
			return nil
		case <-tick.C:
			if st, err := t.Stat(); err == nil && st != nil {
				b.logf("tun   %s", st.TUNSt.EpStats)
			}
		}
	}
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
	return netsh(cmds)
}

// fullTunnel sends all IPv4 traffic to the adapter with two /1 routes, which
// beat any 0.0.0.0/0 default route without replacing it.
func fullTunnel(name string) error {
	return netsh([][]string{
		{"interface", "ipv4", "add", "route", "prefix=0.0.0.0/1", "interface=" + name, "nexthop=0.0.0.0", "metric=0", "store=active"},
		{"interface", "ipv4", "add", "route", "prefix=128.0.0.0/1", "interface=" + name, "nexthop=0.0.0.0", "metric=0", "store=active"},
	})
}

func netsh(cmds [][]string) error {
	for _, args := range cmds {
		out, err := exec.Command("netsh", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("netsh %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// Dial strategies for -dial-strategy. Desync is left out: Windows falls
// back to a plain dial for it (intra/dialers/desync_windows.go).
const (
	dialNever    = "never"
	dialAuto     = "auto"
	dialSplitTCP = "split-tcp"
	dialSplitTLS = "split-tls"
)

// setDialer applies the anti-censorship options. The Android app fixes
// them to never split and never retry; here they are a choice.
func setDialer(o options) error {
	strat := map[string]int32{
		dialNever:    settings.SplitNever,
		dialAuto:     settings.SplitAuto,
		dialSplitTCP: settings.SplitTCP,
		dialSplitTLS: settings.SplitTCPOrTLS,
	}
	s, ok := strat[o.dialStrategy]
	if !ok {
		return fmt.Errorf("-dial-strategy must be never, auto, split-tcp or split-tls, not %q", o.dialStrategy)
	}
	retry := o.dialRetry
	if retry == "" {
		retry = "plain"
		if s == settings.SplitNever {
			retry = "never"
		}
	}
	r, ok := map[string]int32{
		"never": settings.RetryNever,
		"split": settings.RetryWithSplit,
		"plain": settings.RetryAfterSplit,
	}[retry]
	if !ok {
		return fmt.Errorf("-dial-retry must be never, split or plain, not %q", o.dialRetry)
	}
	settings.SetDialerOpts(s, r, int32(o.dialTimeout), o.keepAlive)
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

// prepareExit returns the proxy id and config for the chosen exit, if any.
// For -masque and -chain it registers usque and returns its setup instead of
// a config: the config is the proxy address of usque, which run starts later.
func prepareExit(o options) (id, cfg string, us *usqueSetup, err error) {
	n := 0
	for _, set := range []bool{o.wg != "", o.warp, o.proxy != "", o.masque, o.chain != ""} {
		if set {
			n++
		}
	}
	if n > 1 {
		return "", "", nil, errors.New("choose one of -wg, -warp, -proxy, -masque and -chain")
	}
	exe, err := os.Executable()
	if err != nil {
		return "", "", nil, err
	}
	here := filepath.Dir(exe)
	switch {
	case o.wg != "":
		b, err := readUserFile(o.wg)
		if err != nil {
			return "", "", nil, err
		}
		cfg, err := wgQuickToUAPI(string(b))
		return exitWG, cfg, nil, err
	case o.warp:
		path := o.warpFile
		if path == "" {
			path = filepath.Join(here, "fswin-warp.json")
		}
		a, err := loadOrRegisterWarp(path)
		if err != nil {
			return "", "", nil, err
		}
		cfg, err := a.uapi()
		return exitWarp, cfg, nil, err
	case o.proxy != "":
		if !strings.HasPrefix(o.proxy, "socks5://") && !strings.HasPrefix(o.proxy, "http://") {
			return "", "", nil, errors.New("-proxy must start with socks5:// or http://")
		}
		return exitProxy, o.proxy, nil, nil
	case o.masque || o.chain != "":
		extra, err := usqueFlags(o.usqueFlags)
		if err != nil {
			return "", "", nil, err
		}
		s := usqueSetup{
			exe:     o.usqueExe,
			dir:     o.usqueDir,
			chainWG: o.chain,
			extra:   extra,
			logf:    func(f string, a ...any) { fmt.Printf(f+"\n", a...) },
		}
		if s.exe == "" {
			s.exe = filepath.Join(here, "usque.exe")
		}
		if s.dir == "" {
			s.dir = here
		}
		id := exitMasque
		if o.chain != "" {
			id = exitChain
			if err := statUserFile(o.chain); err != nil {
				return "", "", nil, fmt.Errorf("-chain: %w", err)
			}
		}
		if err := prepareUsque(s); err != nil {
			return "", "", nil, err
		}
		return id, "", &s, nil
	}
	return "", "", nil, nil
}

func exitName(id string) string {
	switch id {
	case exitWG:
		return "WireGuard"
	case exitWarp:
		return "Cloudflare WARP"
	case exitProxy:
		return "proxy"
	case exitMasque:
		return "Cloudflare WARP (MASQUE)"
	case exitChain:
		return "WARP chain"
	case x.Base:
		return "direct"
	case x.Block:
		return "blocked"
	}
	return id
}

// redirectOutput sends stdout, stderr and the standard logger to path, for
// when the app window starts fswin without a console. The log is the app's
// file: it is opened with the user's rights.
func redirectOutput(path string) error {
	var f *os.File
	err := asUser.do(func() (err error) {
		f, err = os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		return err
	})
	if err != nil {
		return err
	}
	os.Stdout, os.Stderr = f, f
	log.SetOutput(f)
	flog.SetOutput(f) // firestack's own logs, which say why a DNS query or dial failed
	_ = windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, windows.Handle(f.Fd()))
	_ = windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(f.Fd()))
	return nil
}
