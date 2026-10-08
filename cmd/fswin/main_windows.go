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
	"github.com/celzero/firestack/intra/netstack"
	"github.com/celzero/firestack/win/dnspolicy"
	"github.com/celzero/firestack/win/ifbind"
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
	block     string
	wg        string
	warp      bool
	proxy     string
	warpFile  string
	api       string
	tokenFile string
	logFile   string
	golog     int32
}

func main() {
	var o options
	var golog int
	flag.StringVar(&o.name, "name", "port1897", "Wintun adapter name")
	flag.IntVar(&o.mtu, "mtu", 1500, "adapter MTU")
	flag.StringVar(&o.doh, "doh", "https://cloudflare-dns.com/dns-query", "DoH server URL")
	flag.StringVar(&o.dohips, "doh-ips", "1.1.1.1,1.0.0.1", "comma-separated IPs of the DoH server")
	flag.BoolVar(&o.setdns, "set-dns", true, "point the adapter's DNS at the tunnel and give it the lowest metric")
	flag.BoolVar(&o.full, "full", false, "route all IPv4 traffic through the tunnel, not just DNS")
	flag.BoolVar(&o.nrpt, "nrpt", false, "send every DNS query to the tunnel with an NRPT rule, whatever other adapters use; removed on exit")
	flag.BoolVar(&o.cleanup, "cleanup", false, "remove fswin's NRPT rule (left behind if fswin was killed) and exit")
	flag.StringVar(&o.block, "block", "", "comma-separated programs to block (exe names like chrome.exe, or full paths); needs -full")
	flag.StringVar(&o.wg, "wg", "", "send all traffic through the WireGuard server in this wg-quick .conf file (implies -full)")
	flag.BoolVar(&o.warp, "warp", false, "send all traffic through free Cloudflare WARP; registers on first use and saves fswin-warp.json next to fswin.exe (implies -full)")
	flag.StringVar(&o.proxy, "proxy", "", "send all traffic through this proxy: socks5://[user:pass@]host:port or http://... (implies -full)")
	flag.IntVar(&golog, "log", 3, "firestack log level: 0 very verbose ... 5 errors, 8 none")
	flag.StringVar(&o.warpFile, "warp-file", "", "where -warp keeps its account (default: fswin-warp.json next to fswin.exe)")
	flag.StringVar(&o.api, "api", "", "serve the control API for the app window on this loopback address, e.g. 127.0.0.1:47897")
	flag.StringVar(&o.tokenFile, "token-file", "", "file holding the secret every -api request must present")
	flag.StringVar(&o.logFile, "logfile", "", "write output to this file instead of the console")
	showVersion := flag.Bool("version", false, "print the build and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("fswin", version)
		return
	}
	o.golog = int32(golog)

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
		if err := dnspolicy.Remove(); err != nil {
			return err
		}
		fmt.Println("fswin: removed fswin's NRPT rule, if any")
		return nil
	}

	intra.LogLevel(o.golog, 8 /*no console logs; Go logs go to stderr*/)

	// prepare the exit first: WARP registers over the normal network
	exitID, exitCfg, err := prepareExit(o)
	if err != nil {
		return err
	}
	if exitID != "" {
		o.full = true // a VPN exit only sees traffic in the tunnel
	}

	if o.block != "" && !o.full {
		fmt.Println("fswin: -block only affects traffic in the tunnel; without -full that is DNS only")
	}

	tun.WintunTunnelType = "port1897"
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
	phys4, _ := binder.Indexes()
	if o.full && phys4 == 0 {
		_ = dev.Close()
		return errors.New("-full: no IPv4 default route outside the tunnel to send firestack's own traffic over")
	}

	ipports := withPort(o.dohips, "443")
	dtr, err := intra.NewDefaultDNS(x.StrOf(x.DOH), x.StrOf(o.doh), x.StrOf(ipports))
	if err != nil {
		_ = dev.Close()
		return fmt.Errorf("default dns: %w", err)
	}

	b := newBridge(binder, o.block)
	// fakedns must be ip:port; a bare ip is rejected and DNS goes unrecognized.
	t, err := intra.Connect(id, o.mtu, o.mtu, ifaddr4+"/24", fakedns4+":53", dtr, b)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer t.Disconnect()

	if err := intra.AddDoHTransport(t, x.StrOf(x.Preferred), x.StrOf(o.doh), x.StrOf(o.dohips)); err != nil {
		return fmt.Errorf("add doh %s: %w", o.doh, err)
	}

	if exitID != "" {
		pxs, err := t.GetProxies()
		if err != nil {
			return fmt.Errorf("proxies: %w", err)
		}
		if _, err := pxs.AddProxy(x.StrOf(exitID), x.StrOf(exitCfg)); err != nil {
			return fmt.Errorf("add exit %s: %w", exitID, err)
		}
		b.setExit(exitID)
	}

	if o.nrpt {
		if others, err := dnspolicy.Others(); err == nil && len(others) > 0 {
			fmt.Printf("fswin: warning: other catch-all DNS rules compete with -nrpt: %s; disconnect that VPN for a clean test\n",
				strings.Join(others, "; "))
		}
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
	if exitID != "" {
		mode += "; exit: " + exitName(exitID)
	}
	fmt.Printf("fswin %s: up on %q (%s); DNS %s:53 -> %s. Ctrl+C to stop.\n", version, name, mode, fakedns4, o.doh)
	if blocked := b.blockedList(); blocked != "" {
		fmt.Printf("fswin: blocking %s\n", blocked)
	}

	apiStop := make(chan struct{})
	if o.api != "" {
		started := time.Now()
		var once sync.Once
		srv, err := serveAPI(o.api, o.tokenFile, b,
			func() apiStatus { return statusOf(b, o, started, exitID) },
			func() { once.Do(func() { close(apiStop) }) })
		if err != nil {
			return fmt.Errorf("api: %w", err)
		}
		defer srv.Close()
		fmt.Printf("fswin: control API on %s
", o.api)
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
func prepareExit(o options) (id, cfg string, err error) {
	n := 0
	for _, set := range []bool{o.wg != "", o.warp, o.proxy != ""} {
		if set {
			n++
		}
	}
	if n > 1 {
		return "", "", errors.New("choose one of -wg, -warp and -proxy")
	}
	switch {
	case o.wg != "":
		b, err := os.ReadFile(o.wg)
		if err != nil {
			return "", "", err
		}
		cfg, err := wgQuickToUAPI(string(b))
		return exitWG, cfg, err
	case o.warp:
		exe, err := os.Executable()
		if err != nil {
			return "", "", err
		}
		path := o.warpFile
		if path == "" {
			path = filepath.Join(filepath.Dir(exe), "fswin-warp.json")
		}
		a, err := loadOrRegisterWarp(path)
		if err != nil {
			return "", "", err
		}
		cfg, err := a.uapi()
		return exitWarp, cfg, err
	case o.proxy != "":
		if !strings.HasPrefix(o.proxy, "socks5://") && !strings.HasPrefix(o.proxy, "http://") {
			return "", "", errors.New("-proxy must start with socks5:// or http://")
		}
		return exitProxy, o.proxy, nil
	}
	return "", "", nil
}

func exitName(id string) string {
	switch id {
	case exitWG:
		return "WireGuard"
	case exitWarp:
		return "Cloudflare WARP"
	case exitProxy:
		return "proxy"
	case x.Base:
		return "direct"
	case x.Block:
		return "blocked"
	}
	return id
}

// redirectOutput sends stdout, stderr and the standard logger to path, for
// when the app window starts fswin without a console.
func redirectOutput(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	os.Stdout, os.Stderr = f, f
	log.SetOutput(f)
	_ = windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, windows.Handle(f.Fd()))
	_ = windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(f.Fd()))
	return nil
}
