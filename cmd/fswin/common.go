// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//go:build windows || linux

package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/win/ifbind"
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

	service    string // install, uninstall or run AuroraVPN Service (service_windows.go)
	serviceApp string // with -service install: the app allowed to use it
	stopHandle uint64 // set by the service: an event that stops the engine
	userToken  uint64 // set by the service: the token of the user who asked
}

// defineFlags declares the engine's flags, the same on every system; the
// ones a system has no use for are accepted and ignored there.
func defineFlags(o *options, golog *int) {
	flag.StringVar(&o.name, "name", "AuroraVPN", "Wintun adapter name")
	flag.IntVar(&o.mtu, "mtu", 0, "adapter MTU, 1280 to 1500; 0: automatic, from the network and the exit (mtu_windows.go)")
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
	flag.IntVar(golog, "log", 3, "firestack log level: 0 very verbose ... 5 errors, 8 none")
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
	flag.StringVar(&o.service, "service", "", "install, uninstall or run AuroraVPN Service, which starts the engine for the app without a UAC prompt")
	flag.StringVar(&o.serviceApp, "app", "", "with -service install: the path of AuroraVPN.exe, the only program the service answers")
	flag.Uint64Var(&o.stopHandle, "stop-handle", 0, "set by AuroraVPN Service: an inherited event that, once set, stops the engine")
	flag.Uint64Var(&o.userToken, "user-token", 0, "set by AuroraVPN Service, which runs the engine as SYSTEM: the inherited token of the user who asked; the user's files are opened, and usque started, with it")
}

// stopAt is when a stop was asked for; stopStep logs how long each part of
// the stop took after it, to see what holds a stop up (one took 15 s).
var stopAt time.Time

func stopStep(what string) {
	if !stopAt.IsZero() {
		fmt.Printf("fswin: stop: %s after %d ms\n", what, time.Since(stopAt).Milliseconds())
	}
}

// startStep logs how long the start took up to a step: one took 22 s, 19
// of them between the adapter's creation and the DNS setup, with nothing in
// the log to say where.
func startStep(began time.Time, what string) {
	fmt.Printf("fswin: start: %s after %d ms\n", what, time.Since(began).Milliseconds())
}

// networkWait is how long a start waits for a network. The app resumes
// protection as Windows signs in, before Wi-Fi is up: fswin failed at once
// with "-full: no IPv4 default route" (app.log 2026-10-10 05:27, twice, and
// 2026-10-11 05:20), and a start 55 s later worked. The app waits 60 s for
// the engine.
const networkWait = 30 * time.Second

// defaultRoute4 is the interface of the IPv4 default route, 0 if none;
// tests replace it.
var defaultRoute4 = func() uint32 {
	_, idx := ifbind.LinkMTU(0)
	return idx
}

// waitForNetwork waits up to d for an IPv4 default route; false if none
// came, or stop closed first.
func waitForNetwork(d time.Duration, stop <-chan struct{}) bool {
	if defaultRoute4() != 0 {
		return true
	}
	fmt.Printf("fswin: start: no network yet (no IPv4 default route); waiting up to %s\n", d)
	began := time.Now()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	deadline := time.After(d)
	for {
		select {
		case <-stop:
			return false
		case <-deadline:
			return false
		case <-tick.C:
			if defaultRoute4() != 0 {
				fmt.Printf("fswin: start: network up after %d ms\n", time.Since(began).Milliseconds())
				return true
			}
		}
	}
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
			s.exe = filepath.Join(here, "usque"+exeSuffix)
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
