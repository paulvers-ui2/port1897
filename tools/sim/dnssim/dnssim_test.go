// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// dnssim_test.go simulates DoH failures (blackholed upstream, refused,
// bad TLS, server errors) through the resolver wiring fswin uses:
// NewDefaultDNS + ipn.NewProxifier + dnsx.NewResolver, with the DoH server
// added as "Preferred" by doh.NewTransport (what intra.AddDoHTransport does),
// and queries sent through Resolver.LookupFor (what a query to the fake DNS
// address goes through). For each query it prints the x.DNSSummary that the
// app's OnResponse gets, the line fswin writes for it, the text fswin's
// dnsFailure (cmd/fswin/bridge_windows.go @ f30df2ea/b1e26381) would put in
// the DNS log, the text of the proposed change, and the firestack log lines
// written at the chosen level.
//
// Needs intra/log.SetOutput (b1e26381). Run one scenario per process, as
// ipmap/dialer state is global:
//
//	go test ./intra -run '^TestDNSSim$/^refused$' -count=1 -v -timeout 15m
//
// Env: SIM_LOG       firestack log level (default 3 = INFO, the app's default)
//      SIM_ONLINE=1  also run scenarios that need the internet
//      SIM_BLACKHOLE_IPS  for blackhole-testnet (default 192.0.2.1,198.51.100.1)
//      SIM_NO443=1   do not try to listen on port 443 (default: try, so the
//                    local scenarios take the same dial path as production)

//go:build dnssim

package intra

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/doh"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/x64"
	"github.com/miekg/dns"
)

const simRealURL = "https://cloudflare-dns.com/dns-query"

// ---- listener: Controller + ProxyListener + DNSListener, like fswin's bridge

type simListener struct {
	mu    sync.Mutex
	smms  []*x.DNSSummary
	bind4 int
	tid   string
	pid   string
}

var _ x.DNSListener = (*simListener)(nil)
var _ x.ProxyListener = (*simListener)(nil)
var _ x.Controller = (*simListener)(nil)

func (l *simListener) OnQuery(uid, domain *x.Gostr, qtyp int) *x.DNSOpts {
	return &x.DNSOpts{TIDCSV: l.tid, PIDCSV: l.pid} // as bridge.OnQuery: Preferred via Base
}
func (l *simListener) OnUpstreamAnswer(smm *x.DNSSummary, ipcsv *x.Gostr) *x.DNSOpts {
	return nil
}
func (l *simListener) OnResponse(s *x.DNSSummary) {
	if s == nil {
		return
	}
	c := *s
	l.mu.Lock()
	l.smms = append(l.smms, &c)
	l.mu.Unlock()
}
func (l *simListener) OnDNSAdded(id *x.Gostr)     {}
func (l *simListener) OnDNSRemoved(id *x.Gostr)   {}
func (l *simListener) OnDNSStopped()              {}
func (l *simListener) OnProxyAdded(id *x.Gostr)   {}
func (l *simListener) OnProxyRemoved(id *x.Gostr) {}
func (l *simListener) OnProxyStopped(id *x.Gostr) {}
func (l *simListener) OnProxiesStopped()          {}

// Bind4 is where fswin pins the socket to the physical (or, in the
// incident, Proton's) adapter with IP_UNICAST_IF; here it only counts.
func (l *simListener) Bind4(who, addrport string, fd int) {
	l.mu.Lock()
	l.bind4++
	l.mu.Unlock()
}
func (l *simListener) Bind6(who, addrport string, fd int) {}
func (l *simListener) Protect(who string, fd int)         {}

func (l *simListener) binds() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.bind4
}

// wait returns (and removes) the summary for name/qtype.
func (l *simListener) wait(name string, qtype int, d time.Duration) *x.DNSSummary {
	want := strings.TrimSuffix(strings.ToLower(name), ".")
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		l.mu.Lock()
		for i, s := range l.smms {
			if strings.TrimSuffix(strings.ToLower(s.QName), ".") == want && s.QType == qtype {
				l.smms = append(l.smms[:i], l.smms[i+1:]...)
				l.mu.Unlock()
				return s
			}
		}
		l.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	return nil
}

// drain returns the other summaries (firestack's own lookups).
func (l *simListener) drain() []*x.DNSSummary {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.smms
	l.smms = nil
	return out
}

// ---- log capture

type simLogBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *simLogBuf) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *simLogBuf) take() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.b.String()
	w.b.Reset()
	return s
}

func simLevel() int32 {
	if v, err := strconv.Atoi(os.Getenv("SIM_LOG")); err == nil {
		return int32(v)
	}
	return 3
}

// ---- environment: what fswin's run() + intra.NewTunnel2 set up for DNS

type simEnv struct {
	ctx  context.Context
	l    *simListener
	px   ipn.ProxyProvider
	r    dnsx.Resolver
	logs *simLogBuf
}

// newSimEnv sets up Default (bootstrap) DoH defURL/defIPPorts, as fswin does
// with -fallback-doh/-fallback-ips (which default to -doh/-doh-ips).
func newSimEnv(t *testing.T, defURL, defIPPorts string) *simEnv {
	t.Helper()
	logs := &simLogBuf{}
	log.SetOutput(logs) // b1e26381: what fswin's redirectOutput now does
	LogLevel(simLevel(), 8 /*no console, as fswin*/)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l := &simListener{tid: x.Preferred, pid: x.Base}

	// fswin's defaults: -dial-strategy never => -dial-retry never
	settings.SetDialerOpts(settings.SplitNever, settings.RetryNever, 0, false)

	dtr, err := NewDefaultDNS(x.StrOf(x.DOH), x.StrOf(defURL), x.StrOf(defIPPorts))
	if err != nil {
		t.Fatalf("default dns: %v", err)
	}
	px := ipn.NewProxifier(ctx, settings.IP46, 1500, l, l)
	if px == nil {
		t.Fatal("no proxifier")
	}
	if err := dtr.kickstart(px); err != nil {
		t.Fatalf("kickstart: %v", err)
	}
	r := dnsx.NewResolver(ctx, "10.111.222.3:53", dtr, l, x64.NewNatPt2(ctx))
	r.Add(newGoosTransport(ctx, px))
	r.Add(newBlockAllTransport())
	dialers.IPProtos(settings.IP46)
	addIPMapper(ctx, r, settings.IP46)
	return &simEnv{ctx: ctx, l: l, px: px, r: r, logs: logs}
}

// addPreferred is intra.AddDoHTransport(t, Preferred, url, ipcsv).
func (e *simEnv) addPreferred(t *testing.T, url string, ips ...string) {
	t.Helper()
	d, err := doh.NewTransport(e.ctx, x.Preferred, url, ips, e.px)
	if err != nil {
		t.Fatalf("doh %s: %v", url, err)
	}
	if !e.r.Add(d) {
		t.Fatal("add Preferred failed")
	}
	time.Sleep(200 * time.Millisecond)
	simPrintLogs("setup", e.logs.take())
	e.l.drain()
}

func (e *simEnv) query(t *testing.T, name string, qtype uint16) *x.DNSSummary {
	t.Helper()
	e.logs.take()
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	b, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	binds := e.l.binds()
	start := time.Now()
	ans, tid, qerr := e.r.LookupFor(b, "10000")
	wall := time.Since(start)
	s := e.l.wait(name, int(qtype), 5*time.Second)
	time.Sleep(300 * time.Millisecond) // late lines (conn close, dial status)

	fmt.Printf("--- query %s %s: LookupFor returned after %s; tid=%q; %d answer bytes; err=%v; Bind4 calls: %d\n",
		name, dns.TypeToString[qtype], wall.Round(time.Millisecond), tid, len(ans), qerr, e.l.binds()-binds)
	if s == nil {
		fmt.Println("    (no OnResponse summary within 5 s)")
	} else {
		fmt.Printf("    summary: Status=%d (%s / firestack %q) RCode=%d (%s) Latency=%.3fs ID=%s Type=%s Server=%q PID=%q RPID=%q RData=%q\n",
			s.Status, simStatusName(s.Status), dnsx.Status2Str(s.Status), s.RCode, dns.RcodeToString[s.RCode],
			s.Latency, s.ID, s.Type, s.Server, s.PID, s.RPID, s.RData)
		fmt.Printf("    Msg: %q\n", s.Msg)
		// bridge.OnResponse's own line (engine.log, any log level)
		fmt.Printf("    fswin: dns   %s (type %d) -> %s via %s %.0fms status %d %s\n",
			s.QName, s.QType, s.RData, s.ID, s.Latency*1000, s.Status, s.Msg)
		now := ""
		if s.Status != x.Complete {
			now = simDNSFailure(s)
		}
		fmt.Printf("    DNS log error now (dnsFailure):  %q\n", now)
		fmt.Printf("    DNS log error with proposal:     %q\n", simProposedFailure(s))
	}
	simPrintLogs(fmt.Sprintf("firestack log at level %d", simLevel()), e.logs.take())
	for _, o := range e.l.drain() {
		fmt.Printf("    other summary (firestack's own lookup): %s %d via %s status %d msg %q\n",
			o.QName, o.QType, o.ID, o.Status, o.Msg)
	}
	return s
}

func simPrintLogs(title, logs string) {
	fmt.Printf("    %s:\n", title)
	n := 0
	for _, ln := range strings.Split(strings.TrimRight(logs, "\n"), "\n") {
		if ln != "" {
			fmt.Printf("      | %s\n", ln)
			n++
		}
	}
	if n == 0 {
		fmt.Println("      (none)")
	}
}

func simHeader(title string) {
	fmt.Printf("\n===== %s\n", title)
}

// ---- fswin's dnsFailure, copied from cmd/fswin/bridge_windows.go (f30df2ea)

func simDNSFailure(s *x.DNSSummary) string {
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

// simProposedFailure is the proposed OnResponse/dnsFailure behaviour:
// report error rcodes in "Complete" answers, and say "no reply from <server>
// in N s" for timeouts.
func simProposedFailure(s *x.DNSSummary) string {
	srv := s.Server
	if srv == "" {
		srv = "the DNS server"
	}
	if s.Status == x.Complete {
		if s.RCode == dns.RcodeSuccess || s.RCode == dns.RcodeNameError {
			return ""
		}
		return fmt.Sprintf("%s answered %s", srv, dns.RcodeToString[s.RCode])
	}
	why := simDNSFailure(s)
	switch {
	case strings.Contains(why, "timeout"):
		return fmt.Sprintf("no reply from %s in %.0f s (%s)", srv, s.Latency, why)
	case strings.HasPrefix(why, "http-status: "):
		return fmt.Sprintf("%s answered HTTP %s", srv, strings.TrimPrefix(why, "http-status: "))
	}
	return why
}

func simStatusName(st int) string {
	switch st {
	case x.Start:
		return "Start"
	case x.Complete:
		return "Complete"
	case x.SendFailed:
		return "SendFailed"
	case x.NoResponse:
		return "NoResponse"
	case x.BadQuery:
		return "BadQuery"
	case x.BadResponse:
		return "BadResponse"
	case x.InternalError:
		return "InternalError"
	case x.TransportError:
		return "TransportError"
	case x.ClientError:
		return "ClientError"
	case x.Paused:
		return "Paused"
	case x.DEnd:
		return "DEnd"
	}
	return "?"
}

// ---- local servers

type simServer struct {
	ip   string
	port int
}

func (s simServer) url(scheme, host string) string {
	if s.port == 443 {
		return scheme + "://" + host + "/dns-query"
	}
	return fmt.Sprintf("%s://%s:%d/dns-query", scheme, host, s.port)
}

func (s simServer) ipport() string {
	return net.JoinHostPort(s.ip, strconv.Itoa(s.port))
}

// simListen listens on ip:443 when allowed (root, or a low
// ip_unprivileged_port_start), so dials take the same split/retrier path as
// production (port 443, non-private IP); else on a random port.
func simListen(t *testing.T, ip string) net.Listener {
	t.Helper()
	if os.Getenv("SIM_NO443") != "1" {
		if ln, err := net.Listen("tcp4", net.JoinHostPort(ip, "443")); err == nil {
			return ln
		}
	}
	ln, err := net.Listen("tcp4", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatalf("listen %s: %v", ip, err)
	}
	return ln
}

func simPort(ln net.Listener) int {
	return ln.Addr().(*net.TCPAddr).Port
}

// simDoHHandler answers DoH by mode: ok, servfail, refused, nxdomain,
// 503, or hang (never sends response headers).
func simDoHHandler(mode, dohHost string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		switch mode {
		case "hang":
			select {
			case <-req.Context().Done():
			case <-time.After(60 * time.Second):
			}
			return
		case "503":
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		var body []byte
		if req.Method == http.MethodGet {
			body, _ = base64.RawURLEncoding.DecodeString(req.URL.Query().Get("dns"))
		} else {
			body, _ = io.ReadAll(req.Body)
		}
		q := new(dns.Msg)
		if err := q.Unpack(body); err != nil || len(q.Question) == 0 {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		m := new(dns.Msg)
		m.SetReply(q)
		switch mode {
		case "servfail":
			m.Rcode = dns.RcodeServerFailure
		case "refused":
			m.Rcode = dns.RcodeRefused
		case "nxdomain":
			m.Rcode = dns.RcodeNameError
		default: // ok; NODATA for the DoH host itself so ipmap keeps its seed IPs
			qn := strings.TrimSuffix(strings.ToLower(q.Question[0].Name), ".")
			if q.Question[0].Qtype == dns.TypeA && qn != dohHost {
				if rr, err := dns.NewRR(q.Question[0].Name + " 60 IN A 93.184.215.14"); err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
		out, err := m.Pack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("content-type", "application/dns-message")
		_, _ = w.Write(out)
	}
}

func simDoHServer(t *testing.T, mode, dohHost string) simServer {
	t.Helper()
	ln := simListen(t, "127.0.0.1")
	hs := httptest.NewUnstartedServer(simDoHHandler(mode, dohHost))
	_ = hs.Listener.Close()
	hs.Listener = ln
	hs.StartTLS()
	t.Cleanup(func() {
		hs.CloseClientConnections()
		hs.Close()
	})
	return simServer{ip: "127.0.0.1", port: simPort(ln)}
}

// simHangServer accepts TCP and never speaks: the TLS handshake stalls.
func simHangServer(t *testing.T) simServer {
	t.Helper()
	ln := simListen(t, "127.0.0.1")
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
	})
	return simServer{ip: "127.0.0.1", port: simPort(ln)}
}

// simClosedPort is a port nothing listens on: connects are refused (RST).
func simClosedPort(t *testing.T, ip string) simServer {
	t.Helper()
	ln := simListen(t, ip)
	p := simPort(ln)
	_ = ln.Close()
	return simServer{ip: ip, port: p}
}

// simDoHPair sets up Default and Preferred the way fswin does by default
// (both the same URL and IPs), then adds Preferred.
func simDoHPair(t *testing.T, url string, port int, ips ...string) *simEnv {
	t.Helper()
	var ipps []string
	for _, ip := range ips {
		ipps = append(ipps, net.JoinHostPort(ip, strconv.Itoa(port)))
	}
	fmt.Printf("setup: Preferred=Default=%s, bootstrap IPs %v\n", url, ips)
	e := newSimEnv(t, url, strings.Join(ipps, ","))
	e.addPreferred(t, url, ips...)
	return e
}

func simOnline(t *testing.T) {
	if os.Getenv("SIM_ONLINE") != "1" {
		t.Skip("needs SIM_ONLINE=1")
	}
}

// ---- scenarios

func TestDNSSim(t *testing.T) {
	t.Run("control-local", func(t *testing.T) {
		simHeader("control: local DoH answers (TLS not verified: http:// URL)")
		srv := simDoHServer(t, "ok", "cloudflare-dns.com")
		e := simDoHPair(t, srv.url("http", "cloudflare-dns.com"), srv.port, srv.ip)
		e.query(t, "example.com", dns.TypeA)
	})

	t.Run("refused", func(t *testing.T) {
		simHeader("connection refused (RST) on the only bootstrap IP")
		srv := simClosedPort(t, "127.0.0.1")
		e := simDoHPair(t, srv.url("https", "cloudflare-dns.com"), srv.port, srv.ip)
		e.query(t, "example.com", dns.TypeA)
		e.query(t, "example.net", dns.TypeA)
	})

	t.Run("refused-2ips", func(t *testing.T) {
		simHeader("connection refused on both bootstrap IPs (127.0.0.1, 127.0.0.2)")
		srv := simClosedPort(t, "127.0.0.1")
		e := simDoHPair(t, srv.url("https", "cloudflare-dns.com"), srv.port, "127.0.0.1", "127.0.0.2")
		e.query(t, "example.com", dns.TypeA)
	})

	t.Run("tls-unknown-ca", func(t *testing.T) {
		simHeader("TLS: server's certificate is not trusted (wrong server behind the IP)")
		srv := simDoHServer(t, "ok", "cloudflare-dns.com")
		e := simDoHPair(t, srv.url("https", "cloudflare-dns.com"), srv.port, srv.ip)
		e.query(t, "example.com", dns.TypeA)
	})

	t.Run("tls-hang", func(t *testing.T) {
		simHeader("TCP connects, TLS handshake never answered")
		srv := simHangServer(t)
		e := simDoHPair(t, srv.url("https", "cloudflare-dns.com"), srv.port, srv.ip)
		e.query(t, "example.com", dns.TypeA)
	})

	t.Run("no-headers", func(t *testing.T) {
		simHeader("TLS ok, HTTP request sent, no response headers ever")
		srv := simDoHServer(t, "hang", "cloudflare-dns.com")
		e := simDoHPair(t, srv.url("http", "cloudflare-dns.com"), srv.port, srv.ip)
		e.query(t, "example.com", dns.TypeA)
	})

	t.Run("http503", func(t *testing.T) {
		simHeader("server answers HTTP 503")
		srv := simDoHServer(t, "503", "cloudflare-dns.com")
		e := simDoHPair(t, srv.url("http", "cloudflare-dns.com"), srv.port, srv.ip)
		e.query(t, "example.com", dns.TypeA)
	})

	for _, mode := range []string{"servfail", "refused", "nxdomain"} {
		t.Run("rcode-"+mode, func(t *testing.T) {
			simHeader("server answers HTTP 200 with DNS rcode " + mode)
			srv := simDoHServer(t, mode, "cloudflare-dns.com")
			e := simDoHPair(t, srv.url("http", "cloudflare-dns.com"), srv.port, srv.ip)
			e.query(t, "example.com", dns.TypeA)
		})
	}

	t.Run("blackhole-local", func(t *testing.T) {
		simHeader("blackhole: SYNs silently dropped on both bootstrap IPs (full listen backlog; linux, no root)")
		port := 443
		if os.Getenv("SIM_NO443") == "1" {
			port = 0
		}
		p, close1, err := simBacklogBlackhole("127.0.0.1", port)
		if err != nil && port == 443 {
			p, close1, err = simBacklogBlackhole("127.0.0.1", 0)
		}
		if err != nil {
			t.Skipf("blackhole 127.0.0.1: %v", err)
		}
		t.Cleanup(close1)
		_, close2, err := simBacklogBlackhole("127.0.0.2", p)
		if err != nil {
			t.Skipf("blackhole 127.0.0.2:%d: %v", p, err)
		}
		t.Cleanup(close2)
		srv := simServer{ip: "127.0.0.1", port: p}
		e := simDoHPair(t, srv.url("https", "cloudflare-dns.com"), p, "127.0.0.1", "127.0.0.2")
		e.query(t, "example.com", dns.TypeA)
		e.query(t, "example.net", dns.TypeA)
	})

	t.Run("blackhole-testnet", func(t *testing.T) {
		ips := strings.Split(os.Getenv("SIM_BLACKHOLE_IPS"), ",")
		if len(ips) == 0 || ips[0] == "" {
			ips = []string{"192.0.2.1", "198.51.100.1"}
		}
		simHeader(fmt.Sprintf("blackhole: real URL, bootstrap IPs %v on 443 (needs a default route that drops them)", ips))
		for _, ip := range ips {
			c, err := net.DialTimeout("tcp4", net.JoinHostPort(ip, "443"), 3*time.Second)
			fmt.Printf("precheck: plain dial %s:443 for 3 s -> %v (want i/o timeout)\n", ip, err)
			if c != nil {
				_ = c.Close()
			}
		}
		e := simDoHPair(t, simRealURL, 443, ips...)
		e.query(t, "example.com", dns.TypeA)
		e.query(t, "example.net", dns.TypeA)
	})

	t.Run("fallback", func(t *testing.T) {
		simHeader("-dns-fallback: Preferred refuses, Default (bootstrap) works")
		good := simDoHServer(t, "ok", "fallback.sim.test")
		bad := simClosedPort(t, "127.0.0.1")
		fmt.Printf("setup: Default=%s; Preferred=%s\n", good.url("http", "fallback.sim.test"), bad.url("https", "cloudflare-dns.com"))
		e := newSimEnv(t, good.url("http", "fallback.sim.test"), good.ipport())
		DefaultDNSAsFallback(true)
		e.addPreferred(t, bad.url("https", "cloudflare-dns.com"), bad.ip)
		e.query(t, "example.com", dns.TypeA)
		e.query(t, "example.net", dns.TypeA)
		fmt.Println("... removing Preferred (fallback applies only to a missing/ended/paused transport)")
		e.r.Remove(x.StrOf(x.Preferred))
		e.query(t, "example.org", dns.TypeA)
	})

	t.Run("wrong-host-tls", func(t *testing.T) {
		simOnline(t)
		simHeader("TLS to the wrong host: cloudflare-dns.com bootstrapped to 8.8.8.8 (dns.google's certificate)")
		e := simDoHPair(t, simRealURL, 443, "8.8.8.8")
		e.query(t, "example.com", dns.TypeA)
	})

	t.Run("real", func(t *testing.T) {
		simOnline(t)
		label := os.Getenv("SIM_LABEL")
		if label == "" {
			label = "real Cloudflare, 1.1.1.1 and 1.0.0.1"
		}
		simHeader(label)
		e := simDoHPair(t, simRealURL, 443, "1.1.1.1", "1.0.0.1")
		e.query(t, "example.com", dns.TypeA)
		e.query(t, "example.net", dns.TypeA)
	})
}
