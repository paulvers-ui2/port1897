// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The control API lets the app window (which runs without admin rights) read
// status and change blocking. It listens on loopback only and every request
// must carry the token from -token-file. Requests from web pages are refused
// (they carry an Origin header), as are other Host names (DNS rebinding).
// TODO(phase 2): move to a named pipe locked down with an ACL.

// apiStatus is what GET /api/status returns.
type apiStatus struct {
	Version   string   `json:"version"`
	StartedAt int64    `json:"startedAt"` // unix millis
	Mode      string   `json:"mode"`      // "dns" or "full"
	Exit      string   `json:"exit"`      // exit name, "" when direct
	DNS       dnsStat  `json:"dns"`
	Firewall  fwStat   `json:"firewall"`
	Traffic   trafStat `json:"traffic"`
	NRPT      bool     `json:"nrpt"`
	AllowLAN  bool     `json:"allowLan"`
	Kill      bool     `json:"killSwitch"`
	// why the kill switch is not on, when turning it on failed
	KillError string   `json:"killSwitchError,omitempty"`
	Paused    int64    `json:"pausedUntil"` // unix millis; 0 when not paused
	Dial      string   `json:"dial"`        // anti-censorship dial strategy
	Conflicts []string `json:"conflicts"`   // other VPNs that break ours
}

type dnsStat struct {
	Server  string `json:"server"`
	Type    string `json:"type"`
	Queries int64  `json:"queries"`
	Failed  int64  `json:"failed"`
	Bogus   int64  `json:"bogus"`
	Blocked int64  `json:"blocked"` // by domain rules or query type
	DNSSEC  bool   `json:"dnssec"`
	Cache   bool   `json:"cache"`
	LastMs  int64  `json:"lastMs"`
	AvgMs   int64  `json:"avgMs"`
}

type fwStat struct {
	Flows       int64    `json:"flows"`
	Blocked     int64    `json:"blocked"`
	BlockedApps []string `json:"blockedApps"`
	AppsSeen    int      `json:"appsSeen"`
}

type trafStat struct {
	Rx int64 `json:"rx"` // bytes, closed connections only
	Tx int64 `json:"tx"`
}

type apiServer struct {
	b     *bridge
	token []byte
	host  string // expected Host header, ip:port
	info  func() apiStatus
	stop  func()
}

// apiPreflight checks, before fswin touches the system, that the control
// API can start: a free loopback address (an engine still running holds it)
// and a readable token.
func apiPreflight(addr, tokenFile string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return errors.New("-api must be a loopback address like 127.0.0.1:47897")
	}
	tok, err := os.ReadFile(filepath.Clean(tokenFile))
	if err != nil {
		return fmt.Errorf("-token-file: %w", err)
	}
	if len(strings.TrimSpace(string(tok))) < 16 {
		return errors.New("-token-file: token must be at least 16 characters")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("%w (is another engine still running?)", err)
	}
	return ln.Close()
}

// serveAPI starts the control API on addr (loopback only).
func serveAPI(addr, tokenFile string, b *bridge, info func() apiStatus, stop func()) (*http.Server, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return nil, errors.New("-api must be a loopback address like 127.0.0.1:47897")
	}
	tok, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("-token-file: %w", err)
	}
	tok = []byte(strings.TrimSpace(string(tok)))
	if len(tok) < 16 {
		return nil, errors.New("-token-file: token must be at least 16 characters")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	a := &apiServer{b: b, token: tok, host: ln.Addr().String(), info: info, stop: stop}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/status", a.status)
	mux.HandleFunc("GET /api/events", a.events)
	mux.HandleFunc("GET /api/stats", a.stats)
	mux.HandleFunc("POST /api/block", a.block)
	mux.HandleFunc("POST /api/rules", a.setRules)
	mux.HandleFunc("GET /api/conns", a.conns)
	mux.HandleFunc("GET /api/proxies", a.proxies)
	mux.HandleFunc("POST /api/close", a.closeConns)
	mux.HandleFunc("POST /api/killswitch", a.killSwitch)
	mux.HandleFunc("POST /api/stop", a.shutdown)

	srv := &http.Server{
		Handler:           a.guard(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	return srv, nil
}

func (a *apiServer) guard(next http.Handler) http.Handler {
	want := "Bearer " + string(a.token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" || r.Host != a.host {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		got := r.Header.Get("Authorization")
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func (a *apiServer) status(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, a.info())
}

// events returns activity after ?after=<id>, at most ?max=<n> (default 200).
func (a *apiServer) events(w http.ResponseWriter, r *http.Request) {
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	n, _ := strconv.Atoi(r.URL.Query().Get("max"))
	if n <= 0 || n > journalSize {
		n = 200
	}
	writeJSON(w, a.b.log.since(after, n))
}

func (a *apiServer) stats(w http.ResponseWriter, _ *http.Request) {
	apps, domains := a.b.log.top(20)
	writeJSON(w, map[string]any{"apps": apps, "domains": domains})
}

// block takes {"app": "chrome.exe", "block": true}.
func (a *apiServer) block(w http.ResponseWriter, r *http.Request) {
	var req struct {
		App   string `json:"app"`
		Block bool   `json:"block"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || strings.TrimSpace(req.App) == "" {
		http.Error(w, "want {\"app\": \"name.exe\", \"block\": true}", http.StatusBadRequest)
		return
	}
	a.b.setBlocked(req.App, req.Block)
	writeJSON(w, map[string]any{"blockedApps": a.b.blockedApps()})
}

// setRules takes the whole rule set (rules_windows.go) and applies it at
// once; open connections that it blocks are closed.
func (a *apiServer) setRules(w http.ResponseWriter, r *http.Request) {
	var rs ruleSet
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&rs); err != nil {
		http.Error(w, "bad rules: "+err.Error(), http.StatusBadRequest)
		return
	}
	res := map[string]any{"ok": true}
	if err := a.b.setRules(rs); err != nil {
		res["warnings"] = err.Error() // rules that did not parse were skipped
	}
	writeJSON(w, res)
}

// proxies reports the exit and the per-app routes.
func (a *apiServer) proxies(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, a.b.proxyStats())
}

// conns lists open connections, of ?app=name.exe only if given.
func (a *apiServer) conns(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, a.b.conns.list(r.URL.Query().Get("app")))
}

// closeConns takes {"app": "chrome.exe"}, {"app": ""} for all, or
// {"cids": ["12"]} for single connections, as the Logs screen closes them.
func (a *apiServer) closeConns(w http.ResponseWriter, r *http.Request) {
	var req struct {
		App  string   `json:"app"`
		CIDs []string `json:"cids"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "want {\"app\": \"name.exe\"} or {\"cids\": [\"12\"]}", http.StatusBadRequest)
		return
	}
	if len(req.CIDs) > 0 {
		writeJSON(w, map[string]int{"closed": a.b.closeIDs(req.CIDs)})
		return
	}
	writeJSON(w, map[string]int{"closed": a.b.closeApp(req.App)})
}

// killSwitch takes {"on": true, "allowLan": false} and turns the kill switch
// on or off at once, for the app's kill switch button.
func (a *apiServer) killSwitch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		On       bool `json:"on"`
		AllowLAN bool `json:"allowLan"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := a.b.kill.set(req.On, req.AllowLAN); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errKillNeedsFull) || errors.Is(err, errNoKillSwitch) {
			code = http.StatusConflict
		}
		http.Error(w, err.Error(), code)
		return
	}
	a.b.logf("kill switch %s (from the app)", map[bool]string{true: "on", false: "off"}[req.On])
	writeJSON(w, map[string]bool{"killSwitch": a.b.kill.isOn()})
}

func (a *apiServer) shutdown(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]bool{"stopping": true})
	go a.stop()
}

// statusOf builds the API status from the bridge and the run options.
func statusOf(b *bridge, o options, started time.Time, exitID, dnsLabel string) apiStatus {
	l := b.log
	st := apiStatus{
		Version:   version,
		StartedAt: started.UnixMilli(),
		Mode:      "dns",
		NRPT:      o.nrpt,
		AllowLAN:  o.allowLAN,
		Kill:      b.kill.isOn(),
		KillError: b.kill.lastError(),
		DNS: dnsStat{
			Server:  dnsLabel,
			Type:    o.dnsType,
			Queries: l.dnsQueries.Load(),
			Failed:  l.dnsFailed.Load(),
			Bogus:   l.dnsBogus.Load(),
			Blocked: l.dnsBlocked.Load(),
			DNSSEC:  o.dnssec,
			Cache:   o.dnsCache,
			LastMs:  l.dnsLastMs.Load(),
		},
		Firewall: fwStat{
			Flows:       l.flows.Load(),
			Blocked:     l.flowsBlocked.Load(),
			BlockedApps: b.blockedApps(),
			AppsSeen:    l.appsSeen(),
		},
		Traffic:   trafStat{Rx: l.rx.Load(), Tx: l.tx.Load()},
		Dial:      o.dialStrategy,
		Conflicts: append([]string{}, o.conflicts...),
	}
	if r := b.rules.Load(); r.isPaused(time.Now().UnixMilli()) {
		st.Paused = r.paused
	}
	if ok := st.DNS.Queries - st.DNS.Failed; ok > 0 {
		st.DNS.AvgMs = l.dnsTotalMs.Load() / ok
	}
	if o.full {
		st.Mode = "full"
	}
	if exitID != "" {
		st.Exit = exitName(exitID)
	}
	return st
}
