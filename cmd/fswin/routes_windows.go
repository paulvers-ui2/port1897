// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/celzero/firestack/intra"
	x "github.com/celzero/firestack/intra/backend"
)

// Per-app routes, like the Android app's WireGuard "advanced" mode and its
// proxy app lists: extra WireGuard tunnels or SOCKS5 / HTTP proxies that the
// apps given them (appRule.Route) use instead of the main exit.

const (
	routeWGPrefix = x.WG + "app" // WireGuard ids must start with "wg"
	routeSocks    = "pxsocks"
	routeHTTP     = "pxhttp"
)

type route struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	Kind string `json:"kind"`           // "wg" or "proxy"
	File string `json:"file,omitempty"` // wg-quick .conf, for wg
	URL  string `json:"url,omitempty"`  // socks5://... or http://..., for proxy
}

// loadRoutes adds the routes in path as proxies and returns their names by
// id. Routes that fail are skipped and reported in err.
func loadRoutes(t intra.Tunnel, path string) (map[string]string, error) {
	b, err := readUserFile(path)
	if err != nil {
		return nil, err
	}
	var rs []route
	if err := json.Unmarshal(b, &rs); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	pxs, err := t.GetProxies()
	if err != nil {
		return nil, err
	}
	loaded := map[string]string{}
	var errs []error
	for _, r := range rs {
		var cfg string
		switch r.Kind {
		case "wg":
			if !strings.HasPrefix(r.ID, routeWGPrefix) {
				errs = append(errs, fmt.Errorf("route %s: WireGuard ids start with %s", r.ID, routeWGPrefix))
				continue
			}
			conf, rerr := readUserFile(r.File)
			if rerr != nil {
				errs = append(errs, fmt.Errorf("route %s: %w", r.ID, rerr))
				continue
			}
			cfg, rerr = wgQuickToUAPI(string(conf))
			if rerr != nil {
				errs = append(errs, fmt.Errorf("route %s: %w", r.ID, rerr))
				continue
			}
		case "proxy":
			if !strings.HasPrefix(r.URL, "socks5://") && !strings.HasPrefix(r.URL, "http://") {
				errs = append(errs, fmt.Errorf("route %s: proxy url must start with socks5:// or http://", r.ID))
				continue
			}
			cfg = r.URL
		default:
			errs = append(errs, fmt.Errorf("route %s: kind must be wg or proxy, not %q", r.ID, r.Kind))
			continue
		}
		if _, aerr := pxs.AddProxy(x.StrOf(r.ID), x.StrOf(cfg)); aerr != nil {
			errs = append(errs, fmt.Errorf("route %s: %w", r.ID, aerr))
			continue
		}
		name := r.Name
		if name == "" {
			name = r.ID
		}
		loaded[r.ID] = name
	}
	return loaded, errors.Join(errs...)
}

// proxyStat is what GET /api/proxies returns per tunnel: the exit and the
// per-app routes, as the Android app's WireGuard and proxy screens show them.
type proxyStat struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Addrs  string `json:"addrs,omitempty"`
	Rx     int64  `json:"rx"`
	Tx     int64  `json:"tx"`
	LastOK int64  `json:"lastOK,omitempty"` // unix millis of the last handshake or good dial
	Since  int64  `json:"since,omitempty"`
}

func proxyStatus(s int) string {
	switch s {
	case x.TOK:
		return "connected"
	case x.TUP:
		return "up"
	case x.TZZ:
		return "idle"
	case x.TNT:
		return "not responding"
	case x.TKO:
		return "failing"
	case x.TPU:
		return "paused"
	case x.END:
		return "stopped"
	}
	return "unknown"
}

// proxyStats reports the exit and the routes; a proxy that is missing or
// fails to report is listed as such.
func (b *bridge) proxyStats() []proxyStat {
	out := []proxyStat{}
	t, ok := b.tun.Load().(intra.Tunnel)
	if !ok || t == nil {
		return out
	}
	pxs, err := t.GetProxies()
	if err != nil {
		return out
	}
	ids := map[string]string{}
	if e := b.exitID(); e != x.Base {
		ids[e] = exitName(e)
	}
	if p := b.routes.Load(); p != nil {
		for k, v := range *p {
			ids[k] = v
		}
	}
	for id, name := range ids {
		out = append(out, statOf(pxs, id, name))
	}
	slices.SortFunc(out, func(a, b proxyStat) int { return strings.Compare(a.Name, b.Name) })
	return out
}

func statOf(pxs x.Proxies, id, name string) (st proxyStat) {
	st = proxyStat{ID: id, Name: name, Status: "missing"}
	defer func() {
		if r := recover(); r != nil {
			st.Status = "unknown"
		}
	}()
	px, err := pxs.GetProxy(x.StrOf(id))
	if err != nil || px == nil {
		return
	}
	st.Status = proxyStatus(px.Status())
	if r := px.Router(); r != nil {
		if s := r.Stat(); s != nil {
			st.Addrs, st.Rx, st.Tx, st.LastOK, st.Since = s.Addrs, s.Rx, s.Tx, s.LastOK, s.Since
		}
	}
	return
}

// setRoutes records the routes that loaded, so flows can use them.
func (b *bridge) setRoutes(r map[string]string) {
	b.routes.Store(&r)
}

// routeName is the name of a loaded route, or "" if id is not one.
func (b *bridge) routeName(id string) string {
	if p := b.routes.Load(); p != nil {
		return (*p)[id]
	}
	return ""
}
