// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"cmp"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// maxConns bounds the open-connection table; flows past it are still
// firewalled, just not closed early when a rule changes.
const maxConns = 50000

// liveConn is an open connection, kept so that a new rule can close it.
type liveConn struct {
	uid     int32
	proto   int32
	dst     netip.AddrPort
	domains []string
	app     string
	at      int64 // unix millis
}

type connTable struct {
	mu sync.Mutex
	m  map[string]liveConn // by connection id
}

func newConnTable() *connTable {
	return &connTable{m: map[string]liveConn{}}
}

func (t *connTable) add(cid string, c liveConn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.m) < maxConns {
		t.m[cid] = c
	}
}

func (t *connTable) remove(cid string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.m, cid)
}

// all returns a copy of the table.
func (t *connTable) all() map[string]liveConn {
	t.mu.Lock()
	defer t.mu.Unlock()
	return maps.Clone(t.m)
}

// openConn is what GET /api/conns returns per connection.
type openConn struct {
	CID    string `json:"cid"`
	App    string `json:"app"`
	Proto  string `json:"proto"`
	Dst    string `json:"dst"`
	Domain string `json:"domain,omitempty"`
	Since  int64  `json:"since"` // unix millis
}

// list returns the open connections of app (all if ""), newest first.
func (t *connTable) list(app string) []openConn {
	app = strings.ToLower(app)
	out := []openConn{}
	for cid, c := range t.all() {
		if app != "" && strings.ToLower(c.app) != app {
			continue
		}
		o := openConn{CID: cid, App: c.app, Proto: proto(c.proto), Dst: c.dst.String(), Since: c.at}
		if len(c.domains) > 0 {
			o.Domain = c.domains[0]
		}
		out = append(out, o)
	}
	slices.SortFunc(out, func(a, b openConn) int { return cmp.Compare(b.Since, a.Since) })
	return out
}

// whyCache remembers, for a short while, why a DNS query was sent to
// BlockAll, so its answer can be logged with the rule that blocked it.
type whyCache struct {
	mu sync.Mutex
	m  map[string]whyEntry
}

type whyEntry struct {
	why string
	at  time.Time
}

const whyTTL = 30 * time.Second

func newWhyCache() *whyCache {
	return &whyCache{m: map[string]whyEntry{}}
}

func normName(qname string) string {
	return strings.ToLower(strings.TrimSuffix(qname, "."))
}

func (w *whyCache) put(qname, why string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	if len(w.m) > 4096 {
		for k, e := range w.m {
			if now.Sub(e.at) > whyTTL {
				delete(w.m, k)
			}
		}
	}
	w.m[normName(qname)] = whyEntry{why, now}
}

func (w *whyCache) get(qname string) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	k := normName(qname)
	e, ok := w.m[k]
	if !ok {
		return ""
	}
	// kept until it expires: A and AAAA queries for a name share the reason
	if time.Since(e.at) > whyTTL {
		return ""
	}
	return e.why
}
