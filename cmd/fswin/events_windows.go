// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"cmp"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// event is one line of the activity log the UI shows.
type event struct {
	ID        int64  `json:"id"`
	At        int64  `json:"at"`   // unix millis
	Kind      string `json:"kind"` // "flow", "dns" or "close" (a connection ended)
	App       string `json:"app,omitempty"`
	Path      string `json:"path,omitempty"` // the program's full path, when Windows told it
	Proto     string `json:"proto,omitempty"`
	Dst       string `json:"dst,omitempty"`
	Domain    string `json:"domain,omitempty"`
	Country   string `json:"country,omitempty"` // two-letter code of Dst, or of a DNS answer's first address
	Answer    string `json:"answer,omitempty"`
	Via       string `json:"via,omitempty"`
	LatencyMs int64  `json:"latencyMs,omitempty"`
	Blocked   bool   `json:"blocked,omitempty"`
	Rx        int64  `json:"rx,omitempty"` // bytes, on "close"
	Tx        int64  `json:"tx,omitempty"`
	DurMs     int64  `json:"durMs,omitempty"`
	Secure    bool   `json:"secure,omitempty"` // DNSSEC verified (AD bit)
	Cached    bool   `json:"cached,omitempty"` // answered from the DNS cache
	Rule      string `json:"rule,omitempty"`   // the firewall or DNS rule that decided
	CID       string `json:"cid,omitempty"`    // connection id, on "flow" and "close"
	QType     int    `json:"qtype,omitempty"`  // DNS query type, on "dns"
	Error     string `json:"error,omitempty"`  // why a DNS query failed, on "dns"
}

// journalSize bounds how many recent events are kept.
const journalSize = 2000

// journal keeps the most recent events and running counts for the UI.
type journal struct {
	mu      sync.Mutex
	buf     []event // ring, oldest first once full
	head    int     // next write position once full
	next    int64   // next event id
	apps    map[string]int64
	domains map[string]int64

	flows        atomic.Int64
	flowsBlocked atomic.Int64
	dnsQueries   atomic.Int64
	dnsFailed    atomic.Int64
	dnsBogus     atomic.Int64 // bogus answers blocked by the DNSSEC switch
	dnsBlocked   atomic.Int64 // queries blocked by domain rules or query type
	dnsLastMs    atomic.Int64
	dnsTotalMs   atomic.Int64
	rx           atomic.Int64
	tx           atomic.Int64
}

func newJournal() *journal {
	return &journal{
		buf:     make([]event, 0, journalSize),
		next:    1,
		apps:    map[string]int64{},
		domains: map[string]int64{},
	}
}

func (j *journal) add(e event) {
	j.mu.Lock()
	defer j.mu.Unlock()
	e.ID = j.next
	j.next++
	if e.At == 0 {
		e.At = time.Now().UnixMilli()
	}
	if e.Kind == "flow" && e.App != "" {
		j.apps[e.App]++
	}
	if e.Domain != "" {
		j.domains[e.Domain]++
	}
	if len(j.buf) < journalSize {
		j.buf = append(j.buf, e)
		return
	}
	j.buf[j.head] = e
	j.head = (j.head + 1) % journalSize
}

// since returns up to max events with an id above after, oldest first.
func (j *journal) since(after int64, max int) []event {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]event, 0, min(max, len(j.buf)))
	for i := range len(j.buf) {
		e := j.buf[(j.head+i)%len(j.buf)]
		if e.ID > after {
			out = append(out, e)
		}
	}
	if len(out) > max {
		out = out[len(out)-max:]
	}
	return out
}

type count struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

// top returns the n most frequent apps and domains seen so far.
func (j *journal) top(n int) (apps, domains []count) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return topOf(j.apps, n), topOf(j.domains, n)
}

func topOf(m map[string]int64, n int) []count {
	out := make([]count, 0, len(m))
	for k, v := range m {
		out = append(out, count{k, v})
	}
	slices.SortFunc(out, func(a, b count) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.Name, b.Name))
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func (j *journal) appsSeen() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return len(j.apps)
}
