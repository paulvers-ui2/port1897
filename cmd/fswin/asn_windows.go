// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"
)

// The address ranges of the networks (ASNs) the user blocks. The app window
// sends only their numbers; fswin asks RIPEstat which ranges each network
// announces, keeps them in the app's folder (next to rules.json, with the
// user's rights, as its other files) and refreshes them weekly. Until a
// network's ranges first arrive it blocks nothing, and the status says so.

const (
	asnPrefixesURL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS"
	asnOverviewURL = "https://stat.ripe.net/data/as-overview/data.json?resource=AS"
	asnMaxAge      = 7 * 24 * time.Hour
	asnRetry       = 10 * time.Minute // after a failed lookup
	asnMaxReply    = 64 << 20         // the biggest networks announce tens of thousands of ranges
)

type asnEntry struct {
	Name     string   `json:"name,omitempty"`
	Prefixes []string `json:"prefixes"`
	At       int64    `json:"at"` // unix millis, when fetched
}

// asnState is one network's line in /api/status.
type asnState struct {
	ASN    uint32 `json:"asn"`
	Name   string `json:"name,omitempty"`
	Ranges int    `json:"ranges"`
	At     int64  `json:"at,omitempty"`    // when its ranges were fetched
	Error  string `json:"error,omitempty"` // why the last lookup failed
}

type asnTable struct {
	mu      sync.Mutex
	dir     string // where ranges are kept; "" for memory only
	entries map[uint32]*asnEntry
	failed  map[uint32]time.Time // last failed lookup
	errs    map[uint32]string
	busy    bool
	// fetch looks a network up; tests replace it
	fetch func(ctx context.Context, asn uint32) (*asnEntry, error)
}

var asns = &asnTable{
	entries: map[uint32]*asnEntry{},
	failed:  map[uint32]time.Time{},
	errs:    map[uint32]string{},
	fetch:   fetchASN,
}

// setDir keeps fetched ranges in dir from now on.
func (t *asnTable) setDir(dir string) {
	t.mu.Lock()
	t.dir = dir
	t.mu.Unlock()
}

func (t *asnTable) file(asn uint32) string {
	return filepath.Join(t.dir, "AS"+strconv.FormatUint(uint64(asn), 10)+".json")
}

// get returns the ranges of asn known so far, from memory or the disk.
func (t *asnTable) get(asn uint32) *asnEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e := t.entries[asn]; e != nil {
		return e
	}
	if t.dir == "" {
		return nil
	}
	b, err := readUserFile(t.file(asn))
	if err != nil {
		return nil
	}
	var e asnEntry
	if json.Unmarshal(b, &e) != nil || len(e.Prefixes) == 0 {
		return nil
	}
	t.entries[asn] = &e
	return &e
}

// due lists the networks among want to look up now: never fetched or a
// week old, and not failed within asnRetry.
func (t *asnTable) due(want []uint32, now time.Time) (out []uint32) {
	for _, a := range want {
		e := t.get(a)
		t.mu.Lock()
		failed := now.Sub(t.failed[a]) < asnRetry
		t.mu.Unlock()
		if failed {
			continue
		}
		if e == nil || now.Sub(time.UnixMilli(e.At)) > asnMaxAge {
			out = append(out, a)
		}
	}
	return out
}

// refresh looks up the networks of want that are due, one at a time, in
// the background; done runs once if any of them got new ranges. One
// refresh runs at a time; a call while one runs is dropped (the next rule
// change or status poll asks again).
func (t *asnTable) refresh(want []uint32, done func()) {
	list := t.due(want, time.Now())
	if len(list) == 0 {
		return
	}
	t.mu.Lock()
	if t.busy {
		t.mu.Unlock()
		return
	}
	t.busy = true
	t.mu.Unlock()
	go func() {
		got := false
		for _, a := range list {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			e, err := t.fetch(ctx, a)
			cancel()
			t.mu.Lock()
			if err != nil {
				t.failed[a] = time.Now()
				t.errs[a] = err.Error()
				t.mu.Unlock()
				continue
			}
			delete(t.failed, a)
			delete(t.errs, a)
			t.entries[a] = e
			dir := t.dir
			t.mu.Unlock()
			got = true
			if dir != "" {
				if b, err := json.Marshal(e); err == nil {
					_ = writeUserFile(t.file(a), b) // kept in memory either way
				}
			}
		}
		t.mu.Lock()
		t.busy = false
		t.mu.Unlock()
		if got && done != nil {
			done()
		}
	}()
}

// states reports each network of rs, for the status.
func (t *asnTable) states(rs []asnRule) []asnState {
	out := make([]asnState, 0, len(rs))
	for _, a := range rs {
		s := asnState{ASN: a.ASN, Name: cleanName(a.Name)}
		if len(a.Prefixes) > 0 {
			s.Ranges = len(a.Prefixes)
		} else if e := t.get(a.ASN); e != nil {
			s.Ranges, s.At = len(e.Prefixes), e.At
			if s.Name == "" {
				s.Name = e.Name
			}
		}
		t.mu.Lock()
		s.Error = t.errs[a.ASN]
		t.mu.Unlock()
		out = append(out, s)
	}
	return out
}

// fetchASN asks RIPEstat for the ranges asn announces and its holder.
func fetchASN(ctx context.Context, asn uint32) (*asnEntry, error) {
	id := strconv.FormatUint(uint64(asn), 10)
	var p struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if err := getJSON(ctx, asnPrefixesURL+id, &p); err != nil {
		return nil, fmt.Errorf("AS%s: %w", id, err)
	}
	e := &asnEntry{At: time.Now().UnixMilli()}
	for _, x := range p.Data.Prefixes {
		if pf, err := netip.ParsePrefix(x.Prefix); err == nil {
			e.Prefixes = append(e.Prefixes, pf.Masked().String())
		}
	}
	if len(e.Prefixes) == 0 {
		return nil, fmt.Errorf("AS%s announces no address ranges", id)
	}
	slices.Sort(e.Prefixes)
	e.Prefixes = slices.Compact(e.Prefixes)
	var o struct {
		Data struct {
			Holder string `json:"holder"`
		} `json:"data"`
	}
	if getJSON(ctx, asnOverviewURL+id, &o) == nil {
		e.Name = cleanName(o.Data.Holder)
	}
	return e, nil
}

var errASNReply = errors.New("lookup failed")

func getJSON(ctx context.Context, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "AuroraVPN-fswin/"+version)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s", errASNReply, res.Status)
	}
	return json.NewDecoder(io.LimitReader(res.Body, asnMaxReply)).Decode(v)
}
