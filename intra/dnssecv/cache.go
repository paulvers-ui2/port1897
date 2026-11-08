// Copyright (c) 2026 AuroraVPN contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnssecv

import (
	"container/list"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// boundedCache implements resolver.CacheInterface with a hard cap on entries
// and on TTL (SECURITY-FIXES.md VULN-K: unbounded caches are a memory-DoS
// vector, and huge TTLs let a poisoned answer outlive a key rollover).
//
// The resolver caches raw upstream responses per zone and re-runs DNSSEC
// validation on every lookup, so a cache hit never skips signature checks.
type boundedCache struct {
	mu      sync.Mutex
	maxN    int
	maxTTL  time.Duration
	minTTL  time.Duration
	ll      *list.List // front = most recently used
	entries map[string]*list.Element
	now     func() time.Time // injectable for tests
}

type cacheEntry struct {
	key     string
	msg     *dns.Msg
	expires time.Time
}

func newBoundedCache(maxEntries int, maxTTL time.Duration) *boundedCache {
	if maxEntries <= 0 {
		maxEntries = 1
	}
	return &boundedCache{
		maxN:    maxEntries,
		maxTTL:  maxTTL,
		minTTL:  5 * time.Second,
		ll:      list.New(),
		entries: make(map[string]*list.Element, maxEntries),
		now:     time.Now,
	}
}

func cacheKey(zone string, q dns.Question) string {
	var b strings.Builder
	b.Grow(len(zone) + len(q.Name) + 16)
	b.WriteString(dns.CanonicalName(zone))
	b.WriteByte('|')
	b.WriteString(dns.CanonicalName(q.Name))
	b.WriteByte('|')
	b.WriteString(dns.TypeToString[q.Qtype])
	b.WriteByte('|')
	b.WriteString(dns.ClassToString[q.Qclass])
	return b.String()
}

// Get returns (nil, nil) on a miss, which the resolver treats as "not cached".
func (c *boundedCache) Get(zone string, q dns.Question) (*dns.Msg, error) {
	k := cacheKey(zone, q)
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[k]
	if !ok {
		return nil, nil
	}
	e := el.Value.(*cacheEntry)
	if c.now().After(e.expires) {
		c.removeLocked(el)
		return nil, nil
	}
	c.ll.MoveToFront(el)
	return e.msg.Copy(), nil
}

func (c *boundedCache) Update(zone string, q dns.Question, msg *dns.Msg) error {
	if msg == nil {
		return nil
	}
	// Never cache truncated or server-failure responses.
	if msg.Truncated || msg.Rcode == dns.RcodeServerFailure {
		return nil
	}
	ttl := c.clampTTL(minTTL(msg))
	if ttl <= 0 {
		return nil
	}
	k := cacheKey(zone, q)
	e := &cacheEntry{key: k, msg: msg.Copy(), expires: c.now().Add(ttl)}

	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[k]; ok {
		el.Value = e
		c.ll.MoveToFront(el)
		return nil
	}
	c.entries[k] = c.ll.PushFront(e)
	for c.ll.Len() > c.maxN {
		c.removeLocked(c.ll.Back())
	}
	return nil
}

func (c *boundedCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

func (c *boundedCache) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ll.Init()
	c.entries = make(map[string]*list.Element, c.maxN)
}

func (c *boundedCache) removeLocked(el *list.Element) {
	if el == nil {
		return
	}
	c.ll.Remove(el)
	delete(c.entries, el.Value.(*cacheEntry).key)
}

func (c *boundedCache) clampTTL(ttl time.Duration) time.Duration {
	if ttl < c.minTTL {
		ttl = c.minTTL
	}
	if c.maxTTL > 0 && ttl > c.maxTTL {
		ttl = c.maxTTL
	}
	return ttl
}

// minTTL is the smallest TTL across all sections, ignoring OPT pseudo-records.
// A response with no records gets the SOA-less negative floor (minTTL in the cache).
func minTTL(msg *dns.Msg) time.Duration {
	var min uint32
	found := false
	for _, sec := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range sec {
			if rr == nil || rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			t := rr.Header().Ttl
			if soa, ok := rr.(*dns.SOA); ok && soa.Minttl < t {
				t = soa.Minttl // RFC 2308 negative-caching TTL
			}
			if !found || t < min {
				min, found = t, true
			}
		}
	}
	if !found {
		return 0
	}
	return time.Duration(min) * time.Second
}
