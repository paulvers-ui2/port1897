// Copyright (c) 2026 AuroraVPN contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package dnssecv is a local, validating, recursive DNSSEC resolver.
//
// It resolves iteratively from the root servers and validates every answer up
// to the IANA root trust anchors (KSK-2017 and KSK-2024, embedded), including
// authenticated denial of existence (NSEC / NSEC3). Nothing here trusts the
// AD bit of an upstream server.
//
// It wraps a vendored copy of github.com/nsmithuk/resolver (MIT, see
// resolver/LICENSE and PATCHES.md). Upstream marks that library ALPHA, so this
// wrapper fails closed: any error, timeout or panic yields Unknown, never
// Secure.
package dnssecv

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/celzero/firestack/intra/dnssecv/resolver"
	"github.com/celzero/firestack/intra/dnssecv/resolver/dnssec"
	"github.com/miekg/dns"
)

// Status is the validation verdict for one lookup.
type Status int32

const (
	// StatusUnknown: no verdict (network error, timeout, internal error).
	// Callers MUST treat this as "not validated".
	StatusUnknown Status = 0
	// StatusInsecure: provably unsigned (a signed parent proved no DS exists).
	StatusInsecure Status = 1
	// StatusSecure: full chain of trust verified to the root anchor.
	StatusSecure Status = 2
	// StatusBogus: signatures present but invalid, expired, or chain broken.
	// The answer is likely forged and MUST NOT be used.
	StatusBogus Status = 3
)

func (s Status) String() string {
	switch s {
	case StatusInsecure:
		return "insecure"
	case StatusSecure:
		return "secure"
	case StatusBogus:
		return "bogus"
	default:
		return "unknown"
	}
}

var (
	ErrInvalidName = errors.New("dnssecv: invalid domain name")
	ErrInvalidType = errors.New("dnssecv: query type not allowed")
	ErrBusy        = errors.New("dnssecv: too many concurrent validations")
	ErrInternal    = errors.New("dnssecv: internal error")
	ErrNoResponse  = errors.New("dnssecv: no response")
	ErrClosed      = errors.New("dnssecv: validator closed")
)

// Result is a single validated lookup.
type Result struct {
	Name     string
	Qtype    uint16
	Status   Status
	Rcode    int
	Denial   string   // NSEC/NSEC3 proof kind, e.g. "Nsec3NxDomain"; "" if none
	Answers  []string // presentation format; empty when Bogus (RFC 4035 §5.5)
	Duration time.Duration
	Err      error
}

// Config holds the tunables. Zero values fall back to safe defaults.
type Config struct {
	// Dialer must return a dialer that protects its sockets from the VPN
	// (VpnService.protect) on Android; see DialerFactory in resolver/config.go.
	// Required in production; nil only for host-side tests.
	Dialer func() *net.Dialer

	MaxConcurrent int           // default 8
	Timeout       time.Duration // per Validate call; default 6s
	UDPTimeout    time.Duration // per exchange; default 900ms
	TCPTimeout    time.Duration // per exchange; default 2s
	CacheEntries  int           // default 10000 (matches dns_cache_max_entries)
	CacheMaxTTL   time.Duration // default 1h (matches max_dns_cache_ttl_sec)
	MaxQueries    uint32        // per lookup, loop guard; default 100
}

// exchanger is the slice of *resolver.Resolver we use; a fake in tests.
type exchanger interface {
	Exchange(ctx context.Context, m *dns.Msg) *resolver.Response
}

type Validator struct {
	ex      exchanger
	sem     chan struct{}
	timeout time.Duration
	cache   *boundedCache

	dialer atomic.Pointer[func() *net.Dialer]

	mu     sync.RWMutex
	closed bool
}

// The vendored resolver keeps its settings in package globals, so only one
// configuration can be live per process. New enforces that.
var (
	configureMu sync.Mutex
	configured  bool
)

// New builds the process-wide validator. Calling it twice returns an error
// rather than silently re-pointing the globals of a validator already in use.
func New(cfg Config) (*Validator, error) {
	configureMu.Lock()
	defer configureMu.Unlock()
	if configured {
		return nil, errors.New("dnssecv: already configured; reuse the existing validator")
	}

	cfg = withDefaults(cfg)
	cache := newBoundedCache(cfg.CacheEntries, cfg.CacheMaxTTL)

	resolver.TimeoutUDP = cfg.UDPTimeout
	resolver.TimeoutTCP = cfg.TCPTimeout
	resolver.MaxQueriesPerRequest = cfg.MaxQueries
	resolver.MaxAllowedTTL = ttlSeconds(cfg.CacheMaxTTL)
	resolver.SuppressBogusResponseSections = true // RFC 4035 §5.5, never relax
	resolver.Cache = cache
	v := &Validator{
		sem:     make(chan struct{}, cfg.MaxConcurrent),
		timeout: cfg.Timeout,
		cache:   cache,
	}
	v.SetDialer(cfg.Dialer)
	// The resolver reads DialerFactory on every exchange; route it through an
	// atomic so the VPN service can swap protectors on restart without a race.
	resolver.DialerFactory = v.currentDialer
	v.ex = resolver.NewResolver()
	configured = true
	return v, nil
}

// ttlSeconds converts a duration to whole seconds, clamped to uint32.
func ttlSeconds(d time.Duration) uint32 {
	s := int64(d / time.Second)
	if s < 0 {
		return 0
	}
	if s > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(s)
}

func withDefaults(c Config) Config {
	if c.MaxConcurrent <= 0 {
		c.MaxConcurrent = 8
	}
	if c.Timeout <= 0 {
		c.Timeout = 6 * time.Second
	}
	if c.UDPTimeout <= 0 {
		c.UDPTimeout = 900 * time.Millisecond
	}
	if c.TCPTimeout <= 0 {
		c.TCPTimeout = 2 * time.Second
	}
	if c.CacheEntries <= 0 {
		c.CacheEntries = 10000
	}
	if c.CacheMaxTTL <= 0 {
		c.CacheMaxTTL = time.Hour
	}
	if c.MaxQueries == 0 {
		c.MaxQueries = 100
	}
	return c
}

// newForTest wires a fake exchanger without touching resolver globals.
func newForTest(ex exchanger, maxConcurrent int, timeout time.Duration) *Validator {
	return &Validator{ex: ex, sem: make(chan struct{}, maxConcurrent), timeout: timeout}
}

// Validate resolves name/qtype from the root and returns a verdict.
// It never panics and never returns StatusSecure alongside a non-nil Err.
func (v *Validator) Validate(parent context.Context, name string, qtype uint16) (res Result) {
	start := time.Now()
	res = Result{Name: name, Qtype: qtype, Status: StatusUnknown, Rcode: -1}
	defer func() {
		res.Duration = time.Since(start)
		if r := recover(); r != nil {
			// The library is alpha; a panic must not take down the VPN
			// service (see SECURITY-FIXES.md VULN-A). Fail closed.
			res.Status, res.Answers, res.Denial = StatusUnknown, nil, ""
			res.Err = fmt.Errorf("%w: recovered panic: %v", ErrInternal, r)
		}
	}()

	v.mu.RLock()
	closed := v.closed
	v.mu.RUnlock()
	if closed {
		res.Err = ErrClosed
		return res
	}

	fqdn, err := NormalizeName(name)
	if err != nil {
		res.Err = err
		return res
	}
	res.Name = fqdn
	if !AllowedType(qtype) {
		res.Err = ErrInvalidType
		return res
	}

	ctx, cancel := context.WithTimeout(parent, v.timeout)
	defer cancel()

	// Bound concurrency: each lookup can fan out to dozens of upstream
	// queries, so an unbounded caller could turn us into a traffic amplifier.
	select {
	case v.sem <- struct{}{}:
		defer func() { <-v.sem }()
	case <-ctx.Done():
		res.Err = ErrBusy
		return res
	}

	q := new(dns.Msg)
	q.SetQuestion(fqdn, qtype)
	q.RecursionDesired = true
	q.SetEdns0(1232, true) // DO bit; 1232 avoids IP fragmentation (DNS flag day 2020)

	r := v.ex.Exchange(ctx, q)
	return interpret(res, r)
}

// interpret maps a resolver.Response to a Result. Kept pure for unit tests.
func interpret(res Result, r *resolver.Response) Result {
	if r == nil {
		res.Err = ErrNoResponse
		return res
	}
	if r.Err != nil {
		res.Err = r.Err
		// A Bogus verdict is still meaningful with an error attached (the
		// error explains why); anything else is not a verdict at all.
		if r.Auth == dnssec.Bogus {
			res.Status = StatusBogus
		}
		return res
	}
	if r.Msg == nil {
		res.Err = ErrNoResponse
		return res
	}
	res.Rcode = r.Msg.Rcode
	switch r.Auth {
	case dnssec.Secure:
		res.Status = StatusSecure
	case dnssec.Insecure:
		res.Status = StatusInsecure
	case dnssec.Bogus:
		res.Status = StatusBogus
	default:
		res.Status = StatusUnknown
	}
	if r.Doe != dnssec.NotFound {
		res.Denial = r.Doe.String()
	}
	if res.Status != StatusBogus {
		for _, rr := range r.Msg.Answer {
			if rr != nil && rr.Header().Rrtype != dns.TypeRRSIG {
				res.Answers = append(res.Answers, rr.String())
			}
		}
	}
	return res
}

// SetDialer swaps the socket-protecting dialer (e.g. after the VPN service
// restarts with a new protector). nil means "use the default dialer", which
// on Android leaks queries into the tunnel; only tests should pass nil.
func (v *Validator) SetDialer(f func() *net.Dialer) {
	if f == nil {
		v.dialer.Store(nil)
		return
	}
	v.dialer.Store(&f)
}

func (v *Validator) currentDialer() *net.Dialer {
	if p := v.dialer.Load(); p != nil {
		return (*p)()
	}
	return nil
}

// HasDialer reports whether a protecting dialer is installed.
func (v *Validator) HasDialer() bool { return v.dialer.Load() != nil }

// OnNetworkChanged drops state tied to the previous network path.
func (v *Validator) OnNetworkChanged() {
	resolver.ResetIPv6Availability()
	if v.cache != nil {
		v.cache.Purge()
	}
}

func (v *Validator) Close() {
	v.mu.Lock()
	v.closed = true
	v.mu.Unlock()
	if v.cache != nil {
		v.cache.Purge()
	}
}

// ---- input validation (OWASP: treat all input as hostile) ----

const maxNameLen = 253 // presentation form, without the trailing dot

// NormalizeName lower-cases, trims and fully-qualifies a domain name, and
// rejects anything that is not a syntactically valid hostname-ish DNS name.
func NormalizeName(name string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.TrimSuffix(n, ".")
	if n == "" {
		// The root itself is allowed (used by self-tests).
		if strings.TrimSpace(name) == "." {
			return ".", nil
		}
		return "", ErrInvalidName
	}
	if len(n) > maxNameLen {
		return "", ErrInvalidName
	}
	for _, label := range strings.Split(n, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", ErrInvalidName
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
			if !ok {
				return "", ErrInvalidName // rejects escapes, spaces, unicode (use punycode)
			}
		}
	}
	fqdn := dns.Fqdn(n)
	if _, ok := dns.IsDomainName(fqdn); !ok {
		return "", ErrInvalidName
	}
	return fqdn, nil
}

var allowedTypes = map[uint16]struct{}{
	dns.TypeA: {}, dns.TypeAAAA: {}, dns.TypeCNAME: {}, dns.TypeMX: {},
	dns.TypeTXT: {}, dns.TypeNS: {}, dns.TypeSOA: {}, dns.TypeDS: {},
	dns.TypeDNSKEY: {}, dns.TypeHTTPS: {}, dns.TypeSVCB: {}, dns.TypeCAA: {},
	dns.TypePTR: {}, dns.TypeSRV: {}, dns.TypeTLSA: {},
}

// AllowedType is an allowlist; ANY, AXFR, IXFR and obsolete types are refused.
func AllowedType(qtype uint16) bool {
	_, ok := allowedTypes[qtype]
	return ok
}
