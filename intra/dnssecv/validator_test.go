// Copyright (c) 2026 AuroraVPN contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnssecv

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/celzero/firestack/intra/dnssecv/resolver"
	"github.com/celzero/firestack/intra/dnssecv/resolver/dnssec"
	"github.com/miekg/dns"
)

type fakeEx struct {
	fn    func(ctx context.Context, m *dns.Msg) *resolver.Response
	calls atomic.Int32
}

func (f *fakeEx) Exchange(ctx context.Context, m *dns.Msg) *resolver.Response {
	f.calls.Add(1)
	return f.fn(ctx, m)
}

func answer(m *dns.Msg, auth dnssec.AuthenticationResult) *resolver.Response {
	if m == nil || len(m.Question) == 0 {
		panic("test fixture: query without question")
	}
	r := new(dns.Msg)
	r.SetReply(m)
	rr, err := dns.NewRR(m.Question[0].Name + " 300 IN A 192.0.2.1")
	if err != nil || rr == nil {
		panic("test fixture: bad RR")
	}
	r.Answer = []dns.RR{rr}
	return &resolver.Response{Msg: r, Auth: auth}
}

func TestNormalizeName(t *testing.T) {
	good := map[string]string{
		"Example.COM":           "example.com.",
		" example.com.":         "example.com.",
		".":                     ".",
		"_dmarc.a.b":            "_dmarc.a.b.",
		"xn--bcher-kva.example": "xn--bcher-kva.example.",
	}
	for in, want := range good {
		got, err := NormalizeName(in)
		if err != nil || got != want {
			t.Errorf("NormalizeName(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"", " ", "..", "a..b", "exa mple.com", "ex\\046ample.com", "bücher.example",
		"a." + strings.Repeat("b", 64), strings.Repeat("a.", 130) + "com",
		"evil.com\x00.good.com", "*.example.com",
	}
	for _, in := range bad {
		if _, err := NormalizeName(in); !errors.Is(err, ErrInvalidName) {
			t.Errorf("NormalizeName(%q) accepted, want ErrInvalidName", in)
		}
	}
}

func TestAllowedType(t *testing.T) {
	for _, q := range []uint16{dns.TypeANY, dns.TypeAXFR, dns.TypeIXFR, dns.TypeNULL} {
		if AllowedType(q) {
			t.Errorf("type %s must be refused", dns.TypeToString[q])
		}
	}
	if !AllowedType(dns.TypeA) || !AllowedType(dns.TypeHTTPS) {
		t.Error("common types must be allowed")
	}
}

func TestValidateRejectsBadInputWithoutNetwork(t *testing.T) {
	f := &fakeEx{fn: func(ctx context.Context, m *dns.Msg) *resolver.Response { t.Fatal("must not query"); return nil }}
	v := newForTest(f, 2, time.Second)
	if r := v.Validate(context.Background(), "bad name", dns.TypeA); r.Err == nil || r.Status != StatusUnknown {
		t.Errorf("bad name: %+v", r)
	}
	if r := v.Validate(context.Background(), "example.com", dns.TypeANY); !errors.Is(r.Err, ErrInvalidType) {
		t.Errorf("ANY: %+v", r)
	}
}

func TestValidateSetsDOBit(t *testing.T) {
	f := &fakeEx{fn: func(ctx context.Context, m *dns.Msg) *resolver.Response {
		if o := m.IsEdns0(); o == nil || !o.Do() {
			t.Error("DO bit not set")
		}
		if !m.RecursionDesired {
			t.Error("RD not set")
		}
		return answer(m, dnssec.Secure)
	}}
	v := newForTest(f, 2, time.Second)
	if r := v.Validate(context.Background(), "example.com", dns.TypeA); r.Status != StatusSecure || len(r.Answers) != 1 {
		t.Errorf("want secure with 1 answer, got %+v", r)
	}
}

func TestInterpretFailsClosed(t *testing.T) {
	base := Result{Status: StatusUnknown, Rcode: -1}
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)

	cases := []struct {
		name    string
		resp    *resolver.Response
		want    Status
		answers bool
	}{
		{"nil", nil, StatusUnknown, false},
		{"err", &resolver.Response{Err: errors.New("timeout"), Auth: dnssec.Secure}, StatusUnknown, false},
		{"err+bogus", &resolver.Response{Err: errors.New("bad sig"), Auth: dnssec.Bogus}, StatusBogus, false},
		{"nil msg", &resolver.Response{Auth: dnssec.Secure}, StatusUnknown, false},
		{"secure", answer(m, dnssec.Secure), StatusSecure, true},
		{"insecure", answer(m, dnssec.Insecure), StatusInsecure, true},
		{"bogus drops answers", answer(m, dnssec.Bogus), StatusBogus, false},
		{"unknown", answer(m, dnssec.Unknown), StatusUnknown, true},
	}
	for _, c := range cases {
		got := interpret(base, c.resp)
		if got.Status != c.want {
			t.Errorf("%s: status %v want %v", c.name, got.Status, c.want)
		}
		if (len(got.Answers) > 0) != c.answers {
			t.Errorf("%s: answers=%v", c.name, got.Answers)
		}
		if got.Status == StatusSecure && got.Err != nil {
			t.Errorf("%s: Secure with error", c.name)
		}
	}
}

func TestValidateRecoversPanic(t *testing.T) {
	f := &fakeEx{fn: func(ctx context.Context, m *dns.Msg) *resolver.Response { panic("boom") }}
	v := newForTest(f, 1, time.Second)
	r := v.Validate(context.Background(), "example.com", dns.TypeA)
	if r.Status != StatusUnknown || !errors.Is(r.Err, ErrInternal) {
		t.Errorf("panic not contained: %+v", r)
	}
	// The semaphore slot must have been released by the deferred func.
	f.fn = func(ctx context.Context, m *dns.Msg) *resolver.Response { return answer(m, dnssec.Secure) }
	if r := v.Validate(context.Background(), "example.com", dns.TypeA); r.Status != StatusSecure {
		t.Errorf("slot leaked after panic: %+v", r)
	}
}

func TestConcurrencyBound(t *testing.T) {
	release := make(chan struct{})
	var inflight, peak atomic.Int32
	f := &fakeEx{fn: func(ctx context.Context, m *dns.Msg) *resolver.Response {
		n := inflight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		<-release
		inflight.Add(-1)
		return answer(m, dnssec.Secure)
	}}
	v := newForTest(f, 2, 300*time.Millisecond)
	done := make(chan Result, 5)
	for i := 0; i < 5; i++ {
		go func() { done <- v.Validate(context.Background(), "example.com", dns.TypeA) }()
	}
	time.Sleep(400 * time.Millisecond) // the 3 queued calls time out waiting
	close(release)
	busy := 0
	for i := 0; i < 5; i++ {
		if r := <-done; errors.Is(r.Err, ErrBusy) {
			busy++
		}
	}
	if peak.Load() > 2 {
		t.Errorf("peak concurrency %d > 2", peak.Load())
	}
	if busy != 3 {
		t.Errorf("busy=%d want 3", busy)
	}
}

func TestClassify(t *testing.T) {
	p := DefaultProbes // 3 good, 1 bad (last)
	mk := func(good, bad Status) []Result {
		return []Result{{Status: good}, {Status: good}, {Status: good}, {Status: bad}}
	}
	cases := []struct {
		good, bad Status
		want      Health
	}{
		{StatusSecure, StatusBogus, HealthValidating},
		{StatusSecure, StatusSecure, HealthBroken},   // accepted forged data
		{StatusSecure, StatusInsecure, HealthBroken}, // downgrade accepted
		{StatusUnknown, StatusSecure, HealthBroken},
		{StatusSecure, StatusUnknown, HealthDegraded}, // couldn't prove rejection
		{StatusBogus, StatusBogus, HealthDegraded},    // e.g. clock skew
		{StatusUnknown, StatusBogus, HealthDegraded},
		{StatusUnknown, StatusUnknown, HealthUnreachable},
	}
	for _, c := range cases {
		if got := classify(p, mk(c.good, c.bad)); got != c.want {
			t.Errorf("good=%v bad=%v: got %v want %v", c.good, c.bad, got, c.want)
		}
	}
}

func TestCacheBoundsAndTTL(t *testing.T) {
	c := newBoundedCache(3, time.Hour)
	now := time.Unix(1_000_000, 0)
	c.now = func() time.Time { return now }
	put := func(name string, ttl uint32) {
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeA)
		rr, err := dns.NewRR(name + " 1 IN A 192.0.2.1")
		if err != nil || rr == nil {
			t.Fatalf("bad fixture %q: %v", name, err)
		}
		rr.Header().Ttl = ttl
		m.Answer = []dns.RR{rr}
		_ = c.Update(".", m.Question[0], m)
	}
	for _, n := range []string{"a.", "b.", "c.", "d."} {
		put(n, 60)
	}
	if c.Len() != 3 {
		t.Fatalf("len=%d want 3", c.Len())
	}
	if m, _ := c.Get(".", dns.Question{Name: "a.", Qtype: dns.TypeA, Qclass: dns.ClassINET}); m != nil {
		t.Error("LRU did not evict oldest")
	}
	put("huge.", 7*24*3600)
	now = now.Add(2 * time.Hour)
	if m, _ := c.Get(".", dns.Question{Name: "huge.", Qtype: dns.TypeA, Qclass: dns.ClassINET}); m != nil {
		t.Error("TTL not clamped to 1h")
	}
	// Truncated responses are never cached.
	m := new(dns.Msg)
	m.SetQuestion("t.", dns.TypeA)
	m.Truncated = true
	q := dns.Question{Name: "t.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	_ = c.Update(".", q, m)
	if got, _ := c.Get(".", q); got != nil {
		t.Error("cached a truncated response")
	}
}

// Live test against the real DNS hierarchy. Off by default (CI has no
// guarantee of outbound UDP/53). Run with: DNSSECV_LIVE=1 go test -run Live
func TestLiveSelfTest(t *testing.T) {
	if os.Getenv("DNSSECV_LIVE") != "1" {
		t.Skip("set DNSSECV_LIVE=1 to run against the internet")
	}
	v, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	rep := v.SelfTest(context.Background(), nil)
	for _, r := range rep.Results {
		t.Logf("%-20s %-6s status=%-8s rcode=%d denial=%s err=%v (%s)",
			r.Name, dns.TypeToString[r.Qtype], r.Status, r.Rcode, r.Denial, r.Err, r.Duration)
	}
	if rep.Health != HealthValidating {
		t.Fatalf("health=%v want validating", rep.Health)
	}
	nx := v.Validate(context.Background(), "this-does-not-exist-7f3a.isc.org", dns.TypeA)
	t.Logf("nxdomain: status=%v rcode=%d denial=%s err=%v", nx.Status, nx.Rcode, nx.Denial, nx.Err)
	if nx.Status != StatusSecure || nx.Rcode != dns.RcodeNameError || nx.Denial == "" {
		t.Errorf("authenticated denial of existence not proven: %+v", nx)
	}
}
