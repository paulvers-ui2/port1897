// Copyright (c) 2026 AuroraVPN contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnssecv

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Health is the overall verdict shown on the home-screen DNS card.
type Health int32

const (
	// HealthUnknown: self-test not run yet, or cancelled.
	HealthUnknown Health = 0
	// HealthValidating: a signed zone validated Secure AND a deliberately
	// broken zone was rejected as Bogus. This is the only "green" state.
	HealthValidating Health = 1
	// HealthDegraded: the broken zone was rejected, but no signed zone
	// validated Secure (slow/lossy path, partial reachability).
	HealthDegraded Health = 2
	// HealthUnreachable: no verdicts at all; usually UDP/TCP 53 to the
	// internet is blocked on this network (captive portal, hotel, corporate).
	HealthUnreachable Health = 3
	// HealthBroken: the validator ACCEPTED a deliberately broken zone.
	// Critical: validation cannot be trusted. Must never be shown as green.
	HealthBroken Health = 4
)

func (h Health) String() string {
	switch h {
	case HealthValidating:
		return "validating"
	case HealthDegraded:
		return "degraded"
	case HealthUnreachable:
		return "unreachable"
	case HealthBroken:
		return "broken"
	default:
		return "unknown"
	}
}

// Probe is one self-test lookup and the verdict it must produce.
type Probe struct {
	Name    string
	Qtype   uint16
	WantBad bool // true: must come back Bogus
}

// DefaultProbes. Positive probes are long-lived, DNSSEC-signed zones run by
// DNS operators; the negative probe is a public zone kept deliberately broken
// for exactly this purpose. Review yearly: if a test zone disappears the
// result becomes Unreachable/Degraded (fail-safe), never falsely Validating.
var DefaultProbes = []Probe{
	{Name: ".", Qtype: dns.TypeSOA},        // proves the root anchor itself
	{Name: "isc.org", Qtype: dns.TypeSOA},  // signed, NSEC3 parent (.org)
	{Name: "ietf.org", Qtype: dns.TypeSOA}, // signed, independent operator
	{Name: "dnssec-failed.org", Qtype: dns.TypeA, WantBad: true},
}

// SelfTestReport is the full outcome; Results is in probe order.
type SelfTestReport struct {
	Health   Health
	Results  []Result
	Duration time.Duration
}

// SelfTest runs the probes concurrently and classifies the outcome.
func (v *Validator) SelfTest(ctx context.Context, probes []Probe) SelfTestReport {
	if len(probes) == 0 {
		probes = DefaultProbes
	}
	start := time.Now()
	results := make([]Result, len(probes))
	var wg sync.WaitGroup
	for i, p := range probes {
		wg.Add(1)
		go func(i int, p Probe) {
			defer wg.Done()
			results[i] = v.Validate(ctx, p.Name, p.Qtype)
		}(i, p)
	}
	wg.Wait()
	return SelfTestReport{
		Health:   classify(probes, results),
		Results:  results,
		Duration: time.Since(start),
	}
}

// classify is pure so the safety rules can be unit-tested exhaustively.
func classify(probes []Probe, results []Result) Health {
	var goodSecure, goodAny, badBogus, badAny int
	badAccepted := false
	for i, p := range probes {
		r := results[i]
		if p.WantBad {
			switch r.Status {
			case StatusBogus:
				badBogus++
				badAny++
			case StatusSecure, StatusInsecure:
				// Insecure counts as accepted too: the test zone has a DS in
				// its parent, so "provably unsigned" is itself a failure.
				badAccepted = true
				badAny++
			}
			continue
		}
		if r.Status != StatusUnknown {
			goodAny++
		}
		if r.Status == StatusSecure {
			goodSecure++
		}
	}
	switch {
	case badAccepted:
		return HealthBroken
	case goodSecure > 0 && badBogus > 0:
		return HealthValidating
	case badBogus > 0 || (goodAny > 0 && badAny == 0):
		return HealthDegraded
	default:
		return HealthUnreachable
	}
}
