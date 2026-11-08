// Copyright (c) 2026 AuroraVPN contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra

// gomobile-facing API for the local DNSSEC validator (intra/dnssecv).
//
// It lives in package intra, which make-aar already binds, on purpose: a
// second gomobile .aar in the same APK would ship a second Go runtime and
// duplicate go.Seq classes, which fails to build (or crashes) on Android.
//
// Kotlin: com.celzero.firestack.intra.Intra.newDNSSECValidator(controller)

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/celzero/firestack/intra/dnssecv"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
)

// Status values for DNSSECResult.Status (mirror dnssecv.Status).
const (
	DNSSECStatusUnknown  = int32(dnssecv.StatusUnknown)
	DNSSECStatusInsecure = int32(dnssecv.StatusInsecure)
	DNSSECStatusSecure   = int32(dnssecv.StatusSecure)
	DNSSECStatusBogus    = int32(dnssecv.StatusBogus)
)

// Health values for DNSSECReport.Health (mirror dnssecv.Health).
const (
	DNSSECHealthUnknown     = int32(dnssecv.HealthUnknown)
	DNSSECHealthValidating  = int32(dnssecv.HealthValidating)
	DNSSECHealthDegraded    = int32(dnssecv.HealthDegraded)
	DNSSECHealthUnreachable = int32(dnssecv.HealthUnreachable)
	DNSSECHealthBroken      = int32(dnssecv.HealthBroken)
)

const dnssecWho = "dnssec" // owner tag passed to Controller.Protect/Bind*

// DNSSECResult is one validated lookup. Only basic types: gomobile-safe.
type DNSSECResult struct {
	Name       string
	Qtype      int32
	Status     int32
	Rcode      int32  // -1 when no response
	Denial     string // NSEC/NSEC3 proof kind, "" if none
	Answers    string // newline-separated RRs; "" when Bogus
	DurationMs int64
	Err        string // "" on success
}

// DNSSECReport is a self-test outcome.
type DNSSECReport struct {
	Health     int32
	Summary    string // short, log-safe, e.g. "validating (3/3 secure, 1/1 rejected)"
	DurationMs int64
	results    []*DNSSECResult
}

// Count / Get expose results (gomobile cannot bind slices of structs).
func (r *DNSSECReport) Count() int { return len(r.results) }

func (r *DNSSECReport) Get(i int) *DNSSECResult {
	if i < 0 || i >= len(r.results) {
		return nil
	}
	return r.results[i]
}

// DNSSECValidator is a process-wide handle; see NewDNSSECValidator.
type DNSSECValidator struct {
	v *dnssecv.Validator
}

var (
	dnssecMu       sync.Mutex
	dnssecInstance *DNSSECValidator
)

// NewDNSSECValidator returns the process-wide validator, creating it on first
// use. ctl must protect sockets from the VPN (e.g. ProbeController in Kotlin);
// on later calls it replaces the previous protector. A nil ctl is refused,
// because unprotected queries would loop into the tunnel's DNS trap.
func NewDNSSECValidator(ctl Controller) (*DNSSECValidator, error) {
	if ctl == nil {
		return nil, errors.New("dnssec: nil controller")
	}
	dialer := dnssecDialer(ctl)

	dnssecMu.Lock()
	defer dnssecMu.Unlock()
	if dnssecInstance != nil {
		dnssecInstance.v.SetDialer(dialer)
		return dnssecInstance, nil
	}
	v, err := dnssecv.New(dnssecv.Config{Dialer: dialer})
	if err != nil {
		return nil, err
	}
	dnssecInstance = &DNSSECValidator{v: v}
	log.I("dnssec: validator ready")
	return dnssecInstance, nil
}

func dnssecDialer(ctl Controller) func() *net.Dialer {
	return func() *net.Dialer {
		d := protect.MakeNsDialer(dnssecWho, ctl)
		d.Timeout = 2 * time.Second
		return d
	}
}

// SetController swaps the socket protector (call after a VPN service restart).
func (d *DNSSECValidator) SetController(ctl Controller) error {
	if ctl == nil {
		return errors.New("dnssec: nil controller")
	}
	d.v.SetDialer(dnssecDialer(ctl))
	return nil
}

// Validate resolves name/qtype from the root and validates the full chain.
// timeoutMs <= 0 uses the default (6s). Never returns nil.
func (d *DNSSECValidator) Validate(name string, qtype int32, timeoutMs int64) *DNSSECResult {
	if qtype < 0 || qtype > 0xFFFF {
		return &DNSSECResult{Name: name, Qtype: qtype, Rcode: -1, Err: dnssecv.ErrInvalidType.Error()}
	}
	ctx, cancel := dnssecCtx(timeoutMs)
	defer cancel()
	return toDNSSECResult(d.v.Validate(ctx, name, uint16(qtype)))
}

// SelfTest proves the validator both accepts signed data and rejects forged
// data. The home-screen card shows green only for DNSSECHealthValidating.
func (d *DNSSECValidator) SelfTest(timeoutMs int64) *DNSSECReport {
	ctx, cancel := dnssecCtx(timeoutMs)
	defer cancel()
	rep := d.v.SelfTest(ctx, nil)

	out := &DNSSECReport{
		Health:     int32(rep.Health),
		DurationMs: rep.Duration.Milliseconds(),
	}
	var secure, good, rejected, bad int
	for i, r := range rep.Results {
		out.results = append(out.results, toDNSSECResult(r))
		if dnssecv.DefaultProbes[i].WantBad {
			bad++
			if r.Status == dnssecv.StatusBogus {
				rejected++
			}
		} else {
			good++
			if r.Status == dnssecv.StatusSecure {
				secure++
			}
		}
	}
	out.Summary = fmt.Sprintf("%s (%d/%d secure, %d/%d rejected)", rep.Health, secure, good, rejected, bad)
	if rep.Health == dnssecv.HealthBroken {
		log.E("dnssec: SELF-TEST BROKEN: validator accepted a forged zone: %s", out.Summary)
	} else {
		log.I("dnssec: self-test %s in %dms", out.Summary, out.DurationMs)
	}
	return out
}

// OnNetworkChanged clears caches and the IPv6 probe after a link change.
func (d *DNSSECValidator) OnNetworkChanged() { d.v.OnNetworkChanged() }

func dnssecCtx(timeoutMs int64) (context.Context, context.CancelFunc) {
	if timeoutMs <= 0 {
		return context.WithCancel(context.Background())
	}
	const maxMs = 30_000
	if timeoutMs > maxMs {
		timeoutMs = maxMs
	}
	return context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
}

// clampRcode keeps gosec G115 honest: DNS rcodes are 12-bit (0..4095), and
// dnssecv uses -1 for "no response".
func clampRcode(rc int) int32 {
	if rc < -1 || rc > 4095 {
		return -1
	}
	return int32(rc)
}

func toDNSSECResult(r dnssecv.Result) *DNSSECResult {
	out := &DNSSECResult{
		Name:       r.Name,
		Qtype:      int32(r.Qtype),
		Status:     int32(r.Status),
		Rcode:      clampRcode(r.Rcode),
		Denial:     r.Denial,
		Answers:    strings.Join(r.Answers, "\n"),
		DurationMs: r.Duration.Milliseconds(),
	}
	if r.Err != nil {
		out.Err = r.Err.Error()
	}
	return out
}
