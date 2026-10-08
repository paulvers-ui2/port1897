// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/win/ifbind"
)

const testApp = `C:\Program Files\Test\app.exe`

// newTestBridge builds the bridge as run does, with a real binder; there is
// no tunnel adapter in a test, so it skips no interface.
func newTestBridge(t *testing.T, blockcsv string) *bridge {
	t.Helper()
	b := newBridge(ifbind.New(0), nil, blockcsv)
	if b == nil {
		t.Fatal("newBridge returned nil")
	}
	return b
}

// eventsOf returns the journaled events of kind, oldest first.
func eventsOf(b *bridge, kind string) []event {
	var out []event
	for _, e := range b.log.since(0, journalSize) {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

func exitLabel(id string) string {
	if id == "" {
		return "none"
	}
	return id
}

// Queries to the tunnel's DNS address must be marked Base whatever the exit:
// firestack (intra/udp.go, intra/tcp.go) answers them only when
// isAnyBasePid(pids) && h.isDNS(target). They are not flows in the journal.
func TestFlowFakeDNSIsBaseWhateverTheExit(t *testing.T) {
	dst := fakedns4 + ":53"
	if dst != "10.111.222.3:53" {
		t.Fatalf("fakedns4:53 = %q, want 10.111.222.3:53", dst)
	}
	for _, exit := range []string{"", exitWG, exitWarp, exitProxy, exitMasque, exitChain} {
		for _, protocol := range []int32{17, 6} {
			t.Run(fmt.Sprintf("%s/exit=%s", proto(protocol), exitLabel(exit)), func(t *testing.T) {
				b := newTestBridge(t, "")
				if exit != "" {
					b.setExit(exit)
					if got := b.exitID(); got != exit {
						t.Fatalf("exitID() = %q after setExit(%q)", got, exit)
					}
				}
				uid := b.apps.uid(testApp)
				flows, blocked := b.log.flows.Load(), b.log.flowsBlocked.Load()

				m := b.Flow(protocol, uid, x.StrOf("10.111.222.1:50123"), x.StrOf(dst),
					x.StrOf(""), x.StrOf(""), x.StrOf(""), x.StrOf(""))
				if m == nil {
					t.Fatal("Flow returned nil")
				}
				t.Logf("Flow(%s -> %s), exit %s: PIDCSV=%q CID=%q UID=%q",
					proto(protocol), dst, exitLabel(exit), m.PIDCSV, m.CID, m.UID)

				if m.PIDCSV != x.Base {
					t.Errorf("PIDCSV = %q, want %q: firestack answers DNS sent to %s only when the flow is marked Base", m.PIDCSV, x.Base, dst)
				}
				if m.CID == "" {
					t.Error("empty CID")
				}
				if want := strconv.Itoa(int(uid)); m.UID != want {
					t.Errorf("UID = %q, want %q", m.UID, want)
				}
				if got := b.log.flows.Load(); got != flows {
					t.Errorf("flows counter %d -> %d, want unchanged", flows, got)
				}
				if got := b.log.flowsBlocked.Load(); got != blocked {
					t.Errorf("blocked-flows counter %d -> %d, want unchanged", blocked, got)
				}
				if ev := eventsOf(b, "flow"); len(ev) != 0 {
					t.Errorf("journaled %d flow events, want none: %+v", len(ev), ev)
				}
				if n := len(b.conns.all()); n != 0 {
					t.Errorf("%d open connections tracked, want none (DNS gets no OnSocketClosed)", n)
				}
			})
		}
	}
}

// Everything else still leaves through the exit and is journaled.
func TestFlowOrdinaryDstUsesExitAndIsJournaled(t *testing.T) {
	for _, exit := range []string{"", exitWG, exitWarp, exitProxy} {
		want := exit
		if want == "" {
			want = x.Base
		}
		for _, protocol := range []int32{6, 17} {
			t.Run(fmt.Sprintf("%s/exit=%s", proto(protocol), exitLabel(exit)), func(t *testing.T) {
				b := newTestBridge(t, "")
				if exit != "" {
					b.setExit(exit)
				}
				uid := b.apps.uid(testApp)
				flows := b.log.flows.Load()
				dst := "1.1.1.1:443"

				m := b.Flow(protocol, uid, x.StrOf("10.111.222.1:50124"), x.StrOf(dst),
					x.StrOf("1.1.1.1"), x.StrOf("one.one.one.one"), x.StrOf(""), x.StrOf(""))
				if m == nil {
					t.Fatal("Flow returned nil")
				}
				t.Logf("Flow(%s -> %s), exit %s: PIDCSV=%q CID=%q", proto(protocol), dst, exitLabel(exit), m.PIDCSV, m.CID)

				if m.PIDCSV != want {
					t.Errorf("PIDCSV = %q, want %q", m.PIDCSV, want)
				}
				if got := b.log.flows.Load(); got != flows+1 {
					t.Errorf("flows counter %d -> %d, want +1", flows, got)
				}
				ev := eventsOf(b, "flow")
				if len(ev) != 1 {
					t.Fatalf("journaled %d flow events, want 1: %+v", len(ev), ev)
				}
				e := ev[0]
				if e.Dst != dst || e.CID != m.CID || e.Via != exitName(want) || e.App != "app.exe" ||
					e.Proto != proto(protocol) || e.Domain != "one.one.one.one" || e.Blocked {
					t.Errorf("flow event = %+v; want dst %s, cid %s, via %q, app app.exe, domain one.one.one.one, not blocked",
						e, dst, m.CID, exitName(want))
				}
				if _, ok := b.conns.all()[m.CID]; !ok {
					t.Errorf("connection %s not tracked", m.CID)
				}
			})
		}
	}
}

// Only 10.111.222.3:53 is kept local: plain DNS to another server, and other
// ports or addresses of the tunnel, still go to the exit.
func TestFlowOnlyOurDNSAddressIsKeptLocal(t *testing.T) {
	b := newTestBridge(t, "")
	b.setExit(exitWG)
	uid := b.apps.uid(testApp)
	dsts := []string{"8.8.8.8:53", ifaddr4 + ":53", fakedns4 + ":5353", "10.111.222.30:53"}
	for _, dst := range dsts {
		m := b.Flow(17, uid, x.StrOf("10.111.222.1:50125"), x.StrOf(dst), x.StrOf(""), x.StrOf(""), x.StrOf(""), x.StrOf(""))
		if m == nil || m.PIDCSV != exitWG {
			t.Errorf("Flow(udp -> %s) = %+v, want PIDCSV %q", dst, m, exitWG)
		}
	}
	if got := len(eventsOf(b, "flow")); got != len(dsts) {
		t.Errorf("journaled %d flow events, want %d", got, len(dsts))
	}

	// DNS over TLS to our address: the tunnel does not serve it, so it is
	// refused, as the Android app does (trapVpnPrivateDns), and not journaled.
	m := b.Flow(6, uid, x.StrOf("10.111.222.1:50126"), x.StrOf(fakedns4+":853"), x.StrOf(""), x.StrOf(""), x.StrOf(""), x.StrOf(""))
	if m.PIDCSV != x.Block {
		t.Errorf("Flow(tcp -> %s:853) = PIDCSV %q, want %q", fakedns4, m.PIDCSV, x.Block)
	}
	if got := len(eventsOf(b, "flow")); got != len(dsts) {
		t.Errorf("DNS over TLS to our address was journaled: %d flow events, want %d", got, len(dsts))
	}
}

// A blocked app's DNS to our address is still answered, as on Android, where
// trapVpnDns returns Base before the firewall runs; its connections stay
// blocked.
func TestFlowFakeDNSFromBlockedApp(t *testing.T) {
	b := newTestBridge(t, "blocked.exe")
	b.setExit(exitWarp)
	uid := b.apps.uid(`C:\Apps\blocked.exe`)

	m := b.Flow(17, uid, x.StrOf("10.111.222.1:50127"), x.StrOf(fakedns4+":53"), x.StrOf(""), x.StrOf(""), x.StrOf(""), x.StrOf(""))
	if m.PIDCSV != x.Base {
		t.Errorf("DNS from a blocked app: PIDCSV = %q, want %q", m.PIDCSV, x.Base)
	}
	t.Logf("note: blocked.exe's DNS query to %s:53 -> %q (before this change: %q, so -block in DNS-only mode blocked its lookups)",
		fakedns4, m.PIDCSV, x.Block)

	m = b.Flow(6, uid, x.StrOf("10.111.222.1:50128"), x.StrOf("1.1.1.1:443"), x.StrOf(""), x.StrOf(""), x.StrOf(""), x.StrOf(""))
	if m.PIDCSV != x.Block {
		t.Errorf("connection from a blocked app: PIDCSV = %q, want %q", m.PIDCSV, x.Block)
	}
	if got := b.log.flowsBlocked.Load(); got != 1 {
		t.Errorf("blocked flows = %d, want 1", got)
	}
	if ev := eventsOf(b, "flow"); len(ev) != 1 || !ev[0].Blocked {
		t.Errorf("flow events = %+v, want one blocked", ev)
	}
}

func TestOnResponseRecordsWhyAQueryFailed(t *testing.T) {
	b := newTestBridge(t, "")
	uid := strconv.Itoa(int(b.apps.uid(testApp)))
	cases := []struct {
		name    string
		s       x.DNSSummary
		wantErr string
		failed  bool
	}{
		{"no response, no message",
			x.DNSSummary{QName: "example.com.", QType: 1, ID: x.Preferred, Latency: 5, Status: x.NoResponse},
			"the DNS server did not answer", true},
		{"send failed, timed out (the Proton VPN incident)",
			x.DNSSummary{QName: "example.org.", QType: 28, ID: x.Preferred, Server: "cloudflare-dns.com", Latency: 20.004, Status: x.SendFailed,
				Msg: `Post "https://cloudflare-dns.com/dns-query": dial tcp 1.1.1.1:443: i/o timeout | dial tcp 1.0.0.1:443: i/o timeout`},
			`no reply from cloudflare-dns.com in 20 s (Post "https://cloudflare-dns.com/dns-query": dial tcp 1.1.1.1:443: i/o timeout | dial tcp 1.0.0.1:443: i/o timeout)`, true},
		{"server error over HTTP",
			x.DNSSummary{QName: "example.edu.", QType: 1, ID: x.Preferred, Server: "cloudflare-dns.com", Latency: 0.1, Status: x.TransportError, Msg: "http-status: 503"},
			"cloudflare-dns.com answered HTTP 503", true},
		{"refused by a plain DNS server",
			x.DNSSummary{QName: "example.info.", QType: 1, ID: x.Preferred, Latency: 0.1, Status: x.TransportError, Msg: "read udp 10.0.0.2:5000->9.9.9.9:53: connectex: No connection could be made because the target machine actively refused it."},
			"read udp 10.0.0.2:5000->9.9.9.9:53: connectex: No connection could be made because the target machine actively refused it.", true},
		{"answered SERVFAIL",
			x.DNSSummary{QName: "example.biz.", QType: 1, ID: x.Preferred, Server: "127.0.0.1:5353", Latency: 0.01, Status: x.Complete, RCode: 2, Msg: "no error"},
			"127.0.0.1:5353 answered SERVFAIL", true},
		{"answered REFUSED, no server name",
			x.DNSSummary{QName: "example.museum.", QType: 1, ID: x.Preferred, Latency: 0.01, Status: x.Complete, RCode: 5, Msg: "no error"},
			"the DNS server answered REFUSED", true},
		{"NXDOMAIN is an answer",
			x.DNSSummary{QName: "nope.example.", QType: 1, ID: x.Preferred, Latency: 0.02, Status: x.Complete, RCode: 3, Msg: "no error"},
			"", false},
		{"BlockAll answers on purpose",
			x.DNSSummary{QName: "ads.example.", QType: 1, ID: x.BlockAll, Latency: 0, Status: x.Complete, RCode: 5, Msg: "no error"},
			"", false},
		{"complete",
			x.DNSSummary{QName: "example.net.", QType: 1, ID: x.Preferred, Latency: 0.03, Status: x.Complete, RData: "93.184.215.14", Msg: "no error"},
			"", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			queries, failed := b.log.dnsQueries.Load(), b.log.dnsFailed.Load()
			s := c.s
			s.UID = uid
			b.OnResponse(&s)

			if got := b.log.dnsQueries.Load(); got != queries+1 {
				t.Errorf("dnsQueries %d -> %d, want +1", queries, got)
			}
			wantFailed := failed
			if c.failed {
				wantFailed++
			}
			if got := b.log.dnsFailed.Load(); got != wantFailed {
				t.Errorf("dnsFailed %d -> %d, want %d", failed, got, wantFailed)
			}
			ev := eventsOf(b, "dns")
			if len(ev) == 0 {
				t.Fatal("no dns event journaled")
			}
			e := ev[len(ev)-1]
			if e.Domain != strings.TrimSuffix(c.s.QName, ".") {
				t.Errorf("event domain %q, want %q", e.Domain, strings.TrimSuffix(c.s.QName, "."))
			}
			if e.Error != c.wantErr {
				t.Errorf("event error %q, want %q", e.Error, c.wantErr)
			}
			if e.App != "app.exe" {
				t.Errorf("event app %q, want app.exe (the program that asked)", e.App)
			}
			raw, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			if _, has := m["error"]; has != (c.wantErr != "") {
				t.Errorf("JSON %s: has \"error\" = %t, want %t", raw, has, c.wantErr != "")
			}
			t.Logf("event JSON: %s", raw)
		})
	}
	wantFailed := int64(0)
	for _, c := range cases {
		if c.failed {
			wantFailed++
		}
	}
	if got := b.log.dnsFailed.Load(); got != wantFailed {
		t.Errorf("dnsFailed = %d, want %d", got, wantFailed)
	}
	st := statusOf(b, options{}, time.Now(), "", "test")
	if st.DNS.Queries != int64(len(cases)) || st.DNS.Failed != wantFailed {
		t.Errorf("status dns = %+v, want %d queries, %d failed", st.DNS, len(cases), wantFailed)
	}
}

func TestDNSFailureText(t *testing.T) {
	want := map[int]string{
		x.SendFailed:     "could not send the query to the DNS server",
		x.NoResponse:     "the DNS server did not answer",
		x.BadQuery:       "bad query",
		x.BadResponse:    "bad answer from the DNS server",
		x.TransportError: "could not reach the DNS server",
		x.ClientError:    "DNS client error",
		x.InternalError:  "internal error",
		x.Paused:         "DNS is paused",
		x.DEnd:           "DNS stopped",
		99:               "status 99",
	}
	for status, text := range want {
		if got := dnsFailure(&x.DNSSummary{Status: status}); got != text {
			t.Errorf("dnsFailure(status %d) = %q, want %q", status, got, text)
		}
		if got := dnsFailure(&x.DNSSummary{Status: status, Msg: "boom"}); got != "boom" {
			t.Errorf("dnsFailure(status %d, msg boom) = %q, want the message", status, got)
		}
	}
}

// The home screen reads status.conflicts; it must be a JSON array, [] when
// there are none, never null, and a copy of the options' slice.
func TestStatusConflictsIsAlwaysAnArray(t *testing.T) {
	b := newTestBridge(t, "")
	two := []string{
		"another VPN sends all DNS elsewhere: Proton VPN (Force all DNS requests via Proton VPN)",
		"internet traffic leaves through another VPN's adapter: ProtonVPN (ProtonVPN Tunnel)",
	}
	for _, c := range []struct {
		name      string
		conflicts []string
		want      string
	}{
		{"nil", nil, `[]`},
		{"empty", []string{}, `[]`},
		{"two", append([]string{}, two...), mustJSON(t, two)},
	} {
		t.Run(c.name, func(t *testing.T) {
			o := options{conflicts: c.conflicts, dialStrategy: dialNever, dnsType: dnsDoH}
			st := statusOf(b, o, time.Now(), exitWG, "test")
			raw, err := json.Marshal(st)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]json.RawMessage
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			got, ok := m["conflicts"]
			if !ok {
				t.Fatalf("no \"conflicts\" in %s", raw)
			}
			if string(got) != c.want {
				t.Errorf("conflicts = %s, want %s", got, c.want)
			}
			if st.Exit != "WireGuard" {
				t.Errorf("exit = %q, want WireGuard", st.Exit)
			}
			if len(o.conflicts) > 0 {
				o.conflicts[0] = "changed"
				if st.Conflicts[0] == "changed" {
					t.Error("status shares the options' conflicts slice")
				}
			}
			t.Logf("conflicts JSON: %s", got)
		})
	}

	raw := mustJSON(t, apiStatus{Conflicts: append([]string{}, nil...)})
	if !strings.Contains(raw, `"conflicts":[]`) {
		t.Errorf("apiStatus{Conflicts: append([]string{}, nil...)} = %s, want \"conflicts\":[]", raw)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
