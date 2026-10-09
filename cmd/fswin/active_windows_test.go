// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"strings"
	"testing"

	x "github.com/celzero/firestack/intra/backend"
)

// The Logs screen's active connections: an open connection carries the
// country of its address and the exit it leaves through, flows and DNS
// answers in the log carry the country too, and one connection can be
// closed by its id.
func TestActiveConnectionsCarryCountry(t *testing.T) {
	b := newTestBridge(t, "")
	b.setExit(exitMasque)
	var closed []string
	b.closer.Store(func(csv string) string {
		closed = append(closed, strings.Split(csv, ",")...)
		return csv
	})
	uid := b.apps.uid(testApp)
	m := b.Flow(6, uid, x.StrOf("10.111.222.1:50200"), x.StrOf("95.173.136.70:443"),
		x.StrOf("95.173.136.70"), x.StrOf("example.ru"), x.StrOf(""), x.StrOf(""))
	if m == nil {
		t.Fatal("Flow returned nil")
	}

	if ev := eventsOf(b, "flow"); len(ev) != 1 || ev[0].Country != "RU" {
		t.Fatalf("flow events %+v, want one with country RU", ev)
	}
	open := b.conns.list("")
	if len(open) != 1 {
		t.Fatalf("open connections %+v, want 1", open)
	}
	if c := open[0]; c.CID != m.CID || c.Country != "RU" || c.Via != exitName(exitMasque) || c.Domain != "example.ru" {
		t.Errorf("open connection %+v, want cid %s, country RU, via %q, domain example.ru", c, m.CID, exitName(exitMasque))
	}

	if n := b.closeIDs([]string{m.CID, "999999"}); n != 1 {
		t.Errorf("closeIDs closed %d, want 1: the unknown id is skipped", n)
	}
	if len(closed) != 1 || closed[0] != m.CID {
		t.Errorf("closed %v, want [%s]", closed, m.CID)
	}

	b.OnResponse(&x.DNSSummary{QName: "example.ru.", QType: 1, ID: x.Preferred, Status: x.Complete,
		RData: "95.173.136.70,95.173.136.71"})
	if dns := eventsOf(b, "dns"); len(dns) != 1 || dns[0].Country != "RU" {
		t.Errorf("dns events %+v, want one with country RU", dns)
	}
}
