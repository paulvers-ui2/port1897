// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/celzero/firestack/win/ifbind"
	"golang.org/x/net/proxy"
)

// The supervisor keeps usque (WARP over MASQUE, or the chain) up for as long
// as fswin runs. It used to start once: when usque died, or lived on with a
// dead tunnel, the exit pointed at nothing until protection was restarted.
//
// It does what the Android app does (rethink-app-masque BraveVPNService:
// the chain and usque watchdogs, the death callback, restartChain):
//
//   - usque exits: it starts again after restartMin (1 s).
//   - usque runs but nothing gets through: a probe every probeEvery opens a
//     connection through it (SOCKS CONNECT to 1.1.1.1:80, so through every
//     hop of the chain); probeFailures failures in a row restart it. A start
//     gets startGrace first: the SOCKS port opens before the hops carry
//     traffic (WARP1 connects, wg0 handshakes inside it, WARP2 connects).
//   - the network changes (Wi-Fi to Ethernet, another hotspot): usque
//     rebuilds its tunnels by itself; netSettle later a probe checks that it
//     did, and restarts it if not.
//   - back-to-back restarts wait twice as long each time, up to restartMax,
//     until a probe passes: restarting WARP1 in the middle of its own
//     reconnect is how a short outage becomes a long one.
//
// usque itself rebuilds a dead tunnel within seconds (usque v0.0.4: -r 1s,
// --stall-timeout; see usqueDefaults); this is the backstop for what it
// cannot fix from inside.
//
// It restarts usque on the same SOCKS port and credentials, so the exit
// keeps pointing at it; on another port only when that one is taken.
const (
	restartMax    = 60 * time.Second
	probeFailures = 3
	probeTarget   = "1.1.1.1:80"
)

// variables so that tests can make them short
var (
	restartMin   = 1 * time.Second
	probeEvery   = 15 * time.Second
	probeTimeout = 8 * time.Second
	startGrace   = 30 * time.Second
	netEvery     = 5 * time.Second
	netSettle    = 8 * time.Second
)

type supervisor struct {
	s     usqueSetup
	skip  uint32                 // the AuroraVPN adapter, not the network
	readd func(url string) error // points the exit at a new SOCKS address
	logf  func(string, ...any)

	mu  sync.Mutex
	cur *usque // nil while a start failed

	// run's own: the SOCKS address the exit points at (restarts reuse it),
	// and when the current usque started
	port       int
	user, pass string
	startedAt  time.Time

	quit     chan struct{}
	stopOnce sync.Once
	finished chan struct{}

	restarts atomic.Int64
	issue    atomic.Pointer[string] // why it is (re)starting; nil when traffic flows
}

// curSup is the running supervisor, for /api/status.
var curSup atomic.Pointer[supervisor]

// supervise watches u, started with s; skip is the AuroraVPN adapter's
// index, so that a change of the network under it can be told.
func supervise(s usqueSetup, u *usque, skip uint32, readd func(string) error) *supervisor {
	sv := &supervisor{s: s, skip: skip, readd: readd, logf: s.logf, cur: u,
		port: u.port, user: u.user, pass: u.pass, startedAt: time.Now(),
		quit: make(chan struct{}), finished: make(chan struct{})}
	go sv.run()
	return sv
}

// stop ends the supervision and usque.
func (sv *supervisor) stop() {
	if sv == nil {
		return
	}
	sv.stopOnce.Do(func() { close(sv.quit) })
	<-sv.finished
	sv.mu.Lock()
	defer sv.mu.Unlock()
	sv.cur.stop()
	sv.cur = nil
}

// status is what /api/status reports: restarts so far, and why the exit is
// down when it is.
func (sv *supervisor) status() (int64, string) {
	why := ""
	if p := sv.issue.Load(); p != nil {
		why = *p
	}
	return sv.restarts.Load(), why
}

func (sv *supervisor) current() *usque {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	return sv.cur
}

func (sv *supervisor) run() {
	defer close(sv.finished)
	wait := restartMin
	failures := 0
	probes := time.NewTicker(probeEvery)
	defer probes.Stop()
	nets := time.NewTicker(netEvery)
	defer nets.Stop()
	_, link := ifbind.LinkMTU(sv.skip)
	var netChanged time.Time // zero: no check pending

	restart := func(why string) bool {
		failures, netChanged = 0, time.Time{}
		return sv.restart(why, &wait)
	}
	for {
		u := sv.current()
		if u == nil {
			// the last start failed: try again
			if !restart("usque did not start") {
				return
			}
			continue
		}
		select {
		case <-sv.quit:
			return
		case <-u.done:
			if !restart(fmt.Sprintf("usque exited (exit code %s)", exitCode(u.state))) {
				return
			}
		case <-probes.C:
			err := probe(u)
			switch {
			case err == nil:
				if failures > 0 || sv.issue.Load() != nil {
					sv.logf("fswin: usque: traffic flows")
				}
				failures, wait = 0, restartMin
				sv.issue.Store(nil)
			case time.Since(sv.startedAt) < startGrace:
				sv.logf("fswin: usque: no traffic yet, %s after its start: %v", time.Since(sv.startedAt).Round(time.Second), err)
			default:
				failures++
				sv.logf("fswin: usque: probe %d/%d failed: %v", failures, probeFailures, err)
				if failures >= probeFailures && !restart(fmt.Sprintf("no traffic through usque for %d probes", failures)) {
					return
				}
			}
		case <-nets.C:
			if _, idx := ifbind.LinkMTU(sv.skip); idx != link {
				sv.logf("fswin: usque: the network changed (interface #%d -> #%d); checking traffic in %s", link, idx, netSettle)
				link, netChanged = idx, time.Now()
			}
			if netChanged.IsZero() || time.Since(netChanged) < netSettle {
				continue
			}
			netChanged = time.Time{}
			if err := probe(u); err != nil && !restart(fmt.Sprintf("no traffic %s after the network changed: %v", netSettle, err)) {
				return
			}
		}
	}
}

// restart stops usque and starts it again after *wait, which then doubles.
// It reports false when the supervisor was stopped meanwhile.
func (sv *supervisor) restart(why string, wait *time.Duration) bool {
	sv.issue.Store(&why)
	sv.logf("fswin: usque: %s; restarting in %s", why, *wait)
	sv.current().stop()
	select {
	case <-sv.quit:
		return false
	case <-time.After(*wait):
	}
	*wait = min(*wait*2, restartMax)

	var u *usque
	var err error
	if portFree(sv.port) {
		u, err = startUsqueOn(sv.s, sv.port, sv.user, sv.pass)
	} else {
		// another program took the port meanwhile: a new one, and the exit
		// moves to it
		sv.logf("fswin: usque: port %d is taken; moving to another", sv.port)
		if u, err = startUsqueOn(sv.s, 0, "", ""); err == nil {
			if rerr := sv.readd(u.url); rerr != nil {
				sv.logf("fswin: usque: exit not moved to the new port: %v", rerr)
			} else {
				sv.port, sv.user, sv.pass = u.port, u.user, u.pass
			}
		}
	}
	sv.mu.Lock()
	sv.cur = u // nil when it failed: run tries again
	sv.mu.Unlock()
	sv.startedAt = time.Now()
	n := sv.restarts.Add(1)
	if err != nil {
		sv.logf("fswin: usque: restart %d failed: %v", n, err)
		return true
	}
	sv.logf("fswin: usque: restart %d: up on 127.0.0.1:%d (waiting for traffic)", n, u.port)
	return true
}

// portFree tells whether 127.0.0.1:port can be listened on.
func portFree(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// probe opens a connection through usque's SOCKS proxy to probeTarget: it
// passes only when every hop carries traffic.
func probe(u *usque) error {
	d, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", u.port),
		&proxy.Auth{User: u.user, Password: u.pass}, &net.Dialer{Timeout: probeTimeout})
	if err != nil {
		return err
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return fmt.Errorf("socks dialer without context")
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	c, err := cd.DialContext(ctx, "tcp", probeTarget)
	if err != nil {
		return err
	}
	return c.Close()
}
