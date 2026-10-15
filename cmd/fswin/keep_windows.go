// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// AuroraVPN Service keeps protection on once the app asked it to (a start
// with keep): it is the one part of AuroraVPN that always runs, also with the
// app's window closed, the app not running at all, or nobody at the screen
// (a server). It used to live in the app, where a closed or frozen window, a
// sign-out or an app update ended it.
//
//   - The engine ends without a stop (a crash, killed): it starts again with
//     the same flags after keepRestartMin (1 s), doubling up to
//     keepRestartMax (1 min) while it keeps ending, and back to 1 s once it
//     ran keepStable (1 min).
//   - With watch (a VPN exit): the internet is checked through the tunnel
//     every keepProbeEvery (10 s) once the engine has run keepGrace (45 s).
//     After keepMisses (6) misses in a row, about a minute, the engine is
//     restarted: the last resort. The engine repairs its exit itself within
//     about 30 s (supervise_windows.go), and usque its tunnels within about
//     15 s; a restart in the middle of their repair only started it over.
//     Restarts for this wait keepHealthMin (1 min), doubling up to
//     keepHealthMax (10 min) while the internet stays away: a network that is
//     down is not fixed by restarting.
//   - A stop (or unkeep, which the app sends before it stops the engine
//     through the engine's own API) ends the keeping, and so does a start
//     without keep.
//
// Nothing is kept across a restart of the service or of Windows: the engine
// runs with the user's token, which the service only has while the user is
// signed in. The app, started at sign-in, starts protection again.

// variables so that tests can make them short
var (
	keepTick       = time.Second
	keepRestartMin = time.Second
	keepRestartMax = time.Minute
	keepStable     = time.Minute
	keepGrace      = 45 * time.Second
	keepProbeEvery = 10 * time.Second
	keepMisses     = 6
	keepHealthMin  = time.Minute
	keepHealthMax  = 10 * time.Minute
)

// keepProbeURLs are asked at once through the tunnel; one answer is enough.
var keepProbeURLs = []string{
	"https://www.cloudflare.com/cdn-cgi/trace",
	"http://www.msftconnecttest.com/connecttest.txt",
}

// keepHooks is what the keeper does to the engine; the service's pipe server
// in use, fakes in tests.
type keepHooks struct {
	engine func() (up bool, started time.Time)
	start  func(args []string, token windows.Token) error
	stop   func()
	probe  func(ctx context.Context) error
	logf   func(string, ...any)
}

// keeper is what to keep running: set by a start with keep, cleared by a
// stop.
type keeper struct {
	mu    sync.Mutex
	on    bool
	watch bool
	args  []string
	token windows.Token // the user's primary token, ours to close
	user  string
}

// set keeps args running for user, with token (a copy the keeper owns).
func (k *keeper) set(args []string, token windows.Token, user string, watch bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.closeToken()
	k.on, k.watch, k.args, k.token, k.user = true, watch, append([]string(nil), args...), token, user
}

// clear ends the keeping.
func (k *keeper) clear() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.closeToken()
	k.on, k.watch, k.args, k.user = false, false, nil, ""
}

func (k *keeper) closeToken() {
	if k.token != 0 {
		_ = k.token.Close()
		k.token = 0
	}
}

type keepWant struct {
	on, watch bool
	args      []string
	token     windows.Token
	user      string
}

func (k *keeper) want() keepWant {
	k.mu.Lock()
	defer k.mu.Unlock()
	return keepWant{k.on, k.watch, k.args, k.token, k.user}
}

// run keeps the engine up until quit is closed.
func (k *keeper) run(quit <-chan struct{}, h keepHooks) {
	t := time.NewTicker(keepTick)
	defer t.Stop()
	var (
		nextStart  time.Time // zero: no start planned
		wait       = keepRestartMin
		misses     int
		nextProbe  time.Time
		nextHealth time.Time
		healthWait = keepHealthMin
	)
	reset := func() {
		nextStart, wait, misses, nextProbe, nextHealth, healthWait = time.Time{}, keepRestartMin, 0, time.Time{}, time.Time{}, keepHealthMin
	}
	for {
		select {
		case <-quit:
			return
		case <-t.C:
		}
		w := k.want()
		if !w.on {
			reset()
			continue
		}
		now := time.Now()
		up, started := h.engine()
		if !up {
			misses = 0
			if nextStart.IsZero() {
				nextStart = now.Add(wait)
				h.logf("keep: the engine is not running; starting it again in %s (for %s)", wait, w.user)
				continue
			}
			if now.Before(nextStart) {
				continue
			}
			nextStart = time.Time{}
			if err := h.start(w.args, w.token); err != nil {
				h.logf("keep: start failed: %v", err)
			} else {
				h.logf("keep: engine started again")
			}
			wait = min(wait*2, keepRestartMax)
			continue
		}
		nextStart = time.Time{}
		ran := now.Sub(started)
		if ran >= keepStable {
			wait = keepRestartMin
		}
		if !w.watch || ran < keepGrace || now.Before(nextProbe) {
			continue
		}
		nextProbe = now.Add(keepProbeEvery)
		ctx, cancel := context.WithTimeout(context.Background(), keepProbeEvery)
		err := h.probe(ctx)
		cancel()
		if err == nil {
			if misses >= 2 {
				h.logf("keep: the internet answers again")
			}
			misses, healthWait = 0, keepHealthMin
			continue
		}
		misses++
		if misses >= 2 {
			h.logf("keep: no internet through the tunnel (%d/%d): %v", misses, keepMisses, err)
		}
		if misses < keepMisses || now.Before(nextHealth) {
			continue
		}
		misses = 0
		nextHealth = now.Add(healthWait)
		healthWait = min(healthWait*2, keepHealthMax)
		h.logf("keep: no internet through the tunnel for %d checks; restarting the engine (next such restart not before %s)", keepMisses, nextHealth.Format(time.TimeOnly))
		h.stop()
		// the next tick finds it down and starts it after keepRestartMin
		wait = keepRestartMin
	}
}

// keepProbe asks keepProbeURLs at once; any HTTP answer passes.
func keepProbe(ctx context.Context) error {
	c := &http.Client{Timeout: keepProbeEvery}
	errs := make(chan error, len(keepProbeURLs))
	for _, u := range keepProbeURLs {
		go func() {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			if err == nil {
				var r *http.Response
				if r, err = c.Do(req); err == nil {
					_ = r.Body.Close()
				}
			}
			errs <- err
		}()
	}
	var first error
	for range keepProbeURLs {
		err := <-errs
		if err == nil {
			return nil
		}
		if first == nil {
			first = err
		}
	}
	if first == nil {
		first = errors.New("no probe")
	}
	return first
}
