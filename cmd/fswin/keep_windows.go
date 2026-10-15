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
	"net/http"
	"os"
	"path/filepath"
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
// What is kept is also written to keep.json in the install folder (only
// SYSTEM and administrators change it), so it outlives a restart of the
// service or of Windows: at boot the service starts the engine itself,
// before anyone signs in (a server). Without the user's token then, the
// engine opens the app's files and starts usque with its own token,
// lowered (asuser_windows.go). Only a stop, unkeep or a start without keep
// removes the file; the service stopping (Windows shutting down) does not.

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
	file string // keep.json; "" (tests): nothing is written

	mu    sync.Mutex
	on    bool
	watch bool
	args  []string
	token windows.Token // the user's primary token, ours to close
	user  string
}

// keptState is keep.json.
type keptState struct {
	Args  []string `json:"args"`
	Watch bool     `json:"watch"`
	User  string   `json:"user"`
}

// set keeps args running for user, with token (a copy the keeper owns), and
// writes it down for the next start of the service.
func (k *keeper) set(args []string, token windows.Token, user string, watch bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.closeToken()
	k.on, k.watch, k.args, k.token, k.user = true, watch, append([]string(nil), args...), token, user
	if k.file == "" {
		return
	}
	b, err := json.Marshal(keptState{Args: k.args, Watch: watch, User: user})
	if err == nil {
		tmp := k.file + ".tmp"
		if err = os.WriteFile(tmp, b, 0o600); err == nil {
			err = os.Rename(tmp, k.file) // whole or not at all, also on a power cut
		}
	}
	_ = err // kept in memory still; only a restart of the service forgets it
}

// load keeps what keep.json says, without a user token (at boot nobody is
// signed in). It reports whether there was anything to keep.
func (k *keeper) load() (keptState, bool) {
	var st keptState
	if k.file == "" {
		return st, false
	}
	b, err := os.ReadFile(filepath.Clean(k.file))
	if err != nil || json.Unmarshal(b, &st) != nil || len(st.Args) == 0 || checkEngineArgs(st.Args) != nil {
		return st, false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.closeToken()
	k.on, k.watch, k.args, k.user = true, st.Watch, st.Args, st.User
	return st, true
}

// forget ends the keeping for good: a stop, unkeep, a start without keep.
func (k *keeper) forget() {
	k.clear()
	if k.file != "" {
		_ = os.Remove(k.file)
	}
}

// clear ends the keeping in memory: the service stopping. keep.json stays.
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
