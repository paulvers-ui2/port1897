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
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// keptEngine is the engine as the keeper sees it.
type keptEngine struct {
	mu      sync.Mutex
	up      bool
	started time.Time
	starts  int
	stops   int
	args    []string
	online  bool // what probes find
	probes  int
}

func (f *keptEngine) hooks(t *testing.T) keepHooks {
	return keepHooks{
		engine: func() (bool, time.Time) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.up, f.started
		},
		start: func(args []string, _ windows.Token) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.up, f.started, f.args = true, time.Now(), args
			f.starts++
			return nil
		},
		stop: func() {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.up = false
			f.stops++
		},
		probe: func(context.Context) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.probes++
			if f.online {
				return nil
			}
			return errors.New("no answer")
		},
		logf: t.Logf,
	}
}

func (f *keptEngine) get() (starts, stops, probes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.starts, f.stops, f.probes
}

func (f *keptEngine) crash() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.up = false
}

func fastKeeper(t *testing.T) {
	t.Helper()
	old := []any{keepTick, keepRestartMin, keepRestartMax, keepStable, keepGrace, keepProbeEvery, keepMisses, keepHealthMin, keepHealthMax}
	keepTick, keepRestartMin, keepRestartMax, keepStable = 5*time.Millisecond, 20*time.Millisecond, 80*time.Millisecond, time.Hour
	keepGrace, keepProbeEvery, keepMisses, keepHealthMin, keepHealthMax = 0, 10*time.Millisecond, 3, time.Hour, time.Hour
	t.Cleanup(func() {
		keepTick, keepRestartMin, keepRestartMax, keepStable = old[0].(time.Duration), old[1].(time.Duration), old[2].(time.Duration), old[3].(time.Duration)
		keepGrace, keepProbeEvery, keepMisses = old[4].(time.Duration), old[5].(time.Duration), old[6].(int)
		keepHealthMin, keepHealthMax = old[7].(time.Duration), old[8].(time.Duration)
	})
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// An engine that ends by itself starts again with the same flags; one that
// is not kept, or was stopped, does not.
func TestKeepRestartsAnEngineThatEnds(t *testing.T) {
	fastKeeper(t)
	f := &keptEngine{up: true, started: time.Now(), online: true}
	var k keeper
	quit := make(chan struct{})
	defer close(quit)
	go k.run(quit, f.hooks(t))

	f.crash()
	time.Sleep(100 * time.Millisecond)
	if s, _, _ := f.get(); s != 0 {
		t.Fatal("started an engine nobody asked to keep")
	}

	k.set([]string{"-dns", "doh"}, 0, "me", false)
	eventually(t, "a kept engine that ended was not started again", func() bool { s, _, _ := f.get(); return s == 1 })
	if f.args[1] != "doh" {
		t.Fatalf("started with %v", f.args)
	}

	k.clear() // the user's stop
	f.crash()
	time.Sleep(100 * time.Millisecond)
	if s, _, _ := f.get(); s != 1 {
		t.Fatal("started again after a stop")
	}
}

// After keepMisses checks without internet the engine is restarted, once,
// and not again before keepHealthMin; without watch it is never checked.
func TestKeepRestartsAfterTheInternetStaysAway(t *testing.T) {
	fastKeeper(t)
	f := &keptEngine{up: true, started: time.Now(), online: false}
	var k keeper
	quit := make(chan struct{})
	defer close(quit)
	go k.run(quit, f.hooks(t))

	k.set(nil, 0, "me", false)
	time.Sleep(100 * time.Millisecond)
	if _, _, p := f.get(); p != 0 {
		t.Fatal("checked the internet without watch")
	}

	k.set(nil, 0, "me", true)
	eventually(t, "no restart while the internet stayed away", func() bool { s, st, _ := f.get(); return st == 1 && s == 1 })
	if _, _, p := f.get(); p < keepMisses {
		t.Fatalf("restarted after %d checks, want %d", p, keepMisses)
	}
	time.Sleep(200 * time.Millisecond) // keepHealthMin is an hour here
	if _, st, _ := f.get(); st != 1 {
		t.Fatalf("restarted %d times within keepHealthMin", st)
	}
}

// One answer between misses starts the count over.
func TestKeepMissesMustBeInARow(t *testing.T) {
	fastKeeper(t)
	f := &keptEngine{up: true, started: time.Now()}
	var k keeper
	quit := make(chan struct{})
	defer close(quit)
	h := f.hooks(t)
	n := 0
	h.probe = func(context.Context) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		n++
		f.probes = n
		if n%keepMisses == 0 { // every third answers
			return nil
		}
		return errors.New("no answer")
	}
	go k.run(quit, h)
	k.set(nil, 0, "me", true)
	eventually(t, "not enough checks", func() bool { _, _, p := f.get(); return p >= 4*keepMisses })
	if _, st, _ := f.get(); st != 0 {
		t.Fatal("restarted though the internet answered between misses")
	}
}
