// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/celzero/firestack/win/wfp"
)

// apiPreflight refuses, before fswin changes anything on the PC, a port
// another engine holds, a non-loopback address and a missing or short token.
func TestAPIPreflight(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "token")
	short := filepath.Join(dir, "short")
	if err := os.WriteFile(good, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(short, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}

	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freeAddr := free.Addr().String()
	free.Close()

	if err := apiPreflight(freeAddr, good); err != nil {
		t.Errorf("free port: %v", err)
	}
	if err := apiPreflight(held.Addr().String(), good); err == nil || !strings.Contains(err.Error(), "another engine") {
		t.Errorf("held port: %v, want an error naming another engine", err)
	}
	if err := apiPreflight("0.0.0.0:47897", good); err == nil {
		t.Error("a non-loopback address passed")
	}
	if err := apiPreflight(freeAddr, filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing token file passed")
	}
	if err := apiPreflight(freeAddr, short); err == nil {
		t.Error("a short token passed")
	}
}

// A kill switch that cannot turn on reports why in the status, and the
// reason clears once a change succeeds.
func TestKillSwitchReportsFailure(t *testing.T) {
	k := newKillSwitch(wfp.Options{}, false) // DNS only: refused
	if err := k.set(true, false); !errors.Is(err, errKillNeedsFull) {
		t.Fatalf("set(true) = %v, want errKillNeedsFull", err)
	}
	if k.isOn() {
		t.Error("kill switch reports on after a failure")
	}
	if got := k.lastError(); got != errKillNeedsFull.Error() {
		t.Errorf("lastError = %q, want %q", got, errKillNeedsFull.Error())
	}
	if err := k.set(false, false); err != nil {
		t.Fatalf("set(false) = %v", err)
	}
	if got := k.lastError(); got != "" {
		t.Errorf("lastError after turning off = %q, want none", got)
	}
	var none *killSwitch
	if none.lastError() != "" {
		t.Error("a nil kill switch reports an error")
	}
}

// Per-app routes put all traffic in the tunnel after the kill switch was
// made, which then has to know, or the app's button is refused. (Only the
// flag is checked: turning the kill switch on would cut this PC off.)
func TestKillSwitchSetFull(t *testing.T) {
	k := newKillSwitch(wfp.Options{}, false)
	k.setFull(true)
	if !k.full {
		t.Error("setFull(true): the kill switch still sees DNS only")
	}
	var none *killSwitch
	none.setFull(true) // a PC without a Wintun kill switch: no panic
}

// A kill switch left on by an engine that crashed goes at the next start
// even when that start has none; one this engine set is left alone.
func TestKillSwitchLeftoverCleared(t *testing.T) {
	active, disabled := true, 0
	oldActive, oldDisable := wfpActive, wfpDisable
	wfpActive = func() (bool, error) { return active, nil }
	wfpDisable = func() error { disabled++; active = false; return nil }
	t.Cleanup(func() { wfpActive, wfpDisable = oldActive, oldDisable })

	k := newKillSwitch(wfp.Options{}, true)
	if cleared, err := k.clearLeftover(); !cleared || err != nil || disabled != 1 {
		t.Fatalf("leftover: cleared %t, %v, %d removals", cleared, err, disabled)
	}
	if cleared, err := k.clearLeftover(); cleared || err != nil || disabled != 1 {
		t.Errorf("nothing left: cleared %t, %v, %d removals", cleared, err, disabled)
	}
	active, k.on = true, true // this engine's own
	if cleared, _ := k.clearLeftover(); cleared || disabled != 1 {
		t.Error("removed this engine's own kill switch")
	}
	var none *killSwitch
	if cleared, err := none.clearLeftover(); cleared || err != nil {
		t.Error("a PC without a Wintun kill switch: something cleared")
	}
}

// A start before Wi-Fi is up waits for the network instead of failing at
// once; it gives up after the wait, and at once when asked to stop.
func TestWaitForNetwork(t *testing.T) {
	defer func(f func() uint32) { defaultRoute4 = f }(defaultRoute4)
	var calls atomic.Int32
	defaultRoute4 = func() uint32 {
		if calls.Add(1) >= 3 {
			return 7
		}
		return 0
	}
	if !waitForNetwork(5*time.Second, nil) {
		t.Error("the network came up on the 3rd look, but the wait failed")
	}

	defaultRoute4 = func() uint32 { return 0 }
	began := time.Now()
	if waitForNetwork(600*time.Millisecond, nil) {
		t.Error("no network, but the wait succeeded")
	}
	if d := time.Since(began); d < 600*time.Millisecond || d > 3*time.Second {
		t.Errorf("gave up after %s, want about 600ms", d)
	}

	stop := make(chan struct{})
	close(stop)
	began = time.Now()
	if waitForNetwork(time.Minute, stop) || time.Since(began) > time.Second {
		t.Errorf("a stop did not end the wait at once (%s)", time.Since(began))
	}
}
