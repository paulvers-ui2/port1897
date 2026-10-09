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
	"testing"

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
