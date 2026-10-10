// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// fakeUsqueEnv makes this test program a fake usque: a SOCKS5 proxy on the
// -p, -u and -w it is given, whose CONNECT works ("ok") or fails ("dead", a
// tunnel that carries nothing).
const fakeUsqueEnv = "FSWIN_FAKE_USQUE"

func TestMain(m *testing.M) {
	if mode := os.Getenv(fakeUsqueEnv); mode != "" {
		fakeUsque(os.Args[1:])
		return
	}
	os.Exit(m.Run())
}

func fakeUsque(args []string) {
	var port, user, pass string
	for i := 0; i+1 < len(args); i++ {
		switch args[i] {
		case "-p":
			port = args[i+1]
		case "-u":
			user = args[i+1]
		case "-w":
			pass = args[i+1]
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		os.Exit(3)
	}
	ok := os.Getenv(fakeUsqueEnv) == "ok"
	for {
		c, err := ln.Accept()
		if err != nil {
			os.Exit(4)
		}
		go fakeSocks(c, user, pass, ok)
	}
}

// fakeSocks answers one SOCKS5 client: username/password auth (RFC 1929),
// then a CONNECT that succeeds when ok.
func fakeSocks(c net.Conn, user, pass string, ok bool) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 256)
	read := func(n int) []byte {
		if _, err := io.ReadFull(c, b[:n]); err != nil {
			return nil
		}
		return b[:n]
	}
	if h := read(2); h == nil || h[0] != 5 || read(int(h[1])) == nil {
		return // waitListening's connect-and-close
	}
	_, _ = c.Write([]byte{5, 2})
	h := read(2)
	if h == nil {
		return
	}
	u := string(read(int(h[1])))
	pl := read(1)
	if pl == nil {
		return
	}
	if u != user || string(read(int(pl[0]))) != pass {
		_, _ = c.Write([]byte{1, 1})
		return
	}
	_, _ = c.Write([]byte{1, 0})
	if r := read(4); r == nil || r[3] != 1 || read(6) == nil { // IPv4 target only
		return
	}
	rep := byte(0)
	if !ok {
		rep = 1 // general failure: nothing gets through
	}
	_, _ = c.Write([]byte{5, rep, 0, 1, 0, 0, 0, 0, 0, 0})
}

func fakeSetup(t *testing.T) usqueSetup {
	t.Helper()
	me, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	return usqueSetup{exe: me, dir: dir, logf: t.Logf}
}

func fastSupervisor(t *testing.T) {
	t.Helper()
	pe, rm, pt, sg, ne := probeEvery, restartMin, probeTimeout, startGrace, netEvery
	probeEvery, restartMin, probeTimeout, startGrace, netEvery = 100*time.Millisecond, 100*time.Millisecond, time.Second, 0, time.Hour
	t.Cleanup(func() { probeEvery, restartMin, probeTimeout, startGrace, netEvery = pe, rm, pt, sg, ne })
}

func TestProbe(t *testing.T) {
	t.Setenv(fakeUsqueEnv, "ok")
	u, err := startUsque(fakeSetup(t))
	if err != nil {
		t.Fatal(err)
	}
	defer u.stop()
	if err := probe(u); err != nil {
		t.Fatalf("probe through a working proxy: %v", err)
	}
	bad := *u
	bad.pass = "wrong"
	if probe(&bad) == nil {
		t.Fatal("probe with the wrong password passed")
	}
}

// The user's report: the chain failed and did not come back. A usque that
// dies is back within a second, on the same port, so the exit keeps working.
func TestSupervisorRestartsUsqueThatDies(t *testing.T) {
	t.Setenv(fakeUsqueEnv, "ok")
	s := fakeSetup(t)
	u, err := startUsque(s)
	if err != nil {
		t.Fatal(err)
	}
	sv := supervise(s, u, 0, func(string) error { t.Error("the exit moved, though its port was free"); return nil })
	defer sv.stop()

	killed := time.Now()
	if err := u.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	for time.Since(killed) < 15*time.Second {
		if n := sv.current(); n != nil && n != u && !n.exited() && probe(n) == nil {
			if took := time.Since(killed); took > 3*time.Second {
				t.Errorf("back after %s, want about 1 s", took)
			}
			if n.port != u.port || n.user != u.user || n.pass != u.pass {
				t.Errorf("restarted on %d, want the exit's %d with the same credentials", n.port, u.port)
			}
			if restarts, _ := sv.status(); restarts != 1 {
				t.Errorf("restarts = %d, want 1", restarts)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("usque was not restarted")
}

// A usque that runs but carries nothing (a dead tunnel) is restarted after
// probeFailures failed probes, and the issue clears once traffic flows.
func TestSupervisorRestartsUsqueWithNoTraffic(t *testing.T) {
	fastSupervisor(t)
	t.Setenv(fakeUsqueEnv, "dead")
	s := fakeSetup(t)
	u, err := startUsque(s)
	if err != nil {
		t.Fatal(err)
	}
	sv := supervise(s, u, 0, func(string) error { return nil })
	defer sv.stop()

	deadline := time.Now().Add(15 * time.Second)
	for {
		if n, why := sv.status(); n >= 1 && why != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a usque with no traffic was not restarted")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// the tunnel works again from the next start on
	t.Setenv(fakeUsqueEnv, "ok")
	for {
		if _, why := sv.status(); why == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the issue did not clear once traffic flowed")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The Android app's flags come first, so the user's own win; the chain gets
// no --always-reconnect (usque has no such flag there), and -i fits the
// network.
func TestUsqueDefaults(t *testing.T) {
	masque := strings.Join(usqueDefaults(false, 1500), " ")
	if masque != "-i 1350 -k 10s -r 1s --idle-timeout 25s --stall-timeout 2s --always-reconnect" {
		t.Errorf("MASQUE: %s", masque)
	}
	if chain := strings.Join(usqueDefaults(true, 0), " "); strings.Contains(chain, "--always-reconnect") || !strings.HasPrefix(chain, "-i 1350 ") {
		t.Errorf("chain: %s", chain)
	}
	for link, want := range map[int]string{1400: "1350", 1360: "1332", 1000: "1200"} {
		if f := usqueDefaults(true, link); f[1] != want {
			t.Errorf("link %d: -i %s, want %s", link, f[1], want)
		}
	}
}
