// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// fakeEngineEnv makes this test program a fake engine for the service's
// launch: "exit" ends at once with exit code 5; "wait" ends with 0 once the
// event of -stop-handle is set (9 if it is not within 30 s).
const fakeEngineEnv = "FSWIN_FAKE_ENGINE"

func fakeEngine(mode string, args []string) {
	if mode == "exit" {
		os.Exit(5)
	}
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-stop-handle" {
			h, _ := strconv.ParseUint(args[i+1], 10, 64)
			if ev, err := windows.WaitForSingleObject(windows.Handle(h), 30000); err == nil && ev == windows.WAIT_OBJECT_0 {
				os.Exit(0)
			}
		}
	}
	os.Exit(9)
}

// pidGone tells whether pid no longer names the process that had it, as the
// app checks (Node's process.kill(pid, 0)): an ended process whose handle
// someone still holds keeps its id, and the app took it for running.
func pidGone(pid uint32) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return true
	}
	defer windows.CloseHandle(h)
	var code uint32
	const stillActive = 259
	return windows.GetExitCodeProcess(h, &code) == nil && code == stillActive // the id went to a new process
}

func waitPidGone(t *testing.T, pid uint32) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if pidGone(pid) {
			return
		}
	}
	t.Errorf("process %d ended, but its id stays taken: the app waits 15 s for it", pid)
}

// An engine that ends lets go of its process id at once, with or without a
// stop from the service, and its exit code is kept for the log.
func TestServiceLetsGoOfAnEndedEngine(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(fakeEngineEnv, "exit")
	e, err := launch(0, exe, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !e.exited(10 * time.Second) {
		e.kill()
		t.Fatal("the fake engine did not end")
	}
	if e.code != 5 {
		t.Errorf("exit code %s, want 5", winCode(e.code))
	}
	waitPidGone(t, e.pid)
	e.signal() // after the end: does nothing, rather than touch a closed handle
	e.kill()
}

func TestServiceStopsItsEngine(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(fakeEngineEnv, "wait")
	e, err := launch(0, exe, nil)
	if err != nil {
		t.Fatal(err)
	}
	ps := &pipeServer{logf: t.Logf, running: e}
	began := time.Now()
	ps.stopEngine(10 * time.Second)
	if !e.exited(0) || e.code != 0 {
		t.Fatalf("not stopped by its event: ended %t, exit code %s", e.exited(0), winCode(e.code))
	}
	if d := time.Since(began); d > 5*time.Second {
		t.Errorf("stop took %s", d)
	}
	if ps.running != nil {
		t.Error("the service still counts it as running")
	}
	waitPidGone(t, e.pid)
}

func TestWinCode(t *testing.T) {
	if winCode(1) != "1" || winCode(0xC0000005) != "0xC0000005" {
		t.Errorf("%s %s", winCode(1), winCode(0xC0000005))
	}
}

// The service passes the app's flags to the engine, but never those that
// pick a program to run or one of fswin's own modes.
func TestCheckEngineArgs(t *testing.T) {
	ok := [][]string{
		{"-api", "127.0.0.1:47897", "-token-file", `C:\Users\me\AppData\Roaming\AuroraVPN\api-token`, "-full", "-masque"},
		{"-doh", "https://dns.example/dns-query", "-usque-flags", "-s qq.com"},
		{},
	}
	for _, args := range ok {
		if err := checkEngineArgs(args); err != nil {
			t.Errorf("%q refused: %v", args, err)
		}
	}
	refused := [][]string{
		{"-usque", `C:\evil.exe`},
		{"--usque=C:\\evil.exe"},
		{"-full", "-service", "install"},
		{"-app", `C:\evil.exe`},
		{"-stop-handle", "4"},
		{"-user-token", "8"},
		{"--user-token=8"},
		{"-doh", "a\x00b"},
		{"-doh", strings.Repeat("x", 9000)},
		make([]string, 300),
	}
	for _, args := range refused {
		if err := checkEngineArgs(args); err == nil {
			t.Errorf("%.60q passed", args)
		}
	}
}

func TestSamePath(t *testing.T) {
	app := `C:\Program Files\AuroraVPN\AuroraVPN.exe`
	if !samePath(`c:\program files\auroravpn\AURORAVPN.EXE`, app) || !samePath(`C:\Program Files\AuroraVPN\.\AuroraVPN.exe`, app) {
		t.Error("the same program, written differently, does not match")
	}
	if samePath(`C:\Users\me\Downloads\AuroraVPN.exe`, app) || samePath("", "") {
		t.Error("another program matches")
	}
}

func TestInstallRoot(t *testing.T) {
	if got := installRoot(`C:\Program Files\AuroraVPN\resources\engine\fswin.exe`); got != `C:\Program Files\AuroraVPN` {
		t.Errorf("installed engine: %s", got)
	}
	if got := installRoot(`D:\a\port1897\dist\fswin.exe`); got != `D:\a\port1897\dist` {
		t.Errorf("a build: %s", got)
	}
}

func TestValidAdapterName(t *testing.T) {
	for _, n := range []string{"AuroraVPN", "AuroraVPN 2", "port1897", "a.b_c-d"} {
		if !validAdapterName(n) {
			t.Errorf("%q refused", n)
		}
	}
	for _, n := range []string{"", " lead", `x" exec C:\evil.txt "`, "a=b", strings.Repeat("a", 65), "name\nx"} {
		if validAdapterName(n) {
			t.Errorf("%q passed", n)
		}
	}
}

// The token the service hands the engine: a primary copy of the asking
// program's, which the engine (SYSTEM) turns into its user token.
func TestUserTokenFromTheService(t *testing.T) {
	var self windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &self); err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	ut, err := userPrimary(self)
	if err != nil {
		t.Fatal(err)
	}
	u, err := newUserTokenFrom(ut) // takes ut over
	if err != nil {
		t.Fatal(err)
	}
	defer u.close()
	me, _ := self.GetTokenUser()
	got, err := u.primary.GetTokenUser()
	if err != nil || !got.User.Sid.Equals(me.User.Sid) {
		t.Fatalf("user token of another user: %v", err)
	}
	if !slices.ContainsFunc(u.env, func(e string) bool { return strings.HasPrefix(strings.ToUpper(e), "USERPROFILE=") }) {
		t.Errorf("no user environment: %d variables", len(u.env))
	}
	cmd := exec.Command("cmd.exe")
	u.unelevated(cmd)
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Token == 0 || len(cmd.Env) != len(u.env) {
		t.Error("usque would not start as the user, with the user's environment")
	}
}
