// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"os/exec"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

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
