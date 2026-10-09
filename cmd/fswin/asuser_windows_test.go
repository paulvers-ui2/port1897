// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// needAdmin skips a test that needs fswin's admin rights, but not on
// GitHub's runners, which have them: there a skip would hide a regression.
func needAdmin(t *testing.T) {
	t.Helper()
	if windows.GetCurrentProcessToken().IsElevated() {
		return
	}
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		t.Fatal("the CI runner should be admin")
	}
	t.Skip("needs admin")
}

// Acting as the user, fswin can neither write nor read what only admins
// may, such as a system file a planted link points at; the user's own files
// stay usable, and fswin is fully itself again afterwards.
func TestUserTokenKeepsAdminFilesOut(t *testing.T) {
	needAdmin(t)
	u, err := newUserToken()
	if err != nil {
		t.Fatal(err)
	}
	defer u.close()

	// a folder only Administrators and SYSTEM may use, like C:\Windows
	locked := t.TempDir()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(locked, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(locked, "secret.txt")
	if err := os.WriteFile(secret, []byte("admins only"), 0o600); err != nil {
		t.Fatalf("as fswin: %v", err)
	}

	err = u.do(func() error { return os.WriteFile(filepath.Join(locked, "planted.txt"), []byte("x"), 0o600) })
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("as the user, writing in an admin-only folder: %v, want access denied", err)
	}
	asUser = u
	defer func() { asUser = nil }()
	if _, err := readUserFile(secret); !errors.Is(err, os.ErrPermission) {
		t.Errorf("as the user, reading an admin-only file: %v, want access denied", err)
	}

	mine := filepath.Join(t.TempDir(), "mine.txt")
	if err := u.do(func() error { return os.WriteFile(mine, []byte("ok"), 0o600) }); err != nil {
		t.Errorf("as the user, writing the user's own file: %v", err)
	}
	if b, err := readUserFile(mine); err != nil || string(b) != "ok" {
		t.Errorf("as the user, reading it back: %q, %v", b, err)
	}
	if err := os.WriteFile(filepath.Join(locked, "after.txt"), []byte("x"), 0o600); err != nil {
		t.Errorf("fswin lost its rights after acting as the user: %v", err)
	}
}

// usque runs with the user token: at medium integrity, the Administrators
// group for deny only, and no privilege but SeChangeNotify. (Windows keeps
// the "elevated" flag on a restricted copy of an admin token; the groups,
// privileges and integrity are what give rights.)
func TestUserTokenStartsUnelevatedChildren(t *testing.T) {
	needAdmin(t)
	u, err := newUserToken()
	if err != nil {
		t.Fatal(err)
	}
	defer u.close()

	cmd := exec.Command("ping", "-n", "6", "127.0.0.1")
	u.unelevated(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start a child with the user token: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(p)
	var tok windows.Token
	if err := windows.OpenProcessToken(p, windows.TOKEN_QUERY, &tok); err != nil {
		t.Fatal(err)
	}
	defer tok.Close()

	name, err := windows.UTF16PtrFromString("SeChangeNotifyPrivilege")
	if err != nil {
		t.Fatal(err)
	}
	var changeNotify windows.LUID
	if err := windows.LookupPrivilegeValue(nil, name, &changeNotify); err != nil {
		t.Fatal(err)
	}
	for _, priv := range tokenInfo[windows.Tokenprivileges](t, tok, windows.TokenPrivileges).AllPrivileges() {
		if priv.Luid != changeNotify {
			t.Errorf("the child has a privilege besides SeChangeNotify: %+v", priv.Luid)
		}
	}
	const mediumRID = 0x2000 // SECURITY_MANDATORY_MEDIUM_RID
	if rid := integrityRID(t, tok); rid != mediumRID {
		t.Errorf("the child's integrity is %#x, want medium (%#x)", rid, mediumRID)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	groups, err := tok.GetTokenGroups()
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range groups.AllGroups() {
		if g.Sid.Equals(admins) && g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			t.Error("the child can use the Administrators group")
		}
	}
}

// An elevated engine's token lets only Administrators and SYSTEM into what it
// makes, and restrict copies that. Its children could not open themselves
// and died as they started, with no output: usque in AuroraVPN 0.2.7 to
// 0.2.10 ("usque exited before its proxy came up"). The user token's
// children, ping and a Go program like usque, must run to the end. No admin
// needed: the test gives the token an elevated default DACL itself.
func TestUserTokenChildrenRunWithAnElevatedDefaultDACL(t *testing.T) {
	var self windows.Token
	access := uint32(windows.TOKEN_QUERY | windows.TOKEN_DUPLICATE | windows.TOKEN_ASSIGN_PRIMARY | windows.TOKEN_ADJUST_DEFAULT)
	if err := windows.OpenProcessToken(windows.CurrentProcess(), access, &self); err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	r, err := restrict(self)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:(A;;GA;;;BA)(A;;GA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	def := tokenDefaultDACL{dacl: dacl}
	if err := windows.SetTokenInformation(r, windows.TokenDefaultDacl, (*byte)(unsafe.Pointer(&def)), uint32(unsafe.Sizeof(def))); err != nil { //nolint:gosec // G103: the call takes the struct as bytes
		_ = r.Close()
		t.Fatal(err)
	}
	u, err := userTokenFrom(self, r)
	if err != nil {
		t.Fatal(err)
	}
	defer u.close()

	me, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, argv := range [][]string{
		{filepath.Join(os.Getenv("SystemRoot"), "System32", "PING.EXE"), "-n", "1", "127.0.0.1"},
		{me, "-test.run=^$"}, // this test program runs no test and says PASS
	} {
		cmd := exec.Command(argv[0], argv[1:]...) //nolint:gosec // G204: ping and this test program
		// as startUsque runs usque
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
		u.unelevated(cmd)
		out, err := cmd.CombinedOutput()
		if err != nil || len(out) == 0 {
			t.Errorf("%s with the user token: %v, output %q", filepath.Base(argv[0]), err, out)
		}
	}
}

func integrityRID(t *testing.T, tok windows.Token) uint32 {
	t.Helper()
	// S-1-16-<level>, read from the string: SID.SubAuthority returns a
	// pointer from a syscall, which Go's pointer checks (race builds) refuse
	s := tokenInfo[windows.Tokenmandatorylabel](t, tok, windows.TokenIntegrityLevel).Label.Sid.String()
	rid, err := strconv.ParseUint(s[strings.LastIndexByte(s, '-')+1:], 10, 32)
	if err != nil {
		t.Fatalf("integrity SID %q: %v", s, err)
	}
	return uint32(rid)
}

// tokenInfo reads one class of information about tok, as a T.
func tokenInfo[T any](t *testing.T, tok windows.Token, class uint32) *T {
	t.Helper()
	var n uint32
	_ = windows.GetTokenInformation(tok, class, nil, 0, &n)
	if n == 0 {
		t.Fatalf("no token information of class %d", class)
	}
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(tok, class, &buf[0], n, &n); err != nil {
		t.Fatal(err)
	}
	return (*T)(unsafe.Pointer(&buf[0])) //nolint:gosec // G103: the call fills the struct
}
