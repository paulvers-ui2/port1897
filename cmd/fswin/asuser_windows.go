// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fswin runs as admin, but most files it opens belong to the app, in the
// user's own folder (%APPDATA%\AuroraVPN): its log, the API token, rules,
// routes, WireGuard and WARP files, blocklists and packet captures. Malware
// running as that user could swap one of them for a link to a system file
// and have fswin overwrite, delete or read it with admin rights, a common
// way to take over a PC. So fswin opens those files as the user would: with
// its own token minus the Administrators group (deny only) and every
// privilege, at medium integrity, as an unelevated program runs. Windows
// then refuses whatever the user could not reach alone. usque needs no
// admin rights at all and runs with the same token.

// Run by AuroraVPN Service, fswin is SYSTEM, and the token comes from the
// user who asked the service (newUserTokenFrom), lowered the same way; usque
// also gets that user's environment.

// asUser is that token, made at start; nil (most tests) acts as fswin.
var asUser *userToken

type userToken struct {
	primary windows.Token // for child processes
	imp     windows.Token // for impersonation
	env     []string      // the user's environment for children; nil: fswin's
}

var procCreateRestrictedToken = windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")

// CreateRestrictedToken flag: drop every privilege but SeChangeNotify.
const disableMaxPrivilege = 0x1

func newUserToken() (*userToken, error) {
	var self windows.Token
	access := uint32(windows.TOKEN_QUERY | windows.TOKEN_DUPLICATE | windows.TOKEN_ASSIGN_PRIMARY | windows.TOKEN_ADJUST_DEFAULT)
	if err := windows.OpenProcessToken(windows.CurrentProcess(), access, &self); err != nil {
		return nil, fmt.Errorf("user token: %w", err)
	}
	defer self.Close()

	restricted, err := restrict(self)
	if err != nil {
		return nil, err
	}
	return userTokenFrom(self, restricted)
}

// newUserTokenFrom is the user token made from t, the token of the user who
// asked AuroraVPN Service for the engine: restricted and lowered as
// newUserToken's own, with that user's environment. It takes t over.
func newUserTokenFrom(t windows.Token) (*userToken, error) {
	defer t.Close()
	if _, err := t.GetTokenUser(); err != nil {
		return nil, fmt.Errorf("-user-token: %w", err)
	}
	restricted, err := restrict(t)
	if err != nil {
		return nil, err
	}
	u, err := userTokenFrom(t, restricted)
	if err != nil {
		return nil, err
	}
	env, err := t.Environ(false)
	if err != nil {
		u.close()
		return nil, fmt.Errorf("user token: environment: %w", err)
	}
	u.env = env
	return u, nil
}

// restrict is self with the Administrators group for deny only and no
// privilege but SeChangeNotify.
func restrict(self windows.Token) (windows.Token, error) {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return 0, fmt.Errorf("user token: %w", err)
	}
	deny := windows.SIDAndAttributes{Sid: admins}
	var restricted windows.Token
	r, _, e := procCreateRestrictedToken.Call(uintptr(self), disableMaxPrivilege, 1, uintptr(unsafe.Pointer(&deny)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&restricted))) //nolint:gosec // G103: the Win32 call takes pointers
	if r == 0 {
		return 0, fmt.Errorf("user token: restrict: %w", e)
	}
	return restricted, nil
}

// userTokenFrom finishes restricted, a restrict of self, as the user token,
// and owns it from then on.
func userTokenFrom(self, restricted windows.Token) (*userToken, error) {
	u := &userToken{primary: restricted}
	if err := u.lower(self); err != nil {
		u.close()
		return nil, err
	}
	if err := windows.DuplicateTokenEx(restricted, windows.MAXIMUM_ALLOWED, nil,
		windows.SecurityImpersonation, windows.TokenImpersonation, &u.imp); err != nil {
		u.close()
		return nil, fmt.Errorf("user token: impersonation copy: %w", err)
	}
	return u, nil
}

// tokenOwner is TOKEN_OWNER.
type tokenOwner struct{ owner *windows.SID }

// tokenDefaultDACL is TOKEN_DEFAULT_DACL.
type tokenDefaultDACL struct{ dacl *windows.ACL }

// lower makes the restricted token look like an unelevated program's: medium
// integrity, owned by the user, not by the Administrators group it can no
// longer use, and with the user in its default DACL.
//
// The default DACL guards what the token makes, first the process and
// threads of a child it starts. An elevated token's lets in only
// Administrators and SYSTEM; with that group for deny only, usque could not
// open itself, and Windows ended it as it started (0xC0000142), before it
// printed a word. An unelevated program's lets in its user too.
//
//nolint:gosec // G103: SetTokenInformation takes a struct as bytes and a size
func (u *userToken) lower(self windows.Token) error {
	medium, err := windows.CreateWellKnownSid(windows.WinMediumLabelSid)
	if err != nil {
		return fmt.Errorf("user token: %w", err)
	}
	label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: medium, Attributes: windows.SE_GROUP_INTEGRITY}}
	size := uint32(unsafe.Sizeof(label)) + windows.GetLengthSid(medium)
	if err := windows.SetTokenInformation(u.primary, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&label)), size); err != nil {
		return fmt.Errorf("user token: medium integrity: %w", err)
	}

	me, err := self.GetTokenUser()
	if err != nil {
		return fmt.Errorf("user token: %w", err)
	}
	owner := tokenOwner{owner: me.User.Sid}
	if err := windows.SetTokenInformation(u.primary, windows.TokenOwner, (*byte)(unsafe.Pointer(&owner)), uint32(unsafe.Sizeof(owner))); err != nil {
		return fmt.Errorf("user token: owner: %w", err)
	}

	sd, err := windows.SecurityDescriptorFromString("D:(A;;GA;;;" + me.User.Sid.String() + ")(A;;GA;;;BA)(A;;GA;;;SY)")
	if err != nil {
		return fmt.Errorf("user token: default DACL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("user token: default DACL: %w", err)
	}
	def := tokenDefaultDACL{dacl: dacl}
	if err := windows.SetTokenInformation(u.primary, windows.TokenDefaultDacl, (*byte)(unsafe.Pointer(&def)), uint32(unsafe.Sizeof(def))); err != nil {
		return fmt.Errorf("user token: default DACL: %w", err)
	}
	return nil
}

// do runs f on a thread that acts as the user, so the files f opens are
// checked against the user's rights, not fswin's; what f opens stays usable
// afterwards. f must not hand its work to other goroutines.
func (u *userToken) do(f func() error) error {
	if u == nil {
		return f()
	}
	done := make(chan error, 1)
	go func() {
		// impersonation belongs to this thread; a thread that cannot go back
		// to fswin's own token stays locked, and Go ends it with the goroutine
		runtime.LockOSThread()
		if err := windows.SetThreadToken(nil, u.imp); err != nil {
			runtime.UnlockOSThread()
			done <- fmt.Errorf("act as the user: %w", err)
			return
		}
		err := f()
		if windows.RevertToSelf() == nil {
			runtime.UnlockOSThread()
		}
		done <- err
	}()
	return <-done
}

// unelevated makes cmd start with the user token, as an unelevated program.
func (u *userToken) unelevated(cmd *exec.Cmd) {
	if u == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Token = syscall.Token(u.primary)
	if cmd.Env == nil && u.env != nil {
		cmd.Env = u.env
	}
}

func (u *userToken) close() {
	if u == nil {
		return
	}
	if u.imp != 0 {
		_ = u.imp.Close()
	}
	if u.primary != 0 {
		_ = u.primary.Close()
	}
}

// readUserFile reads one of the app's files with the user's rights.
func readUserFile(path string) ([]byte, error) {
	var b []byte
	err := asUser.do(func() (err error) {
		b, err = os.ReadFile(filepath.Clean(path))
		return err
	})
	return b, err
}

// statUserFile checks one of the app's files with the user's rights.
func statUserFile(path string) error {
	return asUser.do(func() error {
		_, err := os.Stat(path)
		return err
	})
}
