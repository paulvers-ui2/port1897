// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build linux

package main

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

// The engine runs as root: it makes the TUN device, routes and firewall
// rules. The app's files (rules, WARP identity, logs) belong to the user
// who runs the app, and usque needs no rights at all: with -user-token
// <uid> (set by the service), or under sudo, files are opened and usque is
// started as that user. A nil *userToken is root itself.

// asUser is the user whose files the engine opens; nil for root's own.
var asUser atomic.Pointer[userToken]

type userToken struct{ uid, gid uint32 }

// newUserToken is the user who ran sudo, or nil when there is none.
func newUserToken() (*userToken, error) {
	uid, err1 := strconv.ParseUint(os.Getenv("SUDO_UID"), 10, 32)
	gid, err2 := strconv.ParseUint(os.Getenv("SUDO_GID"), 10, 32)
	if err1 != nil || err2 != nil || uid == 0 {
		return nil, nil //nolint:nilnil,nilerr // no sudo user: root itself
	}
	return &userToken{uint32(uid), uint32(gid)}, nil
}

// newUserTokenFrom is user uid with its primary group.
func newUserTokenFrom(uid uint64) (*userToken, error) {
	if uid == 0 || uid > 1<<32-2 {
		return nil, errors.New("-user-token: not a user id")
	}
	gid := uint32(uid) //nolint:gosec // G115: checked above
	if b, err := os.ReadFile("/etc/passwd"); err == nil {
		gid = passwdGID(string(b), uint32(uid), gid) //nolint:gosec // G115: checked above
	}
	return &userToken{uint32(uid), gid}, nil //nolint:gosec // G115: checked above
}

// do runs f with the user's rights on files: Linux checks file access
// against the calling thread's fsuid and fsgid.
func (u *userToken) do(f func() error) error {
	if u == nil {
		return f()
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	_ = unix.Setfsgid(int(u.gid))
	_ = unix.Setfsuid(int(u.uid))
	defer func() {
		_ = unix.Setfsuid(0)
		_ = unix.Setfsgid(0)
	}()
	return f()
}

// unelevated makes cmd run as the user, with no supplementary groups.
func (u *userToken) unelevated(cmd *exec.Cmd) {
	if u == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: u.uid, Gid: u.gid}
}

func (u *userToken) close() {}

// refreshUserToken has nothing to refresh: a uid does not go stale.
func refreshUserToken() error { return errors.New("no user token to refresh") }

func readUserFile(path string) (b []byte, err error) {
	err = asUser.Load().do(func() error {
		b, err = os.ReadFile(path) //nolint:gosec // G304: the app's file, read with the user's rights
		return err
	})
	return b, err
}

func writeUserFile(path string, data []byte) error {
	return asUser.Load().do(func() error { return os.WriteFile(path, data, 0o600) })
}

func statUserFile(path string) error {
	return asUser.Load().do(func() error {
		_, err := os.Stat(path)
		return err
	})
}

// passwdGID is uid's primary group in passwd's text, or def.
func passwdGID(passwd string, uid, def uint32) uint32 {
	for len(passwd) > 0 {
		var line string
		line, passwd, _ = cutLine(passwd)
		f := splitColon(line)
		if len(f) < 4 {
			continue
		}
		if u, err := strconv.ParseUint(f[2], 10, 32); err == nil && uint32(u) == uid {
			if g, err := strconv.ParseUint(f[3], 10, 32); err == nil {
				return uint32(g)
			}
		}
	}
	return def
}
