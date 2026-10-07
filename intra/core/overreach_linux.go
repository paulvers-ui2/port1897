// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build linux

package core

import (
	_ "unsafe" // for go:linkname
)

//go:linkname secureMode runtime.secureMode
var secureMode bool

func init() {
	// github.com/golang/go/issues/69868
	// Unfortunately, Android apps have AT_SECURE set
	// (read bytes in /proc/self/auxv on non-rooted Androids).
	// This means, on Go runtime fatal / throws and a few kinds of panics,
	// only one line is output to logcat (Android's stderr) which makes it
	// hard to tell just what went wrong. Android, does use unwinder for
	// native apps, and the Android RunTime has its own unwinder;
	// both of which traceback seemingly oblivious to AT_SECURE.
	// Perhaps, there's security benefits to the Go runtime being this rigid
	// about GOTRACEBACK, but for goos.IsAndroid (and for apps with uid > 10000),
	// using AT_SECURE to determine "setuid-like" protections appears pointless.
	secureMode = false
}

func SecureMode(new bool) (prev bool) {
	prev = secureMode
	secureMode = new
	return prev
}

// RuntimeSecureMode reports whether the Go runtime is in secure mode.
// github.com/golang/go/blob/e2fef50def98/src/runtime/os_linux.go#L296
func RuntimeSecureMode() (them, us bool) {
	return runtime_isSecureMode(), secureMode
}

//go:linkname runtime_isSecureMode runtime.isSecureMode
func runtime_isSecureMode() bool
