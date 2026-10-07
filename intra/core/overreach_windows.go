// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package core

// The Go runtime has no secure mode (AT_SECURE) on Windows.

func SecureMode(new bool) (prev bool) {
	return false
}

// RuntimeSecureMode reports whether the Go runtime is in secure mode.
func RuntimeSecureMode() (them, us bool) {
	return false, false
}
