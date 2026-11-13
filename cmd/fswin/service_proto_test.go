// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"strings"
	"testing"
)

// The service refuses the flags that pick a program to run or a user, on
// Windows and on Linux alike.
func TestCheckEngineArgsShared(t *testing.T) {
	ok := [][]string{
		{"-full", "-dns", "doh", "-doh", "https://x/dns-query"},
		{"--killswitch", "-rules=/home/u/.config/AuroraVPN/rules.json"},
		{"usque"}, // a value, not a flag
	}
	for _, a := range ok {
		if err := checkEngineArgs(a); err != nil {
			t.Errorf("%q: %v", a, err)
		}
	}
	bad := [][]string{
		{"-usque", "/tmp/evil"},
		{"--USQUE=/tmp/evil"},
		{"-user-token", "0"},
		{"-service", "run"},
		{"-app=/tmp/x"},
		{"-stop-handle", "1"},
		{"-full", "a\x00b"},
		{strings.Repeat("x", 8193)},
		make([]string, 257),
	}
	for _, a := range bad {
		if err := checkEngineArgs(a); err == nil {
			t.Errorf("%.40q: accepted", a)
		}
	}
}
