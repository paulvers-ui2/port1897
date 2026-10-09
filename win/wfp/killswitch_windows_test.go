// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package wfp

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// The rule that lets the calling program past the kill switch must work when
// that program is not a Windows service, as fswin is not: it used to need a
// service SID and failed with ERROR_NO_SUCH_GROUP ("The specified group does
// not exist"), so the kill switch never turned on. The filters go into a
// dynamic session, inside a transaction that is aborted: nothing is ever
// blocked. Needs admin rights, which GitHub's Windows runners have.
func TestPermitSelfWithoutServiceSID(t *testing.T) {
	_, sdErr := getCurrentProcessSecurityDescriptor()
	t.Logf("service SID of this process: %v", sdErr)
	if sdErr != nil && !errors.Is(sdErr, windows.ERROR_NO_SUCH_GROUP) {
		t.Fatalf("security descriptor: %v", sdErr)
	}

	session, err := openSession(cFWPM_SESSION_FLAG_DYNAMIC)
	if err != nil {
		// GitHub's runners are admin: a skip there would hide a regression
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatalf("no WFP session on the CI runner: %v", err)
		}
		t.Skipf("no WFP session (needs admin): %v", err)
	}
	defer fwpmEngineClose0(session)

	mu.Lock()
	defer mu.Unlock()
	persisted, seq = false, 0

	if err := fwpmTransactionBegin0(session, 0); err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	defer fwpmTransactionAbort0(session)

	bo, err := addBaseObjects(session, false)
	if err != nil {
		t.Fatalf("base objects: %v", err)
	}
	if err := permitWireGuardService(session, bo, 15); err != nil {
		t.Fatalf("permit this program: %v", err)
	}
	if seq != 4 {
		t.Errorf("filters added: %d, want 4 (in and out, IPv4 and IPv6)", seq)
	}
}
