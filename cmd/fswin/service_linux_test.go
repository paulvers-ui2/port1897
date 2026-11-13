// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSamePathLinux(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "auroravpn")
	if err := os.WriteFile(app, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(app, link); err != nil {
		t.Fatal(err)
	}
	if !samePathLinux(link, app) || !samePathLinux(app+"/.", app) {
		t.Fatal("the same program through a link or an unclean path is not the same")
	}
	if samePathLinux(filepath.Join(dir, "other"), app) {
		t.Fatal("another program is the app")
	}
}

// A request from a program other than the app is refused, with a reason.
func TestServiceRefusesOtherPrograms(t *testing.T) {
	ss := &sockServer{app: "/nonexistent/auroravpn", engine: "/bin/true", logf: t.Logf}
	if r := ss.handle(peer{uid: 1000}, pipeRequest{Cmd: "ping"}); !r.OK || r.Version == "" {
		t.Fatalf("ping: %+v", r)
	}
	if r := ss.handle(peer{uid: 1000}, pipeRequest{Cmd: "start", Args: []string{"-usque", "/tmp/x"}}); r.OK {
		t.Fatal("start with -usque accepted")
	}
	if r := ss.handle(peer{uid: 1000}, pipeRequest{Cmd: "nope"}); r.OK {
		t.Fatal("unknown request accepted")
	}
}
