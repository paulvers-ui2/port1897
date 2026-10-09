// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// prepareExit registers usque but leaves it stopped: run starts it once all
// traffic goes to the tunnel (see startUsque). The usque.exe here is not a
// program, so the test fails if prepareExit tries to run it.
func TestPrepareExitLeavesUsqueStopped(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "usque.exe")
	wg := filepath.Join(dir, "wg0.conf")
	for _, f := range []string{exe, wg, filepath.Join(dir, "warp1.json"), filepath.Join(dir, "warp2.json")} {
		if err := os.WriteFile(f, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	for want, o := range map[string]options{
		exitMasque: {masque: true, usqueExe: exe, usqueDir: dir},
		exitChain:  {chain: wg, usqueExe: exe, usqueDir: dir},
	} {
		id, cfg, us, err := prepareExit(o)
		if err != nil {
			t.Fatalf("%s: %v", want, err)
		}
		if id != want {
			t.Errorf("%s: exit %q", want, id)
		}
		if us == nil || us.exe != exe || us.dir != dir {
			t.Errorf("%s: setup %v, want usque %s in %s", want, us, exe, dir)
		}
		if cfg != "" {
			t.Errorf("%s: proxy %q before usque runs", want, cfg)
		}
	}

	missing := options{masque: true, usqueExe: filepath.Join(dir, "missing.exe"), usqueDir: dir}
	if _, _, _, err := prepareExit(missing); err == nil || !strings.Contains(err.Error(), "usque.exe") {
		t.Errorf("a missing usque.exe: %v", err)
	}
}
