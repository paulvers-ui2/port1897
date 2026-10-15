// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// Writing far past the limit keeps the log near it, with the run before
// kept in .old: a server's disk does not fill.
func TestLogStaysUnderItsLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine.log")
	f, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	limit := int64(4 << 20)
	w := &cappedLog{f: f, path: path, limit: limit}
	line := bytes.Repeat([]byte("x"), 1023)
	line = append(line, '\n')
	for range 40 << 10 { // 40 MB
		if _, err := w.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() > limit+2*logCheckEvery {
		t.Fatalf("log is %d bytes, limit %d", st.Size(), limit)
	}
	old, err := os.Stat(path + ".old")
	if err != nil || old.Size() < limit {
		t.Fatalf("no full .old log: %v %v", old, err)
	}
	// the file still takes writes at its start, not past a hole
	if _, err := w.Write([]byte("last\n")); err != nil {
		t.Fatal(err)
	}
}
