// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	flog "github.com/celzero/firestack/intra/log"
	"golang.org/x/sys/windows"
)

// With -logfile, firestack's own warnings and errors (intra/log) must land
// in the file next to fswin's output, not on the console fswin no longer has.
func TestRedirectOutputCarriesFirestackLogs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine.log")
	stdout, stderr, stdlog := os.Stdout, os.Stderr, log.Writer()
	hout, _ := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	herr, _ := windows.GetStdHandle(windows.STD_ERROR_HANDLE)

	if err := redirectOutput(path); err != nil {
		t.Fatalf("redirectOutput: %v", err)
	}
	f := os.Stdout
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		os.Stdout, os.Stderr = stdout, stderr
		log.SetOutput(stdlog)
		flog.SetOutput(stdout) // firestack's default logger writes W and E to stdout
		_ = windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, hout)
		_ = windows.SetStdHandle(windows.STD_ERROR_HANDLE, herr)
		_ = f.Close()
	}
	defer restore()

	// nothing may call t.Log until restore: the test's own output would go
	// to the file too
	mark := strconv.FormatInt(time.Now().UnixNano(), 36)
	flog.W("fswin test: warning %s", mark)
	flog.E("fswin test: error %s", mark)
	fmt.Println("fswin test: stdout", mark)
	log.Printf("fswin test: std log %s", mark)
	restore()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.ReplaceAll(string(b), "\r\n", "\n")
	t.Logf("%s:\n%s", path, got)
	// firestack's lines start with a time, so they line up with fswin's own
	// uptime-stamped lines
	const stamp = `^\d\d:\d\d:\d\d\.\d{6} `
	for _, want := range []struct{ prefix, text string }{
		{stamp + "W ", "fswin test: warning " + mark},
		{stamp + "E ", "fswin test: error " + mark},
		{"", "fswin test: stdout " + mark},
		{"", "fswin test: std log " + mark},
	} {
		re := regexp.MustCompile(want.prefix)
		found := false
		for _, line := range strings.Split(got, "\n") {
			if re.MatchString(line) && strings.Contains(line, want.text) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no line starting %q with %q in the log file", want.prefix, want.text)
		}
	}
}
