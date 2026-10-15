// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"io"
	"os"
	"sync"
)

// logLimit caps -logfile: past it, the log is copied to <logfile>.old and
// starts over. It used to grow for as long as the engine ran, which on a
// server that runs for months at a verbose log level fills the disk.
var logLimit int64 = 32 << 20

// logCheckEvery is how much is written through cappedLog between two looks
// at the file's real size (fswin's own prints go to the same file directly).
const logCheckEvery = 1 << 20

// cappedLog writes to f, the -logfile, and keeps it under limit. The file
// is emptied in place, not renamed: the standard handles point at it, and a
// crash report written there must still land.
type cappedLog struct {
	mu      sync.Mutex
	f       *os.File
	path    string
	limit   int64
	written int64 // through Write since the last look at the size
}

func (c *cappedLog) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.written += int64(len(p))
	if c.written >= logCheckEvery {
		c.written = 0
		if pos, err := c.f.Seek(0, io.SeekCurrent); err == nil && pos >= c.limit {
			c.startOver()
		}
	}
	return c.f.Write(p)
}

// startOver keeps the last log as <path>.old and empties the log.
func (c *cappedLog) startOver() {
	_ = asUser.Load().do(func() error {
		in, err := os.Open(c.path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(c.path+".old", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, in)
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		return err
	})
	if err := c.f.Truncate(0); err == nil {
		_, _ = c.f.Seek(0, io.SeekStart)
	}
}
