// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"errors"
	"fmt"
	"strings"
)

// The app talks to AuroraVPN Service the same way on Windows (the named pipe
// \\.\pipe\AuroraVPN, service_windows.go) and on Linux (the unix socket
// /run/auroravpn/auroravpn.sock, service_linux.go): one JSON request per
// connection, one JSON reply.

// pipeRequest is one request to the service.
type pipeRequest struct {
	Cmd  string   `json:"cmd"`            // ping, start, stop, unkeep or cleanup
	Args []string `json:"args,omitempty"` // start: the engine's flags
	// start: keep the engine running until a stop or unkeep (keep_windows.go),
	// and with Watch also restart it when the internet stays away (a VPN exit)
	Keep  bool `json:"keep,omitempty"`
	Watch bool `json:"watch,omitempty"`
}

// pipeReply is the service's answer.
type pipeReply struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	PID     uint32 `json:"pid,omitempty"`     // start: the engine's process
	Version string `json:"version,omitempty"` // ping
}

// refusedFlags pick a program for the engine to run, or one of fswin's own
// modes, not a setting.
var refusedFlags = map[string]bool{"service": true, "app": true, "stop-handle": true, "user-token": true, "usque": true}

// checkEngineArgs refuses the flags a client may not pass.
func checkEngineArgs(args []string) error {
	if len(args) > 256 {
		return errors.New("too many flags")
	}
	for _, a := range args {
		if len(a) > 8192 || strings.ContainsRune(a, 0) {
			return errors.New("a flag is too long")
		}
		if !strings.HasPrefix(a, "-") {
			continue
		}
		name, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if refusedFlags[strings.ToLower(name)] {
			return fmt.Errorf("the flag -%s is not allowed through the service", name)
		}
	}
	return nil
}
