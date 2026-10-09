// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"errors"
	"sync"

	"github.com/celzero/firestack/win/wfp"
)

// errKillNeedsFull refuses the kill switch when only DNS goes through the
// tunnel: everything else would be cut off.
var errKillNeedsFull = errors.New("the kill switch needs all traffic in the tunnel; restart protection with the firewall on")

var errNoKillSwitch = errors.New("no kill switch: the tunnel is not a Wintun adapter")

// killSwitch turns the WFP kill switch on and off while fswin runs: at start
// for -killswitch, and later for the app's kill switch button
// (POST /api/killswitch). It is nil when the tunnel is not a Wintun adapter.
type killSwitch struct {
	mu   sync.Mutex
	on   bool
	opts wfp.Options
	full bool  // all IPv4 traffic goes through the tunnel
	err  error // the last change's failure, for the status; nil after a success
}

func newKillSwitch(opts wfp.Options, full bool) *killSwitch {
	return &killSwitch{opts: opts, full: full}
}

// set turns the kill switch on (letting LAN traffic through if allowLAN) or
// off. Turning it on again applies a new allowLAN.
func (k *killSwitch) set(on, allowLAN bool) error {
	if k == nil {
		return errNoKillSwitch
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.err = k.setLocked(on, allowLAN)
	return k.err
}

func (k *killSwitch) setLocked(on, allowLAN bool) error {
	if !on {
		if !k.on {
			return nil
		}
		if err := wfp.Disable(); err != nil {
			return err
		}
		k.on = false
		return nil
	}
	if !k.full {
		return errKillNeedsFull
	}
	o := k.opts
	o.AllowLAN = allowLAN
	if err := wfp.Enable(o); err != nil { // replaces the rules if already on
		k.on = false // Enable removed the old rules before it failed
		return err
	}
	k.on, k.opts = true, o
	return nil
}

// lastError is why the kill switch last failed to change, or "".
func (k *killSwitch) lastError() string {
	if k == nil {
		return ""
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.err == nil {
		return ""
	}
	return k.err.Error()
}

func (k *killSwitch) isOn() bool {
	if k == nil {
		return false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.on
}
