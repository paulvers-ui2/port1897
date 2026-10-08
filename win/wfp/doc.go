// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package wfp is the kill switch: Windows Filtering Platform rules that
// block all traffic except through the tunnel, the engine itself and the
// programs it names. Adapted from wireguard-windows' tunnel/firewall (MIT;
// helpers.go, rules.go, syscall_windows.go, types_windows*.go and
// zsyscall_windows.go are its files, unchanged except for the package name,
// build tags (windows added) and fwpmFilterAdd0 renamed to fwpmFilterAdd0Raw). Unlike
// WireGuard's dynamic session, the rules here can be persistent, so traffic
// stays blocked if the engine crashes. Windows only.
package wfp
