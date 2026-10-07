// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package ifbind keeps sockets off the tunnel on Windows by pinning them to
// the physical default interface; the stand-in for Android's
// VpnService.protect. Windows only.
package ifbind
