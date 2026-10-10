// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package ipconf sets up an adapter with IP Helper calls: its IPv4 address,
// DNS server, metric and routes. It replaces netsh, which started a program
// for each setting (about 0.2 s each, five per start). Windows only.
package ipconf
