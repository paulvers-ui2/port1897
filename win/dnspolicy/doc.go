// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package dnspolicy makes Windows send every DNS query to one server with a
// Name Resolution Policy Table (NRPT) rule, so queries cannot leak out of
// other adapters' DNS servers. Windows only.
package dnspolicy
