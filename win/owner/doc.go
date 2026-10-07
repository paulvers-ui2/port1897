// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package owner finds the process that owns a TCP or UDP flow on Windows;
// the stand-in for Android's ConnectivityManager.getConnectionOwnerUid.
// Windows only.
package owner
