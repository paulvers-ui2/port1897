// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The data path: the userspace stack behind the adapter (`stack`), the
//! engine's decision per flow and the copying (`relay`), the sockets that
//! leave by the physical interface (`dial`), and the seam to the fake DNS
//! server (`resolver`).

pub mod stack;
