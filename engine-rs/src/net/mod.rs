// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The data path: the userspace stack behind the adapter (`stack`), the
//! engine's decision per flow, the copying and the DNS trap (`forward`),
//! the sockets that leave by the physical interface (`dial`), the -proxy
//! exit (`proxy`), and the adapter's packets in and out (`tunnel`).

pub mod dial;
pub mod forward;
pub mod proxy;
pub mod stack;
pub mod tunnel;
