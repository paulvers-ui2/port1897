// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! fswin-rs: AuroraVPN's engine for Windows, in Rust. It is to replace
//! fswin.exe (Go) without the app noticing: the same flags, the same control
//! API and the same service pipe. See PLAN.md for what is done and what is
//! left. The modules here are the parts that need no admin rights; the ones
//! that change the system sit behind traits so they can be tested with fakes.

pub mod api;
pub mod conns;
pub mod dns;
pub mod dnssec;
pub mod engine;
pub mod events;
pub mod exit;
pub mod flags;
pub mod geoip;
pub mod gojson;
pub mod golike;
pub mod killswitch;
pub mod logline;
pub mod mtu;
pub mod net;
pub mod netaddr;
pub mod nrpt;
pub mod rules;
pub mod run;
pub mod service;
pub mod usque;
#[cfg(windows)]
pub mod win;
