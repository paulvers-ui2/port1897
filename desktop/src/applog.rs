// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! app.log: the app's own log, for the debug zip: engine starts and stops,
//! notices, errors and window crashes. Past 1 MB it starts over and keeps
//! the previous one.

use std::io::Write;
use std::sync::Mutex;

use crate::paths;

static LOCK: Mutex<()> = Mutex::new(());

/// The time as the logs and history write it: 2026-10-09T19:43:52.230Z.
pub fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

pub fn log(text: impl AsRef<str>) {
    // unit tests never write to the real app.log
    if cfg!(test) {
        return;
    }
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let f = paths::app_log_file();
    if std::fs::metadata(&f).map(|m| m.len() > 1 << 20).unwrap_or(false) {
        let _ = std::fs::rename(&f, paths::prev_app_log_file());
    }
    let _ = std::fs::create_dir_all(paths::data_dir());
    if let Ok(mut out) = std::fs::OpenOptions::new().create(true).append(true).open(&f) {
        let _ = writeln!(out, "{} {}", now_iso(), text.as_ref());
    }
}

#[macro_export]
macro_rules! applog {
    ($($arg:tt)*) => { $crate::applog::log(format!($($arg)*)) };
}
