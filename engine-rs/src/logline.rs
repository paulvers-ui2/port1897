// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The network layer's own log lines, as firestack writes them (intra/log
//! with Go's Ltime|Lmicroseconds): "15:04:05.000000 W tag: text". The
//! engine's lines ("fswin: ...", "  1.234s flow ...") are printed as they
//! are; these say why a dial or a query failed, and support reads them in
//! engine.log. `-log` sets the level as in Go: 0 very verbose ... 5 errors,
//! 8 none.

use std::sync::atomic::{AtomicI32, Ordering};

pub const DEBUG: i32 = 2;
pub const INFO: i32 = 3;
pub const WARN: i32 = 4;
pub const ERROR: i32 = 5;

static LEVEL: AtomicI32 = AtomicI32::new(INFO);

/// The lowest level written (-log).
pub fn set_level(l: i32) {
    LEVEL.store(l, Ordering::Relaxed);
}

pub fn enabled(level: i32) -> bool {
    level >= LEVEL.load(Ordering::Relaxed)
}

fn letter(level: i32) -> &'static str {
    match level {
        ..=DEBUG => "D",
        INFO => "I",
        WARN => "W",
        _ => "E",
    }
}

/// The line as written, without its newline.
pub fn line(level: i32, tag: &str, msg: &str) -> String {
    format!("{} {} {tag}: {msg}", clock(), letter(level))
}

/// Writes a line if the level allows it.
pub fn log(level: i32, tag: &str, msg: &str) {
    if enabled(level) {
        println!("{}", line(level, tag, msg));
    }
}

/// The local time of day with microseconds, as Go's log prefix.
#[cfg(windows)]
pub fn clock() -> String {
    use windows_sys::Win32::System::SystemInformation::GetLocalTime;
    let mut t = unsafe { std::mem::zeroed() };
    // SAFETY: t is a SYSTEMTIME the call fills in
    unsafe { GetLocalTime(&mut t) };
    // SYSTEMTIME stops at milliseconds; the microseconds within come from
    // the system clock, which is what Go's would show
    let micros = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_micros() % 1000).unwrap_or(0);
    format!("{:02}:{:02}:{:02}.{:03}{:03}", t.wHour, t.wMinute, t.wSecond, t.wMilliseconds, micros)
}

/// UTC elsewhere (tests, tools): no time zone database is at hand.
#[cfg(not(windows))]
pub fn clock() -> String {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let s = d.as_secs() % 86400;
    format!("{:02}:{:02}:{:02}.{:06}", s / 3600, s / 60 % 60, s % 60, d.subsec_micros())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_look_like_gos() {
        let l = line(WARN, "dns", "no reply");
        let (time, rest) = l.split_at(15);
        assert_eq!(rest, " W dns: no reply");
        let b = time.as_bytes();
        assert!(b.iter().enumerate().all(|(i, c)| match i {
            2 | 5 => *c == b':',
            8 => *c == b'.',
            _ => c.is_ascii_digit(),
        }), "{time}");
        assert_eq!(letter(0), "D");
        assert_eq!(letter(ERROR), "E");
        assert!(enabled(ERROR));
    }
}
