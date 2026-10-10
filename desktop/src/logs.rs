// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The engine's log for the Logs screen, read from its end.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::paths;

/// Where "Clear" left the engine log: lines before it are not shown.
static OFFSET: AtomicU64 = AtomicU64::new(0);

pub fn reset_offset() {
    OFFSET.store(0, Ordering::Relaxed);
}

/// At most max bytes from the end of f, from offset on; the first line,
/// cut by the start, is left out. None if f can't be read.
fn read_from(f: &Path, offset: u64, max: u64) -> Option<(String, bool)> {
    let mut file = std::fs::File::open(f).ok()?;
    let size = file.metadata().ok()?.len();
    let start = offset.min(size).max(size.saturating_sub(max));
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = Vec::with_capacity((size - start) as usize);
    file.read_to_end(&mut buf).ok()?;
    let mut text = String::from_utf8_lossy(&buf).into_owned();
    let cut = start > offset;
    if cut {
        text = text.split_once('\n').map(|(_, rest)| rest.to_string()).unwrap_or_default();
    }
    Some((text, start > 0 && cut))
}

/// The end of f, at most max bytes; None if f can't be read.
pub fn read_tail(f: &Path, max: u64) -> Option<String> {
    read_from(f, 0, max).map(|(t, _)| t)
}

/// The last 400 lines of the engine log (usque's lines and registrations
/// for "usque"). The last 4 MB is plenty: a verbose log grows to many MB.
pub fn engine_log_text(filter: &str) -> String {
    let text = read_from(&paths::log_file(), OFFSET.load(Ordering::Relaxed), 4 << 20).map(|(t, _)| t).unwrap_or_default();
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    if filter == "usque" {
        lines.retain(|l| {
            let l = l.to_lowercase();
            ["usque", "chain", "warp", "masque"].iter().any(|w| l.contains(w))
        });
        if let Ok(reg) = std::fs::read_to_string(paths::usque_log()) {
            let mut all: Vec<String> = reg.lines().map(String::from).collect();
            all.extend(lines);
            lines = all;
        }
    }
    lines.retain(|l| !l.is_empty());
    lines[lines.len().saturating_sub(400)..].join("\n")
}

/// "Clear": the log shows only what comes next; usque's registration log goes.
pub fn clear() {
    OFFSET.store(std::fs::metadata(paths::log_file()).map(|m| m.len()).unwrap_or(0), Ordering::Relaxed);
    let _ = std::fs::remove_file(paths::usque_log());
}
