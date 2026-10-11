// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Where AuroraVPN keeps its files. The data folder is the one the Electron
//! app used (%APPDATA%\AuroraVPN), so settings, rules, WARP identities,
//! WireGuard configs and history carry over as they are.

use std::path::PathBuf;
use std::sync::OnceLock;

static ENGINE_DIR: OnceLock<PathBuf> = OnceLock::new();

pub const API_HOST: &str = "127.0.0.1";
pub const API_PORT: u16 = 47897;

/// Sets where fswin.exe, usque.exe and wintun.dll are: engine\ in the app's
/// resources (beside AuroraVPN.exe). A debug build run from source may use
/// FSWIN_PATH's folder or the source tree's ui\engine; a release never does,
/// so nothing in the user's environment can choose what runs as admin.
pub fn init(resource_dir: Option<PathBuf>) {
    let packaged = resource_dir.map(|r| plain(r).join("engine"));
    let dir = if cfg!(debug_assertions) {
        std::env::var_os("FSWIN_PATH")
            .map(PathBuf::from)
            .and_then(|p| p.parent().map(PathBuf::from))
            .or_else(|| packaged.clone().filter(|d| d.join("fswin.exe").exists()))
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("ui").join("engine"))
    } else {
        // never a relative path, which would mean the current folder
        packaged
            .or_else(|| std::env::current_exe().ok().and_then(|e| e.parent().map(|d| d.join("engine"))))
            .unwrap_or_default()
    };
    let _ = ENGINE_DIR.set(dir);
}

/// Tauri's resource folder is canonical, \\?\C:\...; the engine is started
/// (UAC prompt included) and logged by its plain C:\... path. Long paths
/// and \\?\UNC\ ones keep the prefix they need.
fn plain(p: PathBuf) -> PathBuf {
    match p.to_str().and_then(|s| s.strip_prefix(r"\\?\")) {
        Some(rest) if rest.len() < 230 && rest.as_bytes().get(1) == Some(&b':') && rest.as_bytes().get(2) == Some(&b'\\') => PathBuf::from(rest),
        _ => p,
    }
}

pub fn engine_dir() -> PathBuf {
    ENGINE_DIR.get().cloned().unwrap_or_default()
}

pub fn engine_path() -> PathBuf {
    engine_dir().join("fswin.exe")
}

pub fn usque_path() -> PathBuf {
    engine_dir().join("usque.exe")
}

pub fn app_data() -> PathBuf {
    std::env::var_os("APPDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir)
}

pub fn data_dir() -> PathBuf {
    app_data().join("AuroraVPN")
}

pub fn token_file() -> PathBuf {
    data_dir().join("api-token")
}
pub fn settings_file() -> PathBuf {
    data_dir().join("settings.json")
}
pub fn log_file() -> PathBuf {
    data_dir().join("engine.log")
}
pub fn prev_log_file() -> PathBuf {
    data_dir().join("engine.prev.log")
}
pub fn usque_dir() -> PathBuf {
    data_dir().join("usque")
}
pub fn usque_log() -> PathBuf {
    usque_dir().join("usque.log")
}
pub fn wg_dir() -> PathBuf {
    data_dir().join("wireguard")
}
pub fn hist_dir() -> PathBuf {
    data_dir().join("history")
}
pub fn rules_file() -> PathBuf {
    data_dir().join("rules.json")
}
pub fn routes_file() -> PathBuf {
    data_dir().join("routes.json")
}
pub fn pcap_file() -> PathBuf {
    data_dir().join("capture.pcap")
}
pub fn warp_file() -> PathBuf {
    data_dir().join("warp.json")
}
pub fn app_log_file() -> PathBuf {
    data_dir().join("app.log")
}
pub fn prev_app_log_file() -> PathBuf {
    data_dir().join("app.prev.log")
}
pub fn app_paths_file() -> PathBuf {
    data_dir().join("app-paths.json")
}
pub fn bl_dir() -> PathBuf {
    data_dir().join("blocklists")
}

/// Writes a file whole or not at all: a crash mid-write leaves the old one.
pub fn write_atomic(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // a name of its own per write: two writers never share a half-written file
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = path.with_extension(format!("{}.{n}.tmp", std::process::id()));
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::plain;
    use std::path::PathBuf;

    #[test]
    fn verbatim_drive_paths_become_plain() {
        assert_eq!(plain(PathBuf::from(r"\\?\C:\Program Files\AuroraVPN")), PathBuf::from(r"C:\Program Files\AuroraVPN"));
        assert_eq!(plain(PathBuf::from(r"C:\AuroraVPN")), PathBuf::from(r"C:\AuroraVPN"));
        assert_eq!(plain(PathBuf::from(r"\\?\UNC\server\share\AuroraVPN")), PathBuf::from(r"\\?\UNC\server\share\AuroraVPN"));
        let long = format!(r"\\?\C:\{}", "a".repeat(300));
        assert_eq!(plain(PathBuf::from(&long)), PathBuf::from(&long));
    }
}
