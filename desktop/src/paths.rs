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

/// Sets where fswin.exe, usque.exe and wintun.dll are: the app's resources
/// when installed, or FSWIN_PATH's folder (a build run from source).
pub fn init(resource_dir: Option<PathBuf>) {
    let dir = std::env::var_os("FSWIN_PATH")
        .map(PathBuf::from)
        .and_then(|p| p.parent().map(PathBuf::from))
        .or_else(|| resource_dir.map(|r| r.join("engine")).filter(|d| d.join("fswin.exe").exists()))
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("ui").join("engine"));
    let _ = ENGINE_DIR.set(dir);
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
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}
