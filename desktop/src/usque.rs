// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! WARP identities and wg0.conf for usque (Proxy → WARP, Chain mode).

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::{Value, json};

use crate::{applog, paths, wg};

pub fn file(which: &str) -> Result<PathBuf, String> {
    match which {
        "warp1" | "warp2" => Ok(paths::usque_dir().join(format!("{which}.json"))),
        _ => Err("bad identity".into()),
    }
}

pub fn wg0() -> PathBuf {
    paths::usque_dir().join("wg0.conf")
}

fn registered(which: &str) -> bool {
    file(which)
        .ok()
        .and_then(|f| std::fs::read_to_string(f).ok())
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|j| j.get("private_key").cloned())
        .is_some_and(|k| !k.is_null() && k != json!("") && k != json!(false))
}

pub fn status() -> Value {
    let text = std::fs::read_to_string(wg0()).unwrap_or_default();
    json!({
        "warp1": { "registered": registered("warp1") },
        "warp2": { "registered": registered("warp2") },
        "wg0": { "present": !text.trim().is_empty(), "text": text },
    })
}

pub fn append_log(text: &str) {
    let _ = std::fs::create_dir_all(paths::usque_dir());
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(paths::usque_log()) {
        let _ = writeln!(f, "{} {}", applog::now_iso(), text.trim());
    }
}

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Registers a free WARP identity with usque (as the user, no admin), unless
/// one exists; force replaces it, keeping the old one if that fails.
pub async fn register(which: &str, force: bool) -> Value {
    let exe = paths::usque_path();
    if !exe.exists() {
        return json!({ "ok": false, "error": format!("usque.exe not found at {}", exe.display()) });
    }
    let f = match file(which) {
        Ok(f) => f,
        Err(e) => return json!({ "ok": false, "error": e }),
    };
    let _ = std::fs::create_dir_all(paths::usque_dir());
    let bak = f.with_extension("json.bak");
    if f.exists() {
        if !force {
            return json!({ "ok": true });
        }
        let _ = std::fs::rename(&f, &bak);
    }
    append_log(&format!("register {which}: start"));
    let mut cmd = tokio::process::Command::new(&exe);
    cmd.arg("-c").arg(&f).args(["register", "--accept-tos"]).current_dir(paths::usque_dir()).kill_on_drop(true);
    cmd.creation_flags(CREATE_NO_WINDOW);
    let res = tokio::time::timeout(Duration::from_secs(60), cmd.output()).await;
    let (how, out) = match res {
        Ok(Ok(o)) => (
            if o.status.success() { "done".to_string() } else { format!("failed: {}", o.status) },
            format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)),
        ),
        Ok(Err(e)) => (format!("failed: {e}"), String::new()),
        Err(_) => ("failed: timed out after 60 s".to_string(), String::new()),
    };
    append_log(&format!("register {which}: {how}\n{out}"));
    let ok = registered(which);
    if !ok && force && bak.exists() {
        let _ = std::fs::rename(&bak, &f);
    }
    json!({ "ok": ok, "error": if ok { "" } else { "Registration failed — see the log." } })
}

pub fn read_config(which: &str) -> String {
    file(which).ok().and_then(|f| std::fs::read_to_string(f).ok()).unwrap_or_default()
}

pub fn save_config(which: &str, text: &str) -> Value {
    let ok = serde_json::from_str::<Value>(text)
        .ok()
        .and_then(|j| j.get("private_key").cloned())
        .is_some_and(|k| !k.is_null() && k != json!("") && k != json!(false));
    if !ok {
        return json!({ "ok": false, "error": "Invalid config: needs a JSON object with private_key. Not saved." });
    }
    let f = match file(which) {
        Ok(f) => f,
        Err(e) => return json!({ "ok": false, "error": e }),
    };
    match std::fs::create_dir_all(paths::usque_dir()).and_then(|()| std::fs::write(f, text)) {
        Ok(()) => json!({ "ok": true }),
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    }
}

const BAD_WG0: &str = "Invalid wg0.conf — needs [Interface] PrivateKey and [Peer] Endpoint (plain WireGuard; AmneziaWG is not supported)";

pub fn save_wg0(text: &str) -> Value {
    if text.trim().is_empty() {
        let _ = std::fs::remove_file(wg0());
        return json!({ "ok": true });
    }
    if !wg::valid(text, true) {
        return json!({ "ok": false, "error": BAD_WG0 });
    }
    match std::fs::create_dir_all(paths::usque_dir()).and_then(|()| std::fs::write(wg0(), text)) {
        Ok(()) => json!({ "ok": true }),
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    }
}

/// wg0.conf from a file the user picked.
pub fn import_wg0(text: &str) -> Value {
    if !wg::valid(text, true) {
        return json!({ "error": BAD_WG0 });
    }
    match std::fs::create_dir_all(paths::usque_dir()).and_then(|()| std::fs::write(wg0(), text)) {
        Ok(()) => json!({ "ok": true }),
        Err(e) => json!({ "error": e.to_string() }),
    }
}
