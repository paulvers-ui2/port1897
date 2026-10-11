// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! What the window may ask for: the same fixed list of calls the Electron
//! app's preload.js offered (ui/renderer/port-tauri.js maps window.port onto
//! them), with the same checks. Every call runs off the window's thread.

use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Map, Value, json};
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_opener::OpenerExt;

use crate::settings;
use crate::{api, applog, blocklists, debugzip, engine, history, live, logs, net, paths, rules, tray, usque, wg, winutil};

/// The page called settings_get: it loaded, its scripts ran and IPC works
/// (--self-test).
pub static PAGE_UP: AtomicBool = AtomicBool::new(false);

type R = Result<Value, String>;

fn obj(s: settings::S) -> Value {
    Value::Object(s)
}

// ---------- settings and rules ----------

#[tauri::command]
pub async fn settings_get() -> Value {
    PAGE_UP.store(true, Ordering::Relaxed);
    obj(settings::read())
}

#[tauri::command]
pub async fn settings_set(patch: Value) -> Value {
    let p = settings::clean_patch(&patch, None);
    let merged = settings::update(|s| {
        for (k, v) in &p {
            s.insert(k.clone(), v.clone());
        }
        *s = settings::migrate(std::mem::take(s));
    });
    if rules::RULE_KEYS.iter().any(|k| p.contains_key(*k)) {
        rules::push_rules().await;
    }
    obj(merged)
}

/// Rule changes apply at once, without a restart.
#[tauri::command]
pub async fn rules_set(patch: Value) -> Value {
    let p = settings::clean_patch(&patch, Some(&rules::RULE_KEYS));
    let s = settings::update(|s| {
        for (k, v) in p {
            s.insert(k, v);
        }
        *s = settings::migrate(std::mem::take(s));
    });
    let r = rules::push_rules().await;
    json!({ "settings": s, "warnings": r.get("warnings").cloned().unwrap_or(json!("")) })
}

#[tauri::command]
pub async fn engine_pause(app: AppHandle, minutes: Value) -> Value {
    let m = minutes.as_f64().or_else(|| minutes.as_str().and_then(|t| t.parse().ok())).unwrap_or(0.0);
    obj(tray::pause(&app, m.max(0.0)).await)
}

#[tauri::command]
pub async fn engine_block(app: Value, block: bool) -> Value {
    let name = match &app {
        Value::String(t) => t.trim().to_lowercase(),
        v => v.to_string().trim().to_lowercase(),
    };
    let s = settings::read();
    if !settings::safe_key(&name) {
        return obj(s);
    }
    let s = settings::update(|s| {
        let Some(Value::Object(rules)) = s.get_mut("rules") else { return };
        let apps = rules.entry("apps").or_insert_with(|| json!({}));
        let Value::Object(apps) = apps else { return };
        let mut a: Map<String, Value> = apps.get(&name).and_then(Value::as_object).cloned().unwrap_or_default();
        if block {
            a.insert("mode".into(), json!("block"));
        } else if a.get("mode").and_then(Value::as_str) == Some("block") {
            a.remove("mode");
        }
        a.remove("allowUntil");
        if a.is_empty() {
            apps.remove(&name);
        } else {
            apps.insert(name.clone(), Value::Object(a));
        }
    });
    rules::push_rules().await;
    obj(s)
}

// ---------- the engine ----------

#[tauri::command]
pub async fn engine_start(app: AppHandle) -> Value {
    let r = engine::start().await;
    live::refresh(&app).await;
    r
}

#[tauri::command]
pub async fn engine_stop(app: AppHandle) -> Value {
    let r = engine::stop(true).await;
    live::refresh(&app).await;
    r
}

/// Removes a kill switch (and DNS rule) left behind if the engine crashed.
#[tauri::command]
pub async fn engine_cleanup() -> Value {
    // never beside a start, a stop or an engine still ending: it would pull
    // the firewall and DNS rule from under them
    let _g = engine::OP.lock().await;
    if api::status().await.is_some() {
        return json!({ "ok": false, "error": "Stop protection first." });
    }
    engine::wait_ended().await;
    if let Some(r) = engine::service_call(&json!({ "cmd": "cleanup" })).await
        && r.get("ok").and_then(Value::as_bool) == Some(true)
    {
        return json!({ "ok": true });
    }
    match winutil::launch_elevated(&paths::engine_path(), &["-cleanup".to_string()]).await {
        Ok(_) => json!({ "ok": true }),
        Err(e) => json!({ "ok": false, "error": e }),
    }
}

#[tauri::command]
pub async fn engine_status() -> Value {
    match live::last() {
        Some(st) => st,
        None => api::status().await.unwrap_or(Value::Null),
    }
}

/// The kill switch button: applied at once while protection runs with all
/// traffic in the tunnel; in DNS-only mode protection restarts with it, as
/// the kill switch needs the whole tunnel.
#[tauri::command]
pub async fn engine_kill_switch(app: AppHandle, on: bool) -> Value {
    let s = settings::update(|s| {
        s.insert("killSwitch".into(), json!(on));
    });
    applog!("kill switch {} (button)", if on { "on" } else { "off" });
    let Some(st) = api::status().await else {
        return json!({ "ok": true, "applied": "next start" });
    };
    if st.get("mode").and_then(Value::as_str) == Some("full") {
        return match api::post("/api/killswitch", Some(&json!({ "on": on, "allowLan": settings::bool(&s, "allowLan") }))).await {
            Ok(_) => {
                live::refresh(&app).await;
                json!({ "ok": true, "applied": "now" })
            }
            Err(e) => {
                applog!("kill switch failed: {e}");
                json!({ "ok": false, "error": e })
            }
        };
    }
    if !on {
        return json!({ "ok": true, "applied": "now" }); // DNS only: it was never on
    }
    let _g = engine::OP.lock().await;
    let stop = engine::stop_locked(false).await;
    if stop.get("ok").and_then(Value::as_bool) != Some(true) {
        return stop;
    }
    let r = engine::start_locked().await;
    drop(_g);
    live::refresh(&app).await;
    if r.get("ok").and_then(Value::as_bool) == Some(true) { json!({ "ok": true, "applied": "restarted" }) } else { r }
}

#[tauri::command]
pub async fn engine_events(after: Value) -> Value {
    history::events_after(after.as_u64().or_else(|| after.as_f64().map(|f| f as u64)).unwrap_or(0))
}

#[tauri::command]
pub async fn engine_stats(range: String) -> Value {
    history::stats(&range, settings::bool(&settings::read(), "history"))
}

#[tauri::command]
pub async fn engine_app_stats(app: String) -> Value {
    history::app_stats(&app).await
}

#[tauri::command]
pub async fn engine_app_paths() -> Value {
    Value::Object(rules::app_paths())
}

#[tauri::command]
pub async fn engine_proxies() -> Value {
    api::get("/api/proxies").await.unwrap_or_else(|_| json!([]))
}

fn url_encode(t: &str) -> String {
    t.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

#[tauri::command]
pub async fn conns_list(app: Option<String>) -> Value {
    api::get(&format!("/api/conns?app={}", url_encode(app.as_deref().unwrap_or("")))).await.unwrap_or_else(|_| json!([]))
}

#[tauri::command]
pub async fn conns_close(app: Option<String>) -> Value {
    api::post("/api/close", Some(&json!({ "app": app.unwrap_or_default() }))).await.unwrap_or_else(|_| json!({ "closed": 0 }))
}

/// One connection, from the Logs screen's active list; never "all".
#[tauri::command]
pub async fn conns_close_one(cid: Value) -> Value {
    let id = match &cid {
        Value::String(t) => t.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    };
    if id.is_empty() || id.len() > 20 || !id.bytes().all(|b| b.is_ascii_digit()) {
        return json!({ "closed": 0 });
    }
    api::post("/api/close", Some(&json!({ "cids": [id] }))).await.unwrap_or_else(|_| json!({ "closed": 0 }))
}

// ---------- blocklists ----------

#[tauri::command]
pub async fn bl_status() -> Value {
    blocklists::status()
}
#[tauri::command]
pub async fn bl_filetag() -> Value {
    blocklists::filetag().await
}
#[tauri::command]
pub async fn bl_download() -> Value {
    blocklists::download().await
}
#[tauri::command]
pub async fn bl_latest() -> Value {
    blocklists::latest().await
}
#[tauri::command]
pub async fn bl_delete() -> Value {
    // an engine starting or still ending has the lists open too
    let _g = engine::OP.lock().await;
    if api::status().await.is_some() {
        return json!({ "ok": false, "error": "Stop protection first: the engine has the blocklists open." });
    }
    engine::wait_ended().await;
    blocklists::delete()
}

// ---------- WARP identities, wg0 and WireGuard configs ----------

#[tauri::command]
pub async fn usque_status() -> Value {
    usque::status()
}
#[tauri::command]
pub async fn usque_register(which: String, force: Option<bool>) -> Value {
    usque::register(&which, force.unwrap_or(false)).await
}
#[tauri::command]
pub async fn usque_read_config(which: String) -> Value {
    json!(usque::read_config(&which))
}
#[tauri::command]
pub async fn usque_save_config(which: String, text: String) -> Value {
    usque::save_config(&which, &text)
}
#[tauri::command]
pub async fn usque_save_wg0(text: String) -> Value {
    usque::save_wg0(&text)
}

/// A file dialog in front of the app's window.
fn file_dialog(app: &AppHandle) -> tauri_plugin_dialog::FileDialogBuilder<tauri::Wry> {
    let d = app.dialog().file();
    match app.get_webview_window("main") {
        Some(w) => d.set_parent(&w),
        None => d,
    }
}

/// A .conf the user picks: Ok(None) when they cancel, else (its name
/// without .conf, its text).
async fn open_conf(app: &AppHandle, title: &str) -> Result<Option<(String, String)>, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    file_dialog(app).set_title(title).add_filter("WireGuard config", &["conf"]).pick_file(move |p| {
        let _ = tx.send(p);
    });
    let Some(p) = rx.await.ok().flatten().and_then(|p| p.into_path().ok()) else {
        return Ok(None);
    };
    let name = p.file_stem().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let text = tokio::fs::read_to_string(&p).await.map_err(|e| format!("Could not read {}: {e}", p.display()))?;
    Ok(Some((name, text)))
}

#[tauri::command]
pub async fn usque_import_wg0(app: AppHandle) -> Value {
    match open_conf(&app, "Import wg0.conf").await {
        Ok(Some((_, text))) => usque::import_wg0(&text),
        Ok(None) => json!({}),
        Err(e) => json!({ "error": e }),
    }
}

#[tauri::command]
pub async fn wg_list() -> Value {
    wg::list()
}
#[tauri::command]
pub async fn wg_get(id: String) -> Value {
    wg::get(&id)
}
#[tauri::command]
pub async fn wg_save(w: Value) -> Value {
    let id = w.get("id").and_then(Value::as_str);
    let name: String = w.get("name").and_then(Value::as_str).unwrap_or("").chars().take(80).collect();
    let text = w.get("text").and_then(Value::as_str).unwrap_or("");
    wg::save(id, &name, text)
}
#[tauri::command]
pub async fn wg_remove(id: String) -> Value {
    json!(wg::remove(&id))
}
#[tauri::command]
pub async fn wg_import_file(app: AppHandle) -> Value {
    match open_conf(&app, "Import a WireGuard config").await {
        Ok(Some((name, text))) => wg::save(None, &name, &text),
        Ok(None) => json!({}),
        Err(e) => json!({ "error": e }),
    }
}

// ---------- network, logs and the rest ----------

#[tauri::command]
pub async fn net_check_exit() -> Value {
    net::check_exit().await
}
#[tauri::command]
pub async fn net_ping(q: Option<Value>) -> Value {
    net::ping(&q.unwrap_or(json!({}))).await
}
#[tauri::command]
pub async fn log_engine(filter: Option<String>) -> Value {
    let f = filter.unwrap_or_default();
    json!(tokio::task::spawn_blocking(move || logs::engine_log_text(&f)).await.unwrap_or_default())
}
#[tauri::command]
pub async fn log_clear() -> Value {
    logs::clear();
    Value::Null
}

/// The window's errors, for app.log (Electron logged its console).
#[tauri::command]
pub async fn log_window(level: String, message: String) -> Value {
    let level: String = level.chars().take(16).collect();
    let message: String = message.chars().take(2000).collect();
    applog!("window {level}: {message}");
    Value::Null
}

#[tauri::command]
pub async fn clip_copy(app: AppHandle, text: String) -> R {
    use tauri_plugin_clipboard_manager::ClipboardExt;
    app.clipboard().write_text(text).map_err(|e| e.to_string())?;
    Ok(Value::Null)
}

#[tauri::command]
pub async fn app_set_autostart(on: bool) -> R {
    winutil::set_autostart(on).map_err(|e| e.to_string())?;
    Ok(Value::Null)
}

/// Only the project's GitHub pages (source, issues, the release download
/// page) and its Ko-fi page, behind the heart.
#[tauri::command]
pub async fn open_url(app: AppHandle, url: String) -> Value {
    if let Ok(u) = reqwest::Url::parse(&url) {
        let ok = u.scheme() == "https" && (u.host_str() == Some("github.com") || (u.host_str() == Some("ko-fi.com") && u.path() == "/creatoreprints"));
        if ok {
            let _ = app.opener().open_url(u.as_str(), None::<&str>);
        }
    }
    Value::Null
}

#[tauri::command]
pub async fn open_log(app: AppHandle) -> Value {
    let _ = app.opener().open_path(paths::log_file().to_string_lossy(), None::<&str>);
    Value::Null
}

#[tauri::command]
pub async fn open_pcap_folder(app: AppHandle) -> Value {
    let f = paths::pcap_file();
    if f.exists() {
        let _ = app.opener().reveal_item_in_dir(f);
    } else {
        let _ = app.opener().open_path(paths::data_dir().to_string_lossy(), None::<&str>);
    }
    Value::Null
}

#[tauri::command]
pub async fn debug_zip(app: AppHandle) -> Value {
    let stamp = chrono::Utc::now().format("%Y%m%d-%H%M").to_string();
    // the Desktop where Windows has it, OneDrive's included
    let desktop = app.path().desktop_dir().unwrap_or_default();
    let (tx, rx) = tokio::sync::oneshot::channel();
    file_dialog(&app)
        .set_title("Save debug logs")
        .set_directory(desktop)
        .set_file_name(format!("AuroraVPN-debug-{stamp}.zip"))
        .add_filter("Zip", &["zip"])
        .save_file(move |p| {
            let _ = tx.send(p);
        });
    let Some(dest) = rx.await.ok().flatten().and_then(|p| p.into_path().ok()) else {
        return json!({ "ok": false });
    };
    let version = app.package_info().version.to_string();
    match debugzip::write(&dest, &version).await {
        Ok(()) => {
            let _ = app.opener().reveal_item_in_dir(&dest);
            json!({ "ok": true, "file": dest.to_string_lossy() })
        }
        Err(e) => json!({ "ok": false, "error": e }),
    }
}
