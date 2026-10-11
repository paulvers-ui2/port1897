// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! AuroraVPN for Windows: the app around the fswin engine, in Rust on Tauri
//! (Windows' own WebView2 draws the screens of ui/renderer). It starts and
//! stops the engine, talks to its loopback API, and keeps the app's files:
//! settings, rules, WARP identities, WireGuard configs and history.

#![windows_subsystem = "windows"]
#![recursion_limit = "512"]

mod api;
mod applog;
mod blocklists;
mod commands;
mod debugzip;
mod engine;
mod history;
mod live;
mod logs;
mod net;
mod paths;
mod rules;
mod settings;
mod tray;
mod usque;
mod wg;
mod winutil;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use tauri::{AppHandle, Manager, RunEvent, WebviewUrl, WebviewWindowBuilder, WindowEvent};

/// Quit was chosen: the engine is stopping.
static QUITTING: AtomicBool = AtomicBool::new(false);
/// The engine is stopped: the app may end now, and only now.
static EXITING: AtomicBool = AtomicBool::new(false);

fn is_automation(a: &str) -> bool {
    matches!(a, "--start" | "--stop" | "--resume" | "--pause") || a.strip_prefix("--pause=").is_some_and(|m| !m.is_empty() && m.bytes().all(|b| b.is_ascii_digit()))
}

/// The main window: hidden on close (the app stays in the tray), never
/// navigating away from the app's own page.
fn create_window(app: &AppHandle, show: bool) -> tauri::Result<()> {
    let w = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
        .title("AuroraVPN")
        .inner_size(1100.0, 820.0)
        .min_inner_size(720.0, 600.0)
        .visible(show)
        .background_color(tauri::window::Color(0x0e, 0x1b, 0x21, 0xff))
        .on_navigation(|url| matches!(url.scheme(), "http" | "https") && url.host_str() == Some("tauri.localhost"))
        .disable_drag_drop_handler()
        .build()?;
    let ww = w.clone();
    w.on_window_event(move |e| {
        if let WindowEvent::CloseRequested { api, .. } = e
            && !EXITING.load(Ordering::Relaxed)
        {
            api.prevent_close();
            let _ = ww.hide();
        }
    });
    Ok(())
}

pub fn show_window(app: &AppHandle) {
    if !tray::has_window(app) {
        let _ = create_window(app, true);
    }
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

/// Quitting turns protection off, so no engine is left running unseen.
pub fn quit(app: AppHandle) {
    if QUITTING.swap(true, Ordering::Relaxed) {
        return;
    }
    // hidden at once; the app ends once the engine has stopped, which can
    // wait for a start in progress
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.hide();
    }
    tauri::async_runtime::spawn(async move {
        history::save(&settings::read());
        engine::stop(false).await;
        EXITING.store(true, Ordering::Relaxed);
        app.exit(0);
    });
}

/// AuroraVPN.exe --start | --stop | --pause[=minutes] | --resume, from
/// scripts or the Task Scheduler, when Settings → Automation is on.
async fn automate(app: &AppHandle, argv: &[String]) -> bool {
    let Some(cmd) = argv.iter().find(|a| is_automation(a)) else {
        return false;
    };
    if !settings::bool(&settings::read(), "automation") {
        live::notify(app, &format!("Ignored {cmd}: turn on Settings → Automation to let other programs control AuroraVPN."));
        return true;
    }
    let r = match cmd.as_str() {
        "--start" => engine::start().await,
        "--stop" => engine::stop(true).await,
        _ => {
            let m = if cmd == "--resume" { 0.0 } else { cmd.split_once('=').and_then(|(_, m)| m.parse().ok()).unwrap_or(15.0) };
            tray::pause(app, m).await;
            json!({ "ok": true })
        }
    };
    live::refresh(app).await;
    if r.get("ok").and_then(Value::as_bool) != Some(true) {
        live::notify(app, &format!("{cmd} failed: {}", r.get("error").and_then(Value::as_str).unwrap_or("")));
    }
    true
}

/// The app was called port1897 before 0.3. Its folder moves to the new
/// name once, before anything uses it; what cannot move is copied.
fn move_old_data() {
    let now = paths::data_dir();
    let old = paths::app_data().join("port1897");
    if now.join("settings.json").exists() || !old.join("settings.json").exists() {
        return;
    }
    let _ = std::fs::create_dir_all(&now);
    let Ok(rd) = std::fs::read_dir(&old) else { return };
    for e in rd.flatten() {
        let to = now.join(e.file_name());
        if std::fs::rename(e.path(), &to).is_err() {
            let _ = copy_tree(&e.path(), &to);
        }
    }
    applog!("moved the settings of port1897 from {}", old.display());
}

fn copy_tree(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
    if from.is_dir() {
        std::fs::create_dir_all(to)?;
        for e in std::fs::read_dir(from)?.flatten() {
            copy_tree(&e.path(), &to.join(e.file_name()))?;
        }
        Ok(())
    } else if to.exists() {
        Ok(())
    } else {
        std::fs::copy(from, to).map(|_| ())
    }
}

/// --self-test, for CI: open the window hidden, wait until the page asked
/// for its settings (its scripts ran and IPC works), and quit with 0, or 1
/// when it did not. It proves a packaged build starts.
fn self_test(app: &AppHandle) {
    if let Err(e) = create_window(app, false) {
        applog!("self-test failed: {e}");
        std::process::exit(1);
    }
    tauri::async_runtime::spawn(async {
        for _ in 0..600 {
            if commands::PAGE_UP.load(Ordering::Relaxed) {
                applog!("self-test ok");
                std::process::exit(0);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        applog!("self-test failed: the page did not come up");
        std::process::exit(1);
    });
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Err(e) = std::panic::catch_unwind(move_old_data) {
        applog!("could not move the settings of port1897: {e:?}");
    }
    std::panic::set_hook(Box::new(|info| applog!("panic: {info}")));

    let app = tauri::Builder::default()
        // first: a second launch brings this one forward, or runs --start...
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                if !automate(&app, &argv).await {
                    show_window(&app);
                }
            });
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            commands::settings_get,
            commands::settings_set,
            commands::rules_set,
            commands::engine_pause,
            commands::engine_block,
            commands::engine_start,
            commands::engine_stop,
            commands::engine_cleanup,
            commands::engine_status,
            commands::engine_kill_switch,
            commands::engine_events,
            commands::engine_stats,
            commands::engine_app_stats,
            commands::engine_app_paths,
            commands::engine_proxies,
            commands::conns_list,
            commands::conns_close,
            commands::conns_close_one,
            commands::bl_status,
            commands::bl_filetag,
            commands::bl_download,
            commands::bl_latest,
            commands::bl_delete,
            commands::usque_status,
            commands::usque_register,
            commands::usque_read_config,
            commands::usque_save_config,
            commands::usque_save_wg0,
            commands::usque_import_wg0,
            commands::wg_list,
            commands::wg_get,
            commands::wg_save,
            commands::wg_remove,
            commands::wg_import_file,
            commands::net_check_exit,
            commands::net_ping,
            commands::log_engine,
            commands::log_clear,
            commands::log_window,
            commands::clip_copy,
            commands::app_set_autostart,
            commands::open_url,
            commands::open_log,
            commands::open_pcap_folder,
            commands::debug_zip,
        ])
        .setup(move |app| {
            paths::init(app.path().resource_dir().ok());
            let handle = app.handle().clone();
            applog!(
                "AuroraVPN {} started (Tauri {}, WebView2 {}), engine in {}",
                app.package_info().version,
                tauri::VERSION,
                tauri::webview_version().unwrap_or_else(|_| "?".into()),
                paths::engine_dir().display()
            );
            if args.iter().any(|a| a == "--self-test") {
                self_test(&handle);
                return Ok(());
            }
            history::load();
            let s = settings::read();
            // the start-at-login entry names this program's path
            if settings::bool(&s, "autostart")
                && let Err(e) = winutil::set_autostart(true)
            {
                applog!("start at login: {e}");
            }
            let automated = args.iter().any(|a| is_automation(a));
            let autostart = automated || args.iter().any(|a| a == "--autostart");
            create_window(&handle, !autostart)?;
            tray::create(&handle)?;
            // "Block all apps when the PC is locked"
            winutil::watch_lock(|locked| {
                rules::SCREEN_LOCKED.store(locked, Ordering::Relaxed);
                let s = settings::read();
                if settings::sub_bool(&s, "universal", "locked") {
                    tauri::async_runtime::spawn(async move {
                        rules::push_rules(&s).await;
                    });
                }
            });
            live::spawn(handle.clone());
            if automated {
                let args = args.clone();
                tauri::async_runtime::spawn(async move {
                    automate(&handle, &args).await;
                });
            } else if autostart && settings::bool(&s, "wasRunning") {
                tauri::async_runtime::spawn(async move {
                    let r = engine::start().await;
                    live::refresh(&handle).await;
                    if r.get("ok").and_then(Value::as_bool) != Some(true) {
                        live::notify(&handle, &format!("Could not resume protection: {}", r.get("error").and_then(Value::as_str).unwrap_or("")));
                    }
                });
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("AuroraVPN could not start");

    app.run(|app, event| {
        // the app lives in the tray; it ends only through Quit
        if let RunEvent::ExitRequested { api, code, .. } = event
            && code.is_none()
            && !EXITING.load(Ordering::Relaxed)
        {
            api.prevent_exit();
            let _ = app;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automation_flags() {
        assert!(is_automation("--start"));
        assert!(is_automation("--pause=30"));
        assert!(!is_automation("--pause=x"));
        assert!(!is_automation("--autostart"));
    }
}
