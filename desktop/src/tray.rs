// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The tray icon: on or off, and a menu to start, stop, pause, open or quit.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::Value;
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager};

use crate::{applog, engine, live, rules, settings};

static BUSY: AtomicBool = AtomicBool::new(false);
/// What the tray shows: running, exit, paused, busy. Rebuilt only on change.
static SHOWN: Mutex<Option<(bool, String, bool, bool)>> = Mutex::new(None);

fn icon(on: bool) -> Image<'static> {
    let bytes: &'static [u8] = if on { include_bytes!("../../ui/assets/tray-on.png") } else { include_bytes!("../../ui/assets/tray-off.png") };
    Image::from_bytes(bytes).expect("tray icon")
}

pub fn create(app: &AppHandle) -> tauri::Result<()> {
    TrayIconBuilder::with_id("main")
        .icon(icon(false))
        .tooltip("AuroraVPN: not protected")
        .show_menu_on_left_click(false)
        .on_menu_event(|app, ev| on_menu(app, ev.id().as_ref()))
        .on_tray_icon_event(|tray, ev| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = ev {
                crate::show_window(tray.app_handle());
            }
        })
        .build(app)?;
    update(app, None, true);
    Ok(())
}

fn tray(app: &AppHandle) -> Option<TrayIcon> {
    app.tray_by_id("main")
}

/// Shows st (the engine's status, None when off); rebuilds the menu only
/// when what it shows changed, or when force.
pub fn update(app: &AppHandle, st: Option<&Value>, force: bool) {
    let on = st.is_some();
    let exit = st.and_then(|v| v.get("exit")).and_then(Value::as_str).unwrap_or("").to_string();
    let paused = settings::num(&settings::read(), "pausedUntil") > applog::now_ms() as f64;
    let busy = BUSY.load(Ordering::Relaxed);
    let now = (on, exit.clone(), paused, busy);
    {
        let mut shown = SHOWN.lock().unwrap_or_else(|e| e.into_inner());
        if !force && shown.as_ref() == Some(&now) {
            return;
        }
        *shown = Some(now);
    }
    let Some(t) = tray(app) else { return };
    let _ = t.set_icon(Some(icon(on)));
    let via = if exit.is_empty() { String::new() } else { format!(" via {exit}") };
    let _ = t.set_tooltip(Some(if on { format!("AuroraVPN: protected{via}") } else { "AuroraVPN: not protected".into() }));
    let menu = (|| -> tauri::Result<Menu<tauri::Wry>> {
        let state = if on { format!("Protected{}", if exit.is_empty() { String::new() } else { format!(" ({exit})") }) } else { "Not protected".into() };
        let m = Menu::new(app)?;
        m.append(&MenuItem::with_id(app, "state", state, false, None::<&str>)?)?;
        m.append(&PredefinedMenuItem::separator(app)?)?;
        m.append(&MenuItem::with_id(app, "toggle", if on { "Stop protection" } else { "Start protection" }, !busy, None::<&str>)?)?;
        if on && !paused {
            m.append(&MenuItem::with_id(app, "pause15", "Pause for 15 minutes", true, None::<&str>)?)?;
        }
        if on && paused {
            m.append(&MenuItem::with_id(app, "resume", "Resume (paused)", true, None::<&str>)?)?;
        }
        m.append(&MenuItem::with_id(app, "open", "Open AuroraVPN", true, None::<&str>)?)?;
        m.append(&PredefinedMenuItem::separator(app)?)?;
        m.append(&MenuItem::with_id(app, "quit", "Quit (turns protection off)", true, None::<&str>)?)?;
        Ok(m)
    })();
    if let Ok(m) = menu {
        let _ = t.set_menu(Some(m));
    }
}

/// Pauses the firewall for m minutes (0: resumes).
pub async fn pause(app: &AppHandle, minutes: f64) -> settings::S {
    let s = settings::update(|s| {
        let until = if minutes > 0.0 { applog::now_ms() as f64 + minutes * 60_000.0 } else { 0.0 };
        s.insert("pausedUntil".into(), settings::number(until));
    });
    rules::push_rules().await;
    update(app, live::last().as_ref(), true);
    s
}

fn on_menu(app: &AppHandle, id: &str) {
    let app = app.clone();
    match id {
        "toggle" => {
            tauri::async_runtime::spawn(async move {
                BUSY.store(true, Ordering::Relaxed);
                update(&app, live::last().as_ref(), true);
                let r = if live::last().is_some() { engine::stop(true).await } else { engine::start().await };
                BUSY.store(false, Ordering::Relaxed);
                live::refresh(&app).await;
                if r.get("ok").and_then(Value::as_bool) != Some(true) {
                    crate::show_window(&app);
                    let mut msg = r.get("error").and_then(Value::as_str).unwrap_or("").to_string();
                    if let Some(l) = r.get("log").and_then(Value::as_str) {
                        msg = format!("{msg}\n\n{l}");
                    }
                    use tauri_plugin_dialog::{DialogExt, MessageDialogKind};
                    app.dialog().message(msg).title("AuroraVPN").kind(MessageDialogKind::Error).show(|_| {});
                }
            });
        }
        "pause15" => {
            tauri::async_runtime::spawn(async move {
                pause(&app, 15.0).await;
            });
        }
        "resume" => {
            tauri::async_runtime::spawn(async move {
                pause(&app, 0.0).await;
            });
        }
        "open" => crate::show_window(&app),
        "quit" => crate::quit(app),
        _ => {}
    }
}

/// The main window, for show_window.
pub fn has_window(app: &AppHandle) -> bool {
    app.get_webview_window("main").is_some()
}
