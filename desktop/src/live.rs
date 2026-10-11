// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The status loop: asks the engine how it is every 300 ms (a loopback call
//! of about a millisecond), keeps the answer for the window, fetches its
//! events, sends notices, and tells the window ("tick") as soon as anything
//! changed. The Electron window asked every second, and its main process
//! every 1.5 s, so a change took up to 1.5 s to show.

use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use serde_json::Value;
use tauri::{AppHandle, Emitter};

use crate::{api, engine, history, rules, settings, tray};

const HOUR_MS: i64 = 3600 * 1000;

static LAST: Mutex<Option<Value>> = Mutex::new(None);

/// The engine's status from the last look, at most 300 ms old.
pub fn last() -> Option<Value> {
    LAST.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn set(st: Option<Value>) {
    *LAST.lock().unwrap_or_else(|e| e.into_inner()) = st;
}

/// Looks now, for a caller that just started or stopped the engine, and
/// tells the window.
pub async fn refresh(app: &AppHandle) -> Option<Value> {
    let st = api::status().await;
    set(st.clone());
    tray::update(app, st.as_ref(), false);
    let _ = app.emit_to("main", "tick", ());
    st
}

pub fn notify(app: &AppHandle, body: &str) {
    crate::applog!("notice: {body}");
    use tauri_plugin_notification::NotificationExt;
    let _ = app.notification().builder().title("AuroraVPN").body(body).show();
}

/// Runs the status loop, and runs it again should it ever fail: without it
/// the tray, the window and history would stop following the engine.
pub fn spawn(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            match tauri::async_runtime::spawn(run(app.clone())).await {
                Ok(()) => break,
                Err(e) => {
                    crate::applog!("status loop stopped ({e}); starting it again");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    });
}

async fn run(app: AppHandle) {
    {
        let mut was = false;
        let mut last_emit: Option<Instant> = None;
        let mut last_save = Instant::now();
        let mut auto_disabled_for = 0i64;
        loop {
            let st = api::status().await;
            let s = settings::read();
            let on = st.is_some();
            set(st.clone());
            tray::update(&app, st.as_ref(), false);
            if was && !on {
                if !engine::EXPECTED_STOP.load(Ordering::Relaxed) && settings::bool(&s, "notify") {
                    let extra = if settings::bool(&s, "killSwitch") { " The kill switch keeps the internet blocked until you start it again." } else { "" };
                    notify(&app, &format!("Protection stopped unexpectedly.{extra}"));
                } else if settings::bool(&s, "statusAlerts") {
                    notify(&app, "Protection is off.");
                }
            } else if !was && on && settings::bool(&s, "statusAlerts") {
                let exit = st.as_ref().and_then(|v| v.get("exit")).and_then(Value::as_str).unwrap_or("");
                notify(&app, &if exit.is_empty() { "Protected.".to_string() } else { format!("Protected via {exit}.") });
            }
            if !on {
                engine::EXPECTED_STOP.store(false, Ordering::Relaxed);
            }
            let mut fresh = 0;
            if let Some(st) = &st {
                let p = history::pump(st, &s).await;
                fresh = p.fresh;
                if p.learned.changed {
                    // beside the loop: a push may wait its turn behind one
                    // from the window, and sends the newest rules then
                    let push = p.learned.push;
                    tauri::async_runtime::spawn(async move {
                        if push {
                            rules::push_rules().await;
                        } else {
                            rules::save_rules().await;
                        }
                    });
                }
                if let Some(n) = p.learned.notice {
                    notify(&app, &n);
                }
                // WARP auto-disable after 11 hours
                let started = st.get("startedAt").and_then(Value::as_i64).unwrap_or(0);
                let exit = settings::str(&s, "exit");
                if settings::bool(&s, "warpAutoDisable")
                    && (exit == "masque" || exit == "warp")
                    && crate::applog::now_ms() - started > 11 * HOUR_MS
                    && auto_disabled_for != started
                {
                    auto_disabled_for = started;
                    // on its own: a start in progress holds the engine for
                    // up to a minute, and this loop must keep going
                    let app = app.clone();
                    tauri::async_runtime::spawn(async move {
                        engine::stop(true).await;
                        refresh(&app).await;
                        notify(&app, "WARP was turned off after running for 11 hours.");
                    });
                }
            }
            // the window hears of a start or stop at once, of new events
            // within 250 ms, and of counters (traffic, lookups) every second
            let since = last_emit.map_or(Duration::MAX, |t| t.elapsed());
            if was != on || (fresh > 0 && since >= Duration::from_millis(250)) || (on && since >= Duration::from_secs(1)) {
                let _ = app.emit_to("main", "tick", ());
                last_emit = Some(Instant::now());
            }
            was = on;
            if last_save.elapsed() >= Duration::from_secs(60) {
                history::save(&settings::read());
                last_save = Instant::now();
            }
            tokio::time::sleep(Duration::from_millis(if on { 300 } else { 700 })).await;
        }
    }
}
