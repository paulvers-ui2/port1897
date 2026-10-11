// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Firewall rules: the rule set fswin applies (cmd/fswin/rules_windows.go),
//! per-app routes, apps seen for the first time, and where apps run from.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Map, Value, json};

use crate::settings::{self, S};
use crate::{api, applog, paths, wg};

/// "Block all apps when the PC is locked": whether it is locked now.
pub static SCREEN_LOCKED: AtomicBool = AtomicBool::new(false);

/// The settings that are rules: they apply at once, without a restart.
pub const RULE_KEYS: [&str; 6] = ["rules", "universal", "dnsTypesAuto", "dnsTypes", "knownApps", "pausedUntil"];

/// The reason fswin gives for flows "Allow outgoing only" let through.
const OUTGOING_ALLOWED: &str = "universal: outgoing allowed";

/// Per-app routes: "wg:<id>" (a saved WireGuard config), "socks" or "http"
/// (the proxies set up in Proxy), as fswin's route ids (routes_windows.go).
pub fn route_id(r: &str) -> String {
    if let Some(id) = r.strip_prefix("wg:")
        && id.len() == 16
        && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return format!("wgapp{id}");
    }
    match r {
        "socks" => "pxsocks".into(),
        "http" => "pxhttp".into(),
        _ => String::new(),
    }
}

pub fn proxy_url(kind: &str, p: &Map<String, Value>) -> String {
    let enc = |t: &str| -> String {
        t.bytes()
            .map(|b| if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
            .collect()
    };
    let user = p.get("user").and_then(Value::as_str).unwrap_or("");
    let pass = p.get("pass").and_then(Value::as_str).unwrap_or("");
    let auth = if user.is_empty() { String::new() } else { format!("{}:{}@", enc(user), enc(pass)) };
    let host = p.get("host").and_then(Value::as_str).unwrap_or("");
    let port = match p.get("port") {
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(t)) => t.clone(),
        _ => String::new(),
    };
    format!("{}://{auth}{host}:{port}", if kind == "http" { "http" } else { "socks5" })
}

fn apps_of(s: &S) -> Map<String, Value> {
    settings::obj(s, "rules").and_then(|r| r.get("apps")).and_then(Value::as_object).cloned().unwrap_or_default()
}

pub fn routes_of(s: &S) -> Vec<Value> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let names: HashMap<String, String> = wg::index()
        .into_iter()
        .filter_map(|e| Some((e.get("id")?.as_str()?.to_string(), e.get("name")?.as_str()?.to_string())))
        .collect();
    for a in apps_of(s).values() {
        let route = a.get("route").and_then(Value::as_str).unwrap_or("");
        let id = route_id(route);
        if id.is_empty() || !seen.insert(id.clone()) {
            continue;
        }
        if let Some(wid) = route.strip_prefix("wg:") {
            if let Some(f) = wg::file(wid) {
                let name = names.get(wid).cloned().unwrap_or_else(|| "config".into());
                out.push(json!({ "id": id, "name": format!("WireGuard: {name}"), "kind": "wg", "file": f.to_string_lossy() }));
            }
        } else if let Some(p) = settings::obj(s, route)
            && !p.get("host").and_then(Value::as_str).unwrap_or("").is_empty()
        {
            let name = if route == "socks" { "SOCKS5 proxy" } else { "HTTP proxy" };
            out.push(json!({ "id": id, "name": name, "kind": "proxy", "url": proxy_url(route, p) }));
        }
    }
    out
}

/// The rule set fswin applies.
pub fn rule_set(s: &S) -> Value {
    let mut apps = Map::new();
    for (k, a) in apps_of(s) {
        if !settings::safe_key(&k) {
            continue;
        }
        let route = a.get("route").and_then(Value::as_str).unwrap_or("").to_string();
        if route.is_empty() {
            apps.insert(k, a);
        } else {
            let mut a = a.as_object().cloned().unwrap_or_default();
            a.insert("route".into(), json!(route_id(&route)));
            apps.insert(k, Value::Object(a));
        }
    }
    let rules = settings::obj(s, "rules");
    let paused = settings::num(s, "pausedUntil");
    json!({
        "apps": apps,
        "ips": rules.and_then(|r| r.get("ips")).cloned().unwrap_or(json!([])),
        "domains": rules.and_then(|r| r.get("domains")).cloned().unwrap_or(json!([])),
        "universal": s.get("universal").cloned().unwrap_or(json!({})),
        "known": s.get("knownApps").cloned().unwrap_or(json!([])),
        "dnsTypes": if settings::bool(s, "dnsTypesAuto") { json!([]) } else { s.get("dnsTypes").cloned().unwrap_or(json!([])) },
        "pausedUntil": if paused > applog::now_ms() as f64 { settings::number(paused) } else { json!(0) },
        "screenLocked": SCREEN_LOCKED.load(Ordering::Relaxed),
    })
}

fn write_rule_set(rs: &Value) {
    let text = serde_json::to_string(rs).unwrap_or_default();
    if let Err(e) = paths::write_atomic(&paths::rules_file(), text.as_bytes()) {
        applog!("rules: could not write: {e}");
    }
}

// One rules.json write or push at a time, each with the settings as they
// are when its turn comes, not as they were when it was asked for: a push
// that waited behind another (the status loop's newly seen apps, a change
// from the window) never sends older rules than the one before it, so the
// last change is what the engine and rules.json end up with.
static PUSH: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// rules.json for the next start, from the settings as they are now.
pub async fn save_rules() {
    let _g = PUSH.lock().await;
    write_rule_set(&rule_set(&settings::read()));
}

/// Rules apply at once: the file for the next start, the API for now. Call
/// it after the settings changed; it sends them as they are then.
pub async fn push_rules() -> Value {
    let _g = PUSH.lock().await;
    let rs = rule_set(&settings::read());
    write_rule_set(&rs);
    match api::post("/api/rules", Some(&rs)).await {
        Ok(r) => json!({ "ok": true, "warnings": r.get("warnings").cloned().unwrap_or(json!("")) }),
        Err(_) => json!({ "ok": true, "warnings": "" }), // not running; applies on next start
    }
}

// ---------- where apps run from ----------

// chrome.exe: C:\Program Files\Google\Chrome\Application\chrome.exe, learned
// from the engine's events for the Apps screen; the latest path wins. Kept
// apart from the settings: it is no rule.
static APP_PATHS: Mutex<Option<Map<String, Value>>> = Mutex::new(None);

pub fn app_paths() -> Map<String, Value> {
    let mut g = APP_PATHS.lock().unwrap_or_else(|e| e.into_inner());
    g.get_or_insert_with(|| {
        let mut m = Map::new();
        if let Ok(Value::Object(o)) = std::fs::read_to_string(paths::app_paths_file())
            .map_err(|e| e.to_string())
            .and_then(|t| serde_json::from_str::<Value>(&t).map_err(|e| e.to_string()))
        {
            for (k, v) in o {
                if settings::safe_key(&k) && v.is_string() {
                    m.insert(k, v);
                }
            }
        }
        m
    })
    .clone()
}

pub fn learn_paths(evs: &[Value]) {
    let mut m = app_paths();
    let mut changed = false;
    for e in evs {
        let (Some(p), Some(a)) = (e.get("path").and_then(Value::as_str), e.get("app").and_then(Value::as_str)) else {
            continue;
        };
        let k = a.to_lowercase();
        if !p.is_empty() && settings::safe_key(&k) && m.get(&k).and_then(Value::as_str) != Some(p) {
            m.insert(k, json!(p));
            changed = true;
        }
    }
    if changed {
        let _ = paths::write_atomic(&paths::app_paths_file(), serde_json::to_string(&m).unwrap_or_default().as_bytes());
        *APP_PATHS.lock().unwrap_or_else(|e| e.into_inner()) = Some(m);
    }
}

// ---------- apps seen for the first time ----------

/// What learn_apps decided: whether the rules changed (then save_rules), or
/// changed so the engine needs them now (push_rules), and a notice.
#[derive(Default)]
pub struct Learned {
    pub changed: bool,
    pub push: bool,
    pub notice: Option<String>,
}

/// Apps seen for the first time: remembered, and blocked when "Block newly
/// installed apps" is on (fswin already blocked them; this makes it a rule
/// the user can see and undo).
pub fn learn_apps(evs: &[Value]) -> Learned {
    let none = Learned::default();
    // (name, the rule fswin gave) of each flow from a named app
    let flows: Vec<(String, String)> = evs
        .iter()
        .filter(|e| e.get("kind").and_then(Value::as_str) == Some("flow"))
        .filter_map(|e| {
            let app = e.get("app").and_then(Value::as_str).unwrap_or("");
            let name = app.to_lowercase();
            (!app.is_empty() && app != "?" && !is_pid_name(app) && settings::safe_key(&name)).then(|| (name, e.get("rule").and_then(Value::as_str).unwrap_or("").to_string()))
        })
        .collect();
    if flows.is_empty() {
        return none;
    }
    let mut blocked: Vec<String> = Vec::new();
    let mut allowed: BTreeSet<String> = BTreeSet::new();
    // one change of the settings, so nothing else's change is lost meanwhile
    let (s, changed) = settings::update_if(|s| {
        let mut known: BTreeSet<String> = settings::arr(s, "knownApps").iter().filter_map(|v| v.as_str().map(String::from)).collect();
        let mut apps = apps_of(s);
        let mut fresh: Vec<(String, bool)> = Vec::new();
        for (name, rule) in &flows {
            if rule == OUTGOING_ALLOWED && !apps.contains_key(name) {
                allowed.insert(name.clone());
            }
            if known.insert(name.clone()) {
                fresh.push((name.clone(), rule == "universal: new app"));
            }
        }
        if fresh.is_empty() && allowed.is_empty() {
            return false;
        }
        s.insert("knownApps".into(), json!(known.iter().collect::<Vec<_>>()));
        blocked = fresh.iter().filter(|(n, b)| *b && !apps.contains_key(n)).map(|(n, _)| n.clone()).collect();
        for n in &blocked {
            apps.insert(n.clone(), json!({ "mode": "block" }));
        }
        // whitelisted: the app keeps working whatever the universal rules say
        for n in &allowed {
            apps.insert(n.clone(), json!({ "mode": "bypassUniversal" }));
        }
        if let Some(Value::Object(r)) = s.get_mut("rules") {
            r.insert("apps".into(), Value::Object(apps));
        }
        true
    });
    if !changed {
        return none;
    }
    if !allowed.is_empty() {
        applog!("allowed (outgoing only): {}", allowed.iter().cloned().collect::<Vec<_>>().join(", "));
    }
    let notice = (!blocked.is_empty() && settings::bool(&s, "notify")).then(|| format!("New app blocked: {}. Allow it in Apps.", blocked.join(", ")));
    // apps only now known need no push: the engine has seen them
    Learned { changed: true, push: !blocked.is_empty() || !allowed.is_empty(), notice }
}

fn is_pid_name(a: &str) -> bool {
    a.strip_prefix("pid").is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_ids_match_fswin() {
        assert_eq!(route_id("wg:0123456789abcdef"), "wgapp0123456789abcdef");
        assert_eq!(route_id("wg:0123"), "");
        assert_eq!(route_id("socks"), "pxsocks");
        assert_eq!(route_id("http"), "pxhttp");
        assert_eq!(route_id("other"), "");
    }

    #[test]
    fn proxy_urls_escape_the_password() {
        let p = json!({ "host": "h", "port": 1080, "user": "u", "pass": "p@ss:w" });
        assert_eq!(proxy_url("socks", p.as_object().unwrap()), "socks5://u:p%40ss%3Aw@h:1080");
    }
}
