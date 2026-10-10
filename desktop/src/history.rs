// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! History for the Stats and Logs screens: the engine's events (the last
//! 3000 in memory, a week in history\events-<day>.jsonl) and hourly totals
//! (history\buckets.json), in the Electron app's formats.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use serde_json::{Map, Value, json};

use crate::settings::{self, S};
use crate::{api, applog, paths, rules};

const HOUR: i64 = 3600 * 1000;

#[derive(Default, Clone)]
struct AppB {
    n: u64,
    blocked: u64,
    rx: u64,
    tx: u64,
}

#[derive(Default, Clone)]
struct DomB {
    n: u64,
    blocked: u64,
}

#[derive(Default, Clone)]
struct Bucket {
    rx: u64,
    tx: u64,
    flows: u64,
    apps: HashMap<String, AppB>,
    domains: HashMap<String, DomB>,
}

#[derive(Default)]
struct Hist {
    buf: VecDeque<Value>,
    seq: u64,
    engine_last: u64,
    engine_started: i64,
    buckets: BTreeMap<i64, Bucket>,
    dirty: bool,
}

static H: Mutex<Option<Hist>> = Mutex::new(None);

fn with<R>(f: impl FnOnce(&mut Hist) -> R) -> R {
    let mut g = H.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(Hist::default))
}

fn u(v: Option<&Value>) -> u64 {
    v.and_then(Value::as_f64).map(|x| x.max(0.0) as u64).unwrap_or(0)
}

/// Reads the hourly totals the last run saved.
pub fn load() {
    let Ok(text) = std::fs::read_to_string(paths::hist_dir().join("buckets.json")) else {
        return;
    };
    let Ok(Value::Object(raw)) = serde_json::from_str::<Value>(&text) else {
        return;
    };
    with(|h| {
        for (k, v) in raw {
            let Ok(at) = k.parse::<i64>() else { continue };
            let mut b = Bucket { rx: u(v.get("rx")), tx: u(v.get("tx")), flows: u(v.get("flows")), ..Default::default() };
            if let Some(Value::Object(apps)) = v.get("apps") {
                for (name, a) in apps {
                    b.apps.insert(name.clone(), AppB { n: u(a.get("n")), blocked: u(a.get("blocked")), rx: u(a.get("rx")), tx: u(a.get("tx")) });
                }
            }
            if let Some(Value::Object(ds)) = v.get("domains") {
                for (name, d) in ds {
                    b.domains.insert(name.clone(), DomB { n: u(d.get("n")), blocked: u(d.get("blocked")) });
                }
            }
            h.buckets.insert(at, b);
        }
    });
}

fn add_event(h: &mut Hist, e: &Value) {
    let at = e.get("at").and_then(Value::as_i64).unwrap_or_else(applog::now_ms);
    let b = h.buckets.entry(at.div_euclid(HOUR) * HOUR).or_default();
    let app = b.apps.entry(e.get("app").and_then(Value::as_str).filter(|a| !a.is_empty()).unwrap_or("?").to_string()).or_default();
    let blocked = e.get("blocked").and_then(Value::as_bool) == Some(true);
    let domain = e.get("domain").and_then(Value::as_str).unwrap_or("");
    match e.get("kind").and_then(Value::as_str) {
        Some("flow") => {
            b.flows += 1;
            if blocked {
                app.blocked += 1;
            } else {
                app.n += 1;
            }
            if blocked && !domain.is_empty() {
                b.domains.entry(domain.to_string()).or_default().blocked += 1;
            }
        }
        Some("dns") if !domain.is_empty() => {
            let d = b.domains.entry(domain.to_string()).or_default();
            d.n += 1;
            if blocked {
                d.blocked += 1;
            }
        }
        Some("close") => {
            let (rx, tx) = (u(e.get("rx")), u(e.get("tx")));
            app.rx += rx;
            app.tx += tx;
            b.rx += rx;
            b.tx += tx;
        }
        _ => {}
    }
    h.dirty = true;
}

/// What pump found: new events, settings to push, a notice.
pub struct Pumped {
    pub fresh: usize,
    pub learned: rules::Learned,
}

/// Fetches the engine's new events into memory, the totals and the files.
pub async fn pump(st: &Value, s: &S) -> Pumped {
    let started = st.get("startedAt").and_then(Value::as_i64).unwrap_or(0);
    let after = with(|h| {
        if started != h.engine_started {
            h.engine_started = started;
            h.engine_last = 0;
        }
        h.engine_last
    });
    let evs = match api::get(&format!("/api/events?after={after}&max=1000")).await {
        Ok(Value::Array(a)) => a,
        _ => return Pumped { fresh: 0, learned: rules::Learned { push: None, notice: None } },
    };
    let learned = rules::learn_apps(&evs);
    rules::learn_paths(&evs);
    let keep = settings::bool(s, "history");
    let mut lines = String::new();
    with(|h| {
        for e in &evs {
            if let Some(id) = e.get("id").and_then(Value::as_u64) {
                h.engine_last = id;
            }
            h.seq += 1;
            let mut m = e.clone();
            if let Value::Object(o) = &mut m {
                o.insert("id".into(), json!(h.seq));
            }
            add_event(h, &m);
            if keep && m.get("kind").and_then(Value::as_str) != Some("close") {
                lines.push_str(&m.to_string());
                lines.push('\n');
            }
            h.buf.push_back(m);
        }
        while h.buf.len() > 3000 {
            h.buf.pop_front();
        }
    });
    if !lines.is_empty() {
        let day = &applog::now_iso()[..10];
        let _ = std::fs::create_dir_all(paths::hist_dir());
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(paths::hist_dir().join(format!("events-{day}.jsonl"))) {
            let _ = f.write_all(lines.as_bytes());
        }
    }
    Pumped { fresh: evs.len(), learned }
}

/// The events after id, at most the last 300, for the Logs screen.
pub fn events_after(after: u64) -> Value {
    with(|h| {
        let fresh: Vec<&Value> = h.buf.iter().filter(|e| e.get("id").and_then(Value::as_u64).unwrap_or(0) > after).collect();
        Value::Array(fresh[fresh.len().saturating_sub(300)..].iter().map(|e| (*e).clone()).collect())
    })
}

/// Totals for the last hour, day or week (Stats screen, Apps).
pub fn stats(range: &str, history_on: bool) -> Value {
    let hours = match range {
        "7d" => 168,
        "24h" => 24,
        _ => 1,
    };
    let cutoff = applog::now_ms() - hours * HOUR;
    let (rx, tx, flows, apps, domains) = with(|h| {
        let (mut rx, mut tx, mut flows) = (0u64, 0u64, 0u64);
        let mut apps: HashMap<String, AppB> = HashMap::new();
        let mut domains: HashMap<String, DomB> = HashMap::new();
        for (k, b) in h.buckets.range(cutoff - HOUR + 1..) {
            if k + HOUR <= cutoff {
                continue;
            }
            rx += b.rx;
            tx += b.tx;
            flows += b.flows;
            for (name, a) in &b.apps {
                let t = apps.entry(name.clone()).or_default();
                t.n += a.n;
                t.blocked += a.blocked;
                t.rx += a.rx;
                t.tx += a.tx;
            }
            for (name, d) in &b.domains {
                let t = domains.entry(name.clone()).or_default();
                t.n += d.n;
                t.blocked += d.blocked;
            }
        }
        (rx, tx, flows, apps, domains)
    });
    let app_list = |keep: &dyn Fn(&AppB) -> bool, key: &dyn Fn(&AppB) -> u64| -> Value {
        let mut v: Vec<(&String, &AppB)> = apps.iter().filter(|(n, a)| n.as_str() != "?" && keep(a)).collect();
        v.sort_by_key(|x| std::cmp::Reverse(key(x.1)));
        Value::Array(v.into_iter().take(50).map(|(n, a)| json!({ "name": n, "n": a.n, "blocked": a.blocked, "rx": a.rx, "tx": a.tx })).collect())
    };
    let dom_list = |keep: &dyn Fn(&DomB) -> bool, key: &dyn Fn(&DomB) -> u64| -> Value {
        let mut v: Vec<(&String, &DomB)> = domains.iter().filter(|(n, d)| n.as_str() != "?" && keep(d)).collect();
        v.sort_by_key(|x| std::cmp::Reverse(key(x.1)));
        Value::Array(v.into_iter().take(50).map(|(n, d)| json!({ "name": n, "n": d.n, "blocked": d.blocked })).collect())
    };
    json!({
        "history": history_on,
        "rx": rx,
        "tx": tx,
        "flows": flows,
        "allowedApps": app_list(&|a| a.n > 0, &|a| a.rx + a.tx + a.n),
        "blockedApps": app_list(&|a| a.blocked > 0, &|a| a.blocked),
        "domains": dom_list(&|d| d.n > 0, &|d| d.n),
        "blockedDomains": dom_list(&|d| d.blocked > 0, &|d| d.blocked),
    })
}

fn day_file(days_back: i64) -> PathBuf {
    let t = chrono::Utc::now() - chrono::Duration::days(days_back);
    paths::hist_dir().join(format!("events-{}.jsonl", t.format("%Y-%m-%d")))
}

/// One app's flows in the event files of yesterday and today.
fn scan(want: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for f in [day_file(1), day_file(0)] {
        let Ok(meta) = std::fs::metadata(&f) else { continue };
        if meta.len() > 64 << 20 {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&f) else { continue };
        for line in text.lines() {
            if line.is_empty() || !line.to_lowercase().contains(want) {
                continue;
            }
            if let Ok(e) = serde_json::from_str::<Value>(line)
                && e.get("kind").and_then(Value::as_str) == Some("flow")
                && e.get("app").and_then(Value::as_str).unwrap_or("").to_lowercase() == want
            {
                out.push(e);
            }
        }
    }
    out
}

/// Most contacted domains and IPs of one app, from recent events (memory
/// and two days of event files, read on a thread of its own), for App info.
pub async fn app_stats(app: &str) -> Value {
    let want = app.to_lowercase();
    let w = want.clone();
    let mut evs = tokio::task::spawn_blocking(move || scan(&w)).await.unwrap_or_default();
    evs.extend(with(|h| h.buf.iter().cloned().collect::<Vec<_>>()));
    let mut domains: HashMap<String, DomB> = HashMap::new();
    let mut ips: HashMap<String, DomB> = HashMap::new();
    let mut seen = HashSet::new();
    for e in evs {
        if e.get("kind").and_then(Value::as_str) != Some("flow") || e.get("app").and_then(Value::as_str).unwrap_or("").to_lowercase() != want {
            continue;
        }
        let dst = e.get("dst").and_then(Value::as_str).unwrap_or("");
        let key = format!("{}|{}|{}", e.get("at").map(Value::to_string).unwrap_or_default(), dst, e.get("cid").and_then(Value::as_str).unwrap_or(""));
        if !seen.insert(key) {
            continue;
        }
        let ip = strip_port(dst);
        let blocked = e.get("blocked").and_then(Value::as_bool) == Some(true);
        for (m, name) in [(&mut domains, e.get("domain").and_then(Value::as_str).unwrap_or("").to_string()), (&mut ips, ip)] {
            if name.is_empty() {
                continue;
            }
            let t = m.entry(name).or_default();
            t.n += 1;
            if blocked {
                t.blocked += 1;
            }
        }
    }
    let top = |m: HashMap<String, DomB>| -> Value {
        let mut v: Vec<(String, DomB)> = m.into_iter().collect();
        v.sort_by_key(|x| std::cmp::Reverse(x.1.n + x.1.blocked));
        Value::Array(v.into_iter().take(30).map(|(n, d)| json!({ "name": n, "n": d.n, "blocked": d.blocked })).collect())
    };
    json!({ "domains": top(domains), "ips": top(ips) })
}

/// 1.2.3.4:443 -> 1.2.3.4; [::1]:443 -> ::1.
fn strip_port(dst: &str) -> String {
    let d = dst.trim();
    if let Some(rest) = d.strip_prefix('[')
        && let Some((addr, _)) = rest.split_once(']')
    {
        return addr.to_string();
    }
    match d.rsplit_once(':') {
        Some((a, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) && !a.contains(':') => a.to_string(),
        _ => d.to_string(),
    }
}

/// Drops totals older than a week, saves the rest when history is on, and
/// keeps a week of event files.
pub fn save(s: &S) {
    let cutoff = applog::now_ms() - 168 * HOUR;
    let out = with(|h| {
        h.buckets.retain(|k, _| *k >= cutoff);
        if !settings::bool(s, "history") || !h.dirty {
            return None;
        }
        h.dirty = false;
        let mut out = Map::new();
        for (k, b) in &h.buckets {
            let mut apps: Vec<(&String, &AppB)> = b.apps.iter().collect();
            apps.sort_by_key(|x| std::cmp::Reverse(x.1.n + x.1.blocked + x.1.rx));
            let mut doms: Vec<(&String, &DomB)> = b.domains.iter().collect();
            doms.sort_by_key(|x| std::cmp::Reverse(x.1.n + x.1.blocked));
            let apps: Map<String, Value> = apps.into_iter().take(300).map(|(n, a)| (n.clone(), json!({ "n": a.n, "blocked": a.blocked, "rx": a.rx, "tx": a.tx }))).collect();
            let doms: Map<String, Value> = doms.into_iter().take(1000).map(|(n, d)| (n.clone(), json!({ "n": d.n, "blocked": d.blocked }))).collect();
            out.insert(k.to_string(), json!({ "rx": b.rx, "tx": b.tx, "flows": b.flows, "apps": apps, "domains": doms }));
        }
        Some(out)
    });
    if let Some(out) = out {
        let _ = paths::write_atomic(&paths::hist_dir().join("buckets.json"), Value::Object(out).to_string().as_bytes());
    }
    let oldest = (chrono::Utc::now() - chrono::Duration::hours(168)).format("%Y-%m-%d").to_string();
    if let Ok(rd) = std::fs::read_dir(paths::hist_dir()) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if let Some(day) = name.strip_prefix("events-").and_then(|r| r.strip_suffix(".jsonl"))
                && day.len() == 10
                && day < oldest.as_str()
            {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_come_off_addresses() {
        assert_eq!(strip_port("1.2.3.4:443"), "1.2.3.4");
        assert_eq!(strip_port("[2606:4700::1]:443"), "2606:4700::1");
        assert_eq!(strip_port("example"), "example");
    }

    #[test]
    fn events_count_into_hourly_totals() {
        let mut h = Hist::default();
        let now = applog::now_ms();
        add_event(&mut h, &json!({ "kind": "flow", "app": "chrome.exe", "at": now, "domain": "a.com" }));
        add_event(&mut h, &json!({ "kind": "flow", "app": "chrome.exe", "at": now, "blocked": true, "domain": "b.com" }));
        add_event(&mut h, &json!({ "kind": "close", "app": "chrome.exe", "at": now, "rx": 10, "tx": 5 }));
        let b = h.buckets.values().next().unwrap();
        let a = &b.apps["chrome.exe"];
        assert_eq!((b.flows, a.n, a.blocked, a.rx, a.tx), (2, 1, 1, 10, 5));
        assert_eq!(b.domains["b.com"].blocked, 1);
    }
}
