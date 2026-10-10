// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! settings.json, as the Electron app wrote it: the defaults below merged
//! with what the file holds. The file is read once and kept in memory; the
//! Electron app read it from disk on nearly every call.

use std::sync::{Mutex, OnceLock};

use serde_json::{Map, Value, json};

use crate::{applog, paths};

pub type S = Map<String, Value>;

pub fn defaults() -> &'static S {
    static D: OnceLock<S> = OnceLock::new();
    D.get_or_init(|| {
        let v = json!({
            // DNS (Android: DNS screen)
            "dnsType": "doh",
            "doh": "https://cloudflare-dns.com/dns-query",
            "dohIps": "1.1.1.1,1.0.0.1",
            "dohName": "Cloudflare",
            "dot": "",
            "dotName": "",
            "dnscrypt": "",
            "dnscryptName": "",
            "odoh": "",
            "odohRelay": "",
            "odohName": "",
            "dnsProxy": "",
            "dnsProxyName": "",
            "dnscryptRelays": [],
            "lastOtherType": "doh",
            "customDns": {},
            "blocklistsLocal": false,
            "localFlags": [],
            "localStamp": "",
            "remoteFlags": [],
            "remoteStamp": "",
            "dnsDirect": false,
            "dnsCache": false,
            "dnssec": true,
            "favicons": false,
            "undelegated": false,
            "dnsFallback": false,
            "nrpt": true,
            "fallbackDoh": "https://cloudflare-dns.com/dns-query",
            "fallbackIps": "1.1.1.1,1.0.0.1",
            "fallbackName": "Cloudflare",
            // Proxy; one exit at a time: none | masque | chain | warp | wg | socks | http
            "exit": "none",
            "wgActive": "",
            "socks": { "host": "127.0.0.1", "port": 1080, "user": "", "pass": "" },
            "http": { "host": "", "port": 8080, "user": "", "pass": "" },
            "warpSni": "",
            "exitSni": "",
            "masqueFlags": "",
            "warp1Flags": "",
            "wgFlags": "",
            "warp2Flags": "",
            "warpAutoDisable": false,
            // Network and firewall
            "mode": "both",
            "full": true,
            "killSwitch": false,
            "allowLan": true,
            "rules": { "apps": {}, "ips": [], "domains": [] },
            "universal": { "udp": false, "icmp": true, "http": false, "unknown": false, "dnsBypass": false, "newApps": false, "locked": false, "lockdown": false, "outgoingOnly": false },
            "dnsTypesAuto": true,
            "dnsTypes": [1, 28, 5, 65, 64, 45],
            "knownApps": [],
            "pausedUntil": 0,
            // Anti-censorship and sockets (Network)
            "dialStrategy": "never",
            "mtu": 0,
            "dialRetry": "",
            "dialTimeout": 0,
            "tcpKeepAlive": false,
            "eim": false,
            // Settings
            "history": true,
            "logLevel": 3,
            "notify": true,
            "statusAlerts": true,
            "theme": "darkplus",
            "autostart": false,
            "wasRunning": false,
            "pcap": false,
            "automation": false,
            "welcomed": false
        });
        match v {
            Value::Object(m) => m,
            _ => unreachable!(),
        }
    })
}

static CACHE: Mutex<Option<S>> = Mutex::new(None);

/// The settings: the defaults, then the file's values over them.
pub fn read() -> S {
    let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = c.as_ref() {
        return s.clone();
    }
    let mut s = defaults().clone();
    if let Ok(text) = std::fs::read_to_string(paths::settings_file())
        && let Ok(Value::Object(mut raw)) = serde_json::from_str::<Value>(&text)
    {
        if !raw.contains_key("mode") {
            // before modes
            let full = raw.get("full").and_then(Value::as_bool) != Some(false);
            raw.insert("mode".into(), json!(if full { "both" } else { "dns" }));
        }
        for (k, v) in raw {
            s.insert(k, v);
        }
    }
    let s = migrate(s);
    *c = Some(s.clone());
    s
}

/// Writes the settings, whole or not at all, and keeps them for read.
pub fn write(s: &S) -> std::io::Result<()> {
    let text = serde_json::to_string_pretty(s).unwrap_or_default();
    paths::write_atomic(&paths::settings_file(), text.as_bytes())?;
    *CACHE.lock().unwrap_or_else(|e| e.into_inner()) = Some(s.clone());
    Ok(())
}

/// Changes the settings with f and writes them.
pub fn update(f: impl FnOnce(&mut S)) -> S {
    let mut s = read();
    f(&mut s);
    if let Err(e) = write(&s) {
        applog!("settings: could not write: {e}");
    }
    s
}

// ---------- typed reads ----------

pub fn str<'a>(s: &'a S, k: &str) -> &'a str {
    s.get(k).and_then(Value::as_str).unwrap_or("")
}
pub fn bool(s: &S, k: &str) -> bool {
    s.get(k).and_then(Value::as_bool).unwrap_or(false)
}
pub fn num(s: &S, k: &str) -> f64 {
    s.get(k).and_then(Value::as_f64).unwrap_or(0.0)
}
pub fn obj<'a>(s: &'a S, k: &str) -> Option<&'a Map<String, Value>> {
    s.get(k).and_then(Value::as_object)
}
pub fn arr<'a>(s: &'a S, k: &str) -> &'a [Value] {
    s.get(k).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}
pub fn sub_bool(s: &S, k: &str, sub: &str) -> bool {
    obj(s, k).and_then(|o| o.get(sub)).and_then(Value::as_bool).unwrap_or(false)
}

/// A number as JSON keeps it: 1400, not 1400.0.
pub fn number(n: f64) -> Value {
    if n.fract() == 0.0 && n.abs() < 9.0e15 { json!(n as i64) } else { json!(n) }
}

// ---------- migrations ----------

/// Settings from 0.1.0: exit "proxy" with a URL, a single wgFile, and a list
/// of blocked apps; and the defaults of nested settings.
pub fn migrate(mut s: S) -> S {
    let mut changed = false;
    if str(&s, "exit") == "proxy" && !str(&s, "proxy").is_empty() {
        match reqwest::Url::parse(str(&s, "proxy")) {
            Ok(u) => {
                let kind = if u.scheme() == "http" { "http" } else { "socks" };
                let dec = |t: &str| percent_decode(t);
                s.insert(
                    kind.into(),
                    json!({
                        "host": u.host_str().unwrap_or(""),
                        "port": u.port().map(i64::from).unwrap_or(if kind == "http" { 8080 } else { 1080 }),
                        "user": dec(u.username()),
                        "pass": dec(u.password().unwrap_or("")),
                    }),
                );
                s.insert("exit".into(), json!(kind));
            }
            Err(_) => {
                s.insert("exit".into(), json!("none"));
            }
        }
        changed = true;
    }
    if !str(&s, "wgFile").is_empty() {
        let file = std::path::PathBuf::from(str(&s, "wgFile"));
        if let Ok(text) = std::fs::read_to_string(&file) {
            let wg0 = paths::usque_dir().join("wg0.conf");
            if str(&s, "exit") == "chain" && !wg0.exists() {
                let _ = std::fs::create_dir_all(paths::usque_dir());
                let _ = std::fs::write(&wg0, &text);
            } else if str(&s, "exit") == "wg" {
                let name = file.file_stem().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                let r = crate::wg::save(None, &name, &text);
                let id = r.get("id").and_then(Value::as_str).unwrap_or("").to_string();
                s.insert("wgActive".into(), json!(id));
            }
        }
        changed = true;
    }
    if changed {
        s.remove("proxy");
        s.remove("wgFile");
        if str(&s, "exit") == "proxy" {
            s.insert("exit".into(), json!("none"));
        }
        let _ = write(&s);
    }
    if let Some(Value::Array(blocked)) = s.remove("blocked") {
        let mut rules = obj(&s, "rules").cloned().unwrap_or_default();
        let mut apps = rules.get("apps").and_then(Value::as_object).cloned().unwrap_or_default();
        for name in blocked {
            let n = match &name {
                Value::String(t) => t.clone(),
                v => v.to_string(),
            };
            let mut a = apps.get(&n).and_then(Value::as_object).cloned().unwrap_or_default();
            a.insert("mode".into(), json!("block"));
            apps.insert(n.to_lowercase(), Value::Object(a));
        }
        rules.insert("apps".into(), Value::Object(apps));
        s.insert("rules".into(), Value::Object(rules));
        let _ = write(&s);
    }
    // rules: { apps, ips, domains } with whatever the file adds
    let mut rules = json!({ "apps": {}, "ips": [], "domains": [] }).as_object().cloned().unwrap_or_default();
    if let Some(r) = obj(&s, "rules") {
        for (k, v) in r {
            rules.insert(k.clone(), v.clone());
        }
    }
    s.insert("rules".into(), Value::Object(rules));
    let mut universal = obj(defaults(), "universal").cloned().unwrap_or_default();
    if let Some(u) = obj(&s, "universal") {
        for (k, v) in u {
            universal.insert(k.clone(), v.clone());
        }
    }
    s.insert("universal".into(), Value::Object(universal));
    for k in ["knownApps", "dnscryptRelays", "localFlags", "remoteFlags"] {
        if !s.get(k).is_some_and(Value::is_array) {
            s.insert(k.into(), json!([]));
        }
    }
    s
}

fn percent_decode(t: &str) -> String {
    let b = t.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = ((b[i + 1] as char).to_digit(16), (b[i + 2] as char).to_digit(16))
        {
            out.push((h * 16 + l) as u8);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------- settings from the window ----------

// The window may change only settings that exist, each to a value of its
// default's kind: one line of bounded text, a finite number, true or false,
// or plain data with safe names. Anything else is dropped, and logged, so a
// window gone bad can't plant settings the engine then runs with.
const MAX_TEXT: usize = 8192;
const HTTPS_ONLY: [&str; 4] = ["doh", "fallbackDoh", "odoh", "odohRelay"];

/// Names that become map keys (apps, domains) stay plain names.
pub fn safe_key(k: &str) -> bool {
    !k.is_empty() && k.len() <= 512 && k != "__proto__" && k != "constructor" && k != "prototype"
}

fn clean_data(v: &Value, depth: usize) -> Result<Value, String> {
    if depth > 8 {
        return Err("nested too deep".into());
    }
    match v {
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(v.clone()),
        Value::String(t) => {
            if t.encode_utf16().count() > MAX_TEXT {
                Err("text too long".into())
            } else {
                Ok(v.clone())
            }
        }
        Value::Array(a) => {
            if a.len() > 20000 {
                return Err("list too long".into());
            }
            a.iter().map(|x| clean_data(x, depth + 1)).collect::<Result<Vec<_>, _>>().map(Value::Array)
        }
        Value::Object(o) => {
            if o.len() > 20000 {
                return Err("too many entries".into());
            }
            let mut out = Map::new();
            for (k, x) in o {
                if !safe_key(k) {
                    return Err(format!("bad name {}", Value::String(k.chars().take(40).collect())));
                }
                out.insert(k.clone(), clean_data(x, depth + 1)?);
            }
            Ok(Value::Object(out))
        }
    }
}

fn clean_setting(k: &str, v: &Value) -> Result<Value, String> {
    let def = defaults().get(k).ok_or("not a setting")?;
    match def {
        Value::Bool(_) => v.as_bool().map(Value::Bool).ok_or_else(|| "want true or false".into()),
        Value::Number(_) => {
            let n = match v {
                Value::String(t) if !t.trim().is_empty() => t.trim().parse::<f64>().ok(),
                Value::Number(n) => n.as_f64(),
                _ => None,
            };
            match n {
                Some(n) if n.is_finite() => Ok(number(n)),
                _ => Err("want a number".into()),
            }
        }
        Value::String(_) => {
            let t = v.as_str().ok_or("want one line of text")?;
            if t.encode_utf16().count() > MAX_TEXT || t.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7f) {
                return Err("want one line of text".into());
            }
            if HTTPS_ONLY.contains(&k) && !t.is_empty() && !t.to_ascii_lowercase().starts_with("https://") {
                return Err("want an https:// address".into());
            }
            Ok(v.clone())
        }
        Value::Array(_) => {
            if !v.is_array() {
                return Err("want a list".into());
            }
            clean_data(v, 0)
        }
        _ => {
            if !v.is_object() {
                return Err("want an object".into());
            }
            clean_data(v, 0)
        }
    }
}

/// The settings in patch (only those in keys, if given) that pass the checks.
pub fn clean_patch(patch: &Value, keys: Option<&[&str]>) -> S {
    let mut out = Map::new();
    let Some(p) = patch.as_object() else {
        return out;
    };
    for (k, v) in p {
        if !defaults().contains_key(k) || keys.is_some_and(|ks| !ks.contains(&k.as_str())) {
            applog!("settings: dropped {}: not a setting here", Value::String(k.chars().take(60).collect()));
            continue;
        }
        match clean_setting(k, v) {
            Ok(x) => {
                out.insert(k.clone(), x);
            }
            Err(e) => applog!("settings: dropped {k}: {e}"),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_keeps_only_known_settings_of_their_kind() {
        let p = clean_patch(
            &json!({ "exit": "chain", "mtu": "1400", "nope": 1, "dnssec": "yes", "doh": "http://x", "theme": "a\nb", "rules": { "apps": { "x.exe": { "mode": "block" } } } }),
            None,
        );
        assert_eq!(p.get("exit"), Some(&json!("chain")));
        assert_eq!(p.get("mtu"), Some(&json!(1400)));
        assert!(!p.contains_key("nope"));
        assert!(!p.contains_key("dnssec"));
        assert!(!p.contains_key("doh"));
        assert!(!p.contains_key("theme"));
        assert!(p.contains_key("rules"));
    }

    #[test]
    fn patch_refuses_prototype_names() {
        let p = clean_patch(&json!({ "rules": { "apps": { "__proto__": {} } } }), None);
        assert!(!p.contains_key("rules"));
    }

    #[test]
    fn rule_keys_limit_a_patch() {
        let p = clean_patch(&json!({ "exit": "chain", "pausedUntil": 5 }), Some(&["pausedUntil"]));
        assert_eq!(p.len(), 1);
    }
}
