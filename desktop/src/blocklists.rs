// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! RethinkDNS blocklists (Android: "Configure 195+ blocklists"): the
//! filetag (the list of lists) for RethinkDNS servers, and the on-device
//! download, checked against the md5 sums in basicconfig.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use md5::{Digest, Md5};
use serde_json::{Value, json};

use crate::{applog, net, paths, settings};

const BASE: &str = "https://dl.rethinkdns.com";
// what the Android app downloads; "?compressed" is served brotli-encoded
const FILES: [(&str, &str, &str); 4] = [
    ("basicconfig", "basicconfig.json", "cfgmd5"),
    ("blocklists", "filetag.json", "ftmd5"),
    ("rank?compressed", "rd.txt", "rdmd5"),
    ("trie?compressed", "td.txt", "tdmd5"),
];
const NEEDED: [&str; 4] = ["td.txt", "rd.txt", "basicconfig.json", "filetag.json"];

/// { file, done, total } while downloading; { error } after a failure.
static JOB: Mutex<Value> = Mutex::new(Value::Null);

fn job() -> Value {
    JOB.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn set_job(v: Value) {
    *JOB.lock().unwrap_or_else(|e| e.into_inner()) = v;
}

/// The newest complete on-device download, if any.
fn local_dir() -> Option<PathBuf> {
    let root = paths::bl_dir().join("local");
    let mut dirs: Vec<(u64, PathBuf)> = std::fs::read_dir(&root)
        .ok()?
        .flatten()
        .filter_map(|e| Some((e.file_name().to_str()?.parse::<u64>().ok()?, e.path())))
        .collect();
    dirs.sort_by_key(|d| std::cmp::Reverse(d.0));
    dirs.into_iter().map(|(_, p)| p).find(|p| NEEDED.iter().all(|f| p.join(f).exists()))
}

async fn fetch_to(url: &str, file: &Path, mut on_bytes: impl FnMut(u64, u64)) -> Result<String, String> {
    let mut res = net::web().get(url).send().await.map_err(|e| format!("{url}: {e}"))?;
    if !res.status().is_success() {
        return Err(format!("{url}: HTTP {}", res.status().as_u16()));
    }
    let total = res.content_length().unwrap_or(0);
    let mut out = std::fs::File::create(file).map_err(|e| e.to_string())?;
    let mut hash = Md5::new();
    let mut done = 0u64;
    while let Some(chunk) = res.chunk().await.map_err(|e| format!("{url}: {e}"))? {
        hash.update(&chunk);
        done += chunk.len() as u64;
        on_bytes(done, total);
        out.write_all(&chunk).map_err(|e| e.to_string())?;
    }
    Ok(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// basicconfig's timestamp looks like "2026/1790903143399".
fn timestamp(cfg: &Value) -> String {
    let t = match cfg.get("timestamp") {
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
        None => String::new(),
    };
    let mut best = String::new();
    let mut cur = String::new();
    for c in t.chars() {
        if c.is_ascii_digit() {
            cur.push(c);
        } else {
            if cur.len() >= 10 && best.is_empty() {
                best = cur.clone();
            }
            cur.clear();
        }
    }
    if cur.len() >= 10 && best.is_empty() {
        best = cur;
    }
    best
}

pub async fn latest() -> Value {
    let r = async {
        let res = net::web().get(format!("{BASE}/basicconfig")).send().await.map_err(|e| e.to_string())?;
        if !res.status().is_success() {
            return Err(format!("HTTP {}", res.status().as_u16()));
        }
        let cfg: Value = res.json().await.map_err(|e| e.to_string())?;
        Ok(timestamp(&cfg))
    }
    .await;
    match r {
        Ok(ts) => json!({ "ok": true, "timestamp": ts.parse::<u64>().unwrap_or(0) }),
        Err(e) => json!({ "ok": false, "error": e }),
    }
}

pub fn status() -> Value {
    let local = local_dir().map(|d| {
        let size: u64 = NEEDED.iter().map(|f| std::fs::metadata(d.join(f)).map(|m| m.len()).unwrap_or(0)).sum();
        let ts = d.file_name().and_then(|n| n.to_str()).and_then(|n| n.parse::<u64>().ok()).unwrap_or(0);
        json!({ "timestamp": ts, "size": size })
    });
    let j = job();
    json!({ "local": local, "filetag": paths::bl_dir().join("filetag.json").exists(), "job": if j.is_null() { Value::Null } else { j } })
}

/// Only the filetag (the list of lists, ~50 KB), for RethinkDNS servers.
pub async fn filetag() -> Value {
    let r = async {
        let f = paths::bl_dir().join("filetag.json");
        if !f.exists() {
            std::fs::create_dir_all(paths::bl_dir()).map_err(|e| e.to_string())?;
            let part = f.with_extension("json.part");
            fetch_to(&format!("{BASE}/blocklists"), &part, |_, _| {}).await?;
            std::fs::rename(&part, &f).map_err(|e| e.to_string())?;
        }
        let ft: Value = serde_json::from_str(&std::fs::read_to_string(&f).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let lists: Vec<Value> = ft
            .as_object()
            .map(|o| {
                o.values()
                    .map(|v| {
                        let url = match v.get("url") {
                            Some(Value::Array(a)) => a.first().cloned().unwrap_or(Value::Null),
                            Some(u) => u.clone(),
                            None => Value::Null,
                        };
                        json!({
                            "value": v.get("value"), "vname": v.get("vname"), "group": v.get("group"), "subg": v.get("subg"),
                            "url": url, "entries": v.get("entries"),
                            "pack": v.get("pack").cloned().unwrap_or(json!([])), "level": v.get("level").cloned().unwrap_or(json!([])),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok::<_, String>(lists)
    }
    .await;
    match r {
        Ok(lists) => json!({ "ok": true, "lists": lists }),
        Err(e) => json!({ "ok": false, "error": e }),
    }
}

pub async fn download() -> Value {
    {
        let mut j = JOB.lock().unwrap_or_else(|e| e.into_inner());
        if !j.is_null() && j.get("error").is_none() {
            return json!({ "ok": false, "error": "Already downloading" });
        }
        *j = json!({ "file": "basicconfig.json", "done": 0, "total": 0 });
    }
    let tmp = paths::bl_dir().join(format!("tmp-{}", applog::now_ms()));
    let r = async {
        std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
        let mut sums = serde_json::Map::new();
        for (u, f, key) in FILES {
            set_job(json!({ "file": f, "done": 0, "total": 0 }));
            let sum = fetch_to(&format!("{BASE}/{u}"), &tmp.join(f), |d, t| set_job(json!({ "file": f, "done": d, "total": t }))).await?;
            sums.insert(key.into(), json!(sum));
        }
        let cfg: Value = serde_json::from_str(&std::fs::read_to_string(tmp.join("basicconfig.json")).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        for (_, f, key) in FILES {
            if let Some(want) = cfg.get(key).and_then(Value::as_str)
                && !want.is_empty()
                && sums.get(key).and_then(Value::as_str) != Some(want)
            {
                return Err(format!("{f}: integrity check failed; try again"));
            }
        }
        let ts = Some(timestamp(&cfg)).filter(|t| !t.is_empty()).unwrap_or_else(|| applog::now_ms().to_string());
        let parent = paths::bl_dir().join("local");
        let dest = parent.join(&ts);
        std::fs::create_dir_all(&parent).map_err(|e| e.to_string())?;
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::rename(&tmp, &dest).map_err(|e| e.to_string())?;
        std::fs::copy(dest.join("filetag.json"), paths::bl_dir().join("filetag.json")).map_err(|e| e.to_string())?;
        if let Ok(rd) = std::fs::read_dir(&parent) {
            for e in rd.flatten() {
                if e.file_name().to_str() != Some(ts.as_str()) {
                    let _ = std::fs::remove_dir_all(e.path()); // in use by a running engine: removed next time
                }
            }
        }
        Ok::<_, String>(ts)
    }
    .await;
    match r {
        Ok(ts) => {
            set_job(Value::Null);
            json!({ "ok": true, "timestamp": ts.parse::<u64>().unwrap_or(0) })
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&tmp);
            set_job(json!({ "error": e }));
            json!({ "ok": false, "error": e })
        }
    }
}

/// Removes the on-device download (not while the engine has it open).
pub fn delete() -> Value {
    match std::fs::remove_dir_all(paths::bl_dir().join("local")) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return json!({ "ok": false, "error": format!("Could not delete the blocklists: {e}") }),
        _ => {}
    }
    settings::update(|s| {
        s.insert("blocklistsLocal".into(), json!(false));
    });
    json!({ "ok": true })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_timestamp_is_the_long_number() {
        assert_eq!(timestamp(&json!({ "timestamp": "2026/1790903143399" })), "1790903143399");
        assert_eq!(timestamp(&json!({})), "");
    }
}
