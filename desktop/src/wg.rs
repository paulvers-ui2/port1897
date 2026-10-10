// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Saved WireGuard configs (Proxy → Setup WireGuard): wireguard\<id>.conf
//! and wireguard\index.json with their names.

use std::path::PathBuf;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{Value, json};

use crate::paths;

fn re(p: &'static str) -> Regex {
    Regex::new(p).expect("valid regex")
}

/// n random bytes as hex. Without the OS's random numbers there is no safe
/// token or id to make, so that is fatal.
pub fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).expect("the OS gave no random numbers");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn index() -> Vec<Value> {
    std::fs::read_to_string(paths::wg_dir().join("index.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<Vec<Value>>(&t).ok())
        .unwrap_or_default()
}

fn write_index(idx: &[Value]) -> std::io::Result<()> {
    std::fs::create_dir_all(paths::wg_dir())?;
    std::fs::write(paths::wg_dir().join("index.json"), serde_json::to_string_pretty(idx).unwrap_or_default())
}

fn valid_id(id: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| re(r"^[a-f0-9]{16}$")).is_match(id)
}

/// The config file of id, if it exists.
pub fn file(id: &str) -> Option<PathBuf> {
    if !valid_id(id) {
        return None;
    }
    let f = paths::wg_dir().join(format!("{id}.conf"));
    f.exists().then_some(f)
}

/// Plain WireGuard (wg-quick) with a key and a peer; AmneziaWG is refused.
pub fn valid(text: &str, need_endpoint: bool) -> bool {
    static R: OnceLock<[Regex; 6]> = OnceLock::new();
    let [iface, pk, peer, pubk, amnezia, ep] = R.get_or_init(|| {
        [
            re(r"(?im)^\s*\[Interface\]"),
            re(r"(?im)^\s*PrivateKey\s*="),
            re(r"(?im)^\s*\[Peer\]"),
            re(r"(?im)^\s*PublicKey\s*="),
            re(r"(?im)^\s*(Jc|Jmin|Jmax|S1|S2|H1|H2|H3|H4)\s*="),
            re(r"(?im)^\s*Endpoint\s*="),
        ]
    });
    if !iface.is_match(text) || !pk.is_match(text) || !peer.is_match(text) || !pubk.is_match(text) {
        return false;
    }
    if amnezia.is_match(text) {
        return false;
    }
    !need_endpoint || ep.is_match(text)
}

pub fn save(id: Option<&str>, name: &str, text: &str) -> Value {
    if !valid(text, true) {
        return json!({ "error": "Invalid config: needs [Interface] PrivateKey and a [Peer] with PublicKey and Endpoint (plain WireGuard; AmneziaWG is not supported)" });
    }
    let id = match id.filter(|i| file(i).is_some()) {
        Some(i) => i.to_string(),
        None => random_hex(8),
    };
    let name = if name.is_empty() { "WireGuard" } else { name };
    let result = (|| -> std::io::Result<()> {
        std::fs::create_dir_all(paths::wg_dir())?;
        std::fs::write(paths::wg_dir().join(format!("{id}.conf")), text)?;
        let mut idx = index();
        let entry = json!({ "id": id, "name": name });
        match idx.iter().position(|e| e.get("id").and_then(Value::as_str) == Some(id.as_str())) {
            Some(i) => idx[i] = entry,
            None => idx.push(entry),
        }
        write_index(&idx)
    })();
    match result {
        Ok(()) => json!({ "id": id, "name": name }),
        Err(e) => json!({ "error": e.to_string() }),
    }
}

pub fn list() -> Value {
    static EP: OnceLock<Regex> = OnceLock::new();
    let ep = EP.get_or_init(|| re(r"(?im)^\s*Endpoint\s*=\s*(\S+)"));
    let out: Vec<Value> = index()
        .into_iter()
        .filter_map(|e| {
            let id = e.get("id").and_then(Value::as_str)?.to_string();
            let f = file(&id)?;
            let text = std::fs::read_to_string(f).unwrap_or_default();
            let endpoint = ep.captures(&text).map(|c| c[1].to_string()).unwrap_or_default();
            Some(json!({ "id": id, "name": e.get("name").cloned().unwrap_or(json!("WireGuard")), "endpoint": endpoint }))
        })
        .collect();
    Value::Array(out)
}

pub fn get(id: &str) -> Value {
    let Some(f) = file(id) else {
        return Value::Null;
    };
    let name = index()
        .into_iter()
        .find(|e| e.get("id").and_then(Value::as_str) == Some(id))
        .and_then(|e| e.get("name").cloned())
        .unwrap_or(json!("WireGuard"));
    json!({ "id": id, "name": name, "text": std::fs::read_to_string(f).unwrap_or_default() })
}

pub fn remove(id: &str) -> bool {
    if let Some(f) = file(id) {
        let _ = std::fs::remove_file(f);
    }
    let idx: Vec<Value> = index().into_iter().filter(|e| e.get("id").and_then(Value::as_str) != Some(id)).collect();
    let _ = write_index(&idx);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONF: &str = "[Interface]\nPrivateKey = x\n[Peer]\nPublicKey = y\nEndpoint = 1.2.3.4:51820\n";

    #[test]
    fn plain_wireguard_with_an_endpoint_is_valid() {
        assert!(valid(CONF, true));
        assert!(!valid("[Interface]\nPrivateKey = x\n[Peer]\nPublicKey = y\n", true));
        assert!(valid("[Interface]\nPrivateKey = x\n[Peer]\nPublicKey = y\n", false));
    }

    #[test]
    fn amneziawg_is_refused() {
        assert!(!valid(&format!("{CONF}Jc = 4\n"), true));
    }
}
