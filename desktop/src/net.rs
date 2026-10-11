// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Check exit IP (Chain mode) and the ping test (Network).

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

/// For the internet: through the tunnel like any app, with the system's
/// proxy settings honoured as the Electron app's fetch did.
pub fn web() -> &'static reqwest::Client {
    static C: OnceLock<reqwest::Client> = OnceLock::new();
    C.get_or_init(|| reqwest::Client::builder().user_agent(concat!("AuroraVPN/", env!("CARGO_PKG_VERSION"))).build().expect("http client"))
}

/// What Cloudflare sees from this PC: ip, loc, colo and warp=on|off.
pub async fn check_exit() -> Value {
    let res = async {
        let r = web().get("https://www.cloudflare.com/cdn-cgi/trace").timeout(Duration::from_secs(10)).send().await.map_err(|e| e.to_string())?;
        r.text().await.map_err(|e| e.to_string())
    }
    .await;
    match res {
        Ok(text) => {
            let kv: Map<String, Value> = text.lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.to_string(), json!(v))).collect();
            let g = |k: &str| kv.get(k).cloned().unwrap_or(json!("?"));
            json!({ "ip": g("ip"), "loc": g("loc"), "colo": g("colo"), "warp": g("warp") })
        }
        Err(e) => json!({ "error": e }),
    }
}

async fn tcp_ping(addr: std::net::SocketAddr, d: Duration) -> Value {
    let t0 = Instant::now();
    let r = tokio::time::timeout(d, tokio::net::TcpStream::connect(addr)).await;
    let ms = t0.elapsed().as_millis() as u64;
    match r {
        Ok(Ok(_)) => json!({ "ok": true, "ms": ms }),
        Ok(Err(e)) => json!({ "ok": false, "ms": ms, "error": e.to_string() }),
        Err(_) => json!({ "ok": false, "ms": ms, "error": "timed out" }),
    }
}

/// Network → ping test: a TCP connect to an IP, a lookup of a host name,
/// and a HEAD request to a web address, each optional.
pub async fn ping(q: &Value) -> Value {
    let field = |k: &str| q.get(k).and_then(Value::as_str).unwrap_or("").trim().to_string();
    let (ip, host, url) = (field("ip"), field("host"), field("url"));
    let mut out = Map::new();
    if !ip.is_empty() {
        let v = match ip.parse::<std::net::IpAddr>() {
            Ok(a) => tcp_ping((a, 443).into(), Duration::from_secs(5)).await,
            Err(_) => json!({ "ok": false, "error": "not an IP address" }),
        };
        out.insert("ip".into(), v);
    }
    if !host.is_empty() {
        let t0 = Instant::now();
        let v = if !host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
            json!({ "ok": false, "ms": 0, "error": "not a host name" })
        } else {
            match tokio::net::lookup_host((host.as_str(), 0)).await {
                Ok(addrs) => {
                    let mut list: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
                    list.dedup();
                    json!({ "ok": true, "ms": t0.elapsed().as_millis() as u64, "answer": list.join(", ") })
                }
                Err(e) => json!({ "ok": false, "ms": t0.elapsed().as_millis() as u64, "error": e.to_string() }),
            }
        };
        out.insert("host".into(), v);
    }
    if !url.is_empty() {
        let t0 = Instant::now();
        let v = if !(url.starts_with("http://") || url.starts_with("https://")) || url.contains(char::is_whitespace) {
            json!({ "ok": false, "ms": 0, "error": "not a web address" })
        } else {
            match web().head(&url).timeout(Duration::from_secs(10)).send().await {
                Ok(r) => json!({ "ok": r.status().as_u16() < 500, "ms": t0.elapsed().as_millis() as u64, "answer": format!("HTTP {}", r.status().as_u16()) }),
                Err(e) => json!({ "ok": false, "ms": t0.elapsed().as_millis() as u64, "error": if e.is_timeout() { "timed out".to_string() } else { e.to_string() } }),
            }
        };
        out.insert("url".into(), v);
    }
    Value::Object(out)
}
