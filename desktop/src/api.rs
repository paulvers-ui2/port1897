// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The engine's loopback control API (fswin -api 127.0.0.1:47897), with the
//! token from api-token. One client keeps its connection open, so a call
//! takes about a millisecond.

use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde_json::Value;

use crate::paths;

static TOKEN: Mutex<String> = Mutex::new(String::new());

/// The token stays the same while an engine may be running, so a reopened
/// app can still talk to it.
pub fn ensure_token() -> Result<String, String> {
    let mut t = TOKEN.lock().unwrap_or_else(|e| e.into_inner());
    if !t.is_empty() {
        return Ok(t.clone());
    }
    let mut tok = std::fs::read_to_string(paths::token_file()).unwrap_or_default().trim().to_string();
    if tok.len() < 32 {
        tok = crate::wg::random_hex(32);
        // the engine reads it from this file: without it, no call would pass
        std::fs::create_dir_all(paths::data_dir()).and_then(|()| std::fs::write(paths::token_file(), &tok)).map_err(|e| format!("could not save the API token: {e}"))?;
    }
    *t = tok.clone();
    Ok(tok)
}

fn client() -> &'static reqwest::Client {
    static C: OnceLock<reqwest::Client> = OnceLock::new();
    C.get_or_init(|| {
        reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .connect_timeout(Duration::from_millis(500))
            .pool_idle_timeout(Duration::from_secs(30))
            .build()
            .expect("http client")
    })
}

/// Calls the engine; Err when it is not running or refuses.
pub async fn call(method: reqwest::Method, path: &str, body: Option<&Value>) -> Result<Value, String> {
    let url = format!("http://{}:{}{}", paths::API_HOST, paths::API_PORT, path);
    let mut req = client().request(method, url).bearer_auth(ensure_token()?);
    if let Some(b) = body {
        req = req.json(b);
    }
    let res = req.send().await.map_err(|e| e.to_string())?;
    let code = res.status();
    let text = res.text().await.map_err(|e| e.to_string())?;
    if code != reqwest::StatusCode::OK {
        return Err(format!("{} {}", code.as_u16(), text.trim()));
    }
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

pub async fn get(path: &str) -> Result<Value, String> {
    call(reqwest::Method::GET, path, None).await
}

pub async fn post(path: &str, body: Option<&Value>) -> Result<Value, String> {
    call(reqwest::Method::POST, path, body).await
}

/// The engine's status, or None when it is not running.
pub async fn status() -> Option<Value> {
    get("/api/status").await.ok().filter(Value::is_object)
}
