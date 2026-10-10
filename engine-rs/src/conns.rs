// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Open connections, kept so that a new rule can close them and the Logs
//! screen can list them (GET /api/conns), and the reasons recent DNS
//! queries were blocked. A port of conns_windows.go.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::golike;
use crate::netaddr;

/// Bounds the open-connection table; flows past it are still firewalled,
/// just not closed early when a rule changes.
pub const MAX_CONNS: usize = 50000;

/// An open connection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LiveConn {
    pub uid: i32,
    pub proto: i32,
    pub dst: Option<SocketAddr>,
    pub domains: Vec<String>,
    pub app: String,
    /// the program's full path; "" if unknown
    pub path: String,
    /// the exit or route it leaves through
    pub via: String,
    /// two-letter code of dst
    pub country: String,
    /// unix millis
    pub at: i64,
}

/// What GET /api/conns returns per connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenConn {
    pub cid: String,
    pub app: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub path: String,
    pub proto: String,
    pub dst: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub domain: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub country: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub via: String,
    /// unix millis
    pub since: i64,
}

/// The protocol's name in the logs: icmp, tcp, udp or its number.
pub fn proto_name(p: i32) -> String {
    match p {
        1 => "icmp".into(),
        6 => "tcp".into(),
        17 => "udp".into(),
        n => n.to_string(),
    }
}

#[derive(Default)]
pub struct ConnTable {
    m: Mutex<HashMap<String, LiveConn>>,
}

impl ConnTable {
    pub fn new() -> ConnTable {
        ConnTable::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, LiveConn>> {
        self.m.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn add(&self, cid: &str, c: LiveConn) {
        let mut m = self.lock();
        if m.len() < MAX_CONNS {
            m.insert(cid.to_string(), c);
        }
    }

    pub fn remove(&self, cid: &str) {
        self.lock().remove(cid);
    }

    /// A copy of the table.
    pub fn all(&self) -> HashMap<String, LiveConn> {
        self.lock().clone()
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The open connections of app (all if ""), newest first.
    pub fn list(&self, app: &str) -> Vec<OpenConn> {
        let app = golike::to_lower(app);
        let mut out: Vec<OpenConn> = Vec::new();
        for (cid, c) in self.all() {
            if !app.is_empty() && golike::to_lower(&c.app) != app {
                continue;
            }
            out.push(OpenConn {
                cid,
                app: c.app,
                path: c.path,
                proto: proto_name(c.proto),
                dst: netaddr::addr_port_string(c.dst),
                domain: c.domains.first().cloned().unwrap_or_default(),
                country: c.country,
                via: c.via,
                since: c.at,
            });
        }
        out.sort_by(|a, b| b.since.cmp(&a.since));
        out
    }
}

/// How long a blocked query's reason is kept.
pub const WHY_TTL: Duration = Duration::from_secs(30);

/// Remembers, for a short while, why a DNS query was sent to BlockAll, so
/// its answer can be logged with the rule that blocked it.
#[derive(Default)]
pub struct WhyCache {
    m: Mutex<HashMap<String, (String, Instant)>>,
}

/// A query name as the cache keys it: lowercased, no trailing dot.
pub fn norm_name(qname: &str) -> String {
    golike::to_lower(golike::trim_suffix(qname, "."))
}

impl WhyCache {
    pub fn new() -> WhyCache {
        WhyCache::default()
    }

    pub fn put(&self, qname: &str, why: &str) {
        let mut m = self.m.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if m.len() > 4096 {
            m.retain(|_, (_, at)| now.duration_since(*at) <= WHY_TTL);
        }
        m.insert(norm_name(qname), (why.to_string(), now));
    }

    /// The reason, kept until it expires: A and AAAA queries for a name
    /// share it.
    pub fn get(&self, qname: &str) -> String {
        let m = self.m.lock().unwrap_or_else(|e| e.into_inner());
        match m.get(&norm_name(qname)) {
            Some((why, at)) if at.elapsed() <= WHY_TTL => why.clone(),
            _ => String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_newest_first_by_app() {
        let t = ConnTable::new();
        let c = |app: &str, at: i64, dst: &str| LiveConn {
            app: app.into(),
            proto: 6,
            at,
            dst: netaddr::parse_addr_port(dst),
            domains: vec!["a.com".into(), "b.com".into()],
            ..Default::default()
        };
        t.add("1", c("Chrome.exe", 10, "1.1.1.1:443"));
        t.add("2", c("chrome.exe", 30, "[2001:db8::1]:443"));
        t.add("3", c("x.exe", 20, "bad"));
        let all = t.list("");
        assert_eq!(all.iter().map(|o| o.cid.as_str()).collect::<Vec<_>>(), vec!["2", "3", "1"]);
        assert_eq!(all[0].dst, "[2001:db8::1]:443");
        assert_eq!(all[0].domain, "a.com");
        assert_eq!(all[1].dst, "invalid AddrPort");
        assert_eq!(t.list("CHROME.EXE").len(), 2);
        t.remove("2");
        assert_eq!(t.len(), 2);
        assert_eq!(
            serde_json::to_string(&t.list("x.exe")).unwrap(),
            r#"[{"cid":"3","app":"x.exe","proto":"tcp","dst":"invalid AddrPort","domain":"a.com","since":20}]"#
        );
        assert_eq!(serde_json::to_string(&t.list("none.exe")).unwrap(), "[]");
    }

    #[test]
    fn why_cache() {
        let w = WhyCache::new();
        w.put("Ads.Example.", "domain rule ads.example");
        assert_eq!(w.get("ads.example"), "domain rule ads.example");
        assert_eq!(w.get("other.example"), "");
    }

    #[test]
    fn protos() {
        assert_eq!(proto_name(1), "icmp");
        assert_eq!(proto_name(58), "58");
    }
}
