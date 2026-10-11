// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The activity journal the app's Logs and home screens read through
//! GET /api/events and /api/stats (a port of events_windows.go): the most
//! recent events in a ring, and running counts.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, Ordering};

use serde::Serialize;

fn zero_i64(v: &i64) -> bool {
    *v == 0
}

fn zero_i32(v: &i32) -> bool {
    *v == 0
}

fn not(v: &bool) -> bool {
    !*v
}

/// One line of the activity log the UI shows; field order and omitted
/// empty fields as Go's `event` with its omitempty tags.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Event {
    pub id: i64,
    /// unix millis
    pub at: i64,
    /// "flow", "dns" or "close" (a connection ended)
    pub kind: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub app: String,
    /// the program's full path, when Windows told it
    #[serde(skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub proto: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub dst: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub domain: String,
    /// two-letter code of dst, or of a DNS answer's first address
    #[serde(skip_serializing_if = "String::is_empty")]
    pub country: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub answer: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub via: String,
    #[serde(rename = "latencyMs", skip_serializing_if = "zero_i64")]
    pub latency_ms: i64,
    #[serde(skip_serializing_if = "not")]
    pub blocked: bool,
    /// bytes, on "close"
    #[serde(skip_serializing_if = "zero_i64")]
    pub rx: i64,
    #[serde(skip_serializing_if = "zero_i64")]
    pub tx: i64,
    #[serde(rename = "durMs", skip_serializing_if = "zero_i64")]
    pub dur_ms: i64,
    /// DNSSEC verified (AD bit)
    #[serde(skip_serializing_if = "not")]
    pub secure: bool,
    /// answered from the DNS cache
    #[serde(skip_serializing_if = "not")]
    pub cached: bool,
    /// the firewall or DNS rule that decided
    #[serde(skip_serializing_if = "String::is_empty")]
    pub rule: String,
    /// connection id, on "flow" and "close"
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cid: String,
    /// DNS query type, on "dns"
    #[serde(skip_serializing_if = "zero_i32")]
    pub qtype: i32,
    /// why a DNS query failed, on "dns"
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

/// How many recent events are kept.
pub const JOURNAL_SIZE: usize = 2000;

/// A name and how often it was seen, for /api/stats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Count {
    pub name: String,
    pub count: i64,
}

struct Ring {
    /// oldest first once full
    buf: Vec<Event>,
    /// next write position once full
    head: usize,
    next: i64,
    apps: HashMap<String, i64>,
    domains: HashMap<String, i64>,
}

/// The most recent events and running counts for the UI.
pub struct Journal {
    ring: Mutex<Ring>,

    pub flows: AtomicI64,
    pub flows_blocked: AtomicI64,
    pub dns_queries: AtomicI64,
    pub dns_failed: AtomicI64,
    /// bogus answers blocked by the DNSSEC switch
    pub dns_bogus: AtomicI64,
    /// queries blocked by domain rules or query type
    pub dns_blocked: AtomicI64,
    pub dns_last_ms: AtomicI64,
    pub dns_total_ms: AtomicI64,
    pub rx: AtomicI64,
    pub tx: AtomicI64,
}

impl Default for Journal {
    fn default() -> Self {
        Self::new()
    }
}

/// Now, in unix millis.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl Journal {
    pub fn new() -> Journal {
        Journal {
            ring: Mutex::new(Ring {
                buf: Vec::with_capacity(JOURNAL_SIZE),
                head: 0,
                next: 1,
                apps: HashMap::new(),
                domains: HashMap::new(),
            }),
            flows: AtomicI64::new(0),
            flows_blocked: AtomicI64::new(0),
            dns_queries: AtomicI64::new(0),
            dns_failed: AtomicI64::new(0),
            dns_bogus: AtomicI64::new(0),
            dns_blocked: AtomicI64::new(0),
            dns_last_ms: AtomicI64::new(0),
            dns_total_ms: AtomicI64::new(0),
            rx: AtomicI64::new(0),
            tx: AtomicI64::new(0),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Ring> {
        // a panic while holding it leaves only counts: keep serving them
        self.ring.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Adds e with the next id, stamped now unless it has a time.
    pub fn add(&self, mut e: Event) {
        let mut j = self.lock();
        e.id = j.next;
        j.next += 1;
        if e.at == 0 {
            e.at = now_ms();
        }
        if e.kind == "flow" && !e.app.is_empty() {
            *j.apps.entry(e.app.clone()).or_insert(0) += 1;
        }
        if !e.domain.is_empty() {
            *j.domains.entry(e.domain.clone()).or_insert(0) += 1;
        }
        if j.buf.len() < JOURNAL_SIZE {
            j.buf.push(e);
            return;
        }
        let h = j.head;
        j.buf[h] = e;
        j.head = (h + 1) % JOURNAL_SIZE;
    }

    /// Up to max events with an id above after, oldest first.
    pub fn since(&self, after: i64, max: usize) -> Vec<Event> {
        let j = self.lock();
        let n = j.buf.len();
        let mut out = Vec::with_capacity(max.min(n));
        for i in 0..n {
            let e = &j.buf[(j.head + i) % n];
            if e.id > after {
                out.push(e.clone());
            }
        }
        if out.len() > max {
            out.drain(..out.len() - max);
        }
        out
    }

    /// The n most frequent apps and domains seen so far.
    pub fn top(&self, n: usize) -> (Vec<Count>, Vec<Count>) {
        let j = self.lock();
        (top_of(&j.apps, n), top_of(&j.domains, n))
    }

    pub fn apps_seen(&self) -> usize {
        self.lock().apps.len()
    }

    pub fn get(c: &AtomicI64) -> i64 {
        c.load(Ordering::Relaxed)
    }

    pub fn bump(c: &AtomicI64, by: i64) {
        c.fetch_add(by, Ordering::Relaxed);
    }
}

/// Most seen first, then by name.
fn top_of(m: &HashMap<String, i64>, n: usize) -> Vec<Count> {
    let mut out: Vec<Count> = m.iter().map(|(k, v)| Count { name: k.clone(), count: *v }).collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    out.truncate(n);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(app: &str, domain: &str) -> Event {
        Event { kind: "flow".into(), app: app.into(), domain: domain.into(), ..Default::default() }
    }

    #[test]
    fn ring_keeps_the_newest() {
        let j = Journal::new();
        for i in 0..JOURNAL_SIZE + 5 {
            j.add(flow("a.exe", &format!("d{}", i % 3)));
        }
        let all = j.since(0, JOURNAL_SIZE);
        assert_eq!(all.len(), JOURNAL_SIZE);
        assert_eq!(all[0].id, 6, "the five oldest are gone");
        assert_eq!(all.last().unwrap().id, (JOURNAL_SIZE + 5) as i64);
        assert!(all.windows(2).all(|w| w[0].id < w[1].id), "oldest first");
        let tail = j.since(0, 3);
        assert_eq!(tail.iter().map(|e| e.id).collect::<Vec<_>>(), vec![2003, 2004, 2005], "the newest max");
        assert_eq!(j.since(2004, 200).len(), 1);
        assert!(j.since(5000, 200).is_empty());
        assert!(all.iter().all(|e| e.at > 0));
    }

    #[test]
    fn counts() {
        let j = Journal::new();
        j.add(flow("b.exe", "x.com"));
        j.add(flow("a.exe", "y.com"));
        j.add(flow("b.exe", "x.com"));
        j.add(Event { kind: "dns".into(), app: "c.exe".into(), domain: "x.com".into(), ..Default::default() });
        let (apps, domains) = j.top(20);
        assert_eq!(apps, vec![Count { name: "b.exe".into(), count: 2 }, Count { name: "a.exe".into(), count: 1 }]);
        assert_eq!(domains[0], Count { name: "x.com".into(), count: 3 });
        assert_eq!(j.apps_seen(), 2, "dns events do not count apps");
        assert_eq!(j.top(1).0.len(), 1);
        assert!(Journal::new().top(20).0.is_empty());
    }

    #[test]
    fn json_like_go() {
        let e = Event { id: 7, at: 1, kind: "dns".into(), domain: "a.com".into(), qtype: 28, ..Default::default() };
        assert_eq!(serde_json::to_string(&e).unwrap(), r#"{"id":7,"at":1,"kind":"dns","domain":"a.com","qtype":28}"#);
        let e = Event {
            id: 1, at: 2, kind: "close".into(), app: "a".into(), path: "p".into(), proto: "tcp".into(), dst: "d".into(),
            domain: "x".into(), country: "US".into(), answer: "1.1.1.1".into(), via: "direct".into(), latency_ms: 3,
            blocked: true, rx: 4, tx: 5, dur_ms: 6, secure: true, cached: true, rule: "r".into(), cid: "9".into(),
            qtype: 1, error: "e".into(),
        };
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"id":1,"at":2,"kind":"close","app":"a","path":"p","proto":"tcp","dst":"d","domain":"x","country":"US","answer":"1.1.1.1","via":"direct","latencyMs":3,"blocked":true,"rx":4,"tx":5,"durMs":6,"secure":true,"cached":true,"rule":"r","cid":"9","qtype":1,"error":"e"}"#
        );
    }
}
