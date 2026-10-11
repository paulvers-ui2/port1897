// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The cached transport (firestack's dnsx cached transport, the `Cache`
//! id prefix): the DNS booster `-dns-cache` turns on. It wraps another
//! transport and answers a repeat lookup from memory while the answer's
//! TTL lasts, with the TTL counted down so clients expire it when the
//! real answer would have.
//!
//! The engine asks for it by prefixing the transport id with `Cache`
//! (`engine::CT`), as the Android app does for its DNS booster, so the
//! id the journal shows is `CachePreferred`.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, ResponseCode};

use super::{BoxFuture, QueryError, SharedClock, Transport, msg};
use crate::engine::{self, CT, DnsSummary};

/// An answer is kept at least this long: a one-second TTL still boosts
/// the burst of lookups an app makes when it starts.
pub const MIN_TTL: u32 = 10;
/// And at most this long, so a stale answer cannot outlive a network
/// change by much.
pub const MAX_TTL: u32 = 1800;
/// How many answers are kept. Past this the expired ones go first, and
/// then the whole cache: a DNS cache that forgets is correct, only
/// slower.
pub const MAX_ENTRIES: usize = 10_000;

/// What a cache entry is keyed by: the name as the resolver reads it
/// (lowercased, no trailing dot), the type and the class.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    qname: String,
    qtype: u16,
    class: u16,
}

struct Entry {
    /// the answer as it came, without its TTLs counted down
    answer: Message,
    /// when it was stored
    at: Duration,
    /// how long it may be served for
    ttl: u32,
    /// the server that answered, for the summary
    server: String,
}

/// A transport that answers from memory while an answer is fresh.
pub struct Cached {
    id: String,
    inner: Arc<dyn Transport>,
    clock: SharedClock,
    entries: Mutex<HashMap<Key, Entry>>,
    status: AtomicI32,
}

impl Cached {
    /// Wraps `inner`; the id is `Cache` + the inner id.
    pub fn new(inner: Arc<dyn Transport>, clock: SharedClock) -> Cached {
        Cached {
            id: format!("{CT}{}", inner.id()),
            inner,
            clock,
            entries: Mutex::new(HashMap::new()),
            status: AtomicI32::new(engine::DNS_START),
        }
    }

    /// The transport the answers come from.
    pub fn inner(&self) -> &Arc<dyn Transport> {
        &self.inner
    }

    /// How many answers are held (tests, and `/api/stats` later).
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Forgets everything, as a network change must.
    pub fn clear(&self) {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    fn key(q: &Message) -> Option<Key> {
        let question = q.queries.first()?;
        Some(Key {
            qname: msg::qname(q),
            qtype: u16::from(question.query_type()),
            class: u16::from(question.query_class()),
        })
    }

    /// The answer for q if one is fresh, with its TTLs counted down and
    /// the asker's id and question echoed back.
    fn hit(&self, key: &Key, q: &Message) -> Option<(Message, String)> {
        let now = self.clock.now();
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let e = map.get(key)?;
        let gone = now.saturating_sub(e.at).as_secs();
        let left = u64::from(e.ttl).saturating_sub(gone);
        if left == 0 {
            map.remove(key);
            return None;
        }
        let mut m = e.answer.clone();
        let server = e.server.clone();
        drop(map);
        // the asker's transaction id and its spelling of the name
        m.metadata.id = q.metadata.id;
        m.queries = q.queries.clone();
        msg::with_ttl(&mut m, left as u32);
        Some((m, server))
    }

    /// Stores an answer worth storing. Only NOERROR and NXDOMAIN are
    /// kept: a SERVFAIL or a REFUSED is the server's trouble of the
    /// moment, not an answer.
    fn put(&self, key: Key, answer: &Message, server: &str) {
        let rc = answer.metadata.response_code;
        if rc != ResponseCode::NoError && rc != ResponseCode::NXDomain {
            return;
        }
        if answer.metadata.truncation {
            return;
        }
        let ttl = msg::rttl(answer).clamp(MIN_TTL, MAX_TTL);
        let now = self.clock.now();
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= MAX_ENTRIES && !map.contains_key(&key) {
            map.retain(|_, e| now.saturating_sub(e.at).as_secs() < u64::from(e.ttl));
            if map.len() >= MAX_ENTRIES {
                map.clear();
            }
        }
        map.insert(key, Entry { answer: answer.clone(), at: now, ttl, server: server.to_string() });
    }
}

impl Transport for Cached {
    fn id(&self) -> &str {
        &self.id
    }

    fn addr(&self) -> String {
        self.inner.addr()
    }

    fn status(&self) -> i32 {
        self.status.load(Ordering::Relaxed)
    }

    fn query<'a>(&'a self, pid: &'a str, q: &'a [u8], smm: &'a mut DnsSummary) -> BoxFuture<'a, Result<Vec<u8>, QueryError>> {
        Box::pin(async move {
            let start = Instant::now();
            let query = msg::parse(q).map_err(|e| {
                let e = QueryError::new(engine::DNS_BAD_QUERY, e);
                super::doh::fill(smm, &self.addr(), start, &Err(e.clone()));
                self.status.store(smm.status, Ordering::Relaxed);
                e
            })?;
            let key = Self::key(&query);
            if let Some(key) = key.as_ref()
                && let Some((answer, server)) = self.hit(key, &query) {
                    let wire = msg::pack(&answer).map_err(|e| QueryError::new(engine::DNS_INTERNAL_ERROR, e))?;
                    let r = Ok(wire);
                    super::doh::fill(smm, &server, start, &r);
                    smm.cached = true;
                    self.status.store(smm.status, Ordering::Relaxed);
                    return r;
                }
            let r = self.inner.query(pid, q, smm).await;
            // the inner transport filled the summary; only `cached` is ours
            smm.cached = false;
            self.status.store(smm.status, Ordering::Relaxed);
            if let (Ok(wire), Some(key)) = (&r, key)
                && let Ok(answer) = msg::parse(wire) {
                    let server = if smm.server.is_empty() { self.inner.addr() } else { smm.server.clone() };
                    self.put(key, &answer, &server);
                }
            r
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{Clock, FakeClock, SystemClock};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{RData, Record, RecordType};
    use std::net::Ipv4Addr;
    use std::sync::atomic::AtomicUsize;

    /// A transport that answers from a script and counts its calls.
    struct Fake {
        id: String,
        calls: AtomicUsize,
        ttl: u32,
        rcode: ResponseCode,
        fail: bool,
    }

    impl Fake {
        fn new(ttl: u32) -> Arc<Fake> {
            Arc::new(Fake { id: "Preferred".to_string(), calls: AtomicUsize::new(0), ttl, rcode: ResponseCode::NoError, fail: false })
        }
    }

    impl Transport for Fake {
        fn id(&self) -> &str {
            &self.id
        }

        fn addr(&self) -> String {
            "cloudflare-dns.com".to_string()
        }

        fn status(&self) -> i32 {
            engine::DNS_COMPLETE
        }

        fn query<'a>(&'a self, _pid: &'a str, q: &'a [u8], smm: &'a mut DnsSummary) -> BoxFuture<'a, Result<Vec<u8>, QueryError>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let start = Instant::now();
                let r = if self.fail {
                    Err(QueryError::new(engine::DNS_NO_RESPONSE, "the DNS server did not answer"))
                } else {
                    let query = msg::parse(q).unwrap();
                    let mut a = msg::empty_response(&query).unwrap();
                    a.metadata.response_code = self.rcode;
                    if self.rcode == ResponseCode::NoError {
                        let n = query.queries[0].name().clone();
                        a.answers.push(Record::from_rdata(n, self.ttl, RData::A(A(Ipv4Addr::new(93, 184, 215, 14)))));
                    }
                    Ok(msg::pack(&a).unwrap())
                };
                super::super::doh::fill(smm, &self.addr(), start, &r);
                r
            })
        }
    }

    fn query(name: &str) -> Vec<u8> {
        msg::pack(&msg::test_query(name, RecordType::A)).unwrap()
    }

    fn cached(inner: Arc<dyn Transport>, clock: Arc<FakeClock>) -> Cached {
        Cached::new(inner, clock)
    }

    #[tokio::test]
    async fn answers_once_then_from_memory() {
        let f = Fake::new(300);
        let clock = Arc::new(FakeClock::default());
        let c = cached(f.clone(), clock.clone());
        assert_eq!(c.id(), "CachePreferred");
        assert_eq!(c.addr(), "cloudflare-dns.com");

        let mut smm = DnsSummary::default();
        let a1 = c.query("Base", &query("example.com."), &mut smm).await.unwrap();
        assert_eq!(f.calls.load(Ordering::SeqCst), 1);
        assert!(!smm.cached);
        assert_eq!(smm.rdata, "93.184.215.14");
        assert_eq!(smm.status, engine::DNS_COMPLETE);
        assert_eq!(msg::rttl(&msg::parse(&a1).unwrap()), 300);
        assert_eq!(c.len(), 1);

        // 30 s later the answer comes from memory, with 270 s left
        clock.advance(Duration::from_secs(30));
        let mut smm2 = DnsSummary::default();
        let a2 = c.query("Base", &query("example.com."), &mut smm2).await.unwrap();
        assert_eq!(f.calls.load(Ordering::SeqCst), 1, "the inner transport was asked again");
        assert!(smm2.cached);
        assert_eq!(smm2.rdata, "93.184.215.14");
        assert_eq!(smm2.server, "cloudflare-dns.com");
        assert_eq!(smm2.status, engine::DNS_COMPLETE);
        let m = msg::parse(&a2).unwrap();
        assert_eq!(msg::rttl(&m), 270);
        assert_eq!(m.metadata.id, 0x1234);

        // once it has run out, the inner transport answers again
        clock.advance(Duration::from_secs(271));
        let mut smm3 = DnsSummary::default();
        c.query("Base", &query("example.com."), &mut smm3).await.unwrap();
        assert_eq!(f.calls.load(Ordering::SeqCst), 2);
        assert!(!smm3.cached);
    }

    #[tokio::test]
    async fn the_asker_gets_its_own_id_and_spelling() {
        let f = Fake::new(60);
        let clock = Arc::new(FakeClock::default());
        let c = cached(f.clone(), clock);

        let mut smm = DnsSummary::default();
        c.query("Base", &query("example.com."), &mut smm).await.unwrap();

        // a second asker, different transaction id and different case
        let mut q2 = msg::test_query("Example.COM.", RecordType::A);
        q2.metadata.id = 0x4321;
        let mut smm2 = DnsSummary::default();
        let a = c.query("Base", &msg::pack(&q2).unwrap(), &mut smm2).await.unwrap();
        assert!(smm2.cached, "the name's case must not miss the cache");
        let m = msg::parse(&a).unwrap();
        assert_eq!(m.metadata.id, 0x4321, "the asker's own transaction id comes back");
        // hickory lowercases the names it decodes, so the question comes
        // back lowercased either way; what matters is that it is the
        // name that was asked for
        assert_eq!(m.queries[0].name().to_ascii().to_ascii_lowercase(), "example.com.");
        assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn the_type_is_part_of_the_key() {
        let f = Fake::new(60);
        let clock = Arc::new(FakeClock::default());
        let c = cached(f.clone(), clock);
        let mut smm = DnsSummary::default();
        c.query("Base", &query("example.com."), &mut smm).await.unwrap();
        let aaaa = msg::pack(&msg::test_query("example.com.", RecordType::AAAA)).unwrap();
        let mut smm2 = DnsSummary::default();
        c.query("Base", &aaaa, &mut smm2).await.unwrap();
        assert!(!smm2.cached);
        assert_eq!(f.calls.load(Ordering::SeqCst), 2);
        assert_eq!(c.len(), 2);
    }

    #[tokio::test]
    async fn ttls_are_clamped() {
        // a zero TTL is still held for MIN_TTL
        let f = Fake::new(0);
        let clock = Arc::new(FakeClock::default());
        let c = cached(f.clone(), clock.clone());
        let mut smm = DnsSummary::default();
        c.query("Base", &query("quick.example."), &mut smm).await.unwrap();
        clock.advance(Duration::from_secs(u64::from(MIN_TTL) - 1));
        let mut smm2 = DnsSummary::default();
        c.query("Base", &query("quick.example."), &mut smm2).await.unwrap();
        assert!(smm2.cached);
        assert_eq!(f.calls.load(Ordering::SeqCst), 1);

        // and a very long one no longer than MAX_TTL
        let f2 = Fake::new(86400);
        let clock2 = Arc::new(FakeClock::default());
        let c2 = cached(f2.clone(), clock2.clone());
        let mut smm3 = DnsSummary::default();
        let a = c2.query("Base", &query("slow.example."), &mut smm3).await.unwrap();
        assert_eq!(msg::rttl(&msg::parse(&a).unwrap()), 86400, "the first answer is passed through as it came");
        clock2.advance(Duration::from_secs(u64::from(MAX_TTL) + 1));
        let mut smm4 = DnsSummary::default();
        c2.query("Base", &query("slow.example."), &mut smm4).await.unwrap();
        assert!(!smm4.cached);
        assert_eq!(f2.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn failures_and_servfail_are_not_kept() {
        let mut f = Fake { id: "Preferred".into(), calls: AtomicUsize::new(0), ttl: 60, rcode: ResponseCode::ServFail, fail: false };
        f.fail = false;
        let f = Arc::new(f);
        let clock = Arc::new(FakeClock::default());
        let c = cached(f.clone(), clock);
        let mut smm = DnsSummary::default();
        c.query("Base", &query("broken.example."), &mut smm).await.unwrap();
        assert_eq!(c.len(), 0, "a SERVFAIL must not be cached");

        let bad = Arc::new(Fake { id: "Preferred".into(), calls: AtomicUsize::new(0), ttl: 60, rcode: ResponseCode::NoError, fail: true });
        let c2 = cached(bad.clone(), Arc::new(FakeClock::default()));
        let mut smm2 = DnsSummary::default();
        let e = c2.query("Base", &query("down.example."), &mut smm2).await.unwrap_err();
        assert_eq!(e.status, engine::DNS_NO_RESPONSE);
        assert_eq!(smm2.status, engine::DNS_NO_RESPONSE);
        assert!(!smm2.cached);
        assert_eq!(c2.len(), 0);
    }

    #[tokio::test]
    async fn nxdomain_is_kept() {
        let f = Arc::new(Fake { id: "Preferred".into(), calls: AtomicUsize::new(0), ttl: 60, rcode: ResponseCode::NXDomain, fail: false });
        let c = cached(f.clone(), Arc::new(FakeClock::default()));
        let mut smm = DnsSummary::default();
        c.query("Base", &query("nope.example."), &mut smm).await.unwrap();
        assert_eq!(c.len(), 1);
        let mut smm2 = DnsSummary::default();
        c.query("Base", &query("nope.example."), &mut smm2).await.unwrap();
        assert!(smm2.cached);
        assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_bad_query_is_refused_before_the_inner_transport() {
        let f = Fake::new(60);
        let c = cached(f.clone(), Arc::new(FakeClock::default()));
        let mut smm = DnsSummary::default();
        let e = c.query("Base", &[0u8; 4], &mut smm).await.unwrap_err();
        assert_eq!(e.status, engine::DNS_BAD_QUERY);
        assert_eq!(smm.status, engine::DNS_BAD_QUERY);
        assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn clear_forgets() {
        let f = Fake::new(300);
        let c = cached(f.clone(), Arc::new(FakeClock::default()));
        let mut smm = DnsSummary::default();
        c.query("Base", &query("example.com."), &mut smm).await.unwrap();
        assert!(!c.is_empty());
        c.clear();
        assert!(c.is_empty());
        let mut smm2 = DnsSummary::default();
        c.query("Base", &query("example.com."), &mut smm2).await.unwrap();
        assert_eq!(f.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn the_real_clock_moves_forward() {
        let c = SystemClock::default();
        assert!(c.now() < Duration::from_secs(1));
    }
}
