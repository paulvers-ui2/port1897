// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The fake DNS server behind 10.111.222.3:53 (firestack's dnsx
//! resolver, reached through the netstack's DNS trap): every query the
//! tunnel sees goes to the engine for a verdict, then to the transport
//! the verdict names, and the answer and its timing go back to the
//! journal.
//!
//! What the engine decides is already ported (`Engine::on_query`,
//! `on_upstream_answer`, `on_response`); this is the part that carries a
//! query to a transport and an answer back:
//!
//! 1. `on_query` gives the transport id (`Preferred`, `System`,
//!    `CachePreferred`, ... or `BlockAll`) and the exit the query leaves
//!    by (`Base` for the physical interface),
//! 2. `BlockAll` is answered here, without a server: 0.0.0.0 / :: or
//!    HINFO, as the rules' blocked answer (`msg::block_answer`),
//! 3. anything else goes to the registered transport, with the cached
//!    transport made on demand for a `Cache`-prefixed id,
//! 4. `on_upstream_answer` may still refuse the answer (the DNSSEC
//!    switch, on a public name answered with a bogon address), and then
//!    it is answered by `BlockAll` after all,
//! 5. `on_response` records the summary either way.
//!
//! The sockets are not here: the netstack owns them and hands the query
//! bytes to a [`Resolver`], so this whole path is tested without a
//! tunnel and without admin rights.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use hickory_proto::op::Message;

use super::cache::Cached;
use super::{BoxFuture, QueryError, SharedClock, SystemClock, Transport, msg};
use crate::engine::{self, BLOCK_ALL, CT, DnsSummary, Engine};
use crate::exit::BASE;

/// The id of the bootstrap transport: the `-fallback-doh` server (or
/// `-doh` when there is none), which also answers for the chosen
/// transport when `-dns-fallback` is on. firestack's `Default`.
pub const DEFAULT: &str = "Default";

/// What the netstack hands a port-53 query to.
pub trait Resolver: Send + Sync {
    /// Answers a query in wire format. `uid` is the asking app's uid as
    /// a decimal string (`""` when it is not known), which the journal
    /// turns back into the app's name.
    ///
    /// An answer comes back for anything that can be answered at all,
    /// including a failure as SERVFAIL, the way firestack answers one.
    /// `Err` means there is nothing to answer: the query was not a DNS
    /// message, and the caller drops it.
    fn resolve<'a>(&'a self, uid: &'a str, q: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>, QueryError>>;
}

/// The resolver: the transports by id, and the engine that decides.
pub struct FakeDns {
    engine: Arc<Engine>,
    transports: RwLock<HashMap<String, Arc<dyn Transport>>>,
    /// cached wrappers, made on demand, keyed by their own id
    cached: RwLock<HashMap<String, Arc<Cached>>>,
    clock: SharedClock,
    fallback: AtomicBool,
}

impl FakeDns {
    pub fn new(engine: Arc<Engine>) -> FakeDns {
        FakeDns::with_clock(engine, Arc::new(SystemClock::default()))
    }

    pub fn with_clock(engine: Arc<Engine>, clock: SharedClock) -> FakeDns {
        FakeDns {
            engine,
            transports: RwLock::new(HashMap::new()),
            cached: RwLock::new(HashMap::new()),
            clock,
            fallback: AtomicBool::new(false),
        }
    }

    /// Registers a transport under its own id, replacing one of that id.
    /// Its cached wrapper, if it had one, is dropped with it: the new
    /// server must not answer from the old one's memory.
    pub fn add(&self, t: Arc<dyn Transport>) {
        let id = t.id().to_string();
        self.cached.write().unwrap_or_else(|e| e.into_inner()).remove(&format!("{CT}{id}"));
        self.transports.write().unwrap_or_else(|e| e.into_inner()).insert(id, t);
    }

    /// Forgets a transport and its cached wrapper.
    pub fn remove(&self, id: &str) {
        self.cached.write().unwrap_or_else(|e| e.into_inner()).remove(&format!("{CT}{id}"));
        self.transports.write().unwrap_or_else(|e| e.into_inner()).remove(id);
    }

    /// `-dns-fallback`: the `Default` transport answers when the chosen
    /// one fails (firestack's `DefaultDNSAsFallback`).
    pub fn set_fallback(&self, on: bool) {
        self.fallback.store(on, Ordering::Relaxed);
    }

    /// The registered ids, sorted.
    pub fn ids(&self) -> Vec<String> {
        let mut v: Vec<String> = self.transports.read().unwrap_or_else(|e| e.into_inner()).keys().cloned().collect();
        v.sort();
        v
    }

    /// Forgets every cached answer, as a network change must.
    pub fn clear_cache(&self) {
        for c in self.cached.read().unwrap_or_else(|e| e.into_inner()).values() {
            c.clear();
        }
    }

    /// The transport for an id, with the cached wrapper made on demand
    /// for a `Cache`-prefixed one. None when nothing is registered for
    /// it.
    pub fn transport(&self, id: &str) -> Option<Arc<dyn Transport>> {
        if let Some(inner_id) = id.strip_prefix(CT) {
            if let Some(c) = self.cached.read().unwrap_or_else(|e| e.into_inner()).get(id) {
                return Some(c.clone());
            }
            let inner = self.transports.read().unwrap_or_else(|e| e.into_inner()).get(inner_id).cloned()?;
            let mut map = self.cached.write().unwrap_or_else(|e| e.into_inner());
            // another query may have made it while we had no lock
            let c = map.entry(id.to_string()).or_insert_with(|| Arc::new(Cached::new(inner, self.clock.clone())));
            return Some(c.clone());
        }
        self.transports.read().unwrap_or_else(|e| e.into_inner()).get(id).cloned()
    }

    /// Answers the query, and records it.
    async fn answer(&self, uid: &str, q: &[u8]) -> Result<Vec<u8>, QueryError> {
        let start = Instant::now();
        let query = match msg::parse(q) {
            Ok(m) => m,
            Err(e) => {
                // nothing to answer: no id and no question to echo
                let smm = DnsSummary {
                    uid: uid.to_string(),
                    status: engine::DNS_BAD_QUERY,
                    rcode: 1,
                    msg: e.clone(),
                    latency: start.elapsed().as_secs_f64(),
                    ..Default::default()
                };
                self.engine.on_response(&smm);
                return Err(QueryError::new(engine::DNS_BAD_QUERY, e));
            }
        };
        let qname = msg::qname(&query);
        let qtype = msg::qtype(&query);
        let opts = self.engine.on_query(&qname, i32::from(qtype));
        let pid = first(&opts.pid, BASE);
        let mut smm = DnsSummary { uid: uid.to_string(), qname: qname.clone(), qtype: i32::from(qtype), ..Default::default() };

        let mut answer: Option<Vec<u8>> = None;
        let mut tried: Vec<String> = Vec::new();
        for tid in ids_of(&opts.tid) {
            tried.push(tid.clone());
            match self.query_one(&tid, pid, q, &query, &mut smm).await {
                Some(wire) => {
                    answer = Some(wire);
                    break;
                }
                None => continue,
            }
        }
        // -dns-fallback: the bootstrap server has a go when the chosen
        // transport could not answer
        if answer.is_none() && self.fallback.load(Ordering::Relaxed) && !tried.iter().any(|t| t == DEFAULT) {
            if let Some(wire) = self.query_one(DEFAULT, pid, q, &query, &mut smm).await {
                answer = Some(wire);
            }
        }

        let wire = match answer {
            Some(wire) => wire,
            None => {
                if smm.status == engine::DNS_COMPLETE || smm.status == engine::DNS_START {
                    // no transport took the query at all
                    smm.status = engine::DNS_TRANSPORT_ERROR;
                    smm.rcode = 2;
                    if smm.msg.is_empty() {
                        smm.msg = format!("no DNS transport {}", tried.join(","));
                    }
                }
                if smm.id.is_empty() {
                    smm.id = first(&opts.tid, engine::PREFERRED).to_string();
                }
                // as firestack does: the asker gets SERVFAIL, the
                // journal gets the reason
                self.engine.on_response(&smm);
                return msg::servfail(&query)
                    .and_then(|m| msg::pack(&m).ok())
                    .ok_or_else(|| QueryError::new(smm.status, smm.msg.clone()));
            }
        };

        // the DNSSEC switch may still refuse the answer
        let parsed = msg::parse(&wire).ok();
        let ip_csv = msg::ip_csv(&msg::ips(parsed.as_ref().unwrap_or(&query)));
        let wire = match self.engine.on_upstream_answer(Some(&smm), &ip_csv) {
            Some(block) => {
                let blocked = self.block(&query, &block.tid, &mut smm);
                // the real query's latency stays; only the answer changed
                blocked.unwrap_or(wire)
            }
            None => wire,
        };
        self.engine.on_response(&smm);
        Ok(wire)
    }

    /// Asks one transport (or answers BlockAll here). None when it could
    /// not answer; the summary carries why.
    async fn query_one(&self, tid: &str, pid: &str, q: &[u8], query: &Message, smm: &mut DnsSummary) -> Option<Vec<u8>> {
        if is_block_all(tid) {
            return self.block(query, tid, smm);
        }
        let t = match self.transport(tid) {
            Some(t) => t,
            None => {
                smm.id = tid.to_string();
                smm.status = engine::DNS_TRANSPORT_ERROR;
                smm.rcode = 2;
                smm.msg = format!("no DNS transport {tid}");
                return None;
            }
        };
        smm.id = t.id().to_string();
        t.query(pid, q, smm).await.ok()
    }

    /// The blocked answer the rules ask for, recorded under `tid` so the
    /// journal shows why it was blocked.
    fn block(&self, query: &Message, tid: &str, smm: &mut DnsSummary) -> Option<Vec<u8>> {
        let m = msg::block_answer(query)?;
        let wire = msg::pack(&m).ok()?;
        smm.id = tid.to_string();
        // BlockAll has no server, and answers at once
        smm.server = String::new();
        smm.cached = false;
        smm.rdata = msg::interesting_rdata(Some(&m));
        smm.rcode = msg::rcode(&m);
        smm.ad = false;
        smm.status = engine::DNS_COMPLETE;
        smm.msg = String::new();
        Some(wire)
    }
}

impl Resolver for FakeDns {
    fn resolve<'a>(&'a self, uid: &'a str, q: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>, QueryError>> {
        Box::pin(self.answer(uid, q))
    }
}

/// Whether an id names the BlockAll transport, cached or not: the engine
/// does not wrap BlockAll, but a `Cache`-prefixed one is still BlockAll
/// (`on_response` matches it with `ends_with`).
fn is_block_all(tid: &str) -> bool {
    tid == BLOCK_ALL || tid == format!("{CT}{BLOCK_ALL}")
}

/// The ids of a TIDCSV, in order, without the empty ones. `def` when it
/// names none.
fn ids_of(csv: &str) -> Vec<String> {
    let v: Vec<String> = csv.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).map(|s| s.to_string()).collect();
    if v.is_empty() { vec![engine::PREFERRED.to_string()] } else { v }
}

/// The first id of a csv, or `def`.
fn first<'a>(csv: &'a str, def: &'a str) -> &'a str {
    csv.split(',').map(|s| s.trim()).find(|s| !s.is_empty()).unwrap_or(def)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::FakeClock;
    use crate::engine::{PREFERRED, SYSTEM};
    use crate::rules::{ACT_BLOCK, DomainRule, RuleSet};
    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::{RData, Record, RecordType};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    /// A transport that answers with the address it was made with, or
    /// fails, and counts its calls.
    struct Fake {
        id: String,
        ip: Option<Ipv4Addr>,
        v6: Option<Ipv6Addr>,
        fail: Option<(i32, String)>,
        ttl: u32,
        calls: AtomicUsize,
    }

    impl Fake {
        fn ok(id: &str, ip: [u8; 4]) -> Arc<Fake> {
            Arc::new(Fake {
                id: id.to_string(),
                ip: Some(Ipv4Addr::from(ip)),
                v6: None,
                fail: None,
                ttl: 300,
                calls: AtomicUsize::new(0),
            })
        }

        fn broken(id: &str, status: i32, msg: &str) -> Arc<Fake> {
            Arc::new(Fake {
                id: id.to_string(),
                ip: None,
                v6: None,
                fail: Some((status, msg.to_string())),
                ttl: 0,
                calls: AtomicUsize::new(0),
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Transport for Fake {
        fn id(&self) -> &str {
            &self.id
        }

        fn addr(&self) -> String {
            format!("{}.example", self.id.to_lowercase())
        }

        fn status(&self) -> i32 {
            engine::DNS_COMPLETE
        }

        fn query<'a>(&'a self, _pid: &'a str, q: &'a [u8], smm: &'a mut DnsSummary) -> BoxFuture<'a, Result<Vec<u8>, QueryError>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let start = Instant::now();
                let r = match &self.fail {
                    Some((status, m)) => Err(QueryError::new(*status, m.clone())),
                    None => {
                        let query = msg::parse(q).unwrap();
                        let mut a = msg::empty_response(&query).unwrap();
                        a.metadata.authentic_data = true;
                        let n = query.queries[0].name().clone();
                        if let Some(ip) = self.ip {
                            a.answers.push(Record::from_rdata(n.clone(), self.ttl, RData::A(A(ip))));
                        }
                        if let Some(ip) = self.v6 {
                            a.answers.push(Record::from_rdata(n, self.ttl, RData::AAAA(AAAA(ip))));
                        }
                        Ok(msg::pack(&a).unwrap())
                    }
                };
                crate::dns::doh::fill(smm, &self.addr(), start, &r);
                r
            })
        }
    }

    /// An engine whose log lines the test can read. `setup` sets the
    /// switches that are plain fields, before the engine is shared.
    fn engine_with(setup: impl FnOnce(&mut Engine)) -> (Arc<Engine>, Arc<Mutex<Vec<String>>>) {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let l = lines.clone();
        let mut e = Engine::with_self(None, "", r"C:\x\fswin.exe", Box::new(move |s: &str| l.lock().unwrap().push(s.to_string())));
        setup(&mut e);
        (Arc::new(e), lines)
    }

    fn engine() -> (Arc<Engine>, Arc<Mutex<Vec<String>>>) {
        engine_with(|_| {})
    }

    fn query(name: &str, t: RecordType) -> Vec<u8> {
        msg::pack(&msg::test_query(name, t)).unwrap()
    }

    /// The one "dns" event the journal holds.
    fn dns_event(e: &Engine) -> crate::events::Event {
        let evs = e.log.since(0, 100);
        let mut dns: Vec<_> = evs.into_iter().filter(|x| x.kind == "dns").collect();
        assert_eq!(dns.len(), 1, "expected one dns event, got {dns:?}");
        dns.remove(0)
    }

    #[tokio::test]
    async fn a_query_goes_to_the_chosen_transport() {
        let (e, _log) = engine();
        let r = FakeDns::new(e.clone());
        let t = Fake::ok(PREFERRED, [93, 184, 215, 14]);
        r.add(t.clone());
        assert_eq!(r.ids(), vec![PREFERRED.to_string()]);

        let a = r.resolve("1234", &query("example.com.", RecordType::A)).await.unwrap();
        assert_eq!(t.calls(), 1);
        let m = msg::parse(&a).unwrap();
        assert_eq!(m.metadata.id, 0x1234);
        assert_eq!(msg::ips(&m), vec![std::net::IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14))]);

        let ev = dns_event(&e);
        assert_eq!(ev.domain, "example.com");
        assert_eq!(ev.via, PREFERRED);
        assert_eq!(ev.answer, "93.184.215.14");
        assert_eq!(ev.qtype, 1);
        assert!(!ev.blocked);
        assert!(ev.secure, "the AD bit must reach the journal");
        assert!(!ev.cached);
        assert!(ev.error.is_empty());
    }

    #[tokio::test]
    async fn the_rules_block_a_name_here() {
        let (e, _log) = engine();
        let mut rs = RuleSet::default();
        rs.domains.push(DomainRule { domain: "ads.example.com".into(), action: ACT_BLOCK.into(), ..Default::default() });
        e.set_rules(rs);
        let r = FakeDns::new(e.clone());
        let t = Fake::ok(PREFERRED, [93, 184, 215, 14]);
        r.add(t.clone());

        let a = r.resolve("", &query("ads.example.com.", RecordType::A)).await.unwrap();
        assert_eq!(t.calls(), 0, "a blocked name must not reach the server");
        let m = msg::parse(&a).unwrap();
        assert_eq!(m.metadata.response_code, ResponseCode::NoError);
        assert_eq!(msg::ips(&m), vec![std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED)]);

        let ev = dns_event(&e);
        assert_eq!(ev.via, BLOCK_ALL);
        assert_eq!(ev.answer, "0.0.0.0");
        assert!(ev.blocked);
        assert!(!ev.rule.is_empty(), "the journal must say which rule blocked it");
    }

    #[tokio::test]
    async fn an_unknown_transport_answers_servfail() {
        let (e, _log) = engine();
        let r = FakeDns::new(e.clone());
        // nothing registered at all
        let a = r.resolve("", &query("example.com.", RecordType::A)).await.unwrap();
        let m = msg::parse(&a).unwrap();
        assert_eq!(m.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(m.queries.len(), 1, "SERVFAIL echoes the question");
        assert_eq!(m.metadata.id, 0x1234);

        let ev = dns_event(&e);
        assert_eq!(ev.via, PREFERRED);
        assert_eq!(ev.error, "no DNS transport Preferred");
    }

    #[tokio::test]
    async fn a_failing_transport_answers_servfail_and_says_why() {
        let (e, _log) = engine();
        let r = FakeDns::new(e.clone());
        r.add(Fake::broken(PREFERRED, engine::DNS_NO_RESPONSE, ""));

        let a = r.resolve("", &query("example.com.", RecordType::A)).await.unwrap();
        assert_eq!(msg::parse(&a).unwrap().metadata.response_code, ResponseCode::ServFail);
        let ev = dns_event(&e);
        assert_eq!(ev.via, PREFERRED);
        assert_eq!(ev.error, "the DNS server did not answer");
    }

    #[tokio::test]
    async fn the_fallback_answers_when_the_chosen_transport_fails() {
        let (e, _log) = engine();
        let r = FakeDns::new(e.clone());
        let bad = Fake::broken(PREFERRED, engine::DNS_NO_RESPONSE, "");
        let def = Fake::ok(DEFAULT, [1, 1, 1, 1]);
        r.add(bad.clone());
        r.add(def.clone());

        // off by default: the failure stands
        let a = r.resolve("", &query("example.com.", RecordType::A)).await.unwrap();
        assert_eq!(msg::parse(&a).unwrap().metadata.response_code, ResponseCode::ServFail);
        assert_eq!(def.calls(), 0);

        r.set_fallback(true);
        let a = r.resolve("", &query("example.com.", RecordType::A)).await.unwrap();
        assert_eq!(def.calls(), 1);
        let m = msg::parse(&a).unwrap();
        assert_eq!(m.metadata.response_code, ResponseCode::NoError);
        assert_eq!(msg::ips(&m), vec![std::net::IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
        assert_eq!(bad.calls(), 2);

        let evs: Vec<_> = e.log.since(0, 100).into_iter().filter(|x| x.kind == "dns").collect();
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[1].via, DEFAULT, "the journal names the server that answered");
        assert_eq!(evs[1].answer, "1.1.1.1");
    }

    #[tokio::test]
    async fn the_dns_booster_answers_the_second_lookup() {
        let (e, _log) = engine_with(|e| e.dns_cache = true);
        let clock = Arc::new(FakeClock::default());
        let r = FakeDns::with_clock(e.clone(), clock.clone());
        let t = Fake::ok(PREFERRED, [93, 184, 215, 14]);
        r.add(t.clone());

        let _ = r.resolve("", &query("example.com.", RecordType::A)).await.unwrap();
        clock.advance(Duration::from_secs(5));
        let _ = r.resolve("", &query("example.com.", RecordType::A)).await.unwrap();
        assert_eq!(t.calls(), 1, "the second lookup must come from the cache");

        let evs: Vec<_> = e.log.since(0, 100).into_iter().filter(|x| x.kind == "dns").collect();
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].via, "CachePreferred");
        assert!(!evs[0].cached);
        assert!(evs[1].cached, "the journal must mark the cached answer");
        assert_eq!(evs[1].answer, "93.184.215.14");

        // a new server for the same id must not answer from the old memory
        r.add(Fake::ok(PREFERRED, [9, 9, 9, 9]));
        let a = r.resolve("", &query("example.com.", RecordType::A)).await.unwrap();
        assert_eq!(msg::ips(&msg::parse(&a).unwrap()), vec![std::net::IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
    }

    #[tokio::test]
    async fn the_dnssec_switch_blocks_a_bogus_answer() {
        let (e, log) = engine_with(|e| e.dnssec = true);
        let r = FakeDns::new(e.clone());
        // a public name answered with a private address
        r.add(Fake::ok(PREFERRED, [192, 168, 1, 1]));

        let a = r.resolve("", &query("bank.com.", RecordType::A)).await.unwrap();
        let m = msg::parse(&a).unwrap();
        assert_eq!(msg::ips(&m), vec![std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED)], "the bogus address must not reach the app");

        let ev = dns_event(&e);
        assert_eq!(ev.via, BLOCK_ALL);
        assert!(ev.blocked);
        assert_eq!(ev.rule, "DNSSEC: bogus answer 192.168.1.1");
        assert!(log.lock().unwrap().iter().any(|l| l.contains("dnssec: bank.com answered with bogus")));
    }

    #[tokio::test]
    async fn a_local_name_may_answer_with_a_private_address() {
        let (e, _log) = engine_with(|e| e.dnssec = true);
        let r = FakeDns::new(e.clone());
        r.add(Fake::ok(PREFERRED, [192, 168, 1, 1]));

        let a = r.resolve("", &query("printer.lan.", RecordType::A)).await.unwrap();
        assert_eq!(msg::ips(&msg::parse(&a).unwrap()), vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))]);
        assert!(!dns_event(&e).blocked);
    }

    #[tokio::test]
    async fn the_chosen_transport_follows_set_dns() {
        let (e, _log) = engine();
        let r = FakeDns::new(e.clone());
        let p = Fake::ok(PREFERRED, [1, 1, 1, 1]);
        let s = Fake::ok(SYSTEM, [192, 168, 0, 1]);
        r.add(p.clone());
        r.add(s.clone());
        e.set_dns(SYSTEM);

        let _ = r.resolve("", &query("example.com.", RecordType::A)).await.unwrap();
        assert_eq!(s.calls(), 1);
        assert_eq!(p.calls(), 0);
        assert_eq!(dns_event(&e).via, SYSTEM);
    }

    #[tokio::test]
    async fn a_query_that_is_not_dns_is_dropped() {
        let (e, _log) = engine();
        let r = FakeDns::new(e.clone());
        r.add(Fake::ok(PREFERRED, [1, 1, 1, 1]));
        let err = r.resolve("", &[0u8; 4]).await.unwrap_err();
        assert_eq!(err.status, engine::DNS_BAD_QUERY);
        // it is still recorded, so a client that sends rubbish is visible
        assert_eq!(dns_event(&e).error, "dns: packet too small");
    }

    #[tokio::test]
    async fn the_asking_app_reaches_the_journal() {
        let (e, _log) = engine();
        let uid = e.apps.uid(r"C:\Program Files\Google\Chrome\Application\chrome.exe");
        let r = FakeDns::new(e.clone());
        r.add(Fake::ok(PREFERRED, [1, 1, 1, 1]));

        let _ = r.resolve(&uid.to_string(), &query("example.com.", RecordType::A)).await.unwrap();
        let ev = dns_event(&e);
        assert_eq!(ev.app, "chrome.exe");
        assert_eq!(ev.path, r"C:\Program Files\Google\Chrome\Application\chrome.exe");
    }

    #[tokio::test]
    async fn transports_come_and_go() {
        let (e, _log) = engine();
        let r = FakeDns::new(e.clone());
        r.add(Fake::ok(PREFERRED, [1, 1, 1, 1]));
        assert!(r.transport(PREFERRED).is_some());
        assert!(r.transport(&format!("{CT}{PREFERRED}")).is_some(), "the cached wrapper is made on demand");
        assert!(r.transport("nope").is_none());
        assert!(r.transport(&format!("{CT}nope")).is_none());
        r.remove(PREFERRED);
        assert!(r.transport(PREFERRED).is_none());
        assert!(r.transport(&format!("{CT}{PREFERRED}")).is_none());
        assert!(r.ids().is_empty());
    }

    #[tokio::test]
    async fn clear_cache_forgets_every_answer() {
        let (e, _log) = engine_with(|e| e.dns_cache = true);
        let clock = Arc::new(FakeClock::default());
        let r = FakeDns::with_clock(e.clone(), clock);
        let t = Fake::ok(PREFERRED, [1, 1, 1, 1]);
        r.add(t.clone());
        let _ = r.resolve("", &query("example.com.", RecordType::A)).await.unwrap();
        let _ = r.resolve("", &query("example.com.", RecordType::A)).await.unwrap();
        assert_eq!(t.calls(), 1);
        r.clear_cache();
        let _ = r.resolve("", &query("example.com.", RecordType::A)).await.unwrap();
        assert_eq!(t.calls(), 2);
    }

    #[test]
    fn csv_ids() {
        assert_eq!(ids_of(""), vec![PREFERRED.to_string()]);
        assert_eq!(ids_of(" , "), vec![PREFERRED.to_string()]);
        assert_eq!(ids_of("Preferred"), vec!["Preferred".to_string()]);
        assert_eq!(ids_of("Preferred, Default"), vec!["Preferred".to_string(), "Default".to_string()]);
        assert_eq!(first("", BASE), BASE);
        assert_eq!(first("WARP1,wg0", BASE), "WARP1");
        assert!(is_block_all(BLOCK_ALL));
        assert!(is_block_all("CacheBlockAll"));
        assert!(!is_block_all(PREFERRED));
    }

    #[test]
    fn the_clock_is_shared() {
        let c: SharedClock = Arc::new(FakeClock::default());
        c.now();
    }
}
