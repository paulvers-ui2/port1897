// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The engine's decisions (a port of bridge_windows.go): which program owns
//! a flow, what the firewall rules say about it, which exit or DNS
//! transport it goes to, and what the journal records. It knows nothing of
//! the network stack: the stack calls `flow`, `inflow`, `on_socket_closed`,
//! `on_query`, `on_upstream_answer` and `on_response` with what firestack
//! passes the Go bridge, and does what the answers say.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use serde::Serialize;

use crate::conns::{ConnTable, LiveConn, WhyCache, proto_name};
use crate::events::{Event, Journal, now_ms};
use crate::exit::{BASE, BLOCK, exit_name};
use crate::killswitch::KillSwitch;
use crate::rules::{self, AppRule, Decision, MODE_BLOCK, MODE_NONE, Rules};
use crate::{dnssec, geoip, golike, netaddr};

/// The adapter's address.
pub const IFADDR4: &str = "10.111.222.1";
/// The DNS server the adapter is given; only port 53 there is answered.
pub const FAKEDNS4: &str = "10.111.222.3";
const FAKE_DNS: &str = "10.111.222.3:53";
const FAKE_DOT: &str = "10.111.222.3:853";

/// The uid of a flow whose program is not known.
pub const UNKNOWN_UID: i32 = -1;

// firestack's DNS transport ids; the app shows them as "via" in the Logs
pub const PREFERRED: &str = "Preferred";
pub const SYSTEM: &str = "System";
pub const BLOCK_ALL: &str = "BlockAll";
/// The prefix of a cached transport's id ("CachePreferred").
pub const CT: &str = "Cache";

// firestack's DNS transaction status (dnsx/queryerror.go)
pub const DNS_START: i32 = 0;
pub const DNS_COMPLETE: i32 = 1;
pub const DNS_SEND_FAILED: i32 = 2;
pub const DNS_NO_RESPONSE: i32 = 3;
pub const DNS_BAD_QUERY: i32 = 4;
pub const DNS_BAD_RESPONSE: i32 = 5;
pub const DNS_INTERNAL_ERROR: i32 = 6;
pub const DNS_TRANSPORT_ERROR: i32 = 7;
pub const DNS_CLIENT_ERROR: i32 = 8;
pub const DNS_PAUSED: i32 = 9;
pub const DNS_END: i32 = 10;

// DNS response codes the engine treats specially
pub const RCODE_SUCCESS: i32 = 0;
pub const RCODE_NAME_ERROR: i32 = 3;

// firestack's proxy states (backend/ipn_proxies.go)
pub const TOK: i32 = -1;
pub const TUP: i32 = 0;
pub const TZZ: i32 = 1;
pub const TNT: i32 = 2;
pub const TKO: i32 = -2;
pub const TPU: i32 = 3;
pub const END: i32 = -3;

/// Per-app WireGuard routes have ids starting with this (WireGuard ids must
/// start with "wg").
pub const ROUTE_WG_PREFIX: &str = "wgapp";
pub const ROUTE_SOCKS: &str = "pxsocks";
pub const ROUTE_HTTP: &str = "pxhttp";

/// Hands out a stable numeric id per program path, which firestack expects
/// in place of an Android app uid. Ids start at 10000 like Android's.
pub struct Apps {
    m: Mutex<AppsInner>,
}

struct AppsInner {
    /// lowercased path -> uid
    by_path: HashMap<String, i32>,
    /// uid -> path as reported
    by_uid: HashMap<i32, String>,
    next: i32,
}

impl Default for Apps {
    fn default() -> Self {
        Apps { m: Mutex::new(AppsInner { by_path: HashMap::new(), by_uid: HashMap::new(), next: 10000 }) }
    }
}

impl Apps {
    fn lock(&self) -> std::sync::MutexGuard<'_, AppsInner> {
        self.m.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn uid(&self, path: &str) -> i32 {
        let key = golike::to_lower(path);
        let mut a = self.lock();
        if let Some(u) = a.by_path.get(&key) {
            return *u;
        }
        let u = a.next;
        a.next += 1;
        a.by_path.insert(key, u);
        a.by_uid.insert(u, path.to_string());
        u
    }

    /// The path of uid, "" if unknown.
    pub fn path(&self, uid: i32) -> String {
        self.lock().by_uid.get(&uid).cloned().unwrap_or_default()
    }
}

/// What a flow is told: the exit (or Base, or Block), its id and uid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mark {
    pub pid: String,
    pub cid: String,
    pub uid: String,
}

/// The owner of a flow, found before it is decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreMark {
    pub uid: String,
    /// the engine's own socket
    pub is_uid_self: bool,
}

/// Where a DNS query goes: transport, exit, and whether it skips the
/// on-device blocklists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsOpts {
    pub tid: String,
    pub pid: String,
    pub noblock: bool,
}

/// What firestack reports of a DNS query (backend.DNSSummary), as far as
/// the engine reads it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DnsSummary {
    /// the transport id
    pub id: String,
    /// who asked; may be ""
    pub uid: String,
    /// seconds
    pub latency: f64,
    pub qname: String,
    pub qtype: i32,
    pub cached: bool,
    /// a csv of the answer's data
    pub rdata: String,
    pub rcode: i32,
    pub server: String,
    pub status: i32,
    pub blocklists: String,
    /// DNSSEC validated
    pub ad: bool,
    pub msg: String,
}

/// What firestack reports of a closed connection (intra.SocketSummary).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SocketSummary {
    pub proto: String,
    pub id: String,
    /// the exit it left by
    pub pid: String,
    pub uid: String,
    pub target: String,
    pub rx: i64,
    pub tx: i64,
    /// millis
    pub duration: i64,
    pub msg: String,
}

/// Finds the process behind a flow on the Windows side (win/owner).
pub trait Owners: Send + Sync {
    fn tcp4(&self, src: SocketAddr, dst: SocketAddr) -> Result<u32, String>;
    fn udp4(&self, src: SocketAddr) -> Result<u32, String>;
    fn exe_path(&self, pid: u32) -> Result<String, String>;
}

/// The owner pid of a flow: src is the program's address on the adapter,
/// dst the remote one. Only TCP and UDP have owner tables.
pub fn owner_pid(owners: &dyn Owners, protocol: i32, src: &str, dst: &str) -> Result<u32, String> {
    let s = netaddr::parse_addr_port(src).ok_or_else(|| format!("bad address {}", golike::quote(src)))?;
    match protocol {
        6 => {
            let d = netaddr::parse_addr_port(dst).ok_or_else(|| format!("bad address {}", golike::quote(dst)))?;
            owners.tcp4(s, d)
        }
        17 => owners.udp4(s),
        _ => Err("fswin: no owner lookup for protocol".to_string()),
    }
}

/// A tunnel's counters, from its router (backend.RouterStats).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouterStat {
    pub addrs: String,
    pub rx: i64,
    pub tx: i64,
    pub last_ok: i64,
    pub since: i64,
}

/// One exit or route as the stack reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyInfo {
    pub status: i32,
    pub stat: Option<RouterStat>,
}

/// The stack's exits and routes, for GET /api/proxies.
pub trait Proxies: Send + Sync {
    /// None when there is no such proxy.
    fn get(&self, id: &str) -> Option<ProxyInfo>;
}

/// What GET /api/proxies returns per tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProxyStat {
    pub id: String,
    pub name: String,
    pub status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub addrs: String,
    pub rx: i64,
    pub tx: i64,
    /// unix millis of the last handshake or good dial
    #[serde(rename = "lastOK", skip_serializing_if = "is_zero")]
    pub last_ok: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub since: i64,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

/// A proxy state in the words the app shows.
pub fn proxy_status(s: i32) -> &'static str {
    match s {
        TOK => "connected",
        TUP => "up",
        TZZ => "idle",
        TNT => "not responding",
        TKO => "failing",
        TPU => "paused",
        END => "stopped",
        _ => "unknown",
    }
}

/// Closes connections by a csv of ids and says which (the tunnel's
/// CloseConns).
pub type Closer = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// Where the engine's own log lines go.
pub type LogSink = Box<dyn Fn(&str) + Send + Sync>;

/// The engine's state between the network stack and the API.
pub struct Engine {
    start: Instant,
    cid: AtomicI64,
    pub apps: Apps,
    /// serializes rule updates
    rule_mu: Mutex<()>,
    rules: RwLock<Arc<Rules>>,
    pub conns: ConnTable,
    closer: RwLock<Option<Closer>>,
    /// why recent queries were answered by BlockAll
    pub dns_why: WhyCache,
    pub log: Journal,
    /// lowercased exe path let straight out (usque)
    bypass: RwLock<String>,
    /// the transport DNS queries go to
    dns_tid: RwLock<String>,
    /// per-app routes that loaded: id -> name
    routes: RwLock<Option<Arc<HashMap<String, String>>>>,
    proxies: RwLock<Option<Arc<dyn Proxies>>>,
    /// never send DNS through the exit
    pub dns_direct: bool,
    /// "DNS booster": answer repeat lookups from the cache
    pub dns_cache: bool,
    /// block bogus (bogon) answers
    pub dnssec: bool,
    pub self_pid: u32,
    pub self_uid: i32,
    /// proxy id for allowed flows and DNS; "" is Base
    exit: RwLock<String>,
    /// set once before the API starts; None without Wintun
    pub kill: Option<Arc<KillSwitch>>,
    sink: LogSink,
}

fn read<T: Clone>(l: &RwLock<T>) -> T {
    l.read().unwrap_or_else(|e| e.into_inner()).clone()
}

fn write<T>(l: &RwLock<T>, v: T) {
    *l.write().unwrap_or_else(|e| e.into_inner()) = v;
}

impl Engine {
    /// The engine with initial rules (or none) and the -block csv. Its own
    /// program gets the first uid.
    pub fn new(initial: Option<Rules>, block_csv: &str) -> Engine {
        let self_path = std::env::current_exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| "fswin.exe".to_string());
        Engine::with_self(initial, block_csv, &self_path, Box::new(|s| println!("{s}")))
    }

    /// Engine::new for a given own path and log sink (tests).
    pub fn with_self(initial: Option<Rules>, block_csv: &str, self_path: &str, sink: LogSink) -> Engine {
        let mut e = Engine {
            start: Instant::now(),
            cid: AtomicI64::new(0),
            apps: Apps::default(),
            rule_mu: Mutex::new(()),
            rules: RwLock::new(Arc::new(initial.unwrap_or_default())),
            conns: ConnTable::new(),
            closer: RwLock::new(None),
            dns_why: WhyCache::new(),
            log: Journal::new(),
            bypass: RwLock::new(String::new()),
            dns_tid: RwLock::new(String::new()),
            routes: RwLock::new(None),
            proxies: RwLock::new(None),
            dns_direct: false,
            dns_cache: false,
            dnssec: false,
            self_pid: std::process::id(),
            self_uid: 0,
            exit: RwLock::new(String::new()),
            kill: None,
            sink,
        };
        e.self_uid = e.apps.uid(self_path);
        for s in block_csv.split(',') {
            e.set_blocked(s, true);
        }
        e
    }

    pub fn logf(&self, msg: &str) {
        (self.sink)(&format!("{:8.3}s {msg}", self.start.elapsed().as_secs_f64()));
    }

    /// The rules in force.
    pub fn rules(&self) -> Arc<Rules> {
        read(&self.rules)
    }

    /// Lets the program at path connect directly, never through the exit:
    /// usque's own connections to Cloudflare would otherwise loop into it.
    pub fn set_bypass(&self, path: &str) {
        write(&self.bypass, golike::to_lower(path));
    }

    fn is_bypass(&self, path: &str) -> bool {
        let p = read(&self.bypass);
        !p.is_empty() && golike::equal_fold(&p, path)
    }

    /// Sends DNS queries to transport tid (Preferred or System).
    pub fn set_dns(&self, tid: &str) {
        write(&self.dns_tid, tid.to_string());
    }

    /// Sends allowed flows and DNS queries through proxy id.
    pub fn set_exit(&self, id: &str) {
        write(&self.exit, id.to_string());
    }

    /// The proxy allowed traffic leaves through; Base is direct.
    pub fn exit_id(&self) -> String {
        let id = read(&self.exit);
        if id.is_empty() { BASE.to_string() } else { id }
    }

    /// Records the stack's CloseConns, so rule changes close connections.
    pub fn set_closer(&self, f: Closer) {
        write(&self.closer, Some(f));
    }

    /// Records the stack's exits and routes, for proxy_stats.
    pub fn set_proxies(&self, p: Arc<dyn Proxies>) {
        write(&self.proxies, Some(p));
    }

    /// Records the routes that loaded, so flows can use them.
    pub fn set_routes(&self, r: HashMap<String, String>) {
        write(&self.routes, Some(Arc::new(r)));
    }

    /// The name of a loaded route, or "" if id is not one.
    pub fn route_name(&self, id: &str) -> String {
        read(&self.routes).and_then(|r| r.get(id).cloned()).unwrap_or_default()
    }

    /// Swaps in a new rule set and closes the open connections it now
    /// blocks. Rules that do not parse are skipped and reported.
    pub fn set_rules(&self, rs: rules::RuleSet) -> Option<String> {
        let (r, err) = rules::compile(rs);
        {
            let _g = self.rule_mu.lock().unwrap_or_else(|e| e.into_inner());
            write(&self.rules, Arc::new(r));
        }
        self.enforce();
        err
    }

    /// Blocks or unblocks app, an exe name or a full path, keeping its
    /// other settings.
    pub fn set_blocked(&self, app: &str, block: bool) {
        let app = golike::to_lower(golike::trim_space(app));
        if app.is_empty() {
            return;
        }
        {
            let _g = self.rule_mu.lock().unwrap_or_else(|e| e.into_inner());
            let mut rs = read(&self.rules).source().clone();
            let mut apps: HashMap<String, AppRule> = rs.apps.drain().map(|(k, v)| (golike::to_lower(&k), v)).collect();
            let mut a = apps.get(&app).cloned().unwrap_or_default();
            if block {
                a.mode = MODE_BLOCK.to_string();
            } else if a.mode == MODE_BLOCK {
                a.mode = MODE_NONE.to_string();
            }
            a.allow_until = 0;
            if a == AppRule::default() {
                apps.remove(&app);
            } else {
                apps.insert(app, a);
            }
            rs.apps = apps;
            write(&self.rules, Arc::new(rules::compile(rs).0));
        }
        self.enforce();
    }

    /// The blocked exe names and paths, sorted.
    pub fn blocked_apps(&self) -> Vec<String> {
        let r = self.rules();
        let mut out: Vec<String> = r.apps().iter().filter(|(_, a)| a.mode == MODE_BLOCK).map(|(k, _)| k.clone()).collect();
        out.sort();
        out
    }

    pub fn blocked_list(&self) -> String {
        self.blocked_apps().join(", ")
    }

    /// Applies the rules to a flow from the program at path.
    pub fn decide(&self, protocol: i32, path: &str, dst: Option<SocketAddr>, domains: &[String]) -> Decision {
        if self.is_bypass(path) {
            return Decision { no_proxy: true, why: "usque".to_string(), ..Default::default() };
        }
        let r = self.rules();
        r.decide(protocol, path, r.known_app(path), dst, domains, now_ms())
    }

    /// Closes the open connections the current rules block, as the Android
    /// app does when a rule changes.
    pub fn enforce(&self) {
        let cids: Vec<String> = self
            .conns
            .all()
            .into_iter()
            .filter(|(_, c)| self.decide(c.proto, &self.apps.path(c.uid), c.dst, &c.domains).block)
            .map(|(cid, _)| cid)
            .collect();
        self.close_conns(&cids);
    }

    /// Closes the open connections of app (exe name or path), or all of
    /// them if app is "".
    pub fn close_app(&self, app: &str) -> usize {
        let app = golike::to_lower(golike::trim_space(app));
        let cids: Vec<String> = self
            .conns
            .all()
            .into_iter()
            .filter(|(_, c)| {
                let (full, exe) = rules::app_keys(&self.apps.path(c.uid));
                app.is_empty() || app == full || app == exe
            })
            .map(|(cid, _)| cid)
            .collect();
        self.close_conns(&cids);
        cids.len()
    }

    /// Closes the open connections among ids and returns how many it found
    /// open.
    pub fn close_ids(&self, ids: &[String]) -> usize {
        let open = self.conns.all();
        let cids: Vec<String> = ids.iter().filter(|id| open.contains_key(*id)).cloned().collect();
        self.close_conns(&cids);
        cids.len()
    }

    fn close_conns(&self, cids: &[String]) {
        if cids.is_empty() {
            return;
        }
        if let Some(f) = read(&self.closer) {
            let closed = f(&cids.join(","));
            self.logf(&format!("closed {} connections: {closed}", cids.len()));
        }
    }

    /// The exe name for uid, or "?" if the owner is unknown.
    pub fn app_name(&self, uid: i32) -> String {
        let p = self.apps.path(uid);
        if p.is_empty() { "?".to_string() } else { golike::base(&p) }
    }

    /// uid's full program path, for the logs: "" when only a pid or a name
    /// like "System" is known.
    pub fn app_path(&self, uid: i32) -> String {
        let p = self.apps.path(uid);
        if golike::is_abs(&p) { p } else { String::new() }
    }

    /// Finds the program behind a new flow, before it is decided.
    pub fn preflow(&self, owners: &dyn Owners, protocol: i32, src: &str, dst: &str) -> PreMark {
        let Ok(pid) = owner_pid(owners, protocol, src, dst) else {
            return PreMark { uid: UNKNOWN_UID.to_string(), is_uid_self: false };
        };
        if pid == self.self_pid {
            // our own socket should have been bound out of the tunnel
            return PreMark { uid: self.self_uid.to_string(), is_uid_self: true };
        }
        let path = owners.exe_path(pid).unwrap_or_else(|_| format!("pid{pid}"));
        PreMark { uid: self.apps.uid(&path).to_string(), is_uid_self: false }
    }

    /// Decides a new outgoing flow; firestack's Flow. domains and probable
    /// are csvs of the names the app looked up, and of likely ones.
    pub fn flow(&self, protocol: i32, uid: i32, src: &str, dst: &str, domains: &str, probable: &str) -> Mark {
        let cid = (self.cid.fetch_add(1, Ordering::Relaxed) + 1).to_string();
        let mark = |pid: &str| Mark { pid: pid.to_string(), cid: cid.clone(), uid: uid.to_string() };
        match dst {
            // a query to our DNS address: firestack answers it only when
            // marked Base, whatever the exit, and it shows in the DNS log,
            // not as a flow
            FAKE_DNS => return mark(BASE),
            // DNS over TLS to our address, which we do not serve; refused,
            // as the Android app does, so Windows falls back to port 53
            FAKE_DOT => return mark(BLOCK),
            _ => {}
        }
        let path = self.apps.path(uid);
        // None if unparsable: IP rules then skip it
        let dap = netaddr::parse_addr_port(dst);
        let doms = split_domains(domains, probable);
        let d = self.decide(protocol, &path, dap, &doms);
        let mut pid = self.exit_id();
        let mut verdict = "";
        if d.block {
            pid = BLOCK.to_string();
            verdict = " BLOCKED";
        } else if d.no_proxy {
            pid = BASE.to_string();
        } else if !d.route.is_empty() && !self.route_name(&d.route).is_empty() {
            pid = d.route.clone();
        }
        let app = self.app_name(uid);
        let via = match self.route_name(&pid) {
            n if !n.is_empty() => n,
            _ => exit_name(&pid),
        };
        self.logf(&format!("flow  #{cid} {} {app} {src} -> {dst} [{}]{verdict} {}", proto_name(protocol), doms.join(","), d.why));
        let domain = doms.first().cloned().unwrap_or_default();
        let cc = geoip::country(dap.map(|a| a.ip()));
        Journal::bump(&self.log.flows, 1);
        if d.block {
            Journal::bump(&self.log.flows_blocked, 1);
        } else {
            self.conns.add(
                &cid,
                LiveConn {
                    uid,
                    proto: protocol,
                    dst: dap,
                    domains: doms.clone(),
                    app: app.clone(),
                    path: self.app_path(uid),
                    via: via.clone(),
                    country: cc.clone(),
                    at: now_ms(),
                },
            );
        }
        self.log.add(Event {
            kind: "flow".into(),
            app,
            path: self.app_path(uid),
            proto: proto_name(protocol),
            dst: dst.to_string(),
            domain,
            country: cc,
            via,
            blocked: d.block,
            rule: d.why,
            cid: cid.clone(),
            ..Default::default()
        });
        mark(&pid)
    }

    /// Decides a connection coming in through the tunnel (from a VPN exit
    /// or a per-app route): allowed, unless "Allow outgoing only" is on.
    pub fn inflow(&self, protocol: i32, uid: i32, src: &str, dst: &str) -> Mark {
        let cid = (self.cid.fetch_add(1, Ordering::Relaxed) + 1).to_string();
        let mut mark = Mark { pid: BASE.to_string(), cid: cid.clone(), uid: uid.to_string() };
        let p = proto_name(protocol);
        if !self.rules().blocks_incoming(now_ms()) {
            self.logf(&format!("inflow #{cid} {p} {src} -> {dst}"));
            return mark;
        }
        const WHY: &str = "universal: incoming blocked";
        self.logf(&format!("inflow #{cid} {p} {src} -> {dst} BLOCKED {WHY}"));
        Journal::bump(&self.log.flows, 1);
        Journal::bump(&self.log.flows_blocked, 1);
        // the remote end is the source; the event shows it as the address
        let sap = netaddr::parse_addr_port(src);
        self.log.add(Event {
            kind: "flow".into(),
            app: self.app_name(uid),
            path: self.app_path(uid),
            proto: format!("{p} in"),
            dst: src.to_string(),
            country: geoip::country(sap.map(|a| a.ip())),
            via: exit_name(BLOCK),
            blocked: true,
            rule: WHY.to_string(),
            cid,
            ..Default::default()
        });
        mark.pid = BLOCK.to_string();
        mark
    }

    pub fn on_socket_closed(&self, s: &SocketSummary) {
        self.logf(&format!(
            "close #{} {} -> {} via {} rx {} tx {} {}ms {}",
            s.id, s.proto, s.target, s.pid, s.rx, s.tx, s.duration, s.msg
        ));
        self.conns.remove(&s.id);
        Journal::bump(&self.log.rx, s.rx);
        Journal::bump(&self.log.tx, s.tx);
        let (app, path) = match golike::parse_int(&s.uid, 10, 32) {
            Ok(u) => (self.app_name(u as i32), self.app_path(u as i32)),
            Err(_) => ("?".to_string(), String::new()),
        };
        self.log.add(Event {
            kind: "close".into(),
            app,
            path,
            proto: s.proto.clone(),
            dst: s.target.clone(),
            via: exit_name(&s.pid),
            rx: s.rx,
            tx: s.tx,
            dur_ms: s.duration,
            cid: s.id.clone(),
            ..Default::default()
        });
    }

    /// Where a DNS query goes, and whether the rules answer it with
    /// BlockAll.
    pub fn on_query(&self, domain: &str, qtype: i32) -> DnsOpts {
        let mut tid = read(&self.dns_tid);
        if tid.is_empty() {
            tid = PREFERRED.to_string();
        }
        if self.dns_cache && tid != BLOCK_ALL && !tid.starts_with(CT) {
            tid = format!("{CT}{tid}"); // as the Android app does for its DNS booster
        }
        let pid = if self.dns_direct { BASE.to_string() } else { self.exit_id() };
        let (block, trust, why) = self.rules().dns_verdict(domain, qtype as i64, now_ms());
        if block {
            self.dns_why.put(domain, &why);
            Journal::bump(&self.log.dns_blocked, 1);
            return DnsOpts { tid: BLOCK_ALL.to_string(), pid: BASE.to_string(), noblock: false };
        }
        DnsOpts { tid, pid, noblock: trust }
    }

    /// Blocks bogus answers when the DNSSEC switch is on: a public name
    /// answered with a bogon address is answered again by BlockAll. None
    /// keeps the answer.
    pub fn on_upstream_answer(&self, smm: Option<&DnsSummary>, unmodified_ip_csv: &str) -> Option<DnsOpts> {
        let smm = smm?;
        if !self.dnssec || dnssec::is_local_name(&smm.qname) {
            return None;
        }
        let bad = dnssec::bogons_in(unmodified_ip_csv);
        if bad.is_empty() {
            return None;
        }
        Journal::bump(&self.log.dns_bogus, 1);
        self.dns_why.put(&smm.qname, &format!("DNSSEC: bogus answer {}", bad.join(",")));
        self.logf(&format!("dnssec: {} answered with bogus [{}] via {} (AD {}); blocked", smm.qname, bad.join(" "), smm.id, smm.ad));
        Some(DnsOpts { tid: BLOCK_ALL.to_string(), pid: BASE.to_string(), noblock: false })
    }

    /// Records a DNS answer (or failure) in the journal and counters.
    pub fn on_response(&self, s: &DnsSummary) {
        self.logf(&format!(
            "dns   {} (type {}) -> {} via {} ({}) {:.0}ms status {} rcode {} {}",
            s.qname,
            s.qtype,
            s.rdata,
            s.id,
            s.server,
            s.latency * 1000.0,
            s.status,
            s.rcode,
            s.msg
        ));
        let ms = (s.latency * 1000.0) as i64;
        Journal::bump(&self.log.dns_queries, 1);
        let mut failure = String::new();
        if s.status != DNS_COMPLETE {
            Journal::bump(&self.log.dns_failed, 1);
            failure = dns_failure(s);
        } else if bad_rcode(s) {
            // answered, but with an error such as SERVFAIL or REFUSED
            Journal::bump(&self.log.dns_failed, 1);
            failure = format!("{} answered {}", dns_server(s), rcode_name(s.rcode));
        } else {
            self.log.dns_last_ms.store(ms, Ordering::Relaxed);
            Journal::bump(&self.log.dns_total_ms, ms);
        }
        let mut why = String::new();
        if s.id.ends_with(BLOCK_ALL) {
            why = self.dns_why.get(&s.qname);
        }
        if why.is_empty() && !s.blocklists.is_empty() {
            why = format!("blocklists: {}", s.blocklists);
        }
        let (app, path) = match golike::parse_int(&s.uid, 10, 32) {
            // who asked; "?" if unknown
            Ok(u) => (self.app_name(u as i32), self.app_path(u as i32)),
            Err(_) => (String::new(), String::new()),
        };
        let blocked = !why.is_empty() || (s.status == DNS_COMPLETE && is_unspecified_answer(&s.rdata));
        self.log.add(Event {
            kind: "dns".into(),
            app,
            path,
            domain: golike::trim_suffix(&s.qname, ".").to_string(),
            answer: s.rdata.clone(),
            country: geoip::answer_country(&s.rdata),
            via: s.id.clone(),
            latency_ms: ms,
            secure: s.ad,
            cached: s.cached,
            blocked,
            rule: why,
            qtype: s.qtype,
            error: failure,
            ..Default::default()
        });
    }

    /// The exit and the routes with their state; a proxy that is missing is
    /// listed as such. Sorted by name.
    pub fn proxy_stats(&self) -> Vec<ProxyStat> {
        let Some(pxs) = read(&self.proxies) else {
            return Vec::new();
        };
        let mut ids: HashMap<String, String> = HashMap::new();
        let e = self.exit_id();
        if e != BASE {
            ids.insert(e.clone(), exit_name(&e));
        }
        if let Some(r) = read(&self.routes) {
            for (k, v) in r.iter() {
                ids.insert(k.clone(), v.clone());
            }
        }
        let mut out: Vec<ProxyStat> = ids.into_iter().map(|(id, name)| stat_of(pxs.as_ref(), id, name)).collect();
        // Go sorts by name only; the id makes equal names come out the same
        // way each time
        out.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
        out
    }
}

fn stat_of(pxs: &dyn Proxies, id: String, name: String) -> ProxyStat {
    let mut st = ProxyStat { id, name, status: "missing".into(), addrs: String::new(), rx: 0, tx: 0, last_ok: 0, since: 0 };
    let Some(px) = pxs.get(&st.id) else {
        return st;
    };
    st.status = proxy_status(px.status).to_string();
    if let Some(s) = px.stat {
        (st.addrs, st.rx, st.tx, st.last_ok, st.since) = (s.addrs, s.rx, s.tx, s.last_ok, s.since);
    }
    st
}

/// firestack's domain csvs as a lowercased list, preferring the domains
/// this app looked up over probable ones.
pub fn split_domains(domains: &str, probable: &str) -> Vec<String> {
    let csv = if golike::trim_space(domains).is_empty() { probable } else { domains };
    csv.split(',')
        .map(|d| golike::to_lower(golike::trim_suffix(golike::trim_space(d), ".")))
        .filter(|d| !d.is_empty())
        .collect()
}

/// Why a query got no answer, in words a user can act on: a timeout means
/// the server was never reached.
pub fn dns_failure(s: &DnsSummary) -> String {
    let why = dns_failure_msg(s);
    if why.contains("timeout") {
        return format!("no reply from {} in {:.0} s ({why})", dns_server(s), s.latency);
    }
    if let Some(code) = why.strip_prefix("http-status: ") {
        return format!("{} answered HTTP {code}", dns_server(s));
    }
    why
}

/// An upstream answer that is an error. NXDOMAIN is a real answer, and
/// blocked names are answered by BlockAll on purpose.
pub fn bad_rcode(s: &DnsSummary) -> bool {
    s.rcode != RCODE_SUCCESS && s.rcode != RCODE_NAME_ERROR && !s.id.ends_with(BLOCK_ALL)
}

fn dns_server(s: &DnsSummary) -> &str {
    if s.server.is_empty() { "the DNS server" } else { &s.server }
}

fn dns_failure_msg(s: &DnsSummary) -> String {
    if !s.msg.is_empty() {
        return s.msg.clone();
    }
    match s.status {
        DNS_SEND_FAILED => "could not send the query to the DNS server",
        DNS_NO_RESPONSE => "the DNS server did not answer",
        DNS_BAD_QUERY => "bad query",
        DNS_BAD_RESPONSE => "bad answer from the DNS server",
        DNS_TRANSPORT_ERROR => "could not reach the DNS server",
        DNS_CLIENT_ERROR => "DNS client error",
        DNS_INTERNAL_ERROR => "internal error",
        DNS_PAUSED => "DNS is paused",
        DNS_END => "DNS stopped",
        n => return format!("status {n}"),
    }
    .to_string()
}

/// A response code's name as miekg/dns's RcodeToString has it ("" for
/// codes it does not list).
pub fn rcode_name(rcode: i32) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        11 => "DSOTYPENI",
        16 => "BADSIG",
        17 => "BADKEY",
        18 => "BADTIME",
        19 => "BADMODE",
        20 => "BADNAME",
        21 => "BADALG",
        22 => "BADTRUNC",
        23 => "BADCOOKIE",
        _ => "",
    }
}

/// Answers of 0.0.0.0 / ::, which is how blocklists answer blocked names.
pub fn is_unspecified_answer(rdata: &str) -> bool {
    if rdata.is_empty() {
        return false;
    }
    rdata.split(',').all(|a| netaddr::parse_addr(golike::trim_space(a)).is_some_and(|ip| ip.is_unspecified()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::{EXIT_CHAIN, EXIT_MASQUE, EXIT_PROXY, EXIT_WARP, EXIT_WG};
    use crate::events::JOURNAL_SIZE;

    const TEST_APP: &str = r"C:\Program Files\Test\app.exe";

    fn new_engine(block_csv: &str) -> Engine {
        Engine::with_self(None, block_csv, r"C:\Program Files\AuroraVPN\fswin.exe", Box::new(|_| {}))
    }

    fn events_of(e: &Engine, kind: &str) -> Vec<Event> {
        e.log.since(0, JOURNAL_SIZE).into_iter().filter(|ev| ev.kind == kind).collect()
    }

    fn get(c: &AtomicI64) -> i64 {
        Journal::get(c)
    }

    #[test]
    fn fake_dns_addresses() {
        assert_eq!(FAKE_DNS, format!("{FAKEDNS4}:53"));
        assert_eq!(FAKE_DOT, format!("{FAKEDNS4}:853"));
        assert_eq!(FAKE_DNS, "10.111.222.3:53");
    }

    // Queries to the tunnel's DNS address must be marked Base whatever the
    // exit: firestack answers them only then. They are not flows.
    #[test]
    fn flow_fake_dns_is_base_whatever_the_exit() {
        for exit in ["", EXIT_WG, EXIT_WARP, EXIT_PROXY, EXIT_MASQUE, EXIT_CHAIN] {
            for protocol in [17, 6] {
                let e = new_engine("");
                if !exit.is_empty() {
                    e.set_exit(exit);
                    assert_eq!(e.exit_id(), exit);
                }
                let uid = e.apps.uid(TEST_APP);
                let m = e.flow(protocol, uid, "10.111.222.1:50123", FAKE_DNS, "", "");
                assert_eq!(m.pid, BASE, "{exit}/{protocol}");
                assert!(!m.cid.is_empty());
                assert_eq!(m.uid, uid.to_string());
                assert_eq!(get(&e.log.flows), 0);
                assert_eq!(get(&e.log.flows_blocked), 0);
                assert!(events_of(&e, "flow").is_empty());
                assert!(e.conns.is_empty(), "DNS gets no OnSocketClosed");
            }
        }
    }

    // Everything else still leaves through the exit and is journaled.
    #[test]
    fn flow_ordinary_dst_uses_exit_and_is_journaled() {
        for exit in ["", EXIT_WG, EXIT_WARP, EXIT_PROXY] {
            let want = if exit.is_empty() { BASE } else { exit };
            for protocol in [6, 17] {
                let e = new_engine("");
                if !exit.is_empty() {
                    e.set_exit(exit);
                }
                let uid = e.apps.uid(TEST_APP);
                let dst = "1.1.1.1:443";
                let m = e.flow(protocol, uid, "10.111.222.1:50124", dst, "one.one.one.one", "");
                assert_eq!(m.pid, want);
                assert_eq!(get(&e.log.flows), 1);
                let ev = events_of(&e, "flow");
                assert_eq!(ev.len(), 1);
                let v = &ev[0];
                assert!(
                    v.dst == dst
                        && v.cid == m.cid
                        && v.via == exit_name(want)
                        && v.app == "app.exe"
                        && v.path == TEST_APP
                        && v.proto == proto_name(protocol)
                        && v.domain == "one.one.one.one"
                        && !v.blocked,
                    "{v:?}"
                );
                assert!(e.conns.all().contains_key(&m.cid), "connection {} not tracked", m.cid);
            }
        }
    }

    // Only 10.111.222.3:53 is kept local.
    #[test]
    fn flow_only_our_dns_address_is_kept_local() {
        let e = new_engine("");
        e.set_exit(EXIT_WG);
        let uid = e.apps.uid(TEST_APP);
        let dsts = ["8.8.8.8:53", &format!("{IFADDR4}:53"), &format!("{FAKEDNS4}:5353"), "10.111.222.30:53"];
        for dst in dsts {
            let m = e.flow(17, uid, "10.111.222.1:50125", dst, "", "");
            assert_eq!(m.pid, EXIT_WG, "{dst}");
        }
        assert_eq!(events_of(&e, "flow").len(), dsts.len());
        // DNS over TLS to our address is refused and not journaled
        let m = e.flow(6, uid, "10.111.222.1:50126", FAKE_DOT, "", "");
        assert_eq!(m.pid, BLOCK);
        assert_eq!(events_of(&e, "flow").len(), dsts.len());
    }

    // A blocked app's DNS to our address is still answered, as on Android;
    // its connections stay blocked.
    #[test]
    fn flow_fake_dns_from_blocked_app() {
        let e = new_engine("blocked.exe");
        e.set_exit(EXIT_WARP);
        let uid = e.apps.uid(r"C:\Apps\blocked.exe");
        assert_eq!(e.flow(17, uid, "10.111.222.1:50127", FAKE_DNS, "", "").pid, BASE);
        assert_eq!(e.flow(6, uid, "10.111.222.1:50128", "1.1.1.1:443", "", "").pid, BLOCK);
        assert_eq!(get(&e.log.flows_blocked), 1);
        let ev = events_of(&e, "flow");
        assert!(ev.len() == 1 && ev[0].blocked && ev[0].via == "blocked", "{ev:?}");
        assert!(e.conns.is_empty(), "a blocked flow is not an open connection");
    }

    #[test]
    fn on_response_records_why_a_query_failed() {
        let e = new_engine("");
        let uid = e.apps.uid(TEST_APP).to_string();
        let s = |qname: &str, qtype, id: &str, server: &str, latency, status, rcode, msg: &str, rdata: &str| DnsSummary {
            qname: qname.into(),
            qtype,
            id: id.into(),
            server: server.into(),
            latency,
            status,
            rcode,
            msg: msg.into(),
            rdata: rdata.into(),
            ..Default::default()
        };
        let cases: Vec<(&str, DnsSummary, &str, bool)> = vec![
            ("no response, no message", s("example.com.", 1, PREFERRED, "", 5.0, DNS_NO_RESPONSE, 0, "", ""), "the DNS server did not answer", true),
            (
                "send failed, timed out (the Proton VPN incident)",
                s("example.org.", 28, PREFERRED, "cloudflare-dns.com", 20.004, DNS_SEND_FAILED, 0, r#"Post "https://cloudflare-dns.com/dns-query": dial tcp 1.1.1.1:443: i/o timeout | dial tcp 1.0.0.1:443: i/o timeout"#, ""),
                r#"no reply from cloudflare-dns.com in 20 s (Post "https://cloudflare-dns.com/dns-query": dial tcp 1.1.1.1:443: i/o timeout | dial tcp 1.0.0.1:443: i/o timeout)"#,
                true,
            ),
            ("server error over HTTP", s("example.edu.", 1, PREFERRED, "cloudflare-dns.com", 0.1, DNS_TRANSPORT_ERROR, 0, "http-status: 503", ""), "cloudflare-dns.com answered HTTP 503", true),
            (
                "refused by a plain DNS server",
                s("example.info.", 1, PREFERRED, "", 0.1, DNS_TRANSPORT_ERROR, 0, "read udp 10.0.0.2:5000->9.9.9.9:53: connectex: No connection could be made because the target machine actively refused it.", ""),
                "read udp 10.0.0.2:5000->9.9.9.9:53: connectex: No connection could be made because the target machine actively refused it.",
                true,
            ),
            ("answered SERVFAIL", s("example.biz.", 1, PREFERRED, "127.0.0.1:5353", 0.01, DNS_COMPLETE, 2, "no error", ""), "127.0.0.1:5353 answered SERVFAIL", true),
            ("answered REFUSED, no server name", s("example.museum.", 1, PREFERRED, "", 0.01, DNS_COMPLETE, 5, "no error", ""), "the DNS server answered REFUSED", true),
            ("NXDOMAIN is an answer", s("nope.example.", 1, PREFERRED, "", 0.02, DNS_COMPLETE, 3, "no error", ""), "", false),
            ("BlockAll answers on purpose", s("ads.example.", 1, BLOCK_ALL, "", 0.0, DNS_COMPLETE, 5, "no error", ""), "", false),
            ("complete", s("example.net.", 1, PREFERRED, "", 0.03, DNS_COMPLETE, 0, "no error", "93.184.215.14"), "", false),
        ];
        let mut want_failed = 0;
        for (name, mut sm, want_err, failed) in cases.clone() {
            let (queries, before) = (get(&e.log.dns_queries), get(&e.log.dns_failed));
            sm.uid = uid.clone();
            e.on_response(&sm);
            assert_eq!(get(&e.log.dns_queries), queries + 1, "{name}");
            if failed {
                want_failed += 1;
            }
            assert_eq!(get(&e.log.dns_failed), before + failed as i64, "{name}");
            let ev = events_of(&e, "dns");
            let v = ev.last().expect("no dns event journaled");
            assert_eq!(v.domain, sm.qname.trim_end_matches('.'), "{name}");
            assert_eq!(v.error, want_err, "{name}");
            assert_eq!(v.app, "app.exe", "{name}: the program that asked");
            let j = serde_json::to_value(v).unwrap();
            assert_eq!(j.get("error").is_some(), !want_err.is_empty(), "{name}: {j}");
        }
        assert_eq!(get(&e.log.dns_failed), want_failed);
        assert_eq!(get(&e.log.dns_queries), cases.len() as i64);
        // only the good answers count towards the latency
        assert_eq!(get(&e.log.dns_last_ms), 30);
        assert_eq!(get(&e.log.dns_total_ms), 20 + 30);
    }

    #[test]
    fn dns_failure_text() {
        let want = [
            (DNS_SEND_FAILED, "could not send the query to the DNS server"),
            (DNS_NO_RESPONSE, "the DNS server did not answer"),
            (DNS_BAD_QUERY, "bad query"),
            (DNS_BAD_RESPONSE, "bad answer from the DNS server"),
            (DNS_TRANSPORT_ERROR, "could not reach the DNS server"),
            (DNS_CLIENT_ERROR, "DNS client error"),
            (DNS_INTERNAL_ERROR, "internal error"),
            (DNS_PAUSED, "DNS is paused"),
            (DNS_END, "DNS stopped"),
            (99, "status 99"),
        ];
        for (status, text) in want {
            assert_eq!(dns_failure(&DnsSummary { status, ..Default::default() }), text);
            assert_eq!(dns_failure(&DnsSummary { status, msg: "boom".into(), ..Default::default() }), "boom");
        }
        assert_eq!(rcode_name(16), "BADSIG");
        assert_eq!(rcode_name(12), "");
    }

    #[test]
    fn blocking_by_api_keeps_other_settings_and_closes_connections() {
        let closed = Arc::new(Mutex::new(Vec::<String>::new()));
        let e = new_engine(" Chrome.EXE ,,");
        assert_eq!(e.blocked_apps(), vec!["chrome.exe"]);
        let c2 = closed.clone();
        e.set_closer(Arc::new(move |csv: &str| {
            c2.lock().unwrap().push(csv.to_string());
            csv.to_string()
        }));
        let uid = e.apps.uid(r"C:\Apps\Notepad.exe");
        let m = e.flow(6, uid, "10.111.222.1:1000", "1.1.1.1:443", "", "");
        assert_eq!(m.pid, BASE);
        // a route kept across block and unblock
        let mut rs = e.rules().source().clone();
        rs.apps.insert("NOTEPAD.exe".into(), AppRule { route: "wgapp1".into(), ..Default::default() });
        assert!(e.set_rules(rs).is_none());
        assert!(closed.lock().unwrap().is_empty(), "nothing newly blocked");
        e.set_blocked("notepad.exe", true);
        assert_eq!(*closed.lock().unwrap(), vec![m.cid.clone()]);
        assert_eq!(e.blocked_apps(), vec!["chrome.exe", "notepad.exe"]);
        assert_eq!(e.rules().app(r"C:\Apps\Notepad.exe").route, "wgapp1");
        e.set_blocked("notepad.exe", false);
        let a = e.rules().app(r"C:\Apps\Notepad.exe");
        assert!(a.mode.is_empty() && a.route == "wgapp1", "{a:?}");
        // a rule left empty is dropped
        e.set_blocked("chrome.exe", false);
        assert!(!e.rules().source().apps.contains_key("chrome.exe"));
        assert_eq!(e.blocked_list(), "");
        // closing by app and by id
        let m2 = e.flow(17, uid, "10.111.222.1:1001", "9.9.9.9:443", "", "");
        assert_eq!(e.close_ids(&["nope".into(), m2.cid.clone()]), 1);
        assert_eq!(e.close_app("NOTEPAD.EXE"), 2); // the first flow was never closed by the stack
        assert_eq!(e.close_app(r"c:\apps\notepad.exe"), 2);
        assert_eq!(e.close_app("other.exe"), 0);
        assert_eq!(e.close_app(""), 2);
    }

    #[test]
    fn routes_and_bypass() {
        let e = new_engine("");
        e.set_exit(EXIT_WG);
        let uid = e.apps.uid(TEST_APP);
        let mut rs = rules::RuleSet::default();
        rs.apps.insert("app.exe".into(), AppRule { route: "wgapp1".into(), ..Default::default() });
        e.set_rules(rs);
        // a route that did not load: the exit
        assert_eq!(e.flow(6, uid, "10.111.222.1:1", "1.1.1.1:443", "", "").pid, EXIT_WG);
        e.set_routes(HashMap::from([("wgapp1".to_string(), "Office".to_string())]));
        let m = e.flow(6, uid, "10.111.222.1:2", "1.1.1.1:443", "", "");
        assert_eq!(m.pid, "wgapp1");
        assert_eq!(events_of(&e, "flow").last().unwrap().via, "Office");
        // usque's own connections leave directly, whatever the rules
        let usque = r"C:\Program Files\AuroraVPN\usque.exe";
        e.set_bypass(usque);
        let u = e.apps.uid(&usque.to_uppercase());
        let m = e.flow(17, u, "10.111.222.1:3", "162.159.198.1:443", "", "");
        assert_eq!(m.pid, BASE);
        assert_eq!(events_of(&e, "flow").last().unwrap().rule, "usque");
    }

    #[test]
    fn inflow_and_close() {
        let e = new_engine("");
        let uid = e.apps.uid(TEST_APP);
        assert_eq!(e.inflow(6, uid, "1.1.1.1:443", "10.111.222.1:5000").pid, BASE);
        assert!(events_of(&e, "flow").is_empty());
        let mut rs = rules::RuleSet::default();
        rs.universal.outgoing_only = true;
        e.set_rules(rs);
        let m = e.inflow(6, uid, "1.1.1.1:443", "10.111.222.1:5000");
        assert_eq!(m.pid, BLOCK);
        let ev = events_of(&e, "flow");
        assert!(ev.len() == 1 && ev[0].proto == "tcp in" && ev[0].dst == "1.1.1.1:443" && ev[0].country == "AU", "{ev:?}");
        assert_eq!((get(&e.log.flows), get(&e.log.flows_blocked)), (1, 1));

        let f = e.flow(6, uid, "10.111.222.1:6", "1.1.1.1:443", "", "");
        e.on_socket_closed(&SocketSummary { id: f.cid.clone(), proto: "tcp".into(), pid: BASE.into(), uid: uid.to_string(), target: "1.1.1.1:443".into(), rx: 10, tx: 20, duration: 30, ..Default::default() });
        assert!(e.conns.is_empty());
        assert_eq!((get(&e.log.rx), get(&e.log.tx)), (10, 20));
        let c = events_of(&e, "close");
        assert!(c.len() == 1 && c[0].app == "app.exe" && c[0].via == "direct" && c[0].dur_ms == 30, "{c:?}");
        e.on_socket_closed(&SocketSummary { id: "x".into(), uid: "".into(), ..Default::default() });
        assert_eq!(events_of(&e, "close")[1].app, "?");
    }

    #[test]
    fn dns_choices() {
        let mut e = new_engine("");
        assert_eq!(e.on_query("a.com", 1), DnsOpts { tid: PREFERRED.into(), pid: BASE.into(), noblock: false });
        e.set_exit(EXIT_WARP);
        e.set_dns(SYSTEM);
        assert_eq!(e.on_query("a.com", 1), DnsOpts { tid: SYSTEM.into(), pid: EXIT_WARP.into(), noblock: false });
        e.dns_direct = true;
        e.dns_cache = true;
        assert_eq!(e.on_query("a.com", 1), DnsOpts { tid: "CacheSystem".into(), pid: BASE.into(), noblock: false });
        e.set_dns("CachePreferred");
        assert_eq!(e.on_query("a.com", 1).tid, "CachePreferred");
        let mut rs = rules::RuleSet::default();
        rs.domains.push(rules::DomainRule { domain: "*.ads.com".into(), action: rules::ACT_BLOCK.into(), ..Default::default() });
        rs.domains.push(rules::DomainRule { domain: "good.com".into(), action: rules::ACT_TRUST.into(), ..Default::default() });
        e.set_rules(rs);
        assert_eq!(e.on_query("x.ads.com.", 1), DnsOpts { tid: BLOCK_ALL.into(), pid: BASE.into(), noblock: false });
        assert_eq!(get(&e.log.dns_blocked), 1);
        assert!(e.on_query("good.com", 1).noblock);
        // the blocked query's answer carries the rule
        e.on_response(&DnsSummary { qname: "X.ads.com.".into(), id: BLOCK_ALL.into(), status: DNS_COMPLETE, rdata: "0.0.0.0".into(), ..Default::default() });
        let ev = events_of(&e, "dns");
        assert!(ev[0].blocked && ev[0].rule == "domain rule *.ads.com" && ev[0].app.is_empty(), "{ev:?}");
        // blocklists, and unspecified answers from them
        e.on_response(&DnsSummary { qname: "t.com.".into(), id: PREFERRED.into(), status: DNS_COMPLETE, blocklists: "OISD".into(), ..Default::default() });
        e.on_response(&DnsSummary { qname: "u.com.".into(), id: PREFERRED.into(), status: DNS_COMPLETE, rdata: "0.0.0.0,::".into(), ..Default::default() });
        e.on_response(&DnsSummary { qname: "u.com.".into(), id: PREFERRED.into(), status: DNS_SEND_FAILED, rdata: "0.0.0.0".into(), ..Default::default() });
        let ev = events_of(&e, "dns");
        assert!(ev[1].blocked && ev[1].rule == "blocklists: OISD");
        assert!(ev[2].blocked && ev[2].rule.is_empty());
        assert!(!ev[3].blocked);
    }

    #[test]
    fn dnssec_blocks_bogons() {
        let mut e = new_engine("");
        let smm = DnsSummary { qname: "bank.com.".into(), id: PREFERRED.into(), ..Default::default() };
        assert_eq!(e.on_upstream_answer(Some(&smm), "10.0.0.1"), None, "switch off");
        e.dnssec = true;
        assert_eq!(e.on_upstream_answer(None, "10.0.0.1"), None);
        assert_eq!(e.on_upstream_answer(Some(&smm), "93.184.215.14"), None);
        let printer = DnsSummary { qname: "printer.lan.".into(), ..smm.clone() };
        assert_eq!(e.on_upstream_answer(Some(&printer), "192.168.1.5"), None);
        let o = e.on_upstream_answer(Some(&smm), "93.184.215.14,10.0.0.1").unwrap();
        assert_eq!((o.tid.as_str(), o.pid.as_str()), (BLOCK_ALL, BASE));
        assert_eq!(get(&e.log.dns_bogus), 1);
        assert_eq!(e.dns_why.get("BANK.com"), "DNSSEC: bogus answer 10.0.0.1");
    }

    struct FakeOwners;
    impl Owners for FakeOwners {
        fn tcp4(&self, src: SocketAddr, _dst: SocketAddr) -> Result<u32, String> {
            match src.port() {
                1 => Ok(std::process::id()),
                2 => Ok(42),
                3 => Ok(43),
                _ => Err("none".into()),
            }
        }
        fn udp4(&self, _src: SocketAddr) -> Result<u32, String> {
            Ok(42)
        }
        fn exe_path(&self, pid: u32) -> Result<String, String> {
            if pid == 42 { Ok(TEST_APP.into()) } else { Err("gone".into()) }
        }
    }

    #[test]
    fn preflow_owner() {
        let e = new_engine("");
        let o = FakeOwners;
        let me = e.preflow(&o, 6, "10.111.222.1:1", "1.1.1.1:443");
        assert_eq!(me, PreMark { uid: e.self_uid.to_string(), is_uid_self: true });
        let app = e.preflow(&o, 6, "10.111.222.1:2", "1.1.1.1:443");
        assert_eq!(app.uid, e.apps.uid(TEST_APP).to_string());
        assert_eq!(e.preflow(&o, 17, "10.111.222.1:9", "bad").uid, app.uid, "UDP needs no dst");
        let gone = e.preflow(&o, 6, "10.111.222.1:3", "1.1.1.1:443");
        assert_eq!(e.apps.path(gone.uid.parse().unwrap()), "pid43");
        assert_eq!(e.app_name(gone.uid.parse().unwrap()), "pid43");
        assert_eq!(e.app_path(gone.uid.parse().unwrap()), "", "not a path");
        for (p, src, dst) in [(6, "10.111.222.1:4", "1.1.1.1:443"), (6, "x", "1.1.1.1:443"), (6, "10.111.222.1:2", "x"), (1, "10.111.222.1:2", "1.1.1.1:0")] {
            assert_eq!(e.preflow(&o, p, src, dst).uid, "-1", "{p} {src} {dst}");
        }
        assert_eq!(e.app_name(12345), "?");
    }

    struct FakeProxies;
    impl Proxies for FakeProxies {
        fn get(&self, id: &str) -> Option<ProxyInfo> {
            match id {
                EXIT_WG => Some(ProxyInfo { status: TOK, stat: Some(RouterStat { addrs: "10.2.0.2".into(), rx: 1, tx: 2, last_ok: 3, since: 4 }) }),
                "pxsocks" => Some(ProxyInfo { status: 99, stat: None }),
                _ => None,
            }
        }
    }

    #[test]
    fn proxies() {
        let e = new_engine("");
        assert!(e.proxy_stats().is_empty(), "no stack yet");
        e.set_proxies(Arc::new(FakeProxies));
        assert!(e.proxy_stats().is_empty(), "direct: nothing to list");
        e.set_exit(EXIT_WG);
        e.set_routes(HashMap::from([("pxsocks".into(), "Home proxy".into()), ("wgapp2".into(), "Away".into())]));
        let st = e.proxy_stats();
        let names: Vec<&str> = st.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["Away", "Home proxy", "WireGuard"]);
        assert_eq!(st[0].status, "missing");
        assert_eq!(st[1].status, "unknown");
        assert_eq!(
            serde_json::to_string(&st).unwrap(),
            r#"[{"id":"wgapp2","name":"Away","status":"missing","rx":0,"tx":0},{"id":"pxsocks","name":"Home proxy","status":"unknown","rx":0,"tx":0},{"id":"wgconf","name":"WireGuard","status":"connected","addrs":"10.2.0.2","rx":1,"tx":2,"lastOK":3,"since":4}]"#
        );
        for (s, w) in [(TOK, "connected"), (TUP, "up"), (TZZ, "idle"), (TNT, "not responding"), (TKO, "failing"), (TPU, "paused"), (END, "stopped"), (7, "unknown")] {
            assert_eq!(proxy_status(s), w);
        }
    }

    #[test]
    fn helpers() {
        assert_eq!(split_domains(" A.com., b.COM ,,", "c.com"), vec!["a.com", "b.com"]);
        assert_eq!(split_domains("  ", "C.com."), vec!["c.com"]);
        assert!(split_domains("", "").is_empty());
        assert!(is_unspecified_answer("0.0.0.0, ::"));
        assert!(!is_unspecified_answer("0.0.0.0,1.1.1.1"));
        assert!(!is_unspecified_answer(""));
        assert!(!is_unspecified_answer("x"));
        let lines = Arc::new(Mutex::new(Vec::<String>::new()));
        let l2 = lines.clone();
        let e = Engine::with_self(None, "", "fswin.exe", Box::new(move |s| l2.lock().unwrap().push(s.to_string())));
        e.logf("hello");
        let l = lines.lock().unwrap();
        assert!(l[0].ends_with("s hello") && l[0].len() == "   0.000s hello".len(), "{l:?}");
        assert_eq!(e.self_uid, 10000);
        assert_eq!(e.apps.uid("FSWIN.EXE"), 10000);
    }
}
