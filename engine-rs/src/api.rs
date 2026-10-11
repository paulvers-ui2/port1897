// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The control API the app window (which runs without admin rights) uses
//! to read status and change blocking (a port of api_windows.go). It
//! listens on loopback only and every request must carry the token from
//! -token-file. Requests from web pages are refused (they carry an Origin
//! header), as are other Host names (DNS rebinding).
//!
//! The replies are byte for byte what Go's net/http and encoding/json
//! send, where the app could tell: the status codes, the Allow header, the
//! JSON field order and escaping, `[]` for empty lists and the trailing
//! newline.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderValue};
use hyper::{Method, Request, Response, StatusCode, Version};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::Serialize;
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::task::JoinSet;

use crate::engine::Engine;
use crate::events::JOURNAL_SIZE;
use crate::exit::exit_name;
use crate::flags::Options;
use crate::gojson::{self, JValue, Obj};
use crate::killswitch;
use crate::mtu::MtuPlan;
use crate::rules::RuleSet;
use crate::{events, golike, netaddr};

/// What GET /api/status returns; field order as Go's apiStatus.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ApiStatus {
    pub version: String,
    /// unix millis
    #[serde(rename = "startedAt")]
    pub started_at: i64,
    /// "dns" or "full"
    pub mode: String,
    /// exit name, "" when direct
    pub exit: String,
    pub dns: DnsStat,
    pub firewall: FwStat,
    pub traffic: TrafStat,
    pub nrpt: bool,
    #[serde(rename = "allowLan")]
    pub allow_lan: bool,
    #[serde(rename = "killSwitch")]
    pub kill: bool,
    /// why the kill switch is not on, when turning it on failed
    #[serde(rename = "killSwitchError", skip_serializing_if = "String::is_empty")]
    pub kill_error: String,
    /// unix millis; 0 when not paused
    #[serde(rename = "pausedUntil")]
    pub paused: i64,
    /// anti-censorship dial strategy
    pub dial: String,
    /// other VPNs that break ours
    pub conflicts: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<MtuPlan>,
    /// WARP (MASQUE) and the chain: how often usque was restarted, and why
    /// the exit is down while it is
    #[serde(rename = "exitRestarts", skip_serializing_if = "is_zero")]
    pub exit_restarts: i64,
    #[serde(rename = "exitIssue", skip_serializing_if = "String::is_empty")]
    pub exit_issue: String,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DnsStat {
    pub server: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub queries: i64,
    pub failed: i64,
    pub bogus: i64,
    /// by domain rules or query type
    pub blocked: i64,
    pub dnssec: bool,
    pub cache: bool,
    #[serde(rename = "lastMs")]
    pub last_ms: i64,
    #[serde(rename = "avgMs")]
    pub avg_ms: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FwStat {
    pub flows: i64,
    pub blocked: i64,
    #[serde(rename = "blockedApps")]
    pub blocked_apps: Vec<String>,
    #[serde(rename = "appsSeen")]
    pub apps_seen: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TrafStat {
    /// bytes, closed connections only
    pub rx: i64,
    pub tx: i64,
}

/// What the status needs from the run besides the engine and options.
#[derive(Debug, Clone, Default)]
pub struct RunInfo {
    pub version: String,
    pub started_ms: i64,
    pub exit_id: String,
    pub dns_label: String,
    pub mtu: Option<MtuPlan>,
    pub exit_restarts: i64,
    pub exit_issue: String,
}

/// Builds the API status from the engine and the run options.
pub fn status_of(e: &Engine, o: &Options, run: &RunInfo) -> ApiStatus {
    let l = &e.log;
    let g = events::Journal::get;
    let kill = e.kill.as_deref();
    let mut st = ApiStatus {
        version: run.version.clone(),
        started_at: run.started_ms,
        mode: "dns".into(),
        nrpt: o.nrpt,
        allow_lan: o.allow_lan,
        kill: kill.is_some_and(|k| k.is_on()),
        kill_error: kill.map(|k| k.last_error()).unwrap_or_default(),
        mtu: run.mtu.clone(),
        dns: DnsStat {
            server: run.dns_label.clone(),
            kind: o.dns_type.clone(),
            queries: g(&l.dns_queries),
            failed: g(&l.dns_failed),
            bogus: g(&l.dns_bogus),
            blocked: g(&l.dns_blocked),
            dnssec: o.dnssec,
            cache: o.dns_cache,
            last_ms: g(&l.dns_last_ms),
            avg_ms: 0,
        },
        firewall: FwStat { flows: g(&l.flows), blocked: g(&l.flows_blocked), blocked_apps: e.blocked_apps(), apps_seen: l.apps_seen() },
        traffic: TrafStat { rx: g(&l.rx), tx: g(&l.tx) },
        dial: o.dial_strategy.clone(),
        conflicts: o.conflicts.clone(),
        exit_restarts: run.exit_restarts,
        exit_issue: run.exit_issue.clone(),
        ..Default::default()
    };
    let r = e.rules();
    if r.is_paused(events::now_ms()) {
        st.paused = r.paused_until();
    }
    let ok = st.dns.queries - st.dns.failed;
    if ok > 0 {
        st.dns.avg_ms = g(&l.dns_total_ms) / ok;
    }
    if o.full {
        st.mode = "full".into();
    }
    if !run.exit_id.is_empty() {
        st.exit = exit_name(&run.exit_id);
    }
    st
}

/// The -api address, which must be a loopback ip:port.
pub fn check_addr(addr: &str) -> Result<SocketAddr, String> {
    const NOT_LOOPBACK: &str = "-api must be a loopback address like 127.0.0.1:47897";
    let (host, port) = split_host_port(addr)?;
    let ip = netaddr::parse_addr(host).filter(|ip| netaddr::is_loopback(netaddr::unmap(*ip))).ok_or(NOT_LOOPBACK)?;
    let port = golike::parse_uint(port, 10, 16).map_err(|_| format!("address {addr}: invalid port"))?;
    Ok(SocketAddr::new(ip, port as u16))
}

/// net.SplitHostPort for the forms an -api address takes: host:port or
/// [v6]:port.
fn split_host_port(addr: &str) -> Result<(&str, &str), String> {
    let missing = || format!("address {addr}: missing port in address");
    if let Some(rest) = addr.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or_else(|| format!("address {addr}: missing ']' in address"))?;
        let port = after.strip_prefix(':').ok_or_else(missing)?;
        return Ok((host, port));
    }
    let (host, port) = addr.rsplit_once(':').ok_or_else(missing)?;
    if host.contains(':') {
        return Err(format!("address {addr}: too many colons in address"));
    }
    Ok((host, port))
}

/// The token from the -token-file's contents: white space around it is
/// dropped, and it must be 16 characters at least.
pub fn token_from(file: &[u8]) -> Result<Vec<u8>, String> {
    let t = String::from_utf8_lossy(file);
    let t = golike::trim_space(&t);
    if t.len() < 16 {
        return Err("-token-file: token must be at least 16 characters".into());
    }
    Ok(t.as_bytes().to_vec())
}

/// The status, built afresh for each request.
pub type InfoFn = Arc<dyn Fn() -> ApiStatus + Send + Sync>;
/// Asks the engine to stop.
pub type StopFn = Arc<dyn Fn() + Send + Sync>;

struct Api {
    engine: Arc<Engine>,
    /// "Bearer <token>"
    want: Vec<u8>,
    /// the expected Host header, ip:port
    host: String,
    info: InfoFn,
    stop: StopFn,
}

/// A running control API.
pub struct ApiServer {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl ApiServer {
    /// Starts the control API on listener, which the caller has bound to
    /// a loopback address (check_addr).
    pub fn start(listener: TcpListener, token: &[u8], engine: Arc<Engine>, info: InfoFn, stop: StopFn) -> std::io::Result<ApiServer> {
        let addr = listener.local_addr()?;
        let mut want = b"Bearer ".to_vec();
        want.extend_from_slice(token);
        let api = Arc::new(Api { engine, want, host: addr.to_string(), info, stop });
        let task = tokio::spawn(accept_loop(listener, api));
        Ok(ApiServer { addr, task })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stops listening and drops every connection, as Go's Server.Close.
    pub fn close(self) {
        self.task.abort();
    }
}

async fn accept_loop(listener: TcpListener, api: Arc<Api>) {
    // dropped with this task, which aborts the connections too
    let mut conns = JoinSet::new();
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(c) => c,
            Err(_) => {
                // out of sockets or the like: wait a little, as Go does
                tokio::time::sleep(Duration::from_millis(5)).await;
                continue;
            }
        };
        while conns.try_join_next().is_some() {}
        let api = api.clone();
        conns.spawn(async move {
            let svc = hyper::service::service_fn(move |req| {
                let api = api.clone();
                async move { Ok::<_, Infallible>(api.handle(req).await) }
            });
            // a client that stalls, or sends huge headers, cannot tie the
            // API up (Go: ReadHeaderTimeout 5 s, MaxHeaderBytes 16 KiB)
            let _ = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(5))
                .max_buf_size(16 * 1024 + 4096)
                .serve_connection(TokioIo::new(stream), svc)
                .await;
        });
    }
}

type Resp = Response<Full<Bytes>>;

const JSON_LIMIT_SMALL: usize = 4096;
const JSON_LIMIT_RULES: usize = 8 << 20;
/// Go's ReadTimeout: the whole request, body included.
const READ_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Route {
    Status,
    Events,
    Stats,
    Block,
    Rules,
    Conns,
    Proxies,
    Close,
    KillSwitch,
    Stop,
}

/// The routes, as registered with Go's ServeMux.
const ROUTES: &[(&str, &str, Route)] = &[
    ("GET", "/api/status", Route::Status),
    ("GET", "/api/events", Route::Events),
    ("GET", "/api/stats", Route::Stats),
    ("POST", "/api/block", Route::Block),
    ("POST", "/api/rules", Route::Rules),
    ("GET", "/api/conns", Route::Conns),
    ("GET", "/api/proxies", Route::Proxies),
    ("POST", "/api/close", Route::Close),
    ("POST", "/api/killswitch", Route::KillSwitch),
    ("POST", "/api/stop", Route::Stop),
];

/// What Go's ServeMux does with a method and a cleaned path.
#[derive(Debug, PartialEq, Eq)]
enum Found {
    Route(Route),
    /// the path is known, the method is not: these are
    NotAllowed(String),
    Missing,
}

fn find(method: &Method, path: &str) -> Found {
    let mut allowed: Vec<&str> = Vec::new();
    for (m, p, r) in ROUTES {
        if *p != path {
            continue;
        }
        // a GET pattern answers HEAD too
        if method.as_str() == *m || (*m == "GET" && method == Method::HEAD) {
            return Found::Route(*r);
        }
        allowed.push(m);
        if *m == "GET" {
            allowed.push("HEAD");
        }
    }
    if allowed.is_empty() {
        return Found::Missing;
    }
    allowed.sort();
    allowed.dedup();
    Found::NotAllowed(allowed.join(", "))
}

impl Api {
    async fn handle(&self, req: Request<Incoming>) -> Resp {
        let (parts, body) = req.into_parts();
        // what Go's server answers before any handler runs
        if parts.method == Method::OPTIONS && parts.uri == "*" {
            let mut r = Response::new(Full::new(Bytes::new()));
            r.headers_mut().insert("content-length", HeaderValue::from_static("0"));
            return r;
        }
        let hosts = parts.headers.get_all("host").iter().count();
        if hosts > 1 {
            return bad_request("400 Bad Request: too many Host headers");
        }
        if parts.version == Version::HTTP_11 && hosts == 0 && parts.uri.authority().is_none() {
            return bad_request("400 Bad Request: missing required Host header");
        }
        let Some(path) = unescape_path(parts.uri.path()) else {
            return bad_request("400 Bad Request");
        };

        // the guard
        let host = match parts.uri.authority() {
            Some(a) => a.as_str().to_string(),
            None => header(&parts.headers, "host"),
        };
        if !header(&parts.headers, "origin").is_empty() || host != self.host {
            return text(StatusCode::FORBIDDEN, "forbidden");
        }
        let got = parts.headers.get("authorization").map(|v| v.as_bytes()).unwrap_or_default();
        if !bool::from(got.ct_eq(&self.want)) {
            return text(StatusCode::UNAUTHORIZED, "unauthorized");
        }

        // ServeMux: a path not in its clean form is redirected to it
        let clean = clean_path(&path);
        let escaped = parts.uri.path();
        if clean != escaped {
            return redirect(&parts.method, &clean, parts.uri.query());
        }
        let route = match find(&parts.method, &clean) {
            Found::Route(r) => r,
            Found::NotAllowed(allow) => {
                let mut r = text(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
                r.headers_mut().insert("allow", HeaderValue::from_str(&allow).expect("method names"));
                return r;
            }
            Found::Missing => return text(StatusCode::NOT_FOUND, "404 page not found"),
        };
        let query = parts.uri.query().unwrap_or("");
        let limit = match route {
            Route::Rules => JSON_LIMIT_RULES,
            Route::Block | Route::Close | Route::KillSwitch => JSON_LIMIT_SMALL,
            _ => 0,
        };
        let body = if limit > 0 {
            match tokio::time::timeout(READ_TIMEOUT, read_body(body, limit)).await {
                Ok(b) => b,
                Err(_) => return text(StatusCode::REQUEST_TIMEOUT, "request timed out"),
            }
        } else {
            Vec::new()
        };
        self.serve(route, query, &body)
    }

    fn serve(&self, route: Route, query: &str, body: &[u8]) -> Resp {
        let e = &self.engine;
        match route {
            Route::Status => json(&(self.info)()),
            Route::Events => {
                // events after ?after=<id>, at most ?max=<n> (default 200)
                let after = go_parse_int(&query_get(query, "after"));
                let n = go_parse_int(&query_get(query, "max"));
                let n = if n <= 0 || n > JOURNAL_SIZE as i64 { 200 } else { n as usize };
                json(&e.log.since(after, n))
            }
            Route::Stats => {
                // a struct, not json!: that would sort the counts' fields
                #[derive(Serialize)]
                struct Stats {
                    apps: Vec<events::Count>,
                    domains: Vec<events::Count>,
                }
                let (apps, domains) = e.log.top(20);
                json(&Stats { apps, domains })
            }
            Route::Block => {
                const WANT: &str = "want {\"app\": \"name.exe\", \"block\": true}";
                let req = decode(body, JSON_LIMIT_SMALL, "struct { App string \"json:\\\"app\\\"\"; Block bool \"json:\\\"block\\\"\" }", |o| {
                    Ok((o.string("app")?, o.bool("block")?))
                });
                match req {
                    Ok((app, block)) if !golike::trim_space(&app).is_empty() => {
                        e.set_blocked(&app, block);
                        json(&serde_json::json!({"blockedApps": e.blocked_apps()}))
                    }
                    _ => text(StatusCode::BAD_REQUEST, WANT),
                }
            }
            Route::Rules => {
                // the whole rule set at once; open connections it blocks are
                // closed
                let rs = gojson::decode_first(body, JSON_LIMIT_RULES).and_then(|v| RuleSet::from_json(&v));
                match rs {
                    Err(err) => text(StatusCode::BAD_REQUEST, &format!("bad rules: {err}")),
                    Ok(rs) => match e.set_rules(rs) {
                        // rules that did not parse were skipped
                        Some(w) => json(&serde_json::json!({"ok": true, "warnings": w})),
                        None => json(&serde_json::json!({"ok": true})),
                    },
                }
            }
            Route::Proxies => json(&e.proxy_stats()),
            Route::Conns => json(&e.conns.list(&query_get(query, "app"))),
            Route::Close => {
                // {"app": "chrome.exe"}, {"app": ""} for all, or
                // {"cids": ["12"]} for single connections
                let req = decode(body, JSON_LIMIT_SMALL, "struct { App string \"json:\\\"app\\\"\"; CIDs []string \"json:\\\"cids\\\"\" }", |o| {
                    let cids = o.array("cids", "[]string")?.iter().map(|v| o.elem_string("cids", v)).collect::<Result<Vec<_>, _>>()?;
                    Ok((o.string("app")?, cids))
                });
                match req {
                    Err(_) => text(StatusCode::BAD_REQUEST, "want {\"app\": \"name.exe\"} or {\"cids\": [\"12\"]}"),
                    Ok((_, cids)) if !cids.is_empty() => json(&serde_json::json!({"closed": e.close_ids(&cids)})),
                    Ok((app, _)) => json(&serde_json::json!({"closed": e.close_app(&app)})),
                }
            }
            Route::KillSwitch => {
                // {"on": true, "allowLan": false}, for the app's button
                let req = decode(body, JSON_LIMIT_SMALL, "struct { On bool \"json:\\\"on\\\"\"; AllowLAN bool \"json:\\\"allowLan\\\"\" }", |o| {
                    Ok((o.bool("on")?, o.bool("allowLan")?))
                });
                let (on, lan) = match req {
                    Ok(r) => r,
                    Err(err) => return text(StatusCode::BAD_REQUEST, &format!("bad request: {err}")),
                };
                if let Err(err) = killswitch::set(e.kill.as_deref(), on, lan) {
                    let code = if err.is_conflict() { StatusCode::CONFLICT } else { StatusCode::INTERNAL_SERVER_ERROR };
                    return text(code, &err.to_string());
                }
                e.logf(&format!("kill switch {} (from the app)", if on { "on" } else { "off" }));
                json(&serde_json::json!({"killSwitch": e.kill.as_deref().is_some_and(|k| k.is_on())}))
            }
            Route::Stop => {
                let stop = self.stop.clone();
                // after the reply has gone
                tokio::spawn(async move { stop() });
                json(&serde_json::json!({"stopping": true}))
            }
        }
    }
}

/// Reads up to limit + 1 bytes of the body: enough for decode_first to
/// tell a body that is too large, as Go's MaxBytesReader.
async fn read_body(mut body: Incoming, limit: usize) -> Vec<u8> {
    let mut out = Vec::new();
    while out.len() <= limit {
        match body.frame().await {
            Some(Ok(f)) => {
                if let Ok(d) = f.into_data() {
                    out.extend_from_slice(&d);
                }
            }
            // a body cut short is decoded as far as it got
            _ => break,
        }
    }
    out.truncate(limit + 1);
    out
}

/// Decodes the first JSON value of body as Go's Decoder fills a struct of
/// type ty: null leaves it at its zero value.
fn decode<T: Default>(body: &[u8], limit: usize, ty: &str, f: impl FnOnce(&Obj) -> Result<T, String>) -> Result<T, String> {
    let v: JValue = gojson::decode_first(body, limit)?;
    match Obj::of(&v, ty)? {
        None => Ok(T::default()),
        Some(o) => f(&o),
    }
}

fn header(h: &HeaderMap, name: &str) -> String {
    h.get(name).map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned()).unwrap_or_default()
}

/// strconv.ParseInt(s, 10, 64) as the handlers use it, ignoring the
/// error: out of range gives the nearest limit, bad syntax 0.
fn go_parse_int(s: &str) -> i64 {
    match golike::parse_int(s, 10, 64) {
        Ok(n) => n,
        Err(golike::NumError::Range) if s.starts_with('-') => i64::MIN,
        Err(golike::NumError::Range) => i64::MAX,
        Err(_) => 0,
    }
}

/// url.Values.Get: the first value of key; pairs with a ';' or a bad
/// escape are skipped, as url.ParseQuery does.
fn query_get(query: &str, key: &str) -> String {
    for pair in query.split('&') {
        if pair.is_empty() || pair.contains(';') {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let (Some(k), Some(v)) = (query_unescape(k), query_unescape(v)) else {
            continue;
        };
        if k == key {
            return v;
        }
    }
    String::new()
}

fn unhex(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

/// %XX escapes decoded; None for a bad escape. '+' is a space in a query.
fn percent_decode(s: &str, plus: bool) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hi = b.get(i + 1).copied().and_then(unhex)?;
                let lo = b.get(i + 2).copied().and_then(unhex)?;
                out.push(hi << 4 | lo);
                i += 3;
            }
            b'+' if plus => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

fn query_unescape(s: &str) -> Option<String> {
    percent_decode(s, true)
}

fn unescape_path(s: &str) -> Option<String> {
    percent_decode(s, false)
}

/// ServeMux's cleanPath: path.Clean, rooted, keeping a trailing slash.
fn clean_path(p: &str) -> String {
    if p.is_empty() {
        return "/".into();
    }
    let rooted = if p.starts_with('/') { p.to_string() } else { format!("/{p}") };
    let mut parts: Vec<&str> = Vec::new();
    for seg in rooted.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    let mut np = format!("/{}", parts.join("/"));
    if rooted.ends_with('/') && np != "/" {
        np.push('/');
    }
    np
}

/// http.Redirect with 301 to a clean path.
fn redirect(method: &Method, path: &str, query: Option<&str>) -> Resp {
    // url.URL{Path: path}.String() escapes what may not stand in a path
    let mut loc = String::new();
    for c in path.bytes() {
        if c.is_ascii_alphanumeric() || b"-._~/!$&'()*+,;=:@".contains(&c) {
            loc.push(c as char);
        } else {
            loc.push_str(&format!("%{c:02X}"));
        }
    }
    if let Some(q) = query {
        loc.push('?');
        loc.push_str(q);
    }
    let get = *method == Method::GET;
    let body = if get { format!("<a href=\"{}\">Moved Permanently</a>.\n\n", html_escape(&loc)) } else { String::new() };
    let mut r = Response::new(Full::new(Bytes::from(body)));
    *r.status_mut() = StatusCode::MOVED_PERMANENTLY;
    let h = r.headers_mut();
    h.insert("location", HeaderValue::from_str(&loc).unwrap_or(HeaderValue::from_static("/")));
    if get || *method == Method::HEAD {
        h.insert("content-type", HeaderValue::from_static("text/html; charset=utf-8"));
    }
    r
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&#34;").replace('\'', "&#39;")
}

/// What Go's server sends for a request it cannot parse.
fn bad_request(msg: &str) -> Resp {
    let mut r = Response::new(Full::new(Bytes::from(msg.to_string())));
    *r.status_mut() = StatusCode::BAD_REQUEST;
    let h = r.headers_mut();
    h.insert("content-type", HeaderValue::from_static("text/plain; charset=utf-8"));
    h.insert("connection", HeaderValue::from_static("close"));
    r
}

/// http.Error.
fn text(code: StatusCode, msg: &str) -> Resp {
    let mut r = Response::new(Full::new(Bytes::from(format!("{msg}\n"))));
    *r.status_mut() = code;
    let h = r.headers_mut();
    h.insert("content-type", HeaderValue::from_static("text/plain; charset=utf-8"));
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    r
}

/// Go's json.Encoder output: HTML characters and the line and paragraph
/// separators escaped, a newline at the end. They only ever stand inside
/// strings in JSON, so replacing them in the text is safe.
pub fn go_json<T: Serialize + ?Sized>(v: &T) -> String {
    let s = serde_json::to_string(v).expect("API values always encode");
    let mut out = String::with_capacity(s.len() + 1);
    for c in s.chars() {
        match c {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    out.push('\n');
    out
}

/// writeJSON.
fn json<T: Serialize + ?Sized>(v: &T) -> Resp {
    let mut r = Response::new(Full::new(Bytes::from(go_json(v))));
    let h = r.headers_mut();
    h.insert("content-type", HeaderValue::from_static("application/json"));
    h.insert("cache-control", HeaderValue::from_static("no-store"));
    r
}

/// Whether ip is a loopback address, for check_addr's callers.
pub fn is_loopback(ip: IpAddr) -> bool {
    netaddr::is_loopback(netaddr::unmap(ip))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{DNS_COMPLETE, DNS_NO_RESPONSE, DnsSummary, PREFERRED};
    use crate::exit::BASE;
    use crate::exit::EXIT_WG;
    use crate::killswitch::{FakeFirewall, KillSwitch, WfpOptions};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TOKEN: &str = "0123456789abcdef0123";
    const APP: &str = r"C:\Program Files\Test\app.exe";

    fn engine() -> Engine {
        Engine::with_self(None, "", r"C:\x\fswin.exe", Box::new(|_| {}))
    }

    struct T {
        srv: ApiServer,
        e: Arc<Engine>,
        stopped: Arc<AtomicBool>,
        closed: Arc<Mutex<Vec<String>>>,
        _guard: tokio::sync::MutexGuard<'static, ()>,
    }

    // One server at a time: several servers on several runtimes in one
    // process stalled for 10 s now and then on Windows (all of them at
    // once, connects included); one server under parallel load does not,
    // see many_clients_at_once.
    static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn start(e: Engine) -> T {
        let guard = ONE_AT_A_TIME.lock().await;
        let e = Arc::new(e);
        let closed = Arc::new(Mutex::new(Vec::new()));
        let c2 = closed.clone();
        e.set_closer(Arc::new(move |csv: &str| {
            c2.lock().unwrap().push(csv.to_string());
            csv.to_string()
        }));
        let stopped = Arc::new(AtomicBool::new(false));
        let s2 = stopped.clone();
        let e2 = e.clone();
        let info: InfoFn = Arc::new(move || {
            let o = Options { full: true, dns_type: "doh".into(), dial_strategy: "never".into(), ..Default::default() };
            status_of(&e2, &o, &RunInfo { version: "test".into(), started_ms: 5, exit_id: EXIT_WG.into(), dns_label: "https://dns".into(), ..Default::default() })
        });
        // never 47897: the user's engine may hold it
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let srv = ApiServer::start(ln, TOKEN.as_bytes(), e.clone(), info, Arc::new(move || s2.store(true, Ordering::SeqCst))).unwrap();
        T { srv, e, stopped, closed, _guard: guard }
    }

    struct Reply {
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
    }

    impl Reply {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
        }
    }

    /// Sends a raw request and reads the reply until the server closes.
    async fn raw(addr: SocketAddr, req: String) -> Reply {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8(buf).unwrap();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        let mut lines = head.split("\r\n");
        let status = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
        let headers = lines.map(|l| l.split_once(": ").unwrap()).map(|(k, v)| (k.to_string(), v.to_string())).collect();
        Reply { status, headers, body: body.to_string() }
    }

    async fn call(t: &T, method: &str, path: &str, body: &str) -> Reply {
        let a = t.srv.local_addr();
        raw(a, format!("{method} {path} HTTP/1.1\r\nHost: {a}\r\nAuthorization: Bearer {TOKEN}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())).await
    }

    #[tokio::test]
    async fn guard() {
        let t = start(engine()).await;
        let a = t.srv.local_addr();
        let ok = format!("Host: {a}\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n");
        let r = raw(a, format!("GET /api/status HTTP/1.1\r\n{ok}\r\n")).await;
        assert_eq!(r.status, 200);
        assert_eq!(r.header("content-type"), Some("application/json"));
        assert_eq!(r.header("cache-control"), Some("no-store"));
        assert!(r.body.ends_with("}\n"));

        // a web page: refused even with the token
        let r = raw(a, format!("GET /api/status HTTP/1.1\r\n{ok}Origin: http://evil.example\r\n\r\n")).await;
        assert_eq!((r.status, r.body.as_str()), (403, "forbidden\n"));
        assert_eq!(r.header("content-type"), Some("text/plain; charset=utf-8"));
        assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
        // an empty Origin is no Origin, as Header.Get sees it
        assert_eq!(raw(a, format!("GET /api/status HTTP/1.1\r\n{ok}Origin: \r\n\r\n")).await.status, 200);
        // DNS rebinding: another Host name
        let r = raw(a, format!("GET /api/status HTTP/1.1\r\nHost: evil.example:{}\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n\r\n", a.port())).await;
        assert_eq!(r.status, 403);
        let r = raw(a, format!("GET http://localhost:{}/api/status HTTP/1.1\r\n{ok}\r\n", a.port())).await;
        assert_eq!(r.status, 403, "the absolute form's host is the one checked");
        let r = raw(a, format!("GET http://{a}/api/status HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n\r\n")).await;
        assert_eq!(r.status, 200);
        // wrong, missing or differently cased tokens
        for auth in ["", "Authorization: Bearer nope\r\n", &format!("Authorization: bearer {TOKEN}\r\n"), &format!("Authorization: Bearer {TOKEN}x\r\n")] {
            let r = raw(a, format!("GET /api/status HTTP/1.1\r\nHost: {a}\r\n{auth}Connection: close\r\n\r\n")).await;
            assert_eq!((r.status, r.body.as_str()), (401, "unauthorized\n"), "{auth:?}");
        }
        // the guard runs before the routes: no hint of what exists
        let r = raw(a, format!("GET /nope HTTP/1.1\r\nHost: {a}\r\nConnection: close\r\n\r\n")).await;
        assert_eq!(r.status, 401);
        // HTTP/1.1 needs a Host
        let r = raw(a, format!("GET /api/status HTTP/1.1\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n\r\n")).await;
        assert_eq!((r.status, r.body.as_str()), (400, "400 Bad Request: missing required Host header"));
        t.srv.close();
    }

    #[tokio::test]
    async fn routing_like_servemux() {
        let t = start(engine()).await;
        let r = call(&t, "POST", "/api/status", "").await;
        assert_eq!((r.status, r.body.as_str(), r.header("allow")), (405, "Method Not Allowed\n", Some("GET, HEAD")));
        let r = call(&t, "GET", "/api/stop", "").await;
        assert_eq!((r.status, r.header("allow")), (405, Some("POST")));
        assert!(!t.stopped.load(Ordering::SeqCst));
        let r = call(&t, "GET", "/api/nope", "").await;
        assert_eq!((r.status, r.body.as_str()), (404, "404 page not found\n"));
        assert_eq!(call(&t, "GET", "/api/status/", "").await.status, 404);
        let r = call(&t, "HEAD", "/api/status", "").await;
        assert_eq!((r.status, r.body.as_str()), (200, ""));
        assert_eq!(r.header("content-type"), Some("application/json"));
        // paths not in clean form are redirected, escapes too
        let r = call(&t, "GET", "/api//status?x=1", "").await;
        assert_eq!((r.status, r.header("location")), (301, Some("/api/status?x=1")));
        assert_eq!(r.body, "<a href=\"/api/status?x=1\">Moved Permanently</a>.\n\n");
        let r = call(&t, "POST", "/api/./x/../stop", "").await;
        assert_eq!((r.status, r.header("location"), r.body.as_str()), (301, Some("/api/stop"), ""));
        assert_eq!(call(&t, "GET", "/api/%73tatus", "").await.header("location"), Some("/api/status"));
        assert_eq!(call(&t, "GET", "/api/%zz", "").await.status, 400);
        let r = call(&t, "OPTIONS", "*", "").await;
        assert_eq!((r.status, r.header("content-length")), (200, Some("0")));
        t.srv.close();
    }

    #[tokio::test]
    async fn status_shape() {
        let mut e = engine();
        let fw = Arc::new(FakeFirewall::default());
        e.kill = Some(Arc::new(KillSwitch::new(fw, WfpOptions::default(), false)));
        let t = start(e).await;
        let uid = t.e.apps.uid(APP).to_string();
        t.e.on_response(&DnsSummary { qname: "a.com.".into(), uid: uid.clone(), id: PREFERRED.into(), status: DNS_COMPLETE, latency: 0.04, ..Default::default() });
        t.e.on_response(&DnsSummary { qname: "b.com.".into(), uid, id: PREFERRED.into(), status: DNS_NO_RESPONSE, latency: 5.0, ..Default::default() });
        // a failed kill switch shows its error
        assert!(killswitch::set(t.e.kill.as_deref(), true, false).is_err());
        let r = call(&t, "GET", "/api/status", "").await;
        assert_eq!(
            r.body,
            concat!(
                r#"{"version":"test","startedAt":5,"mode":"full","exit":"WireGuard","#,
                r#""dns":{"server":"https://dns","type":"doh","queries":2,"failed":1,"bogus":0,"blocked":0,"dnssec":false,"cache":false,"lastMs":40,"avgMs":40},"#,
                r#""firewall":{"flows":0,"blocked":0,"blockedApps":[],"appsSeen":0},"traffic":{"rx":0,"tx":0},"#,
                r#""nrpt":false,"allowLan":false,"killSwitch":false,"#,
                r#""killSwitchError":"the kill switch needs all traffic in the tunnel; restart protection with the firewall on","#,
                r#""pausedUntil":0,"dial":"never","conflicts":[]}"#,
                "\n"
            )
        );
        t.srv.close();
    }

    // The home screen reads status.conflicts: always an array, a copy of
    // the options' list.
    #[test]
    fn status_conflicts_is_always_an_array() {
        let e = engine();
        let two = vec![
            "another VPN sends all DNS elsewhere: Proton VPN (Force all DNS requests via Proton VPN)".to_string(),
            "internet traffic leaves through another VPN's adapter: ProtonVPN (ProtonVPN Tunnel)".to_string(),
        ];
        for (conflicts, want) in [(vec![], "[]".to_string()), (two.clone(), serde_json::to_string(&two).unwrap())] {
            let o = Options { conflicts, dial_strategy: "never".into(), dns_type: "doh".into(), ..Default::default() };
            let st = status_of(&e, &o, &RunInfo { exit_id: EXIT_WG.into(), version: "test".into(), ..Default::default() });
            let v: serde_json::Value = serde_json::from_str(&go_json(&st)).unwrap();
            assert_eq!(v["conflicts"].to_string(), want);
            assert_eq!(st.exit, "WireGuard");
        }
        // paused rules show until when; mtu and the usque fields when set
        let rs = RuleSet { paused_until: events::now_ms() + 60_000, ..Default::default() };
        e.set_rules(rs.clone());
        let mtu = crate::mtu::plan_mtu(1500, "Wi-Fi 1500", EXIT_WG, "", None, 0);
        let run = RunInfo { mtu: Some(mtu), exit_restarts: 2, exit_issue: "Tunnel connection lost".into(), ..Default::default() };
        let st = status_of(&e, &Options::default(), &run);
        assert_eq!(st.paused, rs.paused_until);
        let s = go_json(&st);
        assert!(s.contains(r#""mtu":{"link":1500,"exit":1420,"adapter":1420,"auto":true,"why":"Wi-Fi 1500, WireGuard 1420"},"exitRestarts":2,"exitIssue":"Tunnel connection lost"}"#), "{s}");
        assert!(s.contains(r#""exit":"""#) && s.contains(r#""mode":"dns""#));
    }

    #[tokio::test]
    async fn events_stats_conns_and_close() {
        let t = start(engine()).await;
        let uid = t.e.apps.uid(APP);
        let m1 = t.e.flow(6, uid, "10.111.222.1:1", "1.1.1.1:443", "<b>&co.example", "");
        let m2 = t.e.flow(17, uid, "10.111.222.1:2", "9.9.9.9:443", "", "");
        let other = t.e.apps.uid(r"C:\x\other.exe");
        let m3 = t.e.flow(6, other, "10.111.222.1:3", "8.8.8.8:443", "", "");
        assert_eq!(m1.pid, BASE);

        let r = call(&t, "GET", "/api/events?after=1&max=1", "").await;
        let v: Vec<serde_json::Value> = serde_json::from_str(&r.body).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0]["id"], 3, "the newest of those after 1");
        for q in ["", "?max=0", "?max=-5", "?max=99999", "?max=abc", "?after=x"] {
            let r = call(&t, "GET", &format!("/api/events{q}"), "").await;
            assert_eq!(serde_json::from_str::<Vec<serde_json::Value>>(&r.body).unwrap().len(), 3, "{q}");
        }
        assert_eq!(call(&t, "GET", "/api/events?after=99999999999999999999", "").await.body, "[]\n");
        assert_eq!(call(&t, "GET", "/api/events?after=3", "").await.body, "[]\n");
        // Go's encoder escapes HTML characters
        let r = call(&t, "GET", "/api/events?after=0&max=3", "").await;
        assert!(r.body.contains(r#""domain":"\u003cb\u003e\u0026co.example""#), "{}", r.body);

        let r = call(&t, "GET", "/api/stats", "").await;
        assert!(r.body.starts_with(r#"{"apps":[{"name":"app.exe","count":2},{"name":"other.exe","count":1}],"domains":[{"name":"\u003cb\u003e\u0026co.example","count":1}]}"#), "{}", r.body);

        let r = call(&t, "GET", "/api/conns?app=APP.EXE", "").await;
        let v: Vec<serde_json::Value> = serde_json::from_str(&r.body).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(call(&t, "GET", "/api/conns?app=nope.exe", "").await.body, "[]\n");

        let r = call(&t, "POST", "/api/close", &format!(r#"{{"cids":["{}","404"]}}"#, m2.cid)).await;
        assert_eq!(r.body, "{\"closed\":1}\n");
        let r = call(&t, "POST", "/api/close", r#"{"app":"other.exe"}"#).await;
        assert_eq!(r.body, "{\"closed\":1}\n");
        assert_eq!(*t.closed.lock().unwrap(), vec![m2.cid.clone(), m3.cid.clone()]);
        // null: all of them, as Go's decoder leaves app ""
        assert_eq!(call(&t, "POST", "/api/close", "null").await.body, "{\"closed\":3}\n");
        for bad in ["", "[1]", r#"{"cids":"12"}"#, r#"{"app":5}"#] {
            let r = call(&t, "POST", "/api/close", bad).await;
            assert_eq!((r.status, r.body.as_str()), (400, "want {\"app\": \"name.exe\"} or {\"cids\": [\"12\"]}\n"), "{bad}");
        }
        t.srv.close();
    }

    #[tokio::test]
    async fn block_rules_and_stop() {
        let t = start(engine()).await;
        let r = call(&t, "POST", "/api/block", r#"{"APP":"Chrome.exe","block":true} trailing junk"#).await;
        assert_eq!((r.status, r.body.as_str()), (200, "{\"blockedApps\":[\"chrome.exe\"]}\n"));
        for bad in ["{}", r#"{"app":"  "}"#, r#"{"app":"a.exe","block":"yes"}"#, "nope", "null"] {
            let r = call(&t, "POST", "/api/block", bad).await;
            assert_eq!((r.status, r.body.as_str()), (400, "want {\"app\": \"name.exe\", \"block\": true}\n"), "{bad}");
        }
        // over 4 KiB
        let big = format!(r#"{{"app":"a.exe","pad":"{}"}}"#, "x".repeat(5000));
        assert_eq!(call(&t, "POST", "/api/block", &big).await.status, 400);
        // a complete value within the limit is enough, whatever follows
        let ok = format!(r#"{{"app":"b.exe","block":true}}{}"#, " ".repeat(5000));
        assert_eq!(call(&t, "POST", "/api/block", &ok).await.status, 200);

        let r = call(&t, "POST", "/api/rules", r#"{"apps":{"x.exe":{"mode":"block"}},"ips":[{"ip":"bad"}]}"#).await;
        assert_eq!(r.status, 200);
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(v["ok"], true);
        assert!(v["warnings"].as_str().unwrap().starts_with("ip rule \"bad\""), "{v}");
        assert_eq!(t.e.blocked_apps(), vec!["x.exe"]);
        assert_eq!(call(&t, "POST", "/api/rules", "{}").await.body, "{\"ok\":true}\n");
        let r = call(&t, "POST", "/api/rules", r#"{"apps":[]}"#).await;
        assert!(r.status == 400 && r.body.starts_with("bad rules: "), "{}", r.body);

        let r = call(&t, "GET", "/api/proxies", "").await;
        assert_eq!(r.body, "[]\n");

        let r = call(&t, "POST", "/api/stop", "").await;
        assert_eq!(r.body, "{\"stopping\":true}\n");
        for _ in 0..100 {
            if t.stopped.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(t.stopped.load(Ordering::SeqCst));
        t.srv.close();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn many_clients_at_once() {
        let t = Arc::new(start(engine()).await);
        let started = std::time::Instant::now();
        let mut set = JoinSet::new();
        for i in 0..64 {
            let t = t.clone();
            set.spawn(async move { call(&t, "GET", if i % 2 == 0 { "/api/status" } else { "/api/events" }, "").await.status });
        }
        while let Some(s) = set.join_next().await {
            assert_eq!(s.unwrap(), 200);
        }
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    }

    #[tokio::test]
    async fn kill_switch_button() {
        let t = start(engine()).await;
        let r = call(&t, "POST", "/api/killswitch", r#"{"on":true}"#).await;
        assert_eq!((r.status, r.body.as_str()), (409, "no kill switch: the tunnel is not a Wintun adapter\n"));
        t.srv.close();
        drop(t._guard);

        let fw = Arc::new(FakeFirewall::default());
        let mut e = engine();
        e.kill = Some(Arc::new(KillSwitch::new(fw.clone(), WfpOptions { tun_luid: 1, ..Default::default() }, true)));
        let t = start(e).await;
        let r = call(&t, "POST", "/api/killswitch", r#"{"on":true,"allowLan":true}"#).await;
        assert_eq!((r.status, r.body.as_str()), (200, "{\"killSwitch\":true}\n"));
        assert!(fw.rules.lock().unwrap().as_ref().unwrap().allow_lan);
        *fw.fail_enable.lock().unwrap() = Some("wfp: enable: denied".into());
        let r = call(&t, "POST", "/api/killswitch", r#"{"on":true}"#).await;
        assert_eq!((r.status, r.body.as_str()), (500, "wfp: enable: denied\n"));
        let r = call(&t, "POST", "/api/killswitch", r#"{"on":1}"#).await;
        assert!(r.status == 400 && r.body.starts_with("bad request: "), "{}", r.body);
        let r = call(&t, "POST", "/api/killswitch", "{}").await;
        assert_eq!((r.status, r.body.as_str()), (200, "{\"killSwitch\":false}\n"));
        t.srv.close();
    }

    #[test]
    fn addresses_and_tokens() {
        assert_eq!(check_addr("127.0.0.1:47897").unwrap().to_string(), "127.0.0.1:47897");
        assert_eq!(check_addr("[::1]:0").unwrap().to_string(), "[::1]:0");
        assert!(check_addr("127.9.9.9:1").is_ok());
        for bad in ["0.0.0.0:47897", "192.168.1.2:1", "localhost:47897", "[::]:1"] {
            assert_eq!(check_addr(bad).unwrap_err(), "-api must be a loopback address like 127.0.0.1:47897", "{bad}");
        }
        assert_eq!(check_addr("127.0.0.1").unwrap_err(), "address 127.0.0.1: missing port in address");
        assert!(check_addr("::1:80").is_err());
        assert_eq!(token_from(b"  0123456789abcdef\r\n").unwrap(), b"0123456789abcdef");
        assert_eq!(token_from(b"short").unwrap_err(), "-token-file: token must be at least 16 characters");
        assert!(is_loopback("::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn helpers() {
        assert_eq!(clean_path("/a/../../b/./c/"), "/b/c/");
        assert_eq!(clean_path(""), "/");
        assert_eq!(clean_path("x"), "/x");
        assert_eq!(query_get("a=1&a=2&b=%41+b", "a"), "1");
        assert_eq!(query_get("a=1&a=2&b=%41+b", "b"), "A b");
        assert_eq!(query_get("x=%zz&x=2;&x=3", "x"), "3");
        assert_eq!(go_parse_int("-99999999999999999999"), i64::MIN);
        assert_eq!(go_parse_int("+7"), 7);
        assert_eq!(go_json("a\u{2028}<"), "\"a\\u2028\\u003c\"\n");
        assert_eq!(find(&Method::PUT, "/api/rules"), Found::NotAllowed("POST".into()));
    }
}
