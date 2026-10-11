// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! DNS over HTTPS (RFC 8484), after firestack's doh transport: POST with
//! application/dns-message, switching to GET for good once the server
//! answers 404 or 405; the query is padded (RFC 8467) and sent with id 0;
//! connections go to the bootstrap IPs (no DNS lookup of the DoH host),
//! HTTP/2 when the server offers it, reused across queries.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::client::conn::{http1, http2};
use hyper::header::{ACCEPT, CONTENT_TYPE, HOST};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ClientConfig;
use tokio::sync::Mutex;

use super::tls::{self, Trust};
use super::{Addrs, BoxFuture, Dialer, QueryError, Transport, msg};
use crate::engine::{self, DnsSummary};

const MIME: &str = "application/dns-message";
/// Go's TLSHandshakeTimeout, here for dial and handshake together.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(7);
/// Go's ResponseHeaderTimeout, here for the whole exchange.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);
/// Larger is not a DNS message.
const MAX_BODY: usize = 65535;

/// The prefix firestack puts on the server of a transport that skips the
/// certificate check.
pub const NOPKI_PREFIX: &str = "nopki.";
/// The prefix on the Default transport's server.
pub const DEFAULT_PREFIX: &str = "d.";

enum Sender {
    H1(http1::SendRequest<Full<Bytes>>),
    H2(http2::SendRequest<Full<Bytes>>),
}

pub struct Doh {
    id: String,
    url: String,
    host: String,
    /// host:port as the Host header has it
    authority: String,
    /// path and query for HTTP/1.1 requests
    path: String,
    skip_verify: bool,
    addrs: Addrs,
    tls: Arc<ClientConfig>,
    dialer: Arc<dyn Dialer>,
    status: AtomicI32,
    prefer_get: AtomicBool,
    /// an open connection per exit
    conns: Mutex<HashMap<String, Sender>>,
}

impl Doh {
    /// A DoH transport for url with the bootstrap IPs in ips_csv (bare IPs
    /// or ip:port). An http:// URL means https without the certificate
    /// check, as in firestack.
    pub fn new(id: &str, url: &str, ips_csv: &str, trust: &Trust, dialer: Arc<dyn Dialer>) -> Result<Doh, String> {
        let (scheme, rest) = url.split_once("://").ok_or_else(|| format!("doh: no scheme in {}", crate::golike::quote(url)))?;
        let skip_verify = match scheme.to_ascii_lowercase().as_str() {
            "https" => false,
            "http" => true,
            s => return Err(format!("unsupported scheme {s}")),
        };
        let (authority, path) = match rest.find(['/', '?', '#']) {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let path = path.split('#').next().unwrap_or("/");
        let path = if path.starts_with('?') { format!("/{path}") } else { path.to_string() };
        let authority = authority.rsplit('@').next().unwrap_or("");
        let (host, port) = split_host_port(authority)?;
        if host.is_empty() {
            return Err(format!("no hostname in {url}"));
        }
        let addrs = Addrs::new(super::bootstrap_addrs(&host, port, ips_csv));
        let tls = tls::client_config(trust, skip_verify, &[b"h2", b"http/1.1"])?;
        tls::server_name(&host)?;
        let authority = if port == 443 { bracket(&host) } else { format!("{}:{port}", bracket(&host)) };
        Ok(Doh {
            id: id.to_string(),
            url: format!("https://{authority}{path}"),
            host,
            authority,
            path,
            skip_verify,
            addrs,
            tls,
            dialer,
            status: AtomicI32::new(engine::DNS_START),
            prefer_get: AtomicBool::new(false),
            conns: Mutex::new(HashMap::new()),
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    async fn connect(&self, pid: &str) -> Result<(Sender, SocketAddr), String> {
        let fut = async {
            let (stream, addr) = self.addrs.dial(self.dialer.as_ref(), pid).await.map_err(|e| format!("dial {}: {e}", self.host))?;
            let name = tls::server_name(&self.host)?;
            let tls = tokio_rustls::TlsConnector::from(self.tls.clone()).connect(name, stream).await.map_err(|e| {
                self.addrs.disconfirm(addr);
                format!("tls {} ({addr}): {e}", self.host)
            })?;
            let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
            let io = TokioIo::new(tls);
            let sender = if h2 {
                let (s, conn) = http2::handshake(TokioExecutor::new(), io).await.map_err(|e| format!("h2 {}: {e}", self.host))?;
                tokio::spawn(conn);
                Sender::H2(s)
            } else {
                let (s, conn) = http1::handshake(io).await.map_err(|e| format!("http {}: {e}", self.host))?;
                tokio::spawn(conn);
                Sender::H1(s)
            };
            Ok((sender, addr))
        };
        tokio::time::timeout(CONNECT_TIMEOUT, fut).await.map_err(|_| format!("dial {}: i/o timeout", self.host))?
    }

    fn request(&self, q: &[u8], h2: bool) -> Result<Request<Full<Bytes>>, String> {
        let get = self.prefer_get.load(Ordering::Relaxed);
        let path = if get { format!("{}?dns={}", self.path, base64url(q)) } else { self.path.clone() };
        let uri = if h2 { format!("https://{}{path}", self.authority) } else { path };
        let b = Request::builder()
            .method(if get { Method::GET } else { Method::POST })
            .uri(uri)
            .header(CONTENT_TYPE, MIME)
            .header(ACCEPT, MIME);
        let b = if h2 { b } else { b.header(HOST, &self.authority) };
        let body = if get { Bytes::new() } else { Bytes::copy_from_slice(q) };
        b.body(Full::new(body)).map_err(|e| format!("doh: request: {e}"))
    }

    /// One exchange on a pooled or new connection. A failure on a pooled
    /// connection is retried once on a new one (firestack retries EOFs).
    async fn exchange(&self, pid: &str, q: &[u8]) -> Result<(StatusCode, Bytes), QueryError> {
        let pooled = self.conns.lock().await.remove(pid);
        let mut tries: Vec<Option<Sender>> = Vec::new();
        if let Some(s) = pooled {
            tries.push(Some(s));
        }
        tries.push(None);
        let mut last = String::new();
        for t in tries {
            let reused = t.is_some();
            let mut sender = match t {
                Some(s) => s,
                None => match self.connect(pid).await {
                    Ok((s, addr)) => {
                        self.addrs.confirm(addr);
                        s
                    }
                    Err(e) => return Err(QueryError::new(engine::DNS_SEND_FAILED, e)),
                },
            };
            match self.send(&mut sender, q).await {
                Ok(r) => {
                    self.keep(pid, sender).await;
                    return Ok(r);
                }
                Err(e) => {
                    last = e;
                    if !reused {
                        break;
                    }
                }
            }
        }
        Err(QueryError::new(engine::DNS_SEND_FAILED, last))
    }

    async fn send(&self, sender: &mut Sender, q: &[u8]) -> Result<(StatusCode, Bytes), String> {
        let res = match sender {
            Sender::H2(s) => {
                s.ready().await.map_err(|e| e.to_string())?;
                s.send_request(self.request(q, true)?).await
            }
            Sender::H1(s) => {
                s.ready().await.map_err(|e| e.to_string())?;
                s.send_request(self.request(q, false)?).await
            }
        }
        .map_err(|e| format!("{} {:?}: {e}", if self.prefer_get.load(Ordering::Relaxed) { "Get" } else { "Post" }, self.url))?;
        let status = res.status();
        let body = Limited::new(res.into_body(), MAX_BODY).collect().await.map_err(|e| e.to_string())?.to_bytes();
        Ok((status, body))
    }

    async fn keep(&self, pid: &str, s: Sender) {
        let open = match &s {
            Sender::H1(s) => !s.is_closed(),
            Sender::H2(s) => !s.is_closed(),
        };
        if open {
            self.conns.lock().await.insert(pid.to_string(), s);
        }
    }

    /// Sends q and returns the answer with q's id, or why there is none
    /// (firestack's doDoh and do).
    async fn do_query(&self, pid: &str, q: &[u8]) -> Result<Vec<u8>, QueryError> {
        let mut m = msg::parse(q).map_err(|e| QueryError::new(engine::DNS_BAD_QUERY, e))?;
        let id = m.metadata.id;
        msg::pad_query(&mut m);
        m.metadata.id = 0;
        let wire = msg::pack(&m).map_err(|e| QueryError::new(engine::DNS_INTERNAL_ERROR, e))?;
        let (status, body) = match tokio::time::timeout(RESPONSE_TIMEOUT, self.exchange(pid, &wire)).await {
            Ok(r) => r?,
            Err(_) => {
                self.conns.lock().await.remove(pid);
                return Err(QueryError::new(engine::DNS_SEND_FAILED, format!("Post {:?}: timeout awaiting response headers", self.url)));
            }
        };
        if status != StatusCode::OK {
            let sc = status.as_u16();
            if sc == 404 || sc == 405 {
                self.prefer_get.store(true, Ordering::Relaxed);
            }
            let st = if (400..500).contains(&sc) { engine::DNS_CLIENT_ERROR } else { engine::DNS_TRANSPORT_ERROR };
            return Err(QueryError::new(st, format!("http-status: {sc}")));
        }
        if msg::parse(&body).is_err() {
            return Err(QueryError::new(engine::DNS_BAD_RESPONSE, format!("parse err: {}", msg::parse(&body).err().unwrap_or_default())));
        }
        let mut ans = body.to_vec();
        ans[..2].copy_from_slice(&id.to_be_bytes());
        Ok(ans)
    }
}

impl Transport for Doh {
    fn id(&self) -> &str {
        &self.id
    }

    fn addr(&self) -> String {
        let mut a = self.host.clone();
        if self.skip_verify {
            a = format!("{NOPKI_PREFIX}{a}");
        }
        if self.id == super::fake::DEFAULT {
            a = format!("{DEFAULT_PREFIX}{a}");
        }
        a
    }

    fn status(&self) -> i32 {
        self.status.load(Ordering::Relaxed)
    }

    fn query<'a>(&'a self, pid: &'a str, q: &'a [u8], smm: &'a mut DnsSummary) -> BoxFuture<'a, Result<Vec<u8>, QueryError>> {
        Box::pin(async move {
            let start = Instant::now();
            let r = self.do_query(pid, q).await;
            fill(smm, &self.addr(), start, &r);
            self.status.store(smm.status, Ordering::Relaxed);
            r
        })
    }
}

/// Fills the summary as firestack's transports do after a query.
pub(crate) fn fill(smm: &mut DnsSummary, server: &str, start: Instant, r: &Result<Vec<u8>, QueryError>) {
    smm.latency = start.elapsed().as_secs_f64();
    smm.server = server.to_string();
    match r {
        Ok(ans) => {
            let m = msg::parse(ans).ok();
            smm.rdata = msg::interesting_rdata(m.as_ref());
            smm.rcode = m.as_ref().map(msg::rcode).unwrap_or(1);
            smm.ad = m.as_ref().is_some_and(|m| m.metadata.authentic_data);
            smm.status = engine::DNS_COMPLETE;
        }
        Err(e) => {
            // firestack answers SERVFAIL internally; the summary shows it
            smm.rdata = String::new();
            smm.rcode = 2;
            smm.status = e.status;
            smm.msg = e.msg.clone();
        }
    }
}

fn bracket(host: &str) -> String {
    if host.contains(':') { format!("[{host}]") } else { host.to_string() }
}

/// host and port of an URL authority; 443 when none.
fn split_host_port(a: &str) -> Result<(String, u16), String> {
    let (host, port) = if let Some(rest) = a.strip_prefix('[') {
        let (h, p) = rest.split_once(']').ok_or_else(|| format!("bad host {}", crate::golike::quote(a)))?;
        (h, p.strip_prefix(':'))
    } else {
        match a.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (a, None),
        }
    };
    let port = match port {
        None | Some("") => 443,
        // as Go: a port that does not parse or is 0 means the default
        Some(p) => p.parse::<u16>().ok().filter(|p| *p > 0).unwrap_or(443),
    };
    Ok((host.to_string(), port))
}

/// base64url without padding (RFC 4648 section 5), as RFC 8484 GETs use.
pub fn base64url(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        let chars = c.len() + 1;
        for i in 0..chars {
            out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod testserver {
    //! A DoH server on a pipe with the test certificate. It answers
    //! every A query with 192.0.2.1 (TTL 60) and counts what it got.

    use std::convert::Infallible;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::body::Incoming;
    use hyper::{Request, Response, StatusCode};
    use hyper_util::rt::{TokioExecutor, TokioIo};

    use crate::dns::msg;
    use crate::dns::pipe::PipeDialer;
    use crate::dns::tls::testcert;

    #[derive(Default)]
    pub struct Seen {
        pub posts: AtomicUsize,
        pub gets: AtomicUsize,
        pub conns: AtomicUsize,
        /// answer POSTs with 405
        pub refuse_post: AtomicBool,
        /// answer everything with 500
        pub fail: AtomicBool,
        pub last_len: AtomicUsize,
        pub last_id: AtomicUsize,
    }

    /// An answer to q: A 192.0.2.1, or rcode NXDOMAIN for nx.test.
    pub fn answer(q: &[u8]) -> Vec<u8> {
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{RData, Record};
        let q = msg::parse(q).unwrap();
        let mut a = msg::empty_response(&q).unwrap();
        if msg::qname(&q) == "nx.test" {
            a.metadata.response_code = hickory_proto::op::ResponseCode::NXDomain;
        } else if q.queries[0].query_type() == hickory_proto::rr::RecordType::A {
            let ip = if msg::qname(&q) == "bogus.example.com" { [192, 168, 1, 1] } else { [192, 0, 2, 1] };
            a.answers.push(Record::from_rdata(q.queries[0].name().clone(), 60, RData::A(A(ip.into()))));
        }
        msg::pack(&a).unwrap()
    }

    async fn handle(seen: Arc<Seen>, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
        let resp = |sc: StatusCode, b: Vec<u8>| {
            Ok(Response::builder().status(sc).header("content-type", "application/dns-message").body(Full::new(Bytes::from(b))).unwrap())
        };
        if seen.fail.load(Ordering::SeqCst) {
            return resp(StatusCode::INTERNAL_SERVER_ERROR, Vec::new());
        }
        let q = if req.method() == hyper::Method::POST {
            seen.posts.fetch_add(1, Ordering::SeqCst);
            if seen.refuse_post.load(Ordering::SeqCst) {
                return resp(StatusCode::METHOD_NOT_ALLOWED, Vec::new());
            }
            if req.headers().get("content-type").map(|v| v.as_bytes()) != Some(b"application/dns-message") {
                return resp(StatusCode::UNSUPPORTED_MEDIA_TYPE, Vec::new());
            }
            req.into_body().collect().await.unwrap().to_bytes().to_vec()
        } else {
            seen.gets.fetch_add(1, Ordering::SeqCst);
            let qs = req.uri().query().unwrap_or("").to_string();
            match qs.strip_prefix("dns=").map(unbase64url) {
                Some(Some(b)) => b,
                _ => return resp(StatusCode::BAD_REQUEST, Vec::new()),
            }
        };
        seen.last_len.store(q.len(), Ordering::SeqCst);
        seen.last_id.store(u16::from_be_bytes([q[0], q[1]]) as usize, Ordering::SeqCst);
        resp(StatusCode::OK, answer(&q))
    }

    fn unbase64url(s: &str) -> Option<Vec<u8>> {
        let mut bits = 0u32;
        let mut n = 0;
        let mut out = Vec::new();
        for c in s.bytes() {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'-' => 62,
                b'_' => 63,
                _ => return None,
            } as u32;
            bits = bits << 6 | v;
            n += 6;
            if n >= 8 {
                n -= 8;
                out.push((bits >> n) as u8);
            }
        }
        Some(out)
    }

    /// Starts the server and returns the dialer that reaches it; alpn
    /// picks HTTP/2 ("h2") or HTTP/1.1. The connections are pipes, not
    /// sockets (see `dns::pipe`).
    pub async fn start(alpn: &'static [u8]) -> (Arc<Seen>, Arc<PipeDialer>) {
        let seen = Arc::new(Seen::default());
        let acceptor = tokio_rustls::TlsAcceptor::from(testcert::server_config(&[alpn]));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let s2 = seen.clone();
        tokio::spawn(async move {
            while let Some(c) = rx.recv().await {
                s2.conns.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                let seen = s2.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(c).await else { return };
                    let svc = hyper::service::service_fn(move |r| handle(seen.clone(), r));
                    let io = TokioIo::new(tls);
                    if alpn == b"h2" {
                        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new()).serve_connection(io, svc).await;
                    } else {
                        let _ = hyper::server::conn::http1::Builder::new().serve_connection(io, svc).await;
                    }
                });
            }
        });
        (seen, PipeDialer::new(tx))
    }
}

#[cfg(test)]
mod tests {
    use super::testserver;
    use super::*;
    use crate::dns::pipe::PipeDialer;
    use crate::dns::tls::testcert;
    use crate::dns::{TokioDialer, msg};
    use hickory_proto::rr::RecordType;

    /// The test server's URL. The dialer ignores the address, so the
    /// bootstrap IP is only there to give `Addrs` something to try.
    const URL: &str = "https://dns.test/dns-query";
    const IP: &str = "127.0.0.1";

    fn doh(dialer: Arc<PipeDialer>) -> Doh {
        Doh::new(engine::PREFERRED, URL, IP, &testcert::trust(), dialer).unwrap()
    }

    fn query(name: &str) -> Vec<u8> {
        msg::pack(&msg::test_query(name, RecordType::A)).unwrap()
    }

    async fn ask(d: &Doh, name: &str) -> (Result<Vec<u8>, QueryError>, DnsSummary) {
        let mut smm = DnsSummary::default();
        let r = d.query(crate::exit::BASE, &query(name), &mut smm).await;
        (r, smm)
    }

    #[test]
    fn urls() {
        let d = |u: &str, ips: &str| Doh::new("x", u, ips, &Trust::System, Arc::new(TokioDialer));
        let c = d("https://cloudflare-dns.com/dns-query", "1.1.1.1,1.0.0.1").unwrap();
        assert_eq!(c.url(), "https://cloudflare-dns.com/dns-query");
        assert_eq!(c.addrs.ordered(), vec!["1.1.1.1:443".parse::<SocketAddr>().unwrap(), "1.0.0.1:443".parse().unwrap()]);
        assert_eq!(c.addr(), "cloudflare-dns.com");
        let c = d("https://dns.example:8443/q?x=1", "").unwrap();
        assert_eq!((c.authority.as_str(), c.path.as_str()), ("dns.example:8443", "/q?x=1"));
        assert!(c.addrs.is_empty());
        let c = d("https://[2606:4700::1111]/dns-query", "").unwrap();
        assert_eq!(c.addrs.ordered(), vec!["[2606:4700::1111]:443".parse::<SocketAddr>().unwrap()]);
        let c = d("http://9.9.9.9", "").unwrap();
        assert_eq!((c.addr().as_str(), c.path.as_str()), ("nopki.9.9.9.9", "/"));
        let c = Doh::new(crate::dns::fake::DEFAULT, "https://dns.google/dns-query", "8.8.8.8", &Trust::System, Arc::new(TokioDialer)).unwrap();
        assert_eq!(c.addr(), "d.dns.google");
        assert_eq!(d("ftp://x/", "").err().unwrap(), "unsupported scheme ftp");
        assert!(d("https:///dns-query", "").is_err());
        assert!(d("dns.google", "").is_err());
    }

    #[test]
    fn b64() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(&[0xfb, 0xff, 0xbf]), "-_-_");
    }

    #[tokio::test]
    async fn post_over_h2() {
        let (seen, dial) = testserver::start(b"h2").await;
        let d = doh(dial);
        for _ in 0..3 {
            let (r, smm) = ask(&d, "example.com.").await;
            let a = msg::parse(&r.unwrap()).unwrap();
            assert_eq!(a.metadata.id, 0x1234, "the query's id is restored");
            assert_eq!(smm.rdata, "192.0.2.1");
            assert_eq!(smm.status, engine::DNS_COMPLETE);
            assert_eq!(smm.server, "dns.test");
        }
        assert_eq!(seen.posts.load(Ordering::SeqCst), 3);
        assert_eq!(seen.conns.load(Ordering::SeqCst), 1, "one connection, reused");
        assert_eq!(seen.last_len.load(Ordering::SeqCst) % 128, 0, "padded");
        assert_eq!(seen.last_id.load(Ordering::SeqCst), 0, "sent with id 0");
        assert_eq!(d.status(), engine::DNS_COMPLETE);
    }

    #[tokio::test]
    async fn http11_and_get_after_405() {
        let (seen, dial) = testserver::start(b"http/1.1").await;
        seen.refuse_post.store(true, Ordering::SeqCst);
        let d = doh(dial);
        let (r, smm) = ask(&d, "example.com.").await;
        assert_eq!(r.unwrap_err(), QueryError::new(engine::DNS_CLIENT_ERROR, "http-status: 405"));
        assert_eq!(smm.status, engine::DNS_CLIENT_ERROR);
        // the transport's own wording is "http-status: 405"; the engine
        // turns it into what the app shows (bridge_windows.go)
        assert_eq!(engine::dns_failure(&smm), "dns.test answered HTTP 405");
        // GET from now on
        let (r, _) = ask(&d, "example.com.").await;
        assert!(r.is_ok());
        let (r, _) = ask(&d, "example.org.").await;
        assert!(r.is_ok());
        assert_eq!((seen.posts.load(Ordering::SeqCst), seen.gets.load(Ordering::SeqCst)), (1, 2));
        assert_eq!(seen.conns.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn server_errors() {
        let (seen, dial) = testserver::start(b"h2").await;
        seen.fail.store(true, Ordering::SeqCst);
        let d = doh(dial);
        let (r, smm) = ask(&d, "example.com.").await;
        assert_eq!(r.unwrap_err().status, engine::DNS_TRANSPORT_ERROR);
        assert_eq!(engine::dns_failure(&smm), "dns.test answered HTTP 500");
    }

    #[tokio::test]
    async fn untrusted_certificate() {
        let (_seen, dial) = testserver::start(b"h2").await;
        // the system does not trust the test CA
        let d = Doh::new("x", URL, IP, &Trust::System, dial.clone()).unwrap();
        let (r, smm) = ask(&d, "example.com.").await;
        let e = r.unwrap_err();
        assert_eq!(e.status, engine::DNS_SEND_FAILED);
        assert!(e.msg.contains("tls"), "{}", e.msg);
        assert_eq!(smm.status, engine::DNS_SEND_FAILED);
        // no-PKI mode (http://) skips the check
        let d = Doh::new("x", "http://dns.test/dns-query", IP, &Trust::System, dial).unwrap();
        assert!(ask(&d, "example.com.").await.0.is_ok());
    }

    #[tokio::test]
    async fn unreachable_then_next_ip() {
        let (_seen, dial) = testserver::start(b"h2").await;
        // a refused address first: the next IP is tried
        let closed: SocketAddr = "127.0.0.9:9".parse().unwrap();
        let good: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let d = Doh::new("x", URL, &format!("{closed},{good}"), &testcert::trust(), dial.refusing(&[closed])).unwrap();
        assert!(ask(&d, "example.com.").await.0.is_ok());
        assert_eq!(d.addrs.ordered()[0], good, "the working address is tried first");
        let d = Doh::new("x", URL, &closed.to_string(), &testcert::trust(), dial.refusing(&[closed])).unwrap();
        assert_eq!(ask(&d, "example.com.").await.0.unwrap_err().status, engine::DNS_SEND_FAILED);
    }

    #[tokio::test]
    async fn reconnects_after_server_closes() {
        let (seen, dial) = testserver::start(b"http/1.1").await;
        let d = doh(dial);
        assert!(ask(&d, "a.example.").await.0.is_ok());
        // drop the pooled connection: the next query opens another
        d.conns.lock().await.clear();
        assert!(ask(&d, "b.example.").await.0.is_ok());
        assert_eq!(seen.conns.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    #[ignore = "network: queries cloudflare-dns.com over the internet"]
    async fn real_cloudflare() {
        let d = Doh::new("x", "https://cloudflare-dns.com/dns-query", "1.1.1.1,1.0.0.1", &Trust::System, Arc::new(TokioDialer)).unwrap();
        let (r, smm) = ask(&d, "example.com.").await;
        assert!(r.is_ok(), "{smm:?}");
    }
}
