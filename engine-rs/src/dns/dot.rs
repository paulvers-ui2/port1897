// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! DNS over TLS (RFC 7858), after firestack's dns53/dot: two-byte length
//! prefixed messages on a TLS connection to port 853 (or the URL's), SNI
//! and the certificate check for the URL's host, a 20 s deadline per
//! exchange and the connection kept for the next query.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use rustls::ClientConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;

use super::doh::{NOPKI_PREFIX, fill};
use super::tls::{self, Trust};
use super::{Addrs, BoxFuture, BoxStream, Dialer, QueryError, Transport, msg};
use crate::engine::{self, DnsSummary};

/// firestack's dottimeout.
const TIMEOUT: Duration = Duration::from_secs(20);
pub const DOT_PORT: u16 = 853;

type Conn = TlsStream<BoxStream>;

pub struct Dot {
    id: String,
    host: String,
    /// host:port as the journal shows it
    addrport: String,
    skip_verify: bool,
    addrs: Addrs,
    tls: Arc<ClientConfig>,
    dialer: Arc<dyn Dialer>,
    status: AtomicI32,
    /// an idle connection per exit
    pool: Mutex<HashMap<String, Conn>>,
}

/// The -dot flag as fswin passes it on: always tls://host[:port], since
/// firestack checks the certificate only for tls: URLs.
pub fn normalize(dot: &str) -> String {
    let l = dot.to_ascii_lowercase();
    let rest = if l.starts_with("tls://") {
        &dot[6..]
    } else if l.starts_with("tls:") {
        &dot[4..]
    } else {
        dot
    };
    format!("tls://{rest}")
}

/// host:port and port of a DoT URL (url2addrport): tls://, tls: or bare,
/// port 853 when none is given.
pub fn url2addrport(url: &str) -> (String, u16) {
    let mut u = url;
    if u.len() > 6 && &u[..6] == "tls://" {
        u = &u[6..];
    }
    if u.len() > 4 && &u[..4] == "tls:" {
        u = &u[4..];
    }
    match split_host_port(u) {
        Some((h, p)) => {
            let port = p.parse::<u16>().ok().filter(|p| *p > 0).unwrap_or(DOT_PORT);
            (format!("{}:{p}", bracket(h)), port)
        }
        // no port: an IPv6 literal is already in brackets here, so it
        // must not be bracketed again
        None => {
            let h = u.strip_prefix('[').and_then(|r| r.strip_suffix(']')).unwrap_or(u);
            (format!("{}:{DOT_PORT}", bracket(h)), DOT_PORT)
        }
    }
}

/// Go's net.SplitHostPort, loosely: None without a port.
fn split_host_port(s: &str) -> Option<(&str, &str)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (h, p) = rest.split_once(']')?;
        return Some((h, p.strip_prefix(':')?));
    }
    let (h, p) = s.rsplit_once(':')?;
    if h.contains(':') {
        return None;
    }
    Some((h, p))
}

fn bracket(h: &str) -> String {
    if h.contains(':') { format!("[{h}]") } else { h.to_string() }
}

impl Dot {
    /// A DoT transport for rawurl (tls://host[:port], tls:host[:port] or
    /// host[:port]; only tls: URLs get the certificate check) with the
    /// bootstrap IPs in ips_csv.
    pub fn new(id: &str, rawurl: &str, ips_csv: &str, trust: &Trust, dialer: Arc<dyn Dialer>) -> Result<Dot, String> {
        let skip_verify = !rawurl.to_ascii_lowercase().starts_with("tls:");
        let (addrport, port) = url2addrport(rawurl);
        let host = match split_host_port(&addrport) {
            Some((h, _)) => h.to_string(),
            None => addrport.clone(),
        };
        if host.is_empty() {
            return Err(format!("dot: no hostname in {}", crate::golike::quote(rawurl)));
        }
        tls::server_name(&host)?;
        Ok(Dot {
            id: id.to_string(),
            addrs: Addrs::new(super::bootstrap_addrs(&host, port, ips_csv)),
            host,
            addrport,
            skip_verify,
            tls: tls::client_config(trust, skip_verify, &[])?,
            dialer,
            status: AtomicI32::new(engine::DNS_START),
            pool: Mutex::new(HashMap::new()),
        })
    }

    async fn connect(&self, pid: &str) -> Result<Conn, String> {
        let (stream, addr) = self.addrs.dial(self.dialer.as_ref(), pid).await.map_err(|e| format!("dial tcp {}: {e}", self.addrport))?;
        let name = tls::server_name(&self.host)?;
        match tokio_rustls::TlsConnector::from(self.tls.clone()).connect(name, stream).await {
            Ok(c) => {
                self.addrs.confirm(addr);
                Ok(c)
            }
            Err(e) => {
                self.addrs.disconfirm(addr);
                Err(format!("tls {} ({addr}): {e}", self.host))
            }
        }
    }

    async fn exchange(c: &mut Conn, q: &[u8]) -> Result<Vec<u8>, String> {
        let mut b = Vec::with_capacity(q.len() + 2);
        b.extend_from_slice(&(q.len() as u16).to_be_bytes());
        b.extend_from_slice(q);
        c.write_all(&b).await.map_err(|e| e.to_string())?;
        c.flush().await.map_err(|e| e.to_string())?;
        let mut l = [0u8; 2];
        c.read_exact(&mut l).await.map_err(|e| e.to_string())?;
        let mut ans = vec![0u8; u16::from_be_bytes(l) as usize];
        c.read_exact(&mut ans).await.map_err(|e| e.to_string())?;
        if ans.len() < 2 || ans[..2] != q[..2] {
            return Err("dns: id mismatch".to_string());
        }
        Ok(ans)
    }

    async fn do_query(&self, pid: &str, q: &[u8]) -> Result<Vec<u8>, QueryError> {
        let m = msg::parse(q).map_err(|e| QueryError::new(engine::DNS_BAD_QUERY, e))?;
        if m.queries.is_empty() {
            return Err(QueryError::new(engine::DNS_BAD_QUERY, "err len(query) 0"));
        }
        // a pooled connection may have been closed by the server; one more
        // try on a new one
        let pooled = self.pool.lock().await.remove(pid);
        let reused = pooled.is_some();
        let mut last = String::new();
        let mut tries = vec![pooled, None];
        if !reused {
            tries.remove(0);
        }
        for c in tries {
            let fut = async {
                let mut c = match c {
                    Some(c) => c,
                    None => self.connect(pid).await?,
                };
                let ans = Self::exchange(&mut c, q).await?;
                Ok::<_, String>((c, ans))
            };
            match tokio::time::timeout(TIMEOUT, fut).await {
                Ok(Ok((c, ans))) => {
                    if msg::parse(&ans).is_err() {
                        return Err(QueryError::new(engine::DNS_BAD_RESPONSE, "dns: no answer"));
                    }
                    self.pool.lock().await.insert(pid.to_string(), c);
                    return Ok(ans);
                }
                Ok(Err(e)) => last = e,
                Err(_) => last = format!("read tcp {}: i/o timeout", self.addrport),
            }
        }
        Err(QueryError::new(engine::DNS_SEND_FAILED, last))
    }
}

impl Transport for Dot {
    fn id(&self) -> &str {
        &self.id
    }

    fn addr(&self) -> String {
        if self.skip_verify { format!("{NOPKI_PREFIX}{}", self.addrport) } else { self.addrport.clone() }
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

#[cfg(test)]
pub(crate) mod testserver {
    //! A DoT server on a pipe with the test certificate, answering as
    //! the DoH test server does.

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::dns::doh::testserver::answer;
    use crate::dns::pipe::PipeDialer;
    use crate::dns::tls::testcert;

    #[derive(Default)]
    pub struct Seen {
        pub conns: AtomicUsize,
        pub queries: AtomicUsize,
        /// close each connection after this many queries (0: never)
        pub close_after: AtomicUsize,
    }

    pub async fn start() -> (Arc<Seen>, Arc<PipeDialer>) {
        let seen = Arc::new(Seen::default());
        let acceptor = tokio_rustls::TlsAcceptor::from(testcert::server_config(&[]));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let s2 = seen.clone();
        tokio::spawn(async move {
            while let Some(c) = rx.recv().await {
                s2.conns.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                let seen = s2.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(c).await else { return };
                    let mut n = 0;
                    loop {
                        let mut l = [0u8; 2];
                        if tls.read_exact(&mut l).await.is_err() {
                            return;
                        }
                        let mut q = vec![0u8; u16::from_be_bytes(l) as usize];
                        if tls.read_exact(&mut q).await.is_err() {
                            return;
                        }
                        seen.queries.fetch_add(1, Ordering::SeqCst);
                        let a = answer(&q);
                        let mut b = (a.len() as u16).to_be_bytes().to_vec();
                        b.extend_from_slice(&a);
                        if tls.write_all(&b).await.is_err() {
                            return;
                        }
                        n += 1;
                        let after = seen.close_after.load(Ordering::SeqCst);
                        if after > 0 && n >= after {
                            let _ = tls.shutdown().await;
                            return;
                        }
                    }
                });
            }
        });
        (seen, PipeDialer::new(tx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::TokioDialer;
    use crate::dns::pipe::PipeDialer;
    use crate::dns::tls::testcert;
    use hickory_proto::rr::RecordType;
    use std::net::SocketAddr;

    #[test]
    fn urls() {
        assert_eq!(normalize("dns.adguard-dns.com"), "tls://dns.adguard-dns.com");
        assert_eq!(normalize("TLS://dns.quad9.net:853"), "tls://dns.quad9.net:853");
        assert_eq!(normalize("tls:1.1.1.1"), "tls://1.1.1.1");
        assert_eq!(url2addrport("tls://dns.google"), ("dns.google:853".to_string(), 853));
        assert_eq!(url2addrport("tls:dns.google:8853"), ("dns.google:8853".to_string(), 8853));
        assert_eq!(url2addrport("1.1.1.1"), ("1.1.1.1:853".to_string(), 853));
        assert_eq!(url2addrport("tls://[2606:4700::1111]"), ("[2606:4700::1111]:853".to_string(), 853));
        assert_eq!(url2addrport("tls://[2606:4700::1111]:9953"), ("[2606:4700::1111]:9953".to_string(), 9953));
        let d = Dot::new("x", "tls://dns.google", "8.8.8.8,8.8.4.4", &Trust::System, Arc::new(TokioDialer)).unwrap();
        assert_eq!(d.addr(), "dns.google:853");
        assert_eq!(d.addrs.ordered(), vec!["8.8.8.8:853".parse::<SocketAddr>().unwrap(), "8.8.4.4:853".parse().unwrap()]);
        let d = Dot::new("x", "dns.google", "8.8.8.8", &Trust::System, Arc::new(TokioDialer)).unwrap();
        assert_eq!(d.addr(), "nopki.dns.google:853");
    }

    /// The test server's URL. The dialer ignores the address, so the
    /// bootstrap IP is only there to give `Addrs` something to try.
    const URL: &str = "tls://dns.test";
    const IP: &str = "127.0.0.1";
    /// how the journal names the test server
    const SERVER: &str = "dns.test:853";

    fn dot(dialer: Arc<PipeDialer>) -> Dot {
        Dot::new(engine::PREFERRED, URL, IP, &testcert::trust(), dialer).unwrap()
    }

    async fn ask(d: &Dot, name: &str) -> (Result<Vec<u8>, QueryError>, DnsSummary) {
        let q = msg::pack(&msg::test_query(name, RecordType::A)).unwrap();
        let mut smm = DnsSummary::default();
        let r = d.query(crate::exit::BASE, &q, &mut smm).await;
        (r, smm)
    }

    #[tokio::test]
    async fn queries_on_one_connection() {
        let (seen, dial) = testserver::start().await;
        let d = dot(dial);
        for _ in 0..3 {
            let (r, smm) = ask(&d, "example.com.").await;
            assert_eq!(msg::parse(&r.unwrap()).unwrap().metadata.id, 0x1234);
            assert_eq!(smm.rdata, "192.0.2.1");
            assert_eq!(smm.server, SERVER);
            assert_eq!(smm.status, engine::DNS_COMPLETE);
        }
        assert_eq!(seen.conns.load(Ordering::SeqCst), 1);
        assert_eq!(seen.queries.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn new_connection_when_the_server_closed() {
        let (seen, dial) = testserver::start().await;
        seen.close_after.store(1, Ordering::SeqCst);
        let d = dot(dial);
        assert!(ask(&d, "a.example.").await.0.is_ok());
        assert!(ask(&d, "b.example.").await.0.is_ok());
        assert_eq!(seen.conns.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn failures() {
        let (_seen, dial) = testserver::start().await;
        let d = Dot::new("x", URL, IP, &Trust::System, dial.clone()).unwrap();
        let (r, smm) = ask(&d, "example.com.").await;
        assert_eq!(r.unwrap_err().status, engine::DNS_SEND_FAILED);
        assert_eq!((smm.status, smm.rcode), (engine::DNS_SEND_FAILED, 2));
        assert_eq!(d.status(), engine::DNS_SEND_FAILED);
        let closed: SocketAddr = "127.0.0.9:853".parse().unwrap();
        let d = Dot::new(engine::PREFERRED, URL, &closed.to_string(), &testcert::trust(), dial.refusing(&[closed])).unwrap();
        assert_eq!(ask(&d, "example.com.").await.0.unwrap_err().status, engine::DNS_SEND_FAILED);
    }

    #[tokio::test]
    #[ignore = "network: queries dns.google over DoT on the internet"]
    async fn real_google() {
        let d = Dot::new("x", "tls://dns.google", "8.8.8.8", &Trust::System, Arc::new(TokioDialer)).unwrap();
        let (r, smm) = ask(&d, "example.com.").await;
        assert!(r.is_ok(), "{smm:?}");
    }
}
