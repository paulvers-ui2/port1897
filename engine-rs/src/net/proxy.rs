// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The -proxy exit: firestack's socks5 and http1 proxies. TCP goes through
//! a SOCKS5 CONNECT (RFC 1928, with RFC 1929 user/password) or an HTTP
//! CONNECT; UDP through a SOCKS5 UDP ASSOCIATE. An HTTP proxy carries no
//! UDP, and as in firestack a UDP flow sent to it fails and counts as a
//! failed dial. The connection to the proxy itself leaves by the physical
//! interface (the Direct dialer).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::watch;

use super::dial::{Dialer, Direct};
use crate::dns::{self, BoxDatagram, BoxFuture, BoxStream, Datagram};
use crate::engine::{Proxies, ProxyInfo, RouterStat, TKO, TOK, TUP, TZZ};
use crate::golike;

/// How long after its last dial a proxy reads as idle (firestack's
/// tzzTimeout).
pub const IDLE_AFTER: Duration = Duration::from_secs(120);

/// The port of an http:// proxy given without one (firestack's h1).
const HTTP_PORT: u16 = 8080;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Socks5,
    Http,
}

/// A -proxy URL: scheme://[user[:pass]@]host[:port].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyUrl {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub pass: String,
}

impl ProxyUrl {
    /// Parses a -proxy value; the scheme check comes first with Go's
    /// wording, as prepareExit makes it.
    pub fn parse(s: &str) -> Result<ProxyUrl, String> {
        let (scheme, rest) = if let Some(r) = s.strip_prefix("socks5://") {
            (Scheme::Socks5, r)
        } else if let Some(r) = s.strip_prefix("http://") {
            (Scheme::Http, r)
        } else {
            return Err("-proxy must start with socks5:// or http://".into());
        };
        let bad = |why: &str| Err(format!("parse {}: {why}", golike::quote(s)));
        let auth = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
        let (userinfo, hostport) = match auth.rfind('@') {
            Some(i) => (Some(&auth[..i]), &auth[i + 1..]),
            None => (None, auth),
        };
        let (mut user, mut pass) = (String::new(), String::new());
        if let Some(ui) = userinfo {
            let (u, p) = ui.split_once(':').unwrap_or((ui, ""));
            let (Some(u), Some(p)) = (unescape(u), unescape(p)) else {
                return bad("invalid URL escape in userinfo");
            };
            (user, pass) = (u, p);
        }
        let (host, port) = if let Some(r) = hostport.strip_prefix('[') {
            let Some(end) = r.find(']') else { return bad("missing ']' in host") };
            (&r[..end], &r[end + 1..])
        } else {
            match hostport.rfind(':') {
                Some(i) => (&hostport[..i], &hostport[i..]),
                None => (hostport, ""),
            }
        };
        if host.is_empty() {
            return bad("missing host");
        }
        let port = match port.strip_prefix(':') {
            Some(p) if !p.is_empty() => match p.parse::<u16>() {
                Ok(n) if n > 0 => n,
                _ => return bad(&format!("invalid port {}", golike::quote(&format!(":{p}")))),
            },
            None if !port.is_empty() => return bad(&format!("invalid port {}", golike::quote(port))),
            _ if scheme == Scheme::Http => HTTP_PORT,
            _ => return bad("missing port"),
        };
        Ok(ProxyUrl { scheme, host: host.to_string(), port, user, pass })
    }

    /// Both a user and a password, as firestack's ProxyOptions.HasAuth:
    /// only then are credentials offered.
    pub fn has_auth(&self) -> bool {
        !self.user.is_empty() && !self.pass.is_empty()
    }

    /// The proxy's addresses: the host itself if it is an IP, else what the
    /// system resolver says. Done before the tunnel is up, since a name
    /// looked up later would ask our own DNS, which needs the proxy.
    pub async fn resolve(&self) -> Result<Vec<SocketAddr>, String> {
        if let Ok(ip) = self.host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, self.port)]);
        }
        let all: Vec<SocketAddr> = tokio::net::lookup_host((self.host.as_str(), self.port)).await.map_err(|e| format!("lookup {}: {e}", self.host))?.collect();
        // IPv4 first: the tunnel's own traffic leaves by the IPv4 default route
        let (mut v4, v6): (Vec<_>, Vec<_>) = all.into_iter().partition(|a| a.is_ipv4());
        v4.extend(v6);
        if v4.is_empty() {
            return Err(format!("lookup {}: no addresses", self.host));
        }
        Ok(v4)
    }
}

/// Percent-decoding of a URL's userinfo; None on a bad escape.
fn unescape(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = b.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

struct State {
    status: i32,
    last_dial: Option<Instant>,
    last_ok: i64,
}

/// The exit: dials through the proxy and keeps its state and counters for
/// /api/proxies.
pub struct ProxyExit {
    id: String,
    url: ProxyUrl,
    servers: Vec<SocketAddr>,
    direct: Direct,
    st: Mutex<State>,
    rx: Arc<AtomicI64>,
    tx: Arc<AtomicI64>,
    since: i64,
}

impl ProxyExit {
    /// An exit with proxy id id through the proxy at servers (url's host,
    /// resolved), reached with direct.
    pub fn new(id: &str, url: ProxyUrl, servers: Vec<SocketAddr>, direct: Direct) -> ProxyExit {
        ProxyExit {
            id: id.to_string(),
            url,
            servers,
            direct,
            st: Mutex::new(State { status: TUP, last_dial: None, last_ok: 0 }),
            rx: Arc::new(AtomicI64::new(0)),
            tx: Arc::new(AtomicI64::new(0)),
            since: crate::events::now_ms(),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// firestack's Status: idle once no dial came for IDLE_AFTER (also
    /// before the first), else how the last dial went.
    pub fn status(&self) -> i32 {
        let st = self.lock();
        match st.last_dial {
            Some(t) if t.elapsed() <= IDLE_AFTER => st.status,
            _ => TZZ,
        }
    }

    /// firestack's localDialStatus after each dial.
    fn dialed<T>(&self, r: &io::Result<T>) {
        let mut st = self.lock();
        st.last_dial = Some(Instant::now());
        if r.is_ok() {
            st.status = TOK;
            st.last_ok = crate::events::now_ms();
        } else {
            st.status = TKO;
        }
    }

    /// Tries each of the proxy's addresses in turn (firestack's
    /// ProxyDials); the last error if none works.
    async fn each_server<'a, T, F>(&'a self, mut f: F) -> io::Result<T>
    where
        F: FnMut(SocketAddr) -> BoxFuture<'a, io::Result<T>>,
    {
        let mut last = io::Error::other("proxy: no address");
        for &s in &self.servers {
            match tokio::time::timeout(self.direct.timeout, f(s)).await {
                Ok(Ok(c)) => return Ok(c),
                Ok(Err(e)) => last = e,
                Err(_) => last = io::Error::new(io::ErrorKind::TimedOut, format!("proxy {s}: i/o timeout")),
            }
        }
        Err(last)
    }

    /// A stream to dst through the proxy, counted.
    pub async fn connect(&self, dst: SocketAddr) -> io::Result<BoxStream> {
        let r = match self.url.scheme {
            Scheme::Socks5 => self.each_server(|s| Box::pin(self.socks_connect(s, dst))).await,
            Scheme::Http => self.each_server(|s| Box::pin(self.http_connect(s, dst))).await,
        };
        self.dialed(&r);
        Ok(Box::new(Counted { inner: r?, rx: self.rx.clone(), tx: self.tx.clone() }))
    }

    /// A datagram socket to dst through the proxy (SOCKS5 only).
    pub async fn associate(&self, dst: SocketAddr) -> io::Result<BoxDatagram> {
        let r = match self.url.scheme {
            Scheme::Socks5 => self.each_server(|s| Box::pin(self.socks_associate(s, dst))).await,
            Scheme::Http => Err(io::Error::new(io::ErrorKind::Unsupported, "http1: tunnel: network type 'udp' unsupported (only 'tcp')")),
        };
        self.dialed(&r);
        r
    }

    async fn socks_hello(&self, server: SocketAddr) -> io::Result<TcpStream> {
        let mut c = self.direct.connect_tcp(server).await?;
        let auth = self.url.has_auth();
        let hello: &[u8] = if auth { &[5, 2, 0, 2] } else { &[5, 1, 0] };
        c.write_all(hello).await?;
        let mut r = [0u8; 2];
        c.read_exact(&mut r).await?;
        if r[0] != 5 {
            return Err(io::Error::other(format!("socks5: {server}: not a SOCKS5 server (version {})", r[0])));
        }
        match r[1] {
            0 => {}
            2 if auth => {
                let (u, p) = (self.url.user.as_bytes(), self.url.pass.as_bytes());
                if u.len() > 255 || p.len() > 255 {
                    return Err(io::Error::other("socks5: user or password longer than 255 bytes"));
                }
                let mut m = vec![1, u.len() as u8];
                m.extend_from_slice(u);
                m.push(p.len() as u8);
                m.extend_from_slice(p);
                c.write_all(&m).await?;
                c.read_exact(&mut r).await?;
                if r[1] != 0 {
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("socks5: {server}: user or password rejected")));
                }
            }
            _ => return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("socks5: {server}: no acceptable authentication method"))),
        }
        Ok(c)
    }

    async fn socks_connect(&self, server: SocketAddr, dst: SocketAddr) -> io::Result<BoxStream> {
        let mut c = self.socks_hello(server).await?;
        socks_request(&mut c, CMD_CONNECT, dst).await?;
        let _ = c.set_nodelay(true);
        Ok(Box::new(c))
    }

    async fn socks_associate(&self, server: SocketAddr, dst: SocketAddr) -> io::Result<BoxDatagram> {
        let mut c = self.socks_hello(server).await?;
        // we cannot know our address as the proxy will see it: all zeros
        // asks it to take datagrams from wherever this client sends them
        let any = if server.is_ipv4() { SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0) } else { SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0) };
        let mut relay = socks_request(&mut c, CMD_UDP_ASSOCIATE, any).await?;
        if relay.ip().is_unspecified() {
            relay.set_ip(server.ip());
        }
        let sock = self.direct.connect_udp(relay).await?;
        // the association lasts as long as its TCP connection
        let (done_tx, done) = watch::channel(false);
        let watcher = tokio::spawn(async move {
            let mut b = [0u8; 64];
            while let Ok(n) = c.read(&mut b).await {
                if n == 0 {
                    break;
                }
            }
            let _ = done_tx.send(true);
        });
        Ok(Box::new(SocksUdp { sock, dst, head: socks_addr(&[0, 0, 0], dst), done, watcher, rx: self.rx.clone(), tx: self.tx.clone() }))
    }

    async fn http_connect(&self, server: SocketAddr, dst: SocketAddr) -> io::Result<BoxStream> {
        let c = self.direct.connect_tcp(server).await.map_err(|e| io::Error::new(e.kind(), format!("http1: tunnel: failed dialing to proxy: {e}")))?;
        let mut c = BufReader::new(c);
        let target = dst.to_string();
        let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: Go-http-client/1.1\r\n");
        if self.url.has_auth() {
            let creds = crate::exit::base64_std_encode(format!("{}:{}", self.url.user, self.url.pass).as_bytes());
            req.push_str(&format!("Proxy-Authorization: Basic {creds}\r\n"));
        }
        req.push_str("\r\n");
        send_request(&mut c, &req).await?;
        let mut resp = read_response(&mut c).await?;
        // a challenge is answered once, with the same Basic credentials
        if resp.code == 407 && self.url.has_auth() {
            if !resp.authenticate.contains("Basic ") {
                return Err(io::Error::other(format!("http1: tunnel: expected 'Basic' Proxy authentication, got: '{}'", resp.authenticate)));
            }
            discard(&mut c, resp.length).await?;
            send_request(&mut c, &req).await?;
            resp = read_response(&mut c).await?;
        }
        if resp.code != 200 {
            return Err(io::Error::new(io::ErrorKind::ConnectionRefused, format!("http1: tunnel: failed proxying {}: {}", resp.code, resp.status)));
        }
        let _ = c.get_ref().set_nodelay(true);
        Ok(Box::new(c))
    }

    /// The exit's state for /api/proxies. addrs stays empty as in
    /// firestack, whose proxies of this kind report no addresses.
    pub fn info(&self) -> ProxyInfo {
        let last_ok = self.lock().last_ok;
        ProxyInfo {
            status: self.status(),
            stat: Some(RouterStat { addrs: String::new(), rx: self.rx.load(Ordering::Relaxed), tx: self.tx.load(Ordering::Relaxed), last_ok, since: self.since }),
        }
    }
}

const CMD_CONNECT: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;

/// prefix + a SOCKS5 address (type, address, port).
fn socks_addr(prefix: &[u8], a: SocketAddr) -> Vec<u8> {
    let mut m = prefix.to_vec();
    match a.ip() {
        IpAddr::V4(v4) => {
            m.push(1);
            m.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            m.push(4);
            m.extend_from_slice(&v6.octets());
        }
    }
    m.extend_from_slice(&a.port().to_be_bytes());
    m
}

/// RFC 1928's reply codes in words.
fn socks_reply(code: u8) -> (&'static str, io::ErrorKind) {
    match code {
        1 => ("general SOCKS server failure", io::ErrorKind::Other),
        2 => ("connection not allowed by ruleset", io::ErrorKind::PermissionDenied),
        3 => ("network unreachable", io::ErrorKind::Other),
        4 => ("host unreachable", io::ErrorKind::Other),
        5 => ("connection refused", io::ErrorKind::ConnectionRefused),
        6 => ("TTL expired", io::ErrorKind::TimedOut),
        7 => ("command not supported", io::ErrorKind::Unsupported),
        8 => ("address type not supported", io::ErrorKind::Unsupported),
        _ => ("unknown error", io::ErrorKind::Other),
    }
}

/// Sends a request and reads the reply; the address the proxy bound.
async fn socks_request(c: &mut TcpStream, cmd: u8, dst: SocketAddr) -> io::Result<SocketAddr> {
    c.write_all(&socks_addr(&[5, cmd, 0], dst)).await?;
    let mut h = [0u8; 4];
    c.read_exact(&mut h).await?;
    let what = if cmd == CMD_CONNECT { "connect" } else { "udp associate" };
    if h[1] != 0 {
        let (why, kind) = socks_reply(h[1]);
        return Err(io::Error::new(kind, format!("socks5: {what} {dst}: {why}")));
    }
    let ip = match h[3] {
        1 => {
            let mut b = [0u8; 4];
            c.read_exact(&mut b).await?;
            IpAddr::from(b)
        }
        4 => {
            let mut b = [0u8; 16];
            c.read_exact(&mut b).await?;
            IpAddr::from(b)
        }
        3 => {
            // a name: of no use to us, so read past it; the proxy's own
            // address stands in for it
            let mut l = [0u8; 1];
            c.read_exact(&mut l).await?;
            let mut b = vec![0u8; l[0] as usize];
            c.read_exact(&mut b).await?;
            IpAddr::from(Ipv4Addr::UNSPECIFIED)
        }
        t => return Err(io::Error::other(format!("socks5: {what} {dst}: bad address type {t} in reply"))),
    };
    let mut p = [0u8; 2];
    c.read_exact(&mut p).await?;
    Ok(SocketAddr::new(ip, u16::from_be_bytes(p)))
}

struct Response {
    code: u16,
    /// "407 Proxy Authentication Required", as Go's resp.Status
    status: String,
    authenticate: String,
    length: u64,
}

async fn send_request(c: &mut BufReader<TcpStream>, req: &str) -> io::Result<()> {
    c.get_mut().write_all(req.as_bytes()).await.map_err(|e| io::Error::new(e.kind(), format!("http1: tunnel: failed writing request: {e}")))
}

/// One line of a response head, without its line end.
async fn read_line(c: &mut BufReader<TcpStream>, line: &mut String) -> io::Result<()> {
    line.clear();
    // a line of more than 64 KiB is not a proxy's answer
    let n = (&mut *c).take(64 << 10).read_line(line).await?;
    if n == 0 || !line.ends_with('\n') {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF"));
    }
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(())
}

/// Reads an HTTP/1.x response head, as Go's http.ReadResponse would for a
/// CONNECT; errors worded as Go's.
async fn read_response(c: &mut BufReader<TcpStream>) -> io::Result<Response> {
    let mut line = String::new();
    read_line(c, &mut line).await?;
    let malformed = |l: &str| io::Error::new(io::ErrorKind::InvalidData, format!("malformed HTTP response {}", golike::quote(l)));
    let Some((proto, status)) = line.split_once(' ') else { return Err(malformed(&line)) };
    if !proto.starts_with("HTTP/1.") {
        return Err(malformed(&line));
    }
    let status = status.trim_start().to_string();
    let code: u16 = match status.get(..3).map(str::parse) {
        Some(Ok(n)) if status.len() == 3 || status.as_bytes()[3] == b' ' => n,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("malformed HTTP status code {}", golike::quote(status.split(' ').next().unwrap_or(""))))),
    };
    let mut r = Response { code, status, authenticate: String::new(), length: 0 };
    // so many header lines is no proxy's answer either
    for _ in 0..1000 {
        read_line(c, &mut line).await?;
        if line.is_empty() {
            return Ok(r);
        }
        let Some((k, v)) = line.split_once(':') else { return Err(io::Error::new(io::ErrorKind::InvalidData, format!("malformed MIME header line: {line}"))) };
        let v = v.trim();
        if k.eq_ignore_ascii_case("proxy-authenticate") && r.authenticate.is_empty() {
            r.authenticate = v.to_string();
        } else if k.eq_ignore_ascii_case("content-length") {
            r.length = v.parse().unwrap_or(0);
        }
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "http1: tunnel: response head too long"))
}

/// Reads past a response's body, so the next request starts clean.
async fn discard(c: &mut BufReader<TcpStream>, n: u64) -> io::Result<()> {
    tokio::io::copy(&mut c.take(n), &mut tokio::io::sink()).await.map(|_| ())
}

/// A stream whose bytes count toward the exit's rx and tx.
struct Counted {
    inner: BoxStream,
    rx: Arc<AtomicI64>,
    tx: Arc<AtomicI64>,
}

impl AsyncRead for Counted {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = r {
            self.rx.fetch_add((buf.filled().len() - before) as i64, Ordering::Relaxed);
        }
        r
    }
}

impl AsyncWrite for Counted {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, b);
        if let Poll::Ready(Ok(n)) = r {
            self.tx.fetch_add(n as i64, Ordering::Relaxed);
        }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A SOCKS5 UDP association to one destination: each datagram carries the
/// proxy's header; the TCP connection that made it is held by a watcher
/// task, which says when the proxy ends it.
struct SocksUdp {
    sock: UdpSocket,
    dst: SocketAddr,
    /// RSV, FRAG and dst as a SOCKS5 address
    head: Vec<u8>,
    done: watch::Receiver<bool>,
    watcher: tokio::task::JoinHandle<()>,
    rx: Arc<AtomicI64>,
    tx: Arc<AtomicI64>,
}

impl Drop for SocksUdp {
    fn drop(&mut self) {
        // closes the TCP connection, which ends the association
        self.watcher.abort();
    }
}

/// The payload's offset in a datagram from the relay if it is a whole one
/// (no fragments) from src.
fn socks_payload(b: &[u8], src: SocketAddr) -> Option<usize> {
    if b.len() < 4 || b[2] != 0 {
        return None;
    }
    let (ip, off) = match b[3] {
        1 if b.len() >= 10 => (IpAddr::from(<[u8; 4]>::try_from(&b[4..8]).ok()?), 8),
        4 if b.len() >= 22 => (IpAddr::from(<[u8; 16]>::try_from(&b[4..20]).ok()?), 20),
        _ => return None,
    };
    let port = u16::from_be_bytes([b[off], b[off + 1]]);
    (SocketAddr::new(ip, port) == src).then_some(off + 2)
}

impl Datagram for SocksUdp {
    fn send<'a>(&'a self, b: &'a [u8]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(async move {
            let mut m = Vec::with_capacity(self.head.len() + b.len());
            m.extend_from_slice(&self.head);
            m.extend_from_slice(b);
            self.sock.send(&m).await?;
            self.tx.fetch_add(b.len() as i64, Ordering::Relaxed);
            Ok(b.len())
        })
    }

    fn recv<'a>(&'a self, b: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(async move {
            let mut done = self.done.clone();
            // room for the header too, so a payload that fits b is whole
            let mut m = vec![0u8; b.len() + 22];
            loop {
                tokio::select! {
                    r = self.sock.recv(&mut m) => {
                        let n = r?;
                        // like a connected socket: only dst's datagrams
                        let Some(off) = socks_payload(&m[..n], self.dst) else { continue };
                        let k = (n - off).min(b.len());
                        b[..k].copy_from_slice(&m[off..off + k]);
                        self.rx.fetch_add(k as i64, Ordering::Relaxed);
                        return Ok(k);
                    }
                    _ = done.wait_for(|d| *d) => {
                        return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "socks5: the proxy ended the udp association"));
                    }
                }
            }
        })
    }
}

impl Dialer for ProxyExit {
    fn tcp(&self, dst: SocketAddr) -> BoxFuture<'_, io::Result<BoxStream>> {
        Box::pin(self.connect(dst))
    }

    fn udp(&self, dst: SocketAddr) -> BoxFuture<'_, io::Result<BoxDatagram>> {
        Box::pin(self.associate(dst))
    }
}

/// The DNS transports' connections: through the proxy for queries given
/// the exit, direct for Base.
impl dns::Dialer for ProxyExit {
    fn dial_tcp<'a>(&'a self, pid: &'a str, addr: SocketAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            if pid == self.id {
                return self.connect(addr).await;
            }
            dns::Dialer::dial_tcp(&self.direct, pid, addr).await
        })
    }

    fn dial_udp<'a>(&'a self, pid: &'a str, addr: SocketAddr) -> BoxFuture<'a, io::Result<BoxDatagram>> {
        Box::pin(async move {
            if pid == self.id {
                return self.associate(addr).await;
            }
            dns::Dialer::dial_udp(&self.direct, pid, addr).await
        })
    }
}

impl Proxies for ProxyExit {
    fn get(&self, id: &str) -> Option<ProxyInfo> {
        (id == self.id).then(|| self.info())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::exit::EXIT_PROXY;
    use tokio::net::TcpListener;

    /// What the test proxies do.
    #[derive(Clone, Default)]
    pub(crate) struct Behaviour {
        /// user and password the proxy wants
        pub auth: Option<(&'static str, &'static str)>,
        /// a SOCKS5 reply code, or an HTTP status line, to refuse with
        pub refuse_socks: Option<u8>,
        pub refuse_http: Option<&'static str>,
    }

    async fn pipe_both(a: TcpStream, b: TcpStream) {
        let (mut ar, mut aw) = a.into_split();
        let (mut br, mut bw) = b.into_split();
        let one = async {
            let _ = tokio::io::copy(&mut ar, &mut bw).await;
            let _ = bw.shutdown().await;
        };
        let two = async {
            let _ = tokio::io::copy(&mut br, &mut aw).await;
            let _ = aw.shutdown().await;
        };
        tokio::join!(one, two);
    }

    /// A SOCKS5 server on 127.0.0.1:0 (CONNECT and UDP ASSOCIATE); it
    /// answers an association with 0.0.0.0, so the client must put the
    /// proxy's address in its place.
    pub(crate) async fn socks_server(b: Behaviour) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((c, _)) = l.accept().await {
                tokio::spawn(socks_conn(c, b.clone()));
            }
        });
        a
    }

    async fn socks_conn(mut c: TcpStream, b: Behaviour) -> io::Result<()> {
        let mut h = [0u8; 2];
        c.read_exact(&mut h).await?;
        let mut methods = vec![0u8; h[1] as usize];
        c.read_exact(&mut methods).await?;
        let want = if b.auth.is_some() { 2 } else { 0 };
        if !methods.contains(&want) {
            c.write_all(&[5, 0xff]).await?;
            return Ok(());
        }
        c.write_all(&[5, want]).await?;
        if let Some((u, p)) = b.auth {
            let mut v = [0u8; 2];
            c.read_exact(&mut v).await?;
            let mut user = vec![0u8; v[1] as usize];
            c.read_exact(&mut user).await?;
            let mut l = [0u8; 1];
            c.read_exact(&mut l).await?;
            let mut pass = vec![0u8; l[0] as usize];
            c.read_exact(&mut pass).await?;
            let ok = user == u.as_bytes() && pass == p.as_bytes();
            c.write_all(&[1, if ok { 0 } else { 1 }]).await?;
            if !ok {
                return Ok(());
            }
        }
        let mut r = [0u8; 4];
        c.read_exact(&mut r).await?;
        let dst = read_addr(&mut c, r[3]).await?;
        if let Some(code) = b.refuse_socks {
            c.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            return Ok(());
        }
        match r[1] {
            CMD_CONNECT => {
                let Ok(t) = TcpStream::connect(dst).await else {
                    c.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                    return Ok(());
                };
                c.write_all(&socks_addr(&[5, 0, 0], t.local_addr()?)).await?;
                pipe_both(c, t).await;
            }
            CMD_UDP_ASSOCIATE => {
                let relay = UdpSocket::bind("127.0.0.1:0").await?;
                let port = relay.local_addr()?.port();
                c.write_all(&socks_addr(&[5, 0, 0], SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port))).await?;
                let out = UdpSocket::bind("127.0.0.1:0").await?;
                let mut client = None;
                let (mut b1, mut b2) = (vec![0u8; 65536], vec![0u8; 65536]);
                let mut t = [0u8; 1];
                loop {
                    tokio::select! {
                        r = relay.recv_from(&mut b1) => {
                            let (n, from) = r?;
                            client = Some(from);
                            let ip = IpAddr::from(<[u8; 4]>::try_from(&b1[4..8]).unwrap());
                            let to = SocketAddr::new(ip, u16::from_be_bytes([b1[8], b1[9]]));
                            out.send_to(&b1[10..n], to).await?;
                        }
                        r = out.recv_from(&mut b2) => {
                            let (n, from) = r?;
                            let mut m = socks_addr(&[0, 0, 0], from);
                            m.extend_from_slice(&b2[..n]);
                            if let Some(cl) = client {
                                relay.send_to(&m, cl).await?;
                            }
                        }
                        r = c.read(&mut t) => {
                            if r.unwrap_or(0) == 0 {
                                return Ok(());
                            }
                        }
                    }
                }
            }
            _ => c.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?,
        }
        Ok(())
    }

    async fn read_addr(c: &mut TcpStream, atyp: u8) -> io::Result<SocketAddr> {
        let ip = if atyp == 1 {
            let mut b = [0u8; 4];
            c.read_exact(&mut b).await?;
            IpAddr::from(b)
        } else {
            let mut b = [0u8; 16];
            c.read_exact(&mut b).await?;
            IpAddr::from(b)
        };
        let mut p = [0u8; 2];
        c.read_exact(&mut p).await?;
        Ok(SocketAddr::new(ip, u16::from_be_bytes(p)))
    }

    /// An HTTP CONNECT proxy on 127.0.0.1:0; it records each request head.
    pub(crate) async fn http_server(b: Behaviour, heads: Arc<Mutex<Vec<String>>>) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((c, _)) = l.accept().await {
                tokio::spawn(http_conn(c, b.clone(), heads.clone()));
            }
        });
        a
    }

    async fn http_conn(c: TcpStream, b: Behaviour, heads: Arc<Mutex<Vec<String>>>) -> io::Result<()> {
        let mut c = BufReader::new(c);
        loop {
            let mut head = String::new();
            let mut line = String::new();
            loop {
                line.clear();
                if c.read_line(&mut line).await? == 0 {
                    return Ok(());
                }
                if line == "\r\n" {
                    break;
                }
                head.push_str(&line);
            }
            heads.lock().unwrap().push(head.clone());
            if let Some(status) = b.refuse_http {
                c.get_mut().write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n").as_bytes()).await?;
                return Ok(());
            }
            if let Some((u, p)) = b.auth {
                let want = format!("Proxy-Authorization: Basic {}\r\n", crate::exit::base64_std_encode(format!("{u}:{p}").as_bytes()));
                if !head.contains(&want) {
                    c.get_mut().write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"test\"\r\nContent-Length: 5\r\n\r\nnope!").await?;
                    continue;
                }
            }
            let target = head.split(' ').nth(1).unwrap().to_string();
            let t = TcpStream::connect(target).await?;
            c.get_mut().write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
            pipe_both(c.into_inner(), t).await;
            return Ok(());
        }
    }

    pub(crate) async fn echo_tcp() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut c, _)) = l.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = c.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                    let _ = w.shutdown().await;
                });
            }
        });
        a
    }

    async fn echo_udp() -> SocketAddr {
        let u = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a = u.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            while let Ok((n, from)) = u.recv_from(&mut b).await {
                let _ = u.send_to(&b[..n], from).await;
            }
        });
        a
    }

    pub(crate) fn exit(url: &str, server: SocketAddr) -> ProxyExit {
        let u = ProxyUrl::parse(url).unwrap();
        ProxyExit::new(EXIT_PROXY, u, vec![server], Direct::new(None))
    }

    async fn round_trip(s: &mut BoxStream, m: &[u8]) -> Vec<u8> {
        s.write_all(m).await.unwrap();
        let mut b = vec![0u8; m.len()];
        s.read_exact(&mut b).await.unwrap();
        b
    }

    #[test]
    fn urls() {
        let u = ProxyUrl::parse("socks5://us%40er:p%3Ass@127.0.0.1:1080").unwrap();
        assert_eq!((u.scheme, u.host.as_str(), u.port, u.user.as_str(), u.pass.as_str()), (Scheme::Socks5, "127.0.0.1", 1080, "us@er", "p:ss"));
        assert!(u.has_auth());
        let u = ProxyUrl::parse("http://proxy.example:3128/").unwrap();
        assert_eq!((u.scheme, u.host.as_str(), u.port, u.has_auth()), (Scheme::Http, "proxy.example", 3128, false));
        assert_eq!(ProxyUrl::parse("http://10.0.0.1").unwrap().port, 8080);
        assert_eq!(ProxyUrl::parse("socks5://[::1]:9050").unwrap().host, "::1");
        assert!(!ProxyUrl::parse("socks5://user@1.2.3.4:1").unwrap().has_auth(), "a user alone is no credentials");
        for (bad, want) in [
            ("https://1.2.3.4:443", "-proxy must start with socks5:// or http://"),
            ("SOCKS5://1.2.3.4:1", "-proxy must start with socks5:// or http://"),
            ("socks5://1.2.3.4", "parse \"socks5://1.2.3.4\": missing port"),
            ("socks5://:1080", "parse \"socks5://:1080\": missing host"),
            ("http://1.2.3.4:http", "parse \"http://1.2.3.4:http\": invalid port \":http\""),
            ("socks5://a%zz:b@1.2.3.4:1", "parse \"socks5://a%zz:b@1.2.3.4:1\": invalid URL escape in userinfo"),
        ] {
            assert_eq!(ProxyUrl::parse(bad).unwrap_err(), want, "{bad}");
        }
    }

    #[tokio::test]
    async fn socks5_connect_with_and_without_auth() {
        let echo = echo_tcp().await;
        let open = socks_server(Behaviour::default()).await;
        let x = exit(&format!("socks5://{open}"), open);
        assert_eq!(x.status(), TZZ, "idle before the first dial");
        let mut s = x.tcp(echo).await.unwrap();
        assert_eq!(round_trip(&mut s, b"hello").await, b"hello");
        let info = x.info();
        assert_eq!(info.status, TOK);
        let st = info.stat.unwrap();
        assert_eq!((st.rx, st.tx, st.addrs.as_str()), (5, 5, ""));
        assert!(st.last_ok > 0 && st.since > 0);

        let locked = socks_server(Behaviour { auth: Some(("me", "secret")), ..Default::default() }).await;
        let x = exit(&format!("socks5://me:secret@{locked}"), locked);
        let mut s = x.tcp(echo).await.unwrap();
        assert_eq!(round_trip(&mut s, b"hi").await, b"hi");
        let x = exit(&format!("socks5://me:wrong@{locked}"), locked);
        let e = x.tcp(echo).await.err().unwrap();
        assert_eq!(e.to_string(), format!("socks5: {locked}: user or password rejected"));
        assert_eq!(x.status(), TKO);
        let x = exit(&format!("socks5://{locked}"), locked);
        let e = x.tcp(echo).await.err().unwrap();
        assert_eq!(e.to_string(), format!("socks5: {locked}: no acceptable authentication method"));
    }

    #[tokio::test]
    async fn socks5_refusals_fail_the_dial_then_a_good_one_recovers() {
        let echo = echo_tcp().await;
        for (code, why) in [(1, "general SOCKS server failure"), (2, "connection not allowed by ruleset"), (5, "connection refused"), (8, "address type not supported")] {
            let px = socks_server(Behaviour { refuse_socks: Some(code), ..Default::default() }).await;
            let x = exit(&format!("socks5://{px}"), px);
            let e = x.tcp(echo).await.err().unwrap();
            assert_eq!(e.to_string(), format!("socks5: connect {echo}: {why}"));
            assert_eq!(x.status(), TKO);
        }
        // nothing listens at the proxy's address
        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let x = exit(&format!("socks5://{dead}"), dead);
        assert!(x.tcp(echo).await.is_err());
        assert_eq!(proxy_state(&x), "failing");
        // the same exit, once its proxy answers, is connected again
        let px = socks_server(Behaviour::default()).await;
        let x = ProxyExit { servers: vec![dead, px], ..exit(&format!("socks5://{px}"), px) };
        x.tcp(echo).await.unwrap();
        assert_eq!(proxy_state(&x), "connected");
    }

    fn proxy_state(x: &ProxyExit) -> &'static str {
        crate::engine::proxy_status(x.status())
    }

    #[tokio::test]
    async fn socks5_udp_associate_round_trip() {
        let echo = echo_udp().await;
        let px = socks_server(Behaviour { auth: Some(("u", "p")), ..Default::default() }).await;
        let x = exit(&format!("socks5://u:p@{px}"), px);
        let d = x.udp(echo).await.unwrap();
        assert_eq!(d.send(b"ping").await.unwrap(), 4);
        let mut b = vec![0u8; 2048];
        let n = tokio::time::timeout(Duration::from_secs(5), d.recv(&mut b)).await.unwrap().unwrap();
        assert_eq!(&b[..n], b"ping");
        let st = x.info().stat.unwrap();
        assert_eq!((st.rx, st.tx), (4, 4));
        assert_eq!(x.status(), TOK);
    }

    #[tokio::test]
    async fn socks5_udp_ends_with_its_tcp_connection() {
        // a proxy that accepts the association, then hangs up
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let px = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut c, _) = l.accept().await.unwrap();
            let mut b = [0u8; 3];
            c.read_exact(&mut b).await.unwrap();
            c.write_all(&[5, 0]).await.unwrap();
            let mut r = [0u8; 10];
            c.read_exact(&mut r).await.unwrap();
            c.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 9]).await.unwrap();
        });
        let x = exit(&format!("socks5://{px}"), px);
        let d = x.udp("127.0.0.1:9".parse().unwrap()).await.unwrap();
        let mut b = [0u8; 16];
        let e = tokio::time::timeout(Duration::from_secs(5), d.recv(&mut b)).await.unwrap().unwrap_err();
        assert_eq!(e.to_string(), "socks5: the proxy ended the udp association");
    }

    #[test]
    fn socks_payload_checks_the_source() {
        let src: SocketAddr = "1.2.3.4:53".parse().unwrap();
        let mut m = socks_addr(&[0, 0, 0], src);
        m.extend_from_slice(b"x");
        assert_eq!(socks_payload(&m, src), Some(10));
        assert_eq!(socks_payload(&m, "1.2.3.4:54".parse().unwrap()), None);
        m[2] = 1; // a fragment
        assert_eq!(socks_payload(&m, src), None);
        assert_eq!(socks_payload(&[0, 0], src), None);
        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(socks_payload(&socks_addr(&[0, 0, 0], v6), v6), Some(22));
    }

    #[tokio::test]
    async fn http_connect_with_and_without_auth() {
        let echo = echo_tcp().await;
        let heads = Arc::new(Mutex::new(Vec::new()));
        let open = http_server(Behaviour::default(), heads.clone()).await;
        let x = exit(&format!("http://{open}"), open);
        let mut s = x.tcp(echo).await.unwrap();
        assert_eq!(round_trip(&mut s, b"hello").await, b"hello");
        assert_eq!(heads.lock().unwrap()[0], format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\nUser-Agent: Go-http-client/1.1\r\n"));
        assert_eq!(x.status(), TOK);

        let heads = Arc::new(Mutex::new(Vec::new()));
        let locked = http_server(Behaviour { auth: Some(("me", "pw")), ..Default::default() }, heads.clone()).await;
        let x = exit(&format!("http://me:pw@{locked}"), locked);
        let mut s = x.tcp(echo).await.unwrap();
        assert_eq!(round_trip(&mut s, b"hi").await, b"hi");
        assert!(heads.lock().unwrap()[0].ends_with("Proxy-Authorization: Basic bWU6cHc=\r\n"));

        // wrong credentials: the challenge is answered once, then it fails
        let heads = Arc::new(Mutex::new(Vec::new()));
        let locked = http_server(Behaviour { auth: Some(("me", "pw")), ..Default::default() }, heads.clone()).await;
        let x = exit(&format!("http://me:bad@{locked}"), locked);
        let e = x.tcp(echo).await.err().unwrap();
        assert_eq!(e.to_string(), "http1: tunnel: failed proxying 407: 407 Proxy Authentication Required");
        assert_eq!(heads.lock().unwrap().len(), 2);
        assert_eq!(x.status(), TKO);
        // no credentials: no retry
        let x = exit(&format!("http://{locked}"), locked);
        let e = x.tcp(echo).await.err().unwrap();
        assert_eq!(e.to_string(), "http1: tunnel: failed proxying 407: 407 Proxy Authentication Required");
    }

    #[tokio::test]
    async fn http_refusals_and_udp() {
        let echo = echo_tcp().await;
        let px = http_server(Behaviour { refuse_http: Some("403 Forbidden"), ..Default::default() }, Default::default()).await;
        let x = exit(&format!("http://{px}"), px);
        let e = x.tcp(echo).await.err().unwrap();
        assert_eq!(e.to_string(), "http1: tunnel: failed proxying 403: 403 Forbidden");
        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let x = exit(&format!("http://{dead}"), dead);
        let e = x.tcp(echo).await.err().unwrap();
        assert!(e.to_string().starts_with("http1: tunnel: failed dialing to proxy: "), "{e}");

        // UDP cannot go through an HTTP proxy; as in firestack, trying
        // counts as a failed dial
        let px = http_server(Behaviour::default(), Default::default()).await;
        let x = exit(&format!("http://{px}"), px);
        x.tcp(echo).await.unwrap();
        assert_eq!(x.status(), TOK);
        let e = x.udp("127.0.0.1:53".parse().unwrap()).await.err().unwrap();
        assert_eq!(e.to_string(), "http1: tunnel: network type 'udp' unsupported (only 'tcp')");
        assert_eq!(x.status(), TKO);
    }

    #[tokio::test]
    async fn dns_dials_go_through_the_exit_only_when_given_it() {
        let echo = echo_tcp().await;
        let px = socks_server(Behaviour::default()).await;
        let x = exit(&format!("socks5://{px}"), px);
        let mut s = dns::Dialer::dial_tcp(&x, EXIT_PROXY, echo).await.unwrap();
        assert_eq!(round_trip(&mut s, b"q").await, b"q");
        assert_eq!(x.info().stat.unwrap().tx, 1);
        let mut s = dns::Dialer::dial_tcp(&x, crate::exit::BASE, echo).await.unwrap();
        assert_eq!(round_trip(&mut s, b"q").await, b"q");
        assert_eq!(x.info().stat.unwrap().tx, 1, "direct is not the proxy's traffic");
        let e = dns::Dialer::dial_tcp(&x, "wg0", echo).await.err().unwrap();
        assert!(e.to_string().contains("not supported"), "{e}");
        let u = echo_udp().await;
        let d = dns::Dialer::dial_udp(&x, EXIT_PROXY, u).await.unwrap();
        d.send(b"a").await.unwrap();
        let mut b = [0u8; 8];
        assert_eq!(tokio::time::timeout(Duration::from_secs(5), d.recv(&mut b)).await.unwrap().unwrap(), 1);
    }

    /// A program's connection through the stack leaves by the SOCKS5 exit
    /// when the engine's exit is the proxy, and its UDP by the
    /// association; the journal names the exit.
    #[tokio::test]
    async fn forwarder_relays_flows_through_the_proxy() {
        use crate::engine::Engine;
        use crate::net::forward::{Forwarder, NoOwners};
        use crate::net::stack::tests::{Host, drive};
        use crate::net::stack::{Parsed, Stack, StackConfig, build_udp, parse};
        use tokio::sync::mpsc;

        let echo = echo_tcp().await;
        let uecho = echo_udp().await;
        let px = socks_server(Behaviour::default()).await;
        let x = Arc::new(exit(&format!("socks5://{px}"), px));
        let e = Arc::new(Engine::with_self(None, "", "C:\\fswin.exe", Box::new(|_| {})));
        e.set_exit(EXIT_PROXY);
        e.set_proxies(x.clone());
        let (st, io) = Stack::new(StackConfig::default());
        let (to_stack, rx) = mpsc::channel(1024);
        tokio::spawn(st.run(rx));
        let mut from_stack = io.out;
        let f = Arc::new(Forwarder::new(e.clone(), Arc::new(NoOwners), Arc::new(Direct::new(None)), Arc::new(crate::dns::FakeDns::new(e.clone()))));
        f.add_exit(EXIT_PROXY, x.clone());
        tokio::spawn(f.clone().run(io.flows));

        let mut host = Host::new();
        let h = host.connect(42000, echo);
        drive(&mut host, &to_stack, &mut from_stack, |h2| h2.tcp(h).may_send()).await;
        host.tcp(h).send_slice(b"via the proxy").unwrap();
        let mut got = Vec::new();
        drive(&mut host, &to_stack, &mut from_stack, |h2| {
            let s = h2.tcp(h);
            while s.can_recv() {
                let mut b = [0u8; 64];
                let n = s.recv_slice(&mut b).unwrap();
                got.extend_from_slice(&b[..n]);
            }
            got.len() == 13
        })
        .await;
        assert_eq!(got, b"via the proxy");
        let flow = e.log.since(0, 100).into_iter().find(|v| v.kind == "flow").unwrap();
        assert_eq!(flow.via, "proxy");
        let st = x.info().stat.unwrap();
        assert_eq!((st.rx, st.tx), (13, 13));
        assert_eq!(e.proxy_stats()[0].status, "connected");

        let me: SocketAddr = "10.111.222.1:5005".parse().unwrap();
        to_stack.send(build_udp(me, uecho, b"dgram").unwrap()).await.unwrap();
        let p = loop {
            let p = tokio::time::timeout(Duration::from_secs(5), from_stack.recv()).await.unwrap().unwrap();
            if matches!(parse(&p), Parsed::Udp { .. }) {
                break p;
            }
        };
        let Parsed::Udp { src, dst, payload } = parse(&p) else { unreachable!() };
        assert_eq!((src, dst, &p[payload]), (uecho, me, &b"dgram"[..]));
        assert_eq!(x.info().stat.unwrap().tx, 18);
    }

    #[tokio::test]
    async fn proxies_lists_the_exit_only() {
        let x = exit("socks5://127.0.0.1:1", "127.0.0.1:1".parse().unwrap());
        assert!(Proxies::get(&x, "pxsocks").is_none());
        let p = Proxies::get(&x, EXIT_PROXY).unwrap();
        assert_eq!(p.status, TZZ);
        let e = crate::engine::Engine::with_self(None, "", "C:\\fswin.exe", Box::new(|_| {}));
        e.set_exit(EXIT_PROXY);
        e.set_proxies(Arc::new(x));
        let st = e.proxy_stats();
        assert_eq!(st.len(), 1);
        assert_eq!((st[0].id.as_str(), st[0].name.as_str(), st[0].status.as_str()), (EXIT_PROXY, "proxy", "idle"));
    }

    #[tokio::test]
    async fn resolve_takes_ips_as_they_are() {
        let u = ProxyUrl::parse("socks5://[::1]:1080").unwrap();
        assert_eq!(u.resolve().await.unwrap(), vec!["[::1]:1080".parse().unwrap()]);
        let u = ProxyUrl::parse("http://localhost:3128").unwrap();
        let all = u.resolve().await.unwrap();
        assert!(all.iter().all(|a| a.ip().is_loopback() && a.port() == 3128), "{all:?}");
    }
}
