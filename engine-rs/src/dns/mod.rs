// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! DNS: the fake DNS server at 10.111.222.3:53 and the transports it
//! forwards to (firestack's dnsx resolver, doh, dns53/dot and the cached
//! transport). The network stack hands port-53 queries to a `Resolver`;
//! transports reach their servers through a `Dialer`, which the stack
//! provides with sockets bound to the physical interface.

pub mod cache;
pub mod dns53;
pub mod doh;
pub mod dot;
pub mod fake;
pub mod msg;
#[cfg(test)]
pub(crate) mod pipe;
pub mod tls;

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::engine::DnsSummary;

pub use fake::{FakeDns, Resolver};

/// A boxed future, as the traits here return them (dyn-compatible).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A byte stream: a TCP socket, or whatever a proxy hands back.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Stream for T {}

pub type BoxStream = Box<dyn Stream>;

/// Opens the transports' connections. `pid` is the exit the query was
/// given ("Base" for the physical interface); the stack's dialer binds
/// Base sockets to the physical interface so they stay out of the tunnel.
pub trait Dialer: Send + Sync {
    fn dial_tcp<'a>(&'a self, pid: &'a str, addr: SocketAddr) -> BoxFuture<'a, io::Result<BoxStream>>;

    /// A UDP socket connected to addr. The default binds an unbound
    /// socket of addr's family, which is all the tests need; the stack's
    /// dialer binds it to the physical interface as it does TCP.
    fn dial_udp<'a>(&'a self, _pid: &'a str, addr: SocketAddr) -> BoxFuture<'a, io::Result<tokio::net::UdpSocket>> {
        Box::pin(async move {
            let local: SocketAddr = if addr.is_ipv4() { (Ipv4Addr::UNSPECIFIED, 0).into() } else { (Ipv6Addr::UNSPECIFIED, 0).into() };
            let s = tokio::net::UdpSocket::bind(local).await?;
            s.connect(addr).await?;
            Ok(s)
        })
    }
}

/// A plain tokio dialer, for tests and tools: no interface binding.
pub struct TokioDialer;

impl Dialer for TokioDialer {
    fn dial_tcp<'a>(&'a self, _pid: &'a str, addr: SocketAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let s = tokio::net::TcpStream::connect(addr).await?;
            let _ = s.set_nodelay(true);
            Ok(Box::new(s) as BoxStream)
        })
    }
}

/// Why a query failed: firestack's QueryError, a transaction status
/// (engine::DNS_*) and the error text the journal shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryError {
    pub status: i32,
    pub msg: String,
}

impl QueryError {
    pub fn new(status: i32, msg: impl Into<String>) -> QueryError {
        QueryError { status, msg: msg.into() }
    }
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

/// A transport status that is not a DNS_* code: never used yet.
pub const STATUS_UNKNOWN: i32 = 100;

/// A DNS transport (firestack's dnsx.Transport): sends a query in wire
/// format and fills the summary (server, latency, rdata, rcode, status,
/// msg) as firestack's transports do.
pub trait Transport: Send + Sync {
    fn id(&self) -> &str;
    /// The server as the journal shows it (GetAddr).
    fn addr(&self) -> String;
    /// The last query's status (engine::DNS_*).
    fn status(&self) -> i32;
    fn query<'a>(&'a self, pid: &'a str, q: &'a [u8], smm: &'a mut DnsSummary) -> BoxFuture<'a, Result<Vec<u8>, QueryError>>;
}

/// A monotonic clock, so TTLs can be tested without waiting.
pub trait Clock: Send + Sync {
    /// Time since an arbitrary fixed start.
    fn now(&self) -> Duration;
}

/// The real clock.
pub struct SystemClock(Instant);

impl Default for SystemClock {
    fn default() -> Self {
        SystemClock(Instant::now())
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
}

/// A clock that moves only when told to (tests).
#[derive(Default)]
pub struct FakeClock(AtomicU64);

impl FakeClock {
    pub fn advance(&self, d: Duration) {
        self.0.fetch_add(d.as_millis() as u64, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Duration {
        Duration::from_millis(self.0.load(Ordering::SeqCst))
    }
}

pub type SharedClock = Arc<dyn Clock>;

/// The bootstrap addresses of a server: the -doh-ips (or -dot-ips) csv
/// with the server's port, or the host itself when it is an IP. Names
/// without IPs are refused: looking them up would loop through our own
/// DNS.
pub fn bootstrap_addrs(host: &str, port: u16, ips_csv: &str) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    for s in ips_csv.split(',') {
        let s = s.trim();
        if s.is_empty() {
            continue;
        }
        // an ip, or an ip:port as withPort makes them
        let a = crate::netaddr::parse_addr_port(s)
            .or_else(|| s.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, port)));
        match a {
            Some(a) if !out.contains(&a) => out.push(a),
            _ => {}
        }
    }
    if out.is_empty() {
        if let Ok(ip) = host.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() {
            out.push(SocketAddr::new(ip, port));
        }
    }
    out
}

/// Remembers which bootstrap address last worked and tries it first, as
/// firestack's dialers confirm and disconfirm IPs.
pub struct Addrs {
    all: Vec<SocketAddr>,
    good: std::sync::Mutex<Option<SocketAddr>>,
}

impl Addrs {
    pub fn new(all: Vec<SocketAddr>) -> Addrs {
        Addrs { all, good: std::sync::Mutex::new(None) }
    }

    pub fn is_empty(&self) -> bool {
        self.all.is_empty()
    }

    /// The addresses in the order to try them.
    pub fn ordered(&self) -> Vec<SocketAddr> {
        let good = *self.good.lock().unwrap_or_else(|e| e.into_inner());
        let mut v = self.all.clone();
        if let Some(i) = good.and_then(|g| v.iter().position(|a| *a == g)) {
            let g = v.remove(i);
            v.insert(0, g);
        }
        v
    }

    pub fn confirm(&self, a: SocketAddr) {
        *self.good.lock().unwrap_or_else(|e| e.into_inner()) = Some(a);
    }

    pub fn disconfirm(&self, a: SocketAddr) {
        let mut g = self.good.lock().unwrap_or_else(|e| e.into_inner());
        if *g == Some(a) {
            *g = None;
        }
    }

    /// Dials the addresses in order until one connects.
    pub async fn dial(&self, dialer: &dyn Dialer, pid: &str) -> io::Result<(BoxStream, SocketAddr)> {
        let mut last = io::Error::new(io::ErrorKind::AddrNotAvailable, "no IP address for the server");
        for a in self.ordered() {
            match dialer.dial_tcp(pid, a).await {
                Ok(s) => return Ok((s, a)),
                Err(e) => {
                    self.disconfirm(a);
                    last = e;
                }
            }
        }
        Err(last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap() {
        assert_eq!(
            bootstrap_addrs("cloudflare-dns.com", 443, "1.1.1.1, 1.0.0.1,,1.1.1.1"),
            vec!["1.1.1.1:443".parse::<SocketAddr>().unwrap(), "1.0.0.1:443".parse().unwrap()]
        );
        assert_eq!(bootstrap_addrs("x", 443, "1.1.1.1:8443,[2606:4700::1111]:443"), vec![
            "1.1.1.1:8443".parse::<SocketAddr>().unwrap(),
            "[2606:4700::1111]:443".parse().unwrap()
        ]);
        assert_eq!(bootstrap_addrs("2606:4700::1111", 853, ""), vec!["[2606:4700::1111]:853".parse::<SocketAddr>().unwrap()]);
        assert_eq!(bootstrap_addrs("[::1]", 853, ""), vec!["[::1]:853".parse::<SocketAddr>().unwrap()]);
        assert!(bootstrap_addrs("dns.google", 853, "").is_empty());
        assert!(bootstrap_addrs("dns.google", 853, "nonsense").is_empty());
    }

    #[test]
    fn confirmed_first() {
        let a: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let b: SocketAddr = "1.0.0.1:443".parse().unwrap();
        let addrs = Addrs::new(vec![a, b]);
        assert_eq!(addrs.ordered(), vec![a, b]);
        addrs.confirm(b);
        assert_eq!(addrs.ordered(), vec![b, a]);
        addrs.disconfirm(a);
        assert_eq!(addrs.ordered(), vec![b, a]);
        addrs.disconfirm(b);
        assert_eq!(addrs.ordered(), vec![a, b]);
    }

    #[test]
    fn fake_clock() {
        let c = FakeClock::default();
        assert_eq!(c.now(), Duration::ZERO);
        c.advance(Duration::from_secs(3));
        assert_eq!(c.now(), Duration::from_secs(3));
    }
}
