// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Plain DNS (port 53), after firestack's dns53 transport: the query goes
//! over UDP as it is, a truncated answer is asked again over TCP, and the
//! servers are tried in order, the one that last answered first. It
//! backs `-dns proxy` (Preferred, one ip:port) and `-dns system` (System,
//! the physical adapter's servers).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::doh::fill;
use super::{Addrs, BoxFuture, Dialer, QueryError, Transport, msg};
use crate::engine::{self, DnsSummary};

/// firestack's dns53 timeout, per server and per protocol.
pub const TIMEOUT: Duration = Duration::from_secs(15);
pub const PORT: u16 = 53;
/// The prefix firestack puts on the System transport's server
/// (protect.UidSystem + ".").
pub const SYSTEM_PREFIX: &str = "system.";

/// The largest DNS message; a UDP answer is read into a buffer this big.
const MAX_MSG: usize = 65535;

pub struct Dns53 {
    id: String,
    addrs: Addrs,
    dialer: Arc<dyn Dialer>,
    status: AtomicI32,
    /// the server last tried, which the journal shows (firestack's lastaddr)
    last: Mutex<Option<SocketAddr>>,
    timeout: Duration,
}

/// The servers in servers_csv (ip or ip:port, IPv6 in brackets when it has
/// a port), as settings.NewDNSOptionsFromHostname reads them: entries
/// that do not parse are skipped, and the first explicit port is the port
/// of every server (firestack's transport has one port).
pub fn parse_servers(servers_csv: &str) -> Vec<SocketAddr> {
    let mut ips = Vec::new();
    let mut port = None;
    for s in servers_csv.split(',') {
        let s = s.trim();
        if let Some(a) = crate::netaddr::parse_addr_port(s) {
            ips.push(a.ip());
            if a.port() > 0 && port.is_none() {
                port = Some(a.port());
            }
        } else if let Some(ip) = crate::netaddr::parse_addr(s.strip_prefix('[').and_then(|r| r.strip_suffix(']')).unwrap_or(s)) {
            ips.push(ip);
        }
    }
    let port = port.unwrap_or(PORT);
    let mut out: Vec<SocketAddr> = Vec::new();
    for ip in ips {
        let a = SocketAddr::new(ip, port);
        if !out.contains(&a) {
            out.push(a);
        }
    }
    out
}

impl Dns53 {
    /// A transport for the servers in servers_csv (see `parse_servers`).
    /// Unlike firestack it refuses a list without a valid IP: such a
    /// transport could never answer.
    pub fn new(id: &str, servers_csv: &str, dialer: Arc<dyn Dialer>) -> Result<Dns53, String> {
        let servers = parse_servers(servers_csv);
        if servers.is_empty() {
            return Err(format!("dns53: no valid ip in {}", crate::golike::quote(servers_csv)));
        }
        Ok(Dns53 {
            id: id.to_string(),
            addrs: Addrs::new(servers),
            dialer,
            status: AtomicI32::new(engine::DNS_START),
            last: Mutex::new(None),
            timeout: TIMEOUT,
        })
    }

    /// The same transport with another timeout per try (tests).
    pub fn with_timeout(mut self, d: Duration) -> Dns53 {
        self.timeout = d;
        self
    }

    /// The servers in the order the next query tries them.
    pub fn servers(&self) -> Vec<SocketAddr> {
        self.addrs.ordered()
    }

    async fn over_udp(&self, pid: &str, a: SocketAddr, q: &[u8]) -> Result<Vec<u8>, String> {
        let fut = async {
            let s = self.dialer.dial_udp(pid, a).await.map_err(|e| format!("dial udp {a}: {e}"))?;
            s.send(q).await.map_err(|e| format!("write udp {a}: {e}"))?;
            let mut buf = vec![0u8; MAX_MSG];
            loop {
                let n = s.recv(&mut buf).await.map_err(|e| format!("read udp {a}: {e}"))?;
                // anyone can send a datagram to our port: one that does not
                // carry the query's id is not the answer (as miekg/dns skips it)
                if n >= 12 && buf[..2] == q[..2] {
                    buf.truncate(n);
                    return Ok(buf);
                }
            }
        };
        tokio::time::timeout(self.timeout, fut).await.map_err(|_| format!("read udp {a}: i/o timeout"))?
    }

    async fn over_tcp(&self, pid: &str, a: SocketAddr, q: &[u8]) -> Result<Vec<u8>, String> {
        let fut = async {
            let mut c = self.dialer.dial_tcp(pid, a).await.map_err(|e| format!("dial tcp {a}: {e}"))?;
            let mut b = Vec::with_capacity(q.len() + 2);
            b.extend_from_slice(&(q.len() as u16).to_be_bytes());
            b.extend_from_slice(q);
            c.write_all(&b).await.map_err(|e| format!("write tcp {a}: {e}"))?;
            c.flush().await.map_err(|e| format!("write tcp {a}: {e}"))?;
            let mut l = [0u8; 2];
            c.read_exact(&mut l).await.map_err(|e| format!("read tcp {a}: {e}"))?;
            let mut ans = vec![0u8; u16::from_be_bytes(l) as usize];
            c.read_exact(&mut ans).await.map_err(|e| format!("read tcp {a}: {e}"))?;
            // a TCP connection is ours alone, so a wrong id is a broken server
            if ans.len() < 12 || ans[..2] != q[..2] {
                return Err("dns: id mismatch".to_string());
            }
            Ok(ans)
        };
        tokio::time::timeout(self.timeout, fut).await.map_err(|_| format!("read tcp {a}: i/o timeout"))?
    }

    /// One server: UDP, then TCP if the answer was cut short.
    async fn ask(&self, pid: &str, a: SocketAddr, q: &[u8]) -> Result<Vec<u8>, String> {
        let ans = self.over_udp(pid, a, q).await?;
        // the TC bit: the server had more to say than fits a datagram
        if ans[2] & 0x02 != 0 {
            return self.over_tcp(pid, a, q).await;
        }
        Ok(ans)
    }

    async fn do_query(&self, pid: &str, q: &[u8]) -> Result<Vec<u8>, QueryError> {
        let m = msg::parse(q).map_err(|e| QueryError::new(engine::DNS_BAD_QUERY, e))?;
        if m.queries.is_empty() {
            return Err(QueryError::new(engine::DNS_BAD_QUERY, "dns53: err parse query"));
        }
        // the System servers are the physical adapter's: never through an exit
        let pid = if self.id == engine::SYSTEM { crate::exit::BASE } else { pid };
        let mut errs: Vec<String> = Vec::new();
        for a in self.addrs.ordered() {
            *self.last.lock().unwrap_or_else(|e| e.into_inner()) = Some(a);
            match self.ask(pid, a, q).await {
                Ok(ans) if msg::parse(&ans).is_ok() => {
                    self.addrs.confirm(a);
                    return Ok(ans);
                }
                Ok(_) => errs.push(format!("{a}: dns: bad answer")),
                Err(e) => errs.push(e),
            }
            self.addrs.disconfirm(a);
        }
        Err(QueryError::new(engine::DNS_SEND_FAILED, errs.join(" | ")))
    }
}

impl Transport for Dns53 {
    fn id(&self) -> &str {
        &self.id
    }

    fn addr(&self) -> String {
        let last = *self.last.lock().unwrap_or_else(|e| e.into_inner());
        let a = last.or_else(|| self.addrs.ordered().first().copied()).map(|a| a.to_string()).unwrap_or_default();
        if self.id == engine::SYSTEM { format!("{SYSTEM_PREFIX}{a}") } else { a }
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
mod tests {
    use super::*;
    use crate::dns::TokioDialer;
    use crate::dns::doh::testserver::answer;
    use hickory_proto::rr::RecordType;
    use tokio::net::{TcpListener, UdpSocket};

    #[derive(Clone, Copy, PartialEq)]
    enum Mode {
        Answer,
        Servfail,
        /// a TC answer over UDP, the full one over TCP
        Truncate,
        /// read the query, never answer
        Drop,
        /// a datagram with another id before the answer
        WrongIdFirst,
    }

    fn query(name: &str) -> Vec<u8> {
        msg::pack(&msg::test_query(name, RecordType::A)).unwrap()
    }

    fn servfail(q: &[u8]) -> Vec<u8> {
        msg::pack(&msg::servfail(&msg::parse(q).unwrap()).unwrap()).unwrap()
    }

    /// A UDP server on 127.0.0.1 (and a TCP one on the same port for
    /// Truncate); returns its address.
    async fn server(mode: Mode) -> SocketAddr {
        let (udp, tcp) = loop {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let a = udp.local_addr().unwrap();
            if mode != Mode::Truncate {
                break (udp, None);
            }
            // the same port for TCP; another try in the rare case it is taken
            if let Ok(t) = TcpListener::bind(a).await {
                break (udp, Some(t));
            }
        };
        let a = udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let Ok((n, from)) = udp.recv_from(&mut buf).await else { return };
                let q = buf[..n].to_vec();
                let ans = match mode {
                    Mode::Drop => continue,
                    Mode::Answer => answer(&q),
                    Mode::Servfail => servfail(&q),
                    Mode::Truncate => {
                        let mut m = msg::pack(&msg::empty_response(&msg::parse(&q).unwrap()).unwrap()).unwrap();
                        m[2] |= 0x02;
                        m
                    }
                    Mode::WrongIdFirst => {
                        let mut stray = answer(&q);
                        stray[0] ^= 0xff;
                        let _ = udp.send_to(&stray, from).await;
                        answer(&q)
                    }
                };
                let _ = udp.send_to(&ans, from).await;
            }
        });
        if let Some(t) = tcp {
            tokio::spawn(async move {
                while let Ok((mut c, _)) = t.accept().await {
                    tokio::spawn(async move {
                        let mut l = [0u8; 2];
                        if c.read_exact(&mut l).await.is_err() {
                            return;
                        }
                        let mut q = vec![0u8; u16::from_be_bytes(l) as usize];
                        if c.read_exact(&mut q).await.is_err() {
                            return;
                        }
                        let ans = answer(&q);
                        let mut b = (ans.len() as u16).to_be_bytes().to_vec();
                        b.extend_from_slice(&ans);
                        let _ = c.write_all(&b).await;
                    });
                }
            });
        }
        a
    }

    fn dns53(id: &str, csv: &str) -> Dns53 {
        Dns53::new(id, csv, Arc::new(TokioDialer)).unwrap().with_timeout(Duration::from_millis(300))
    }

    async fn ask(d: &Dns53, name: &str) -> (Result<Vec<u8>, QueryError>, DnsSummary) {
        let mut smm = DnsSummary::default();
        let r = d.query(crate::exit::BASE, &query(name), &mut smm).await;
        (r, smm)
    }

    #[test]
    fn servers() {
        let p = |s: &str| parse_servers(s).iter().map(|a| a.to_string()).collect::<Vec<_>>();
        assert_eq!(p("1.1.1.1"), vec!["1.1.1.1:53"]);
        assert_eq!(p("127.0.0.1:5353"), vec!["127.0.0.1:5353"]);
        assert_eq!(p("192.168.1.1,fe80::1,[2001:db8::1]"), vec!["192.168.1.1:53", "[fe80::1]:53", "[2001:db8::1]:53"]);
        assert_eq!(p("[2001:db8::1]:5353"), vec!["[2001:db8::1]:5353"]);
        // as firestack: one port for all, the first given
        assert_eq!(p("8.8.8.8,1.1.1.1:5353,9.9.9.9:9953"), vec!["8.8.8.8:5353", "1.1.1.1:5353", "9.9.9.9:5353"]);
        // port 0 is no port; junk is skipped; duplicates once
        assert_eq!(p("1.1.1.1:0, nonsense,,1.1.1.1, 2001:db8::1:53"), vec!["1.1.1.1:53", "[2001:db8::1:53]:53"]);
        assert!(p("dns.google:53").is_empty());
        assert_eq!(Dns53::new("x", " ,x", Arc::new(TokioDialer)).err().unwrap(), "dns53: no valid ip in \" ,x\"");
    }

    #[test]
    fn addr_shown() {
        let d = dns53(engine::PREFERRED, "127.0.0.1:5353");
        assert_eq!(d.addr(), "127.0.0.1:5353");
        let d = dns53(engine::SYSTEM, "192.168.1.1,192.168.1.2");
        assert_eq!(d.addr(), "system.192.168.1.1:53");
    }

    #[tokio::test]
    async fn answers_over_udp() {
        let a = server(Mode::Answer).await;
        let d = dns53(engine::PREFERRED, &a.to_string());
        let (r, smm) = ask(&d, "example.com.").await;
        let m = msg::parse(&r.unwrap()).unwrap();
        assert_eq!(m.metadata.id, 0x1234);
        assert_eq!(smm.rdata, "192.0.2.1");
        assert_eq!((smm.status, smm.rcode), (engine::DNS_COMPLETE, 0));
        assert_eq!(smm.server, a.to_string());
        assert_eq!(d.status(), engine::DNS_COMPLETE);
        // NXDOMAIN is an answer
        let (r, smm) = ask(&d, "nx.test.").await;
        assert!(r.is_ok());
        assert_eq!((smm.status, smm.rcode), (engine::DNS_COMPLETE, 3));
        assert!(!engine::bad_rcode(&smm));
    }

    #[tokio::test]
    async fn servfail_is_an_answer() {
        let a = server(Mode::Servfail).await;
        let d = dns53(engine::PREFERRED, &a.to_string());
        let (r, smm) = ask(&d, "example.com.").await;
        assert!(r.is_ok());
        assert_eq!((smm.status, smm.rcode), (engine::DNS_COMPLETE, 2));
        assert!(smm.msg.is_empty());
        // the engine then says "<server> answered SERVFAIL"
        assert!(engine::bad_rcode(&smm));
        assert_eq!(smm.server, a.to_string());
        assert_eq!(engine::rcode_name(smm.rcode), "SERVFAIL");
    }

    #[tokio::test]
    async fn truncated_then_tcp() {
        let a = server(Mode::Truncate).await;
        let d = dns53(engine::PREFERRED, &a.to_string());
        let (r, smm) = ask(&d, "example.com.").await;
        let m = msg::parse(&r.unwrap()).unwrap();
        assert!(!m.metadata.truncation);
        assert_eq!(smm.rdata, "192.0.2.1");
    }

    #[tokio::test]
    async fn no_reply_is_a_timeout() {
        let a = server(Mode::Drop).await;
        let d = dns53(engine::PREFERRED, &a.to_string());
        let (r, smm) = ask(&d, "example.com.").await;
        let e = r.unwrap_err();
        assert_eq!(e.status, engine::DNS_SEND_FAILED);
        assert_eq!(e.msg, format!("read udp {a}: i/o timeout"));
        assert_eq!(smm.status, engine::DNS_SEND_FAILED);
        assert_eq!(engine::dns_failure(&smm), format!("no reply from {a} in 0 s (read udp {a}: i/o timeout)"));
        assert_eq!(d.status(), engine::DNS_SEND_FAILED);
    }

    #[tokio::test]
    async fn stray_ids_are_ignored() {
        let a = server(Mode::WrongIdFirst).await;
        let d = dns53(engine::PREFERRED, &a.to_string());
        let (r, _) = ask(&d, "example.com.").await;
        assert_eq!(msg::parse(&r.unwrap()).unwrap().metadata.id, 0x1234);
    }

    #[tokio::test]
    async fn next_server_when_the_first_is_dead() {
        let dead = server(Mode::Drop).await;
        let good = server(Mode::Answer).await;
        let d = dns53(engine::SYSTEM, &format!("{},{}", dead.ip(), good.ip()));
        // one port for all: build the list by hand to give each its own
        let d = Dns53 { addrs: Addrs::new(vec![dead, good]), ..d };
        let (r, smm) = ask(&d, "example.com.").await;
        assert!(r.is_ok());
        assert_eq!(smm.server, format!("system.{good}"));
        // the one that answered goes first, so the next query is quick
        assert_eq!(d.servers(), vec![good, dead]);
        let t = Instant::now();
        assert!(ask(&d, "example.org.").await.0.is_ok());
        assert!(t.elapsed() < Duration::from_millis(250));
    }

    #[tokio::test]
    async fn closed_port_moves_on_without_waiting() {
        // a port nobody listens on: the ICMP "port unreachable" fails the
        // read at once, so the next server is asked before the timeout
        let closed = UdpSocket::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
        let good = server(Mode::Answer).await;
        let d = Dns53::new(engine::PREFERRED, "127.0.0.1", Arc::new(TokioDialer)).unwrap().with_timeout(Duration::from_secs(5));
        let d = Dns53 { addrs: Addrs::new(vec![closed, good]), ..d };
        let t = Instant::now();
        let (r, smm) = ask(&d, "example.com.").await;
        assert!(r.is_ok());
        assert_eq!(smm.server, good.to_string());
        assert!(t.elapsed() < Duration::from_secs(4));
    }

    #[tokio::test]
    async fn all_dead() {
        let a = server(Mode::Drop).await;
        let b = server(Mode::Drop).await;
        let d = dns53(engine::PREFERRED, "127.0.0.1");
        let d = Dns53 { addrs: Addrs::new(vec![a, b]), ..d };
        let (r, smm) = ask(&d, "example.com.").await;
        assert_eq!(r.unwrap_err().msg, format!("read udp {a}: i/o timeout | read udp {b}: i/o timeout"));
        assert_eq!(smm.server, b.to_string());
        assert!(engine::dns_failure(&smm).starts_with(&format!("no reply from {b} in 1 s (")), "{}", engine::dns_failure(&smm));
    }

    #[tokio::test]
    async fn bad_query() {
        let d = dns53(engine::PREFERRED, "127.0.0.1");
        let mut smm = DnsSummary::default();
        let e = d.query("Base", b"junk", &mut smm).await.unwrap_err();
        assert_eq!(e.status, engine::DNS_BAD_QUERY);
        assert_eq!(smm.status, engine::DNS_BAD_QUERY);
    }
}
