// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The -wg exit: firestack's WireGuard proxy, on boringtun's sans-IO
//! `Tunn`. One peer, one UDP socket to its endpoint (opened by the Direct
//! dialer, so it leaves by the physical interface), and inside the tunnel a
//! small client TCP/IP stack (smoltcp) that owns the config's interface
//! addresses: a dial through the exit is a smoltcp connection from that
//! address, and its packets are what WireGuard encrypts.
//!
//! One task drives it all: datagrams from the peer, boringtun's timers
//! every 250 ms, and smoltcp's own timers and output. The streams and
//! datagram sockets handed out share the stack with it under a lock.

use std::collections::VecDeque;
use std::fmt;
use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, Instant as StdInstant};

use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::{Duration as SmolDuration, Instant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use super::dial::{DIAL_TIMEOUT, Dialer, Direct};
use crate::dns::{self, BoxDatagram, BoxFuture, BoxStream, Datagram};
use crate::engine::{Proxies, ProxyInfo, RouterStat, TKO, TOK, TUP, TZZ};
use crate::golike::quote;

/// firestack's errProxyConfig.
const ERR_CONFIG: &str = "proxy: invalid config";
/// firestack's MAXMTU: the "auto" MTU.
const MAX_MTU: i64 = 65535;
/// How often boringtun's timers run (handshake retries, keepalives).
const TICK: Duration = Duration::from_millis(250);
/// Room for the largest IP packet plus WireGuard's header and tag.
const SCRATCH: usize = 65536 + 64;
/// smoltcp's buffers per TCP connection (window scaling past 64 KiB).
const TCP_BUFFER: usize = 256 << 10;
/// A closed connection's socket is removed after this at the latest.
const LINGER: Duration = Duration::from_secs(60);

/// An address with its prefix length, as Go's netip.Prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    pub addr: IpAddr,
    pub len: u8,
}

impl Prefix {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip.to_canonical()) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let m = if self.len == 0 { 0 } else { u32::MAX << (32 - self.len as u32) };
                u32::from(a) & m == u32::from(b) & m
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let m = if self.len == 0 { 0 } else { u128::MAX << (128 - self.len as u32) };
                u128::from(a) & m == u128::from(b) & m
            }
            _ => false,
        }
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

/// One address or prefix as firestack's loadIPNets reads it, with Go's
/// netip errors.
fn parse_prefix(s: &str) -> Result<Prefix, String> {
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(Prefix { addr: ip, len: if ip.is_ipv4() { 32 } else { 128 } });
    }
    let bad = |why: String| format!("netip.ParsePrefix({}): {why}", quote(s));
    let Some((a, bits)) = s.rsplit_once('/') else { return Err(bad("no '/'".into())) };
    let Ok(addr) = a.parse::<IpAddr>() else { return Err(bad(format!("ParseAddr({}): unable to parse IP", quote(a)))) };
    if bits.is_empty() || bits.len() > 3 || !bits.bytes().all(|b| b.is_ascii_digit()) || (bits.len() > 1 && bits.starts_with('0')) {
        return Err(bad(format!("bad bits after slash: {}", quote(bits))));
    }
    let len: u8 = bits.parse().map_err(|_| bad(format!("bad bits after slash: {}", quote(bits))))?;
    if len > if addr.is_ipv4() { 32 } else { 128 } {
        return Err(bad("prefix length out of range".into()));
    }
    Ok(Prefix { addr, len })
}

/// A csv of addresses or prefixes (firestack's loadIPNets).
fn load_prefixes(out: &mut Vec<Prefix>, v: &str) -> Result<(), String> {
    for s in v.split(',') {
        out.push(parse_prefix(s.trim())?);
    }
    Ok(())
}

fn hex32(id: &str, what: &str, v: &str) -> Result<[u8; 32], String> {
    let bad = || format!("proxy: wg: {id} bad {what}");
    if v.len() != 64 {
        return Err(bad());
    }
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = u8::from_str_radix(&v[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
    }
    Ok(k)
}

/// A WireGuard exit's config, read from the key=value text firestack takes
/// (what exit::wg_quick_to_uapi makes of a wg-quick file).
#[derive(Clone)]
pub struct WgConfig {
    pub private_key: [u8; 32],
    /// the interface's addresses: the tunnel's end of every connection
    pub addrs: Vec<Prefix>,
    /// the config's DNS servers (names or IPs)
    pub dns: Vec<String>,
    /// the packet size on the link (MAX_MTU for "auto")
    pub mtu: i64,
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    /// host:port, as written
    pub endpoint: String,
    /// where the peer may be sent to and heard from; the DNS servers' IPs
    /// are added, as firestack does
    pub allowed: Vec<Prefix>,
    pub keepalive: Option<u16>,
}

impl fmt::Debug for WgConfig {
    // no keys in logs or test output
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WgConfig").field("addrs", &self.addrs).field("dns", &self.dns).field("mtu", &self.mtu).field("endpoint", &self.endpoint).field("allowed", &self.allowed).field("keepalive", &self.keepalive).finish()
    }
}

impl WgConfig {
    /// Reads the config as firestack's wgIfConfigOf (with its error
    /// wording) and then wireguard-go's IpcSet. One peer only.
    pub fn parse(id: &str, txt: &str) -> Result<WgConfig, String> {
        let mut c = WgConfig { private_key: [0; 32], addrs: vec![], dns: vec![], mtu: MAX_MTU, public_key: [0; 32], preshared_key: None, endpoint: String::new(), allowed: vec![], keepalive: None };
        let (mut saw_private, mut peers) = (false, 0);
        for line in txt.split('\n') {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.is_empty() {
                // a blank line ends the config, as in Go
                break;
            }
            let Some((k, v)) = line.split_once('=') else {
                return Err(format!("proxy: wg: {id} failed to parse line {}", quote(line)));
            };
            let k = crate::golike::to_lower(k.trim());
            let v = crate::golike::to_lower(v.trim());
            match k.as_str() {
                "address" => load_prefixes(&mut c.addrs, &v)?,
                "dns" => {
                    for d in v.split(',').map(str::trim).filter(|d| !d.is_empty()) {
                        c.dns.push(d.to_string());
                        if let Ok(p) = parse_prefix(d) {
                            c.allowed.push(p);
                        }
                    }
                }
                "mtu" => {
                    c.mtu = if v.is_empty() || v == "auto" || v == "(auto)" {
                        MAX_MTU
                    } else {
                        v.parse::<i64>().map_err(|_| format!("strconv.Atoi: parsing {}: invalid syntax", quote(&v)))?
                    };
                    if c.mtu < 0 {
                        c.mtu = MAX_MTU;
                    }
                }
                "allowed_ip" => load_prefixes(&mut c.allowed, &v)?,
                "private_key" => {
                    c.private_key = hex32(id, "private_key", &v)?;
                    saw_private = true;
                }
                "public_key" => {
                    peers += 1;
                    if peers > 1 {
                        return Err(format!("proxy: wg: {id}: more than one [Peer] is not supported by this engine yet"));
                    }
                    c.public_key = hex32(id, "public_key", &v)?;
                }
                "preshared_key" => c.preshared_key = Some(hex32(id, "preshared_key", &v)?),
                "endpoint" => c.endpoint = v.clone(),
                "persistent_keepalive_interval" => {
                    let n: u16 = v.parse().map_err(|_| format!("proxy: wg: {id} bad persistent_keepalive_interval {}", quote(&v)))?;
                    c.keepalive = (n > 0).then_some(n);
                }
                _ => {}
            }
        }
        if c.addrs.is_empty() || c.dns.is_empty() || c.mtu <= 0 || !saw_private || peers == 0 {
            return Err(ERR_CONFIG.into());
        }
        if c.endpoint.is_empty() {
            return Err(format!("proxy: wg: {id}: the [Peer] has no Endpoint"));
        }
        Ok(c)
    }

    /// The peer's address: the endpoint itself if it is ip:port, else what
    /// the system resolver says (IPv4 first). Done before the tunnel is up,
    /// since a name looked up later would ask our own DNS, which needs the
    /// exit.
    pub async fn resolve(&self) -> Result<SocketAddr, String> {
        if let Ok(a) = self.endpoint.parse::<SocketAddr>() {
            return Ok(a);
        }
        let Some((host, port)) = self.endpoint.rsplit_once(':') else {
            return Err(format!("endpoint {}: missing port in address", quote(&self.endpoint)));
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let Ok(port) = port.parse::<u16>() else {
            return Err(format!("endpoint {}: invalid port {}", quote(&self.endpoint), quote(port)));
        };
        let all: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await.map_err(|e| format!("lookup {host}: {e}"))?.collect();
        all.iter().find(|a| a.is_ipv4()).or(all.first()).copied().ok_or_else(|| format!("lookup {host}: no addresses"))
    }

    fn local(&self, v4: bool) -> Option<IpAddr> {
        self.addrs.iter().map(|p| p.addr.to_canonical()).find(|a| a.is_ipv4() == v4)
    }
}

/// The exit's knobs; tests shorten the waits.
#[derive(Debug, Clone)]
pub struct WgOptions {
    /// the size of a packet inside the tunnel (the MTU plan's exit MTU)
    pub mtu: usize,
    pub dial_timeout: Duration,
    /// a handshake unanswered this long marks the exit failing
    pub handshake_timeout: Duration,
}

impl WgOptions {
    pub fn new(mtu: usize) -> WgOptions {
        WgOptions { mtu, dial_timeout: DIAL_TIMEOUT, handshake_timeout: Duration::from_secs(10) }
    }
}

/// smoltcp's view of the tunnel: decrypted packets queued in, packets to
/// encrypt collected out.
struct Queue {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
    mtu: usize,
}

struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut Vec<Vec<u8>>);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut b = vec![0u8; len];
        let r = f(&mut b);
        self.0.push(b);
        r
    }
}

impl Device for Queue {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx<'_>)> {
        let p = self.rx.pop_front()?;
        Some((Rx(p), Tx(&mut self.tx)))
    }

    fn transmit(&mut self, _: Instant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = self.mtu;
        c
    }
}

fn random() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    // the OS-random keys std gives each RandomState: enough for a session
    // index, ISNs and the first local port
    let mut h = std::hash::RandomState::new().build_hasher();
    h.write_u64(StdInstant::now().elapsed().as_nanos() as u64);
    h.finish()
}

/// An interface with addrs (one per family) and default routes through
/// them, over dev.
fn interface(addrs: &[Prefix], dev: &mut Queue) -> Interface {
    let mut c = Config::new(HardwareAddress::Ip);
    c.random_seed = random();
    let mut iface = Interface::new(c, dev, Instant::now());
    let v4 = addrs.iter().map(|p| (p.addr.to_canonical(), p.len)).find(|(a, _)| a.is_ipv4());
    let v6 = addrs.iter().map(|p| (p.addr.to_canonical(), p.len)).find(|(a, _)| a.is_ipv6());
    iface.update_ip_addrs(|a| {
        for (ip, len) in v4.into_iter().chain(v6) {
            let _ = a.push(IpCidr::new(IpAddress::from(ip), len));
        }
    });
    if let Some((IpAddr::V4(ip), _)) = v4 {
        let _ = iface.routes_mut().add_default_ipv4_route(ip);
    }
    if let Some((IpAddr::V6(ip), _)) = v6 {
        let _ = iface.routes_mut().add_default_ipv6_route(ip);
    }
    iface
}

/// The tunnel and the stack inside it.
struct Core {
    tunn: Tunn,
    iface: Interface,
    dev: Queue,
    sockets: SocketSet<'static>,
    scratch: Vec<u8>,
    /// sockets whose streams are gone: removed once closed
    closing: Vec<(SocketHandle, StdInstant)>,
    next_port: u16,
    /// when a handshake initiation went out that is not answered yet
    init_since: Option<StdInstant>,
    /// the last handshake, unix ms
    last_handshake: i64,
    status: i32,
    stopped: bool,
}

impl Core {
    fn set_status(&mut self, id: &str, s: i32, why: &str) {
        if self.status != s {
            let level = if s == TKO { crate::logline::WARN } else { crate::logline::INFO };
            crate::logline::log(level, "wg", &format!("{id}: {why}"));
        }
        self.status = s;
    }

    fn port(&mut self) -> u16 {
        let p = self.next_port;
        self.next_port = if p == u16::MAX { 49152 } else { p + 1 };
        p
    }

    /// A packet on its way to the peer: notes a handshake initiation.
    fn sent(&mut self, p: &[u8], wire: &mut Vec<Vec<u8>>) {
        if p.first() == Some(&1) && self.init_since.is_none() {
            self.init_since = Some(StdInstant::now());
        }
        wire.push(p.to_vec());
    }

    /// A datagram from the peer: handshake messages are answered, data is
    /// decrypted for the stack (if it comes from an allowed address), and
    /// what waited for a session goes out.
    fn incoming(&mut self, x: &Inner, d: &[u8], wire: &mut Vec<Vec<u8>>) {
        let kind = d.first().copied().unwrap_or(0);
        let mut out = std::mem::take(&mut self.scratch);
        let mut first = true;
        let mut handshook = false;
        loop {
            let src: &[u8] = if first { d } else { &[] };
            match self.tunn.decapsulate(None, src, &mut out) {
                TunnResult::WriteToNetwork(p) => {
                    handshook |= first && (kind == 1 || kind == 2);
                    let p = p.to_vec();
                    self.sent(&p, wire);
                }
                TunnResult::WriteToTunnelV4(p, src) => {
                    if x.allowed(IpAddr::V4(src)) {
                        self.dev.rx.push_back(p.to_vec());
                    }
                    break;
                }
                TunnResult::WriteToTunnelV6(p, src) => {
                    if x.allowed(IpAddr::V6(src)) {
                        self.dev.rx.push_back(p.to_vec());
                    }
                    break;
                }
                TunnResult::Done => break,
                TunnResult::Err(e) => {
                    crate::logline::log(crate::logline::DEBUG, "wg", &format!("{}: dropped a datagram: {e:?}", x.id));
                    break;
                }
            }
            first = false;
        }
        self.scratch = out;
        if handshook {
            self.init_since = None;
            self.last_handshake = crate::events::now_ms();
            self.set_status(&x.id, TOK, &format!("handshake with {}", x.endpoint));
        }
    }

    /// boringtun's timers: handshake retries, keepalives, expiry.
    fn timers(&mut self, x: &Inner, wire: &mut Vec<Vec<u8>>) {
        let mut out = std::mem::take(&mut self.scratch);
        match self.tunn.update_timers(&mut out) {
            TunnResult::WriteToNetwork(p) => {
                let p = p.to_vec();
                self.sent(&p, wire);
            }
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                // given up on a handshake, or keys dropped after a long idle
                if self.init_since.is_some() {
                    self.set_status(&x.id, TKO, &format!("no handshake with {}", x.endpoint));
                } else if self.status == TOK {
                    self.set_status(&x.id, TZZ, "idle");
                }
            }
            _ => {}
        }
        self.scratch = out;
        if self.init_since.is_some_and(|t| t.elapsed() > x.opts.handshake_timeout) {
            self.set_status(&x.id, TKO, &format!("no answer to the handshake from {}", x.endpoint));
        }
    }

    /// Lets smoltcp work and encrypts what it sends.
    fn pump(&mut self, wire: &mut Vec<Vec<u8>>) {
        self.iface.poll(Instant::now(), &mut self.dev, &mut self.sockets);
        let now = StdInstant::now();
        let mut keep = Vec::with_capacity(self.closing.len());
        for (h, t) in std::mem::take(&mut self.closing) {
            let s = self.sockets.get_mut::<tcp::Socket>(h);
            match s.state() {
                tcp::State::Closed | tcp::State::TimeWait => {
                    self.sockets.remove(h);
                }
                _ if now.duration_since(t) > LINGER => {
                    s.abort();
                    keep.push((h, now - LINGER));
                }
                _ => keep.push((h, t)),
            }
        }
        self.closing = keep;
        let tx = std::mem::take(&mut self.dev.tx);
        let mut out = std::mem::take(&mut self.scratch);
        for p in tx {
            match self.tunn.encapsulate(&p, &mut out) {
                TunnResult::WriteToNetwork(b) => {
                    let b = b.to_vec();
                    self.sent(&b, wire);
                }
                TunnResult::Err(e) => crate::logline::log(crate::logline::DEBUG, "wg", &format!("encapsulate: {e:?}")),
                _ => {}
            }
        }
        self.scratch = out;
    }
}

/// What the exit, its driver and its connections share.
struct Inner {
    id: String,
    cfg: WgConfig,
    endpoint: SocketAddr,
    opts: WgOptions,
    core: Mutex<Core>,
    /// wakes the driver: a stream read, wrote or closed
    notify: Notify,
    rx: AtomicI64,
    tx: AtomicI64,
    since: i64,
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, Core> {
        self.core.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn allowed(&self, ip: IpAddr) -> bool {
        self.cfg.allowed.iter().any(|p| p.contains(ip))
    }

    /// The local address for a connection to dst, if the peer may be sent
    /// there.
    fn route(&self, dst: SocketAddr) -> io::Result<IpAddr> {
        if !self.allowed(dst.ip()) {
            return Err(io::Error::new(io::ErrorKind::HostUnreachable, format!("dial {dst}: wg: {} is not in the peer's AllowedIPs", dst.ip())));
        }
        let v4 = dst.is_ipv4();
        self.cfg.local(v4).ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, format!("dial {dst}: wg: the config has no IPv{} Address", if v4 { 4 } else { 6 })))
    }

    fn stopped() -> io::Error {
        io::Error::new(io::ErrorKind::NotConnected, "wg: the exit is stopped")
    }
}

/// The datagram socket to the peer and the timers, until the exit stops.
async fn drive(x: Arc<Inner>, sock: UdpSocket) {
    let mut buf = vec![0u8; SCRATCH];
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let delay = {
            let mut c = x.lock();
            let c = &mut *c;
            c.iface.poll_delay(Instant::now(), &c.sockets).map(Duration::from).unwrap_or(TICK).min(TICK)
        };
        let mut wire = Vec::new();
        tokio::select! {
            r = sock.recv(&mut buf) => {
                match r {
                    Ok(n) => {
                        x.rx.fetch_add(n as i64, Ordering::Relaxed);
                        let mut c = x.lock();
                        c.incoming(&x, &buf[..n], &mut wire);
                        // a burst in one go
                        for _ in 0..64 {
                            match sock.try_recv(&mut buf) {
                                Ok(n) => {
                                    x.rx.fetch_add(n as i64, Ordering::Relaxed);
                                    c.incoming(&x, &buf[..n], &mut wire);
                                }
                                Err(_) => break,
                            }
                        }
                    }
                    Err(e) => {
                        // the endpoint refused (ICMP unreachable) or the
                        // network is gone
                        x.lock().set_status(&x.id, TKO, &format!("read from {}: {e}", x.endpoint));
                        tokio::time::sleep(TICK).await;
                    }
                }
            }
            _ = tick.tick() => x.lock().timers(&x, &mut wire),
            _ = x.notify.notified() => {}
            _ = tokio::time::sleep(delay) => {}
        }
        x.lock().pump(&mut wire);
        for p in wire {
            match sock.send(&p).await {
                Ok(n) => {
                    x.tx.fetch_add(n as i64, Ordering::Relaxed);
                }
                Err(e) => x.lock().set_status(&x.id, TKO, &format!("write to {}: {e}", x.endpoint)),
            }
        }
    }
}

/// The exit: dials inside the tunnel and keeps its state and counters for
/// /api/proxies.
pub struct WgExit {
    x: Arc<Inner>,
    driver: JoinHandle<()>,
    /// for the DNS transports' other dials
    direct: Direct,
}

impl Drop for WgExit {
    fn drop(&mut self) {
        self.driver.abort();
        let mut c = self.x.lock();
        c.stopped = true;
        // wakes the connections' readers and writers, who then fail
        for (_, s) in c.sockets.iter_mut() {
            match s {
                smoltcp::socket::Socket::Tcp(t) => t.abort(),
                smoltcp::socket::Socket::Udp(u) => u.close(),
                #[allow(unreachable_patterns)]
                _ => {}
            }
        }
    }
}

impl WgExit {
    /// Starts the exit with proxy id id: opens its socket to endpoint (the
    /// config's, resolved) with direct and runs the tunnel.
    pub async fn start(id: &str, cfg: WgConfig, endpoint: SocketAddr, direct: &Direct, opts: WgOptions) -> Result<WgExit, String> {
        let sock = direct.connect_udp(endpoint).await.map_err(|e| format!("wg: {endpoint}: {e}"))?;
        let secret = StaticSecret::from(cfg.private_key);
        let tunn = Tunn::new(secret, PublicKey::from(cfg.public_key), cfg.preshared_key, cfg.keepalive, (random() as u32) >> 8, None);
        let mut dev = Queue { rx: VecDeque::new(), tx: Vec::new(), mtu: opts.mtu.max(576) };
        let iface = interface(&cfg.addrs, &mut dev);
        let mut core = Core {
            tunn,
            iface,
            dev,
            sockets: SocketSet::new(vec![]),
            scratch: vec![0u8; SCRATCH],
            closing: Vec::new(),
            next_port: 49152 + (random() % 16384) as u16,
            init_since: None,
            last_handshake: 0,
            status: TUP,
            stopped: false,
        };
        // with a persistent keepalive the tunnel comes up at once, as
        // wireguard-go does, rather than at the first dial
        let mut wire = Vec::new();
        if cfg.keepalive.is_some() {
            let mut out = std::mem::take(&mut core.scratch);
            if let TunnResult::WriteToNetwork(p) = core.tunn.format_handshake_initiation(&mut out, false) {
                let p = p.to_vec();
                core.sent(&p, &mut wire);
            }
            core.scratch = out;
        }
        let x = Arc::new(Inner { id: id.to_string(), cfg, endpoint, opts, core: Mutex::new(core), notify: Notify::new(), rx: AtomicI64::new(0), tx: AtomicI64::new(0), since: crate::events::now_ms() });
        for p in wire {
            if let Ok(n) = sock.send(&p).await {
                x.tx.fetch_add(n as i64, Ordering::Relaxed);
            }
        }
        let driver = tokio::spawn(drive(x.clone(), sock));
        Ok(WgExit { x, driver, direct: direct.clone() })
    }

    pub fn id(&self) -> &str {
        &self.x.id
    }

    /// The config's DNS servers.
    pub fn dns(&self) -> &[String] {
        &self.x.cfg.dns
    }

    pub fn status(&self) -> i32 {
        self.x.lock().status
    }

    /// A TCP connection to dst inside the tunnel.
    pub async fn connect(&self, dst: SocketAddr) -> io::Result<BoxStream> {
        let dst = SocketAddr::new(dst.ip().to_canonical(), dst.port());
        let local = self.x.route(dst)?;
        let h = {
            let mut c = self.x.lock();
            if c.stopped {
                return Err(Inner::stopped());
            }
            let mut s = tcp::Socket::new(tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]), tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]));
            s.set_nagle_enabled(false);
            s.set_timeout(Some(SmolDuration::from_secs(120)));
            s.set_keep_alive(Some(SmolDuration::from_secs(60)));
            let port = c.port();
            let c = &mut *c;
            s.connect(c.iface.context(), IpEndpoint::from(dst), (IpAddress::from(local), port)).map_err(|e| io::Error::other(format!("dial {dst}: wg: {e}")))?;
            c.sockets.add(s)
        };
        self.x.notify.notify_one();
        let x = &self.x;
        let opened = poll_fn(|cx| {
            let mut c = x.lock();
            if c.stopped {
                return Poll::Ready(Err(Inner::stopped()));
            }
            let s = c.sockets.get_mut::<tcp::Socket>(h);
            match s.state() {
                tcp::State::Established => Poll::Ready(Ok(())),
                tcp::State::Closed => Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionRefused, format!("dial {dst}: connection refused")))),
                _ => {
                    s.register_send_waker(cx.waker());
                    Poll::Pending
                }
            }
        });
        let r = match tokio::time::timeout(x.opts.dial_timeout, opened).await {
            Ok(r) => r,
            Err(_) => {
                let why = if x.lock().status == TOK { "i/o timeout".to_string() } else { format!("wg: no handshake with {}", x.endpoint) };
                Err(io::Error::new(io::ErrorKind::TimedOut, format!("dial {dst}: {why}")))
            }
        };
        match r {
            Ok(()) => Ok(Box::new(WgTcp { x: x.clone(), h })),
            Err(e) => {
                let mut c = x.lock();
                c.sockets.get_mut::<tcp::Socket>(h).abort();
                c.closing.push((h, StdInstant::now()));
                drop(c);
                x.notify.notify_one();
                Err(e)
            }
        }
    }

    /// A datagram socket to dst inside the tunnel.
    pub fn associate(&self, dst: SocketAddr) -> io::Result<BoxDatagram> {
        let dst = SocketAddr::new(dst.ip().to_canonical(), dst.port());
        let local = self.x.route(dst)?;
        let mut c = self.x.lock();
        if c.stopped {
            return Err(Inner::stopped());
        }
        let buf = || udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0u8; 256 << 10]);
        let mut s = udp::Socket::new(buf(), buf());
        let port = c.port();
        s.bind((IpAddress::from(local), port)).map_err(|e| io::Error::other(format!("dial {dst}: wg: {e}")))?;
        let h = c.sockets.add(s);
        Ok(Box::new(WgUdp { x: self.x.clone(), h, dst: IpEndpoint::from(dst) }))
    }

    /// The exit's state for /api/proxies: rx and tx are the bytes on the
    /// wire, last_ok the last handshake, as wireguard-go reports them.
    pub fn info(&self) -> ProxyInfo {
        let (status, last_ok) = {
            let c = self.x.lock();
            (c.status, c.last_handshake)
        };
        let addrs = self.x.cfg.addrs.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
        ProxyInfo { status, stat: Some(RouterStat { addrs, rx: self.x.rx.load(Ordering::Relaxed), tx: self.x.tx.load(Ordering::Relaxed), last_ok, since: self.x.since }) }
    }
}

/// A TCP connection inside the tunnel.
struct WgTcp {
    x: Arc<Inner>,
    h: SocketHandle,
}

impl AsyncRead for WgTcp {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut c = self.x.lock();
        if c.stopped {
            return Poll::Ready(Err(Inner::stopped()));
        }
        let s = c.sockets.get_mut::<tcp::Socket>(self.h);
        if s.can_recv() {
            let n = s.recv_slice(buf.initialize_unfilled()).map_err(|e| io::Error::other(e.to_string()))?;
            buf.advance(n);
            drop(c);
            // the window opened: the driver tells the peer
            self.x.notify.notify_one();
            return Poll::Ready(Ok(()));
        }
        if !s.may_recv() {
            return Poll::Ready(Ok(()));
        }
        s.register_recv_waker(cx.waker());
        Poll::Pending
    }
}

impl AsyncWrite for WgTcp {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        let mut c = self.x.lock();
        if c.stopped {
            return Poll::Ready(Err(Inner::stopped()));
        }
        let s = c.sockets.get_mut::<tcp::Socket>(self.h);
        if !s.may_send() {
            let kind = if s.state() == tcp::State::Closed { io::ErrorKind::ConnectionReset } else { io::ErrorKind::BrokenPipe };
            return Poll::Ready(Err(kind.into()));
        }
        if !s.can_send() {
            s.register_send_waker(cx.waker());
            return Poll::Pending;
        }
        let n = s.send_slice(b).map_err(|e| io::Error::other(e.to_string()))?;
        drop(c);
        self.x.notify.notify_one();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.x.lock().sockets.get_mut::<tcp::Socket>(self.h).close();
        self.x.notify.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for WgTcp {
    fn drop(&mut self) {
        let mut c = self.x.lock();
        if c.stopped {
            return;
        }
        // sends what is written, then a FIN; the socket goes once closed
        c.sockets.get_mut::<tcp::Socket>(self.h).close();
        c.closing.push((self.h, StdInstant::now()));
        drop(c);
        self.x.notify.notify_one();
    }
}

/// A UDP socket inside the tunnel, "connected" to dst.
struct WgUdp {
    x: Arc<Inner>,
    h: SocketHandle,
    dst: IpEndpoint,
}

impl Datagram for WgUdp {
    fn send<'a>(&'a self, b: &'a [u8]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(poll_fn(move |cx| {
            let mut c = self.x.lock();
            if c.stopped {
                return Poll::Ready(Err(Inner::stopped()));
            }
            let s = c.sockets.get_mut::<udp::Socket>(self.h);
            match s.send_slice(b, self.dst) {
                Ok(()) => {
                    drop(c);
                    self.x.notify.notify_one();
                    Poll::Ready(Ok(b.len()))
                }
                Err(udp::SendError::BufferFull) => {
                    s.register_send_waker(cx.waker());
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(io::Error::other(format!("wg: send to {}: {e}", self.dst)))),
            }
        }))
    }

    fn recv<'a>(&'a self, b: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(poll_fn(move |cx| {
            let mut c = self.x.lock();
            if c.stopped {
                return Poll::Ready(Err(Inner::stopped()));
            }
            let s = c.sockets.get_mut::<udp::Socket>(self.h);
            loop {
                match s.recv() {
                    // like a connected socket: only dst's datagrams
                    Ok((d, meta)) if meta.endpoint == self.dst => {
                        let k = d.len().min(b.len());
                        b[..k].copy_from_slice(&d[..k]);
                        return Poll::Ready(Ok(k));
                    }
                    Ok(_) => continue,
                    Err(_) => {
                        s.register_recv_waker(cx.waker());
                        return Poll::Pending;
                    }
                }
            }
        }))
    }
}

impl Drop for WgUdp {
    fn drop(&mut self) {
        let mut c = self.x.lock();
        if !c.stopped {
            c.sockets.remove(self.h);
        }
    }
}

impl Dialer for WgExit {
    fn tcp(&self, dst: SocketAddr) -> BoxFuture<'_, io::Result<BoxStream>> {
        Box::pin(self.connect(dst))
    }

    fn udp(&self, dst: SocketAddr) -> BoxFuture<'_, io::Result<BoxDatagram>> {
        Box::pin(async move { self.associate(dst) })
    }
}

/// The DNS transports' connections: through the tunnel for queries given
/// the exit, direct for the others.
impl dns::Dialer for WgExit {
    fn dial_tcp<'a>(&'a self, pid: &'a str, addr: SocketAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            if pid == self.x.id {
                return self.connect(addr).await;
            }
            dns::Dialer::dial_tcp(&self.direct, pid, addr).await
        })
    }

    fn dial_udp<'a>(&'a self, pid: &'a str, addr: SocketAddr) -> BoxFuture<'a, io::Result<BoxDatagram>> {
        Box::pin(async move {
            if pid == self.x.id {
                return self.associate(addr);
            }
            dns::Dialer::dial_udp(&self.direct, pid, addr).await
        })
    }
}

impl Proxies for WgExit {
    fn get(&self, id: &str) -> Option<ProxyInfo> {
        (id == self.x.id).then(|| self.info())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::exit::{EXIT_WG, base64_std_encode, wg_quick_to_uapi};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn public(n: u8) -> String {
        base64_std_encode(PublicKey::from(&StaticSecret::from([n; 32])).as_bytes())
    }

    /// A wg-quick file for the exit with private key [me; 32], talking to
    /// the peer whose private key is [peer; 32].
    pub(crate) fn conf(me: u8, peer: u8, endpoint: SocketAddr, allowed: &str) -> String {
        format!(
            "[Interface]\nPrivateKey = {}\nAddress = 10.9.0.2/32\nDNS = 10.9.0.1\n\n[Peer]\nPublicKey = {}\nEndpoint = {endpoint}\nAllowedIPs = {allowed}\n",
            base64_std_encode(&[me; 32]),
            public(peer)
        )
    }

    /// The test's WireGuard server: a peer at 10.9.0.1 on 127.0.0.1 with
    /// a TCP and a UDP echo on port 7 inside the tunnel.
    pub(crate) struct Server {
        pub addr: SocketAddr,
        task: JoinHandle<()>,
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    pub(crate) async fn server(me: u8, client: u8) -> Server {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut tunn = Tunn::new(StaticSecret::from([me; 32]), PublicKey::from(&StaticSecret::from([client; 32])), None, None, 1, None);
            let mut dev = Queue { rx: VecDeque::new(), tx: Vec::new(), mtu: 1420 };
            let mut iface = interface(&[Prefix { addr: "10.9.0.1".parse().unwrap(), len: 24 }], &mut dev);
            let mut sockets = SocketSet::new(vec![]);
            let mut tcps = Vec::new();
            for _ in 0..4 {
                let mut s = tcp::Socket::new(tcp::SocketBuffer::new(vec![0u8; 65536]), tcp::SocketBuffer::new(vec![0u8; 65536]));
                s.listen(7).unwrap();
                tcps.push(sockets.add(s));
            }
            let buf = || udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 65536]);
            let mut u = udp::Socket::new(buf(), buf());
            u.bind(7).unwrap();
            let uh = sockets.add(u);
            let (mut b, mut out) = (vec![0u8; SCRATCH], vec![0u8; SCRATCH]);
            let mut peer = None;
            loop {
                let mut wire = Vec::new();
                if let Ok(Ok((n, from))) = tokio::time::timeout(Duration::from_millis(5), sock.recv_from(&mut b)).await {
                    peer = Some(from);
                    let mut first = true;
                    loop {
                        let src: &[u8] = if first { &b[..n] } else { &[] };
                        match tunn.decapsulate(Some(from.ip()), src, &mut out) {
                            TunnResult::WriteToNetwork(p) => wire.push(p.to_vec()),
                            TunnResult::WriteToTunnelV4(p, _) => {
                                dev.rx.push_back(p.to_vec());
                                break;
                            }
                            _ => break,
                        }
                        first = false;
                    }
                }
                iface.poll(Instant::now(), &mut dev, &mut sockets);
                for &h in &tcps {
                    let s = sockets.get_mut::<tcp::Socket>(h);
                    let room = s.send_capacity() - s.send_queue();
                    if room > 0 && s.can_recv() {
                        let mut t = vec![0u8; room];
                        let n = s.recv_slice(&mut t).unwrap();
                        s.send_slice(&t[..n]).unwrap();
                    }
                    if s.state() == tcp::State::CloseWait && s.send_queue() == 0 {
                        s.close();
                    }
                    if !s.is_open() {
                        s.listen(7).unwrap();
                    }
                }
                let s = sockets.get_mut::<udp::Socket>(uh);
                let mut got = Vec::new();
                while let Ok((d, m)) = s.recv() {
                    got.push((d.to_vec(), m.endpoint));
                }
                for (d, e) in got {
                    s.send_slice(&d, e).unwrap();
                }
                iface.poll(Instant::now(), &mut dev, &mut sockets);
                for p in dev.tx.drain(..) {
                    if let TunnResult::WriteToNetwork(w) = tunn.encapsulate(&p, &mut out) {
                        wire.push(w.to_vec());
                    }
                }
                if let TunnResult::WriteToNetwork(w) = tunn.update_timers(&mut out) {
                    wire.push(w.to_vec());
                }
                if let Some(to) = peer {
                    for w in wire {
                        let _ = sock.send_to(&w, to).await;
                    }
                }
            }
        });
        Server { addr, task }
    }

    pub(crate) async fn exit_with(conf: &str, opts: WgOptions) -> WgExit {
        let cfg = WgConfig::parse(EXIT_WG, &wg_quick_to_uapi(conf).unwrap()).unwrap();
        let ep = cfg.resolve().await.unwrap();
        WgExit::start(EXIT_WG, cfg, ep, &Direct::new(None), opts).await.unwrap()
    }

    fn quick() -> WgOptions {
        WgOptions { mtu: 1420, dial_timeout: Duration::from_secs(5), handshake_timeout: Duration::from_secs(5) }
    }

    fn echo() -> SocketAddr {
        "10.9.0.1:7".parse().unwrap()
    }

    #[tokio::test]
    async fn tcp_and_udp_go_through_the_tunnel() {
        let srv = server(1, 2).await;
        let x = exit_with(&conf(2, 1, srv.addr, "10.9.0.0/24"), quick()).await;
        assert_eq!(x.status(), TUP);
        assert_eq!(x.dns(), ["10.9.0.1"]);

        // more than the windows hold, both ways at once
        let data: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let c = x.connect(echo()).await.unwrap();
        assert_eq!(x.status(), TOK, "the dial needed a handshake");
        let (mut r, mut w) = tokio::io::split(c);
        let send = data.clone();
        let writer = tokio::spawn(async move {
            w.write_all(&send).await.unwrap();
            w.shutdown().await.unwrap();
            w
        });
        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(20), r.read_to_end(&mut got)).await.unwrap().unwrap();
        assert!(got == data, "echoed {} of {} bytes", got.len(), data.len());
        drop(writer.await.unwrap());

        let u = x.associate(echo()).unwrap();
        u.send(b"ping").await.unwrap();
        let mut b = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(5), u.recv(&mut b)).await.unwrap().unwrap();
        assert_eq!(&b[..n], b"ping");

        let info = Proxies::get(&x, EXIT_WG).unwrap();
        let st = info.stat.unwrap();
        assert_eq!(info.status, TOK);
        assert_eq!(st.addrs, "10.9.0.2/32");
        assert!(st.rx > 300_000 && st.tx > 300_000, "{} {}", st.rx, st.tx);
        assert!(st.last_ok > 0 && st.last_ok <= crate::events::now_ms());
        assert!(Proxies::get(&x, "wgapp1").is_none());

        // a closed port inside the tunnel refuses
        let e = x.connect("10.9.0.1:9".parse().unwrap()).await.err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused, "{e}");
    }

    #[tokio::test]
    async fn dns_dials_go_through_the_exit_only_when_given_it() {
        let srv = server(1, 2).await;
        let x = exit_with(&conf(2, 1, srv.addr, "10.9.0.0/24"), quick()).await;
        let mut s = dns::Dialer::dial_tcp(&x, EXIT_WG, echo()).await.unwrap();
        s.write_all(b"q").await.unwrap();
        let mut b = [0u8; 1];
        s.read_exact(&mut b).await.unwrap();
        let u = dns::Dialer::dial_udp(&x, EXIT_WG, echo()).await.unwrap();
        u.send(b"a").await.unwrap();
        assert_eq!(tokio::time::timeout(Duration::from_secs(5), u.recv(&mut b)).await.unwrap().unwrap(), 1);
        let direct = crate::net::proxy::tests::echo_tcp().await;
        let tx = x.info().stat.unwrap().tx;
        let mut s = dns::Dialer::dial_tcp(&x, crate::exit::BASE, direct).await.unwrap();
        s.write_all(b"q").await.unwrap();
        s.read_exact(&mut b).await.unwrap();
        assert_eq!(x.info().stat.unwrap().tx, tx, "direct is not the exit's traffic");
    }

    #[tokio::test]
    async fn a_wrong_peer_key_fails_the_handshake() {
        let srv = server(1, 2).await;
        // the exit thinks the peer's key is [3; 32]: the server cannot read
        // its handshake and stays silent
        let opts = WgOptions { mtu: 1420, dial_timeout: Duration::from_millis(1500), handshake_timeout: Duration::from_millis(500) };
        let x = exit_with(&conf(2, 3, srv.addr, "10.9.0.0/24"), opts).await;
        let e = x.connect(echo()).await.err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert_eq!(e.to_string(), format!("dial 10.9.0.1:7: wg: no handshake with {}", srv.addr));
        assert_eq!(x.status(), TKO);
        let st = x.info().stat.unwrap();
        assert_eq!((st.rx, st.last_ok), (0, 0));
        assert!(st.tx > 0, "the handshake went out");
    }

    #[tokio::test]
    async fn a_persistent_keepalive_brings_the_tunnel_up_at_once() {
        let srv = server(1, 2).await;
        let x = exit_with(&format!("{}PersistentKeepalive = 25\n", conf(2, 1, srv.addr, "10.9.0.0/24")), quick()).await;
        for _ in 0..200 {
            if x.status() == TOK {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(x.status(), TOK, "no dial, yet a handshake");
        assert!(x.info().stat.unwrap().last_ok > 0);
    }

    #[tokio::test]
    async fn dials_outside_the_config_fail_at_once() {
        let srv = server(1, 2).await;
        let x = exit_with(&conf(2, 1, srv.addr, "10.9.0.0/24, ::/0"), quick()).await;
        let e = x.connect("8.8.8.8:53".parse().unwrap()).await.err().unwrap();
        assert_eq!(e.to_string(), "dial 8.8.8.8:53: wg: 8.8.8.8 is not in the peer's AllowedIPs");
        let e = x.associate("[2001:db8::1]:53".parse().unwrap()).err().unwrap();
        assert_eq!(e.to_string(), "dial [2001:db8::1]:53: wg: the config has no IPv6 Address");
        assert_eq!(x.status(), TUP, "nothing was sent");
    }

    #[test]
    fn config_like_firestack() {
        let k = "c809f3e5317e9575c9b5ed78b638b7ce530dabe85ddab614220241801ddf0669";
        let base = format!("private_key={k}\naddress=10.0.0.2/32, FD00::2\ndns=1.1.1.1, dns.example\nmtu=1420\npublic_key={k}\nendpoint=Vpn.Example:51820\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n");
        let c = WgConfig::parse("wgconf", &base).unwrap();
        assert_eq!(c.addrs.iter().map(|p| p.to_string()).collect::<Vec<_>>(), ["10.0.0.2/32", "fd00::2/128"]);
        assert_eq!(c.dns, ["1.1.1.1", "dns.example"]);
        assert_eq!((c.mtu, c.endpoint.as_str(), c.keepalive), (1420, "vpn.example:51820", Some(25)));
        assert_eq!(c.allowed.len(), 2, "the DNS server's IP is allowed too");
        assert!(c.allowed[0].contains("1.1.1.1".parse().unwrap()) && !c.allowed[0].contains("1.1.1.2".parse().unwrap()));
        assert_eq!(WgConfig::parse("wgconf", &base.replace("mtu=1420", "mtu=auto")).unwrap().mtu, 65535);

        let no_addr = base.replace("address=10.0.0.2/32, FD00::2\n", "");
        let two_peers = format!("{base}public_key={k}\n");
        let no_endpoint = base.replace("endpoint=Vpn.Example:51820\n", "");
        for (txt, want) in [
            (no_addr.as_str(), "proxy: invalid config"),
            ("nonsense\n", "proxy: wg: wgconf failed to parse line \"nonsense\""),
            ("address=10.0.0.300\n", "netip.ParsePrefix(\"10.0.0.300\"): no '/'"),
            ("address=x/24\n", "netip.ParsePrefix(\"x/24\"): ParseAddr(\"x\"): unable to parse IP"),
            ("address=10.0.0.1/33\n", "netip.ParsePrefix(\"10.0.0.1/33\"): prefix length out of range"),
            ("address=10.0.0.1/x\n", "netip.ParsePrefix(\"10.0.0.1/x\"): bad bits after slash: \"x\""),
            ("mtu=big\n", "strconv.Atoi: parsing \"big\": invalid syntax"),
            (two_peers.as_str(), "proxy: wg: wgconf: more than one [Peer] is not supported by this engine yet"),
            (no_endpoint.as_str(), "proxy: wg: wgconf: the [Peer] has no Endpoint"),
        ] {
            assert_eq!(WgConfig::parse("wgconf", txt).unwrap_err(), want, "{txt}");
        }
        // a blank line ends the config, as in Go: what follows is not read
        let cut = base.replace("public_key=", "\npublic_key=");
        assert_eq!(WgConfig::parse("wgconf", &cut).unwrap_err(), "proxy: invalid config");
    }

    #[tokio::test]
    async fn endpoints_resolve() {
        let k = "c809f3e5317e9575c9b5ed78b638b7ce530dabe85ddab614220241801ddf0669";
        let cfg = |ep: &str| WgConfig::parse("wgconf", &format!("private_key={k}\naddress=10.0.0.2\ndns=1.1.1.1\npublic_key={k}\nendpoint={ep}\n")).unwrap();
        assert_eq!(cfg("[::1]:51820").resolve().await.unwrap(), "[::1]:51820".parse().unwrap());
        assert_eq!(cfg("localhost:51820").resolve().await.unwrap().port(), 51820);
        assert_eq!(cfg("vpn.example").resolve().await.unwrap_err(), "endpoint \"vpn.example\": missing port in address");
    }

    /// A program's connection through the stack leaves by the WireGuard
    /// exit when the engine's exit is it; the journal names the exit.
    #[tokio::test]
    async fn forwarder_relays_flows_through_the_tunnel() {
        use crate::engine::Engine;
        use crate::net::forward::{Forwarder, NoOwners};
        use crate::net::stack::tests::{Host, drive};
        use crate::net::stack::{Stack, StackConfig};
        use tokio::sync::mpsc;

        let srv = server(1, 2).await;
        let x = Arc::new(exit_with(&conf(2, 1, srv.addr, "0.0.0.0/0"), quick()).await);
        let e = Arc::new(Engine::with_self(None, "", "C:\\fswin.exe", Box::new(|_| {})));
        e.set_exit(EXIT_WG);
        e.set_proxies(x.clone());
        let (st, io) = Stack::new(StackConfig::default());
        let (to_stack, rx) = mpsc::channel(1024);
        tokio::spawn(st.run(rx));
        let mut from_stack = io.out;
        let f = Arc::new(Forwarder::new(e.clone(), Arc::new(NoOwners), Arc::new(Direct::new(None)), Arc::new(crate::dns::FakeDns::new(e.clone()))));
        f.add_exit(EXIT_WG, x.clone());
        tokio::spawn(f.clone().run(io.flows));

        let mut host = Host::new();
        let h = host.connect(42000, echo());
        drive(&mut host, &to_stack, &mut from_stack, |h2| h2.tcp(h).may_send()).await;
        host.tcp(h).send_slice(b"via wireguard").unwrap();
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
        assert_eq!(got, b"via wireguard");
        let flow = e.log.since(0, 100).into_iter().find(|v| v.kind == "flow").unwrap();
        assert_eq!(flow.via, "WireGuard");
        let ps = e.proxy_stats();
        assert_eq!((ps[0].id.as_str(), ps[0].name.as_str(), ps[0].status.as_str()), (EXIT_WG, "WireGuard", "connected"));
    }
}
