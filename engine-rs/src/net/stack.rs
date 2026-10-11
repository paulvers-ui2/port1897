// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The userspace TCP/IP stack between the adapter and the engine (what
//! gVisor's netstack is to firestack). IP packets come in from Wintun; each
//! new TCP connection and UDP 5-tuple comes out as a `Flow`, and what the
//! engine sends back goes out as IP packets for Wintun.
//!
//! TCP runs on smoltcp (0BSD), one socket per connection, behind our own
//! glue rather than a ready-made netstack crate, for firestack's order: a
//! SYN is held, unanswered, until the engine has decided and dialled; then
//! it is accepted (SYN-ACK) or refused (RST). Retransmitted SYNs meanwhile
//! are dropped. UDP needs no TCP machinery: datagrams are parsed and built
//! here, per 5-tuple.
//!
//! Not yet: ICMP (dropped), IP fragments (dropped; gVisor reassembles them).

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant as StdInstant};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration as SmolDuration, Instant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, TcpPacket, UdpPacket, UdpRepr};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc};

/// A connection's 4-tuple: (the program's end, the remote end).
type Key = (SocketAddr, SocketAddr);

/// The stack's sizes.
#[derive(Debug, Clone)]
pub struct StackConfig {
    /// the adapter's MTU: TCP segments are sized to it
    pub mtu: usize,
    /// smoltcp's receive and send buffer per TCP connection; over 64 KiB
    /// turns window scaling on
    pub tcp_buffer: usize,
    /// bytes staged between a TCP socket and its reader or writer
    pub tcp_stage: usize,
    /// datagrams queued per UDP flow before more are dropped
    pub udp_queue: usize,
    /// how long a connection the engine let go of may take to close
    pub linger: Duration,
}

impl Default for StackConfig {
    fn default() -> Self {
        StackConfig { mtu: 1500, tcp_buffer: 256 << 10, tcp_stage: 64 << 10, udp_queue: 128, linger: Duration::from_secs(60) }
    }
}

/// A new flow for the engine to decide.
pub enum Flow {
    Tcp(TcpRequest),
    Udp(UdpFlow),
}

enum Cmd {
    Accept { key: Key, syn: Vec<u8>, conn: Arc<Mutex<Conn>> },
    Refuse { key: Key, syn: Vec<u8> },
}

/// A program's TCP connection attempt, its SYN held until accepted or
/// refused. Dropped undecided, it is refused.
pub struct TcpRequest {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    syn: Option<Vec<u8>>,
    cmd: mpsc::UnboundedSender<Cmd>,
    notify: Arc<Notify>,
    stage: usize,
}

impl TcpRequest {
    /// Completes the handshake; the connection's data flows through the
    /// returned stream.
    pub fn accept(mut self) -> TcpFlow {
        let conn = Arc::new(Mutex::new(Conn::default()));
        if let Some(syn) = self.syn.take() {
            let _ = self.cmd.send(Cmd::Accept { key: (self.src, self.dst), syn, conn: conn.clone() });
        } else {
            conn.lock().unwrap_or_else(|e| e.into_inner()).closed = true;
        }
        TcpFlow { src: self.src, dst: self.dst, conn, notify: self.notify.clone(), cap: self.stage }
    }

    /// Answers the SYN with a reset, as a closed port does.
    pub fn refuse(mut self) {
        self.refuse_now();
    }

    fn refuse_now(&mut self) {
        if let Some(syn) = self.syn.take() {
            let _ = self.cmd.send(Cmd::Refuse { key: (self.src, self.dst), syn });
        }
    }
}

impl Drop for TcpRequest {
    fn drop(&mut self) {
        self.refuse_now();
    }
}

/// What a TCP connection and its stream share.
#[derive(Default)]
struct Conn {
    /// from the program, not yet read
    rx: VecDeque<u8>,
    /// the program sent its FIN (or the connection is gone)
    rx_eof: bool,
    rx_waker: Option<Waker>,
    /// to the program, not yet in the socket
    tx: VecDeque<u8>,
    tx_waker: Option<Waker>,
    /// the stream was shut down for writing: FIN once tx is sent
    shut_wr: bool,
    fin_sent: bool,
    /// the stream was dropped: close once tx is sent, discard input
    dropped: Option<StdInstant>,
    /// reset the connection
    abort: bool,
    /// the socket is gone
    closed: bool,
    /// it went with a reset rather than both FINs
    reset: bool,
}

impl Conn {
    fn wake_rx(&mut self) {
        if let Some(w) = self.rx_waker.take() {
            w.wake();
        }
    }
    fn wake_tx(&mut self) {
        if let Some(w) = self.tx_waker.take() {
            w.wake();
        }
    }
}

fn lock(c: &Mutex<Conn>) -> std::sync::MutexGuard<'_, Conn> {
    c.lock().unwrap_or_else(|e| e.into_inner())
}

/// An accepted TCP connection, as a tokio stream: reads give what the
/// program sends, writes go to it. Shutdown sends a FIN once the written
/// data is out; drop closes it the same way.
pub struct TcpFlow {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    conn: Arc<Mutex<Conn>>,
    notify: Arc<Notify>,
    cap: usize,
}

impl TcpFlow {
    /// Resets the connection, as firestack does for one closed by a rule.
    pub fn abort(&self) {
        lock(&self.conn).abort = true;
        self.notify.notify_one();
    }

    /// Whether the connection ended with a reset.
    pub fn was_reset(&self) -> bool {
        lock(&self.conn).reset
    }

    /// A handle that resets the connection later, once the stream itself
    /// is split into halves for the relay.
    pub fn aborter(&self) -> Aborter {
        Aborter { conn: self.conn.clone(), notify: self.notify.clone() }
    }
}

/// Resets a TCP connection whose stream is elsewhere.
#[derive(Clone)]
pub struct Aborter {
    conn: Arc<Mutex<Conn>>,
    notify: Arc<Notify>,
}

impl Aborter {
    pub fn abort(&self) {
        lock(&self.conn).abort = true;
        self.notify.notify_one();
    }
}

impl AsyncRead for TcpFlow {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut c = lock(&self.conn);
        if c.rx.is_empty() {
            if c.reset {
                return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
            }
            if c.rx_eof || c.closed {
                return Poll::Ready(Ok(()));
            }
            c.rx_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = buf.remaining().min(c.rx.len());
        let (a, b) = c.rx.as_slices();
        let na = n.min(a.len());
        buf.put_slice(&a[..na]);
        buf.put_slice(&b[..n - na]);
        c.rx.drain(..n);
        drop(c);
        // room again: the stack may take more from the socket
        self.notify.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TcpFlow {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let mut c = lock(&self.conn);
        if c.reset {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        if c.closed || c.shut_wr || c.abort {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let room = self.cap.saturating_sub(c.tx.len());
        if room == 0 {
            c.tx_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = room.min(data.len());
        c.tx.extend(&data[..n]);
        drop(c);
        self.notify.notify_one();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        lock(&self.conn).shut_wr = true;
        self.notify.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpFlow {
    fn drop(&mut self) {
        let mut c = lock(&self.conn);
        c.dropped = Some(StdInstant::now());
        c.rx.clear();
        drop(c);
        self.notify.notify_one();
    }
}

/// A UDP 5-tuple's datagrams. Dropped, the stack forgets the tuple: its
/// next datagram starts a new flow.
pub struct UdpFlow {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    rx: mpsc::Receiver<Vec<u8>>,
    reply: UdpReply,
}

impl UdpFlow {
    /// The next datagram the program sent; None once the stack stopped.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }

    /// Sends datagrams back to the program, from dst.
    pub fn reply(&self) -> UdpReply {
        self.reply.clone()
    }
}

/// Sends datagrams to a program, from the remote end of its flow.
#[derive(Clone)]
pub struct UdpReply {
    from: SocketAddr,
    to: SocketAddr,
    out: mpsc::Sender<Vec<u8>>,
}

impl UdpReply {
    /// Queues payload for the adapter; false if it could not be (the
    /// stack stopped, or its queue is full: UDP may drop).
    pub fn send(&self, payload: &[u8]) -> bool {
        match build_udp(self.from, self.to, payload) {
            Some(p) => self.out.try_send(p).is_ok(),
            None => false,
        }
    }
}

/// An IP packet carrying a UDP datagram from src to dst (both of one
/// family), with checksums.
pub fn build_udp(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let udp_len = 8 + payload.len();
    let caps = ChecksumCapabilities::default();
    let udp = UdpRepr { src_port: src.port(), dst_port: dst.port() };
    let (s, d) = (IpAddress::from(src.ip()), IpAddress::from(dst.ip()));
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            if udp_len > 65535 - 20 {
                return None;
            }
            let ip = Ipv4Repr { src_addr: a, dst_addr: b, next_header: IpProtocol::Udp, payload_len: udp_len, hop_limit: 64 };
            let mut buf = vec![0u8; 20 + udp_len];
            ip.emit(&mut Ipv4Packet::new_unchecked(&mut buf[..]), &caps);
            udp.emit(&mut UdpPacket::new_unchecked(&mut buf[20..]), &s, &d, payload.len(), |p| p.copy_from_slice(payload), &caps);
            Some(buf)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            if udp_len > 65535 {
                return None;
            }
            let ip = Ipv6Repr { src_addr: a, dst_addr: b, next_header: IpProtocol::Udp, payload_len: udp_len, hop_limit: 64 };
            let mut buf = vec![0u8; 40 + udp_len];
            ip.emit(&mut Ipv6Packet::new_unchecked(&mut buf[..]));
            udp.emit(&mut UdpPacket::new_unchecked(&mut buf[40..]), &s, &d, payload.len(), |p| p.copy_from_slice(payload), &caps);
            Some(buf)
        }
        _ => None,
    }
}

/// What an IP packet is, as far as the stack routes it.
#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    /// a TCP segment: syn is true for a SYN without ACK
    Tcp { src: SocketAddr, dst: SocketAddr, syn: bool },
    /// a UDP datagram and where its payload is in the packet
    Udp { src: SocketAddr, dst: SocketAddr, payload: std::ops::Range<usize> },
    /// anything else: other protocols, fragments, bad packets
    Other,
}

/// Parses an IP packet's addresses and ports; checksums of UDP are checked
/// (TCP's are, by smoltcp).
pub fn parse(p: &[u8]) -> Parsed {
    let (src, dst, proto, off) = match p.first().map(|b| b >> 4) {
        Some(4) => {
            let Ok(ip) = Ipv4Packet::new_checked(p) else { return Parsed::Other };
            if ip.more_frags() || ip.frag_offset() != 0 || !ip.verify_checksum() {
                return Parsed::Other;
            }
            (IpAddr::V4(ip.src_addr()), IpAddr::V4(ip.dst_addr()), ip.next_header(), ip.header_len() as usize)
        }
        Some(6) => {
            let Ok(ip) = Ipv6Packet::new_checked(p) else { return Parsed::Other };
            // extension headers (fragments among them) are not followed
            (IpAddr::V6(ip.src_addr()), IpAddr::V6(ip.dst_addr()), ip.next_header(), 40)
        }
        _ => return Parsed::Other,
    };
    let body = match p.get(off..) {
        Some(b) => b,
        None => return Parsed::Other,
    };
    match proto {
        IpProtocol::Tcp => {
            let Ok(t) = TcpPacket::new_checked(body) else { return Parsed::Other };
            Parsed::Tcp { src: SocketAddr::new(src, t.src_port()), dst: SocketAddr::new(dst, t.dst_port()), syn: t.syn() && !t.ack() }
        }
        IpProtocol::Udp => {
            let Ok(u) = UdpPacket::new_checked(body) else { return Parsed::Other };
            let (s, d) = (IpAddress::from(src), IpAddress::from(dst));
            if UdpRepr::parse(&u, &s, &d, &ChecksumCapabilities::default()).is_err() {
                return Parsed::Other;
            }
            let start = off + 8;
            let end = off + u.len() as usize;
            Parsed::Udp { src: SocketAddr::new(src, u.src_port()), dst: SocketAddr::new(dst, u.dst_port()), payload: start..end }
        }
        _ => Parsed::Other,
    }
}

/// smoltcp's view of the adapter: packets queued in, packets collected out.
struct QueueDevice {
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

impl Device for QueueDevice {
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

/// The stack's ends for the engine: flows to decide and the packets to
/// write to the adapter.
pub struct StackIo {
    /// new TCP connections and UDP flows
    pub flows: mpsc::Receiver<Flow>,
    /// IP packets for the adapter
    pub out: mpsc::Receiver<Vec<u8>>,
}

/// The stack itself, run as one task by `run`.
pub struct Stack {
    cfg: StackConfig,
    iface: Interface,
    sockets: SocketSet<'static>,
    dev: QueueDevice,
    tcp: HashMap<Key, (SocketHandle, Arc<Mutex<Conn>>)>,
    pending: HashSet<Key>,
    udp: HashMap<Key, mpsc::Sender<Vec<u8>>>,
    flows: mpsc::Sender<Flow>,
    out: mpsc::Sender<Vec<u8>>,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    notify: Arc<Notify>,
    swept: StdInstant,
}

fn seed() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    // the OS-random keys std gives each RandomState; ISNs need no more
    let mut h = std::hash::RandomState::new().build_hasher();
    h.write_u64(StdInstant::now().elapsed().as_nanos() as u64);
    h.finish()
}

impl Stack {
    /// A stack and its ends. Packets from the adapter go to `run`.
    pub fn new(cfg: StackConfig) -> (Stack, StackIo) {
        let (flows_tx, flows) = mpsc::channel(1024);
        let (out_tx, out) = mpsc::channel(4096);
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let mut dev = QueueDevice { rx: VecDeque::new(), tx: Vec::new(), mtu: cfg.mtu };
        let mut c = Config::new(HardwareAddress::Ip);
        c.random_seed = seed();
        let mut iface = Interface::new(c, &mut dev, Instant::now());
        // any address is ours: every connection the programs make ends here
        iface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0));
            let _ = a.push(IpCidr::new(IpAddress::v6(0xfd00, 0, 0, 0, 0, 0, 0, 1), 0));
        });
        let _ = iface.routes_mut().add_default_ipv4_route(std::net::Ipv4Addr::new(0, 0, 0, 1));
        let _ = iface.routes_mut().add_default_ipv6_route(std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        iface.set_any_ip(true);
        let st = Stack {
            cfg,
            iface,
            sockets: SocketSet::new(vec![]),
            dev,
            tcp: HashMap::new(),
            pending: HashSet::new(),
            udp: HashMap::new(),
            flows: flows_tx,
            out: out_tx,
            cmd_tx,
            cmd_rx,
            notify: Arc::new(Notify::new()),
            swept: StdInstant::now(),
        };
        (st, StackIo { flows, out })
    }

    /// Runs until packets stops (the adapter closed); then every
    /// connection reads EOF and every write fails.
    pub async fn run(mut self, mut packets: mpsc::Receiver<Vec<u8>>) {
        loop {
            let delay = self.iface.poll_delay(Instant::now(), &self.sockets).map(Duration::from).unwrap_or(Duration::from_secs(1)).min(Duration::from_secs(1));
            tokio::select! {
                biased;
                c = self.cmd_rx.recv() => {
                    if let Some(c) = c {
                        self.command(c);
                    }
                }
                p = packets.recv() => {
                    let Some(p) = p else { break };
                    self.packet(p);
                    // a burst in one go
                    for _ in 0..256 {
                        match packets.try_recv() {
                            Ok(p) => self.packet(p),
                            Err(_) => break,
                        }
                    }
                }
                _ = self.notify.notified() => {}
                _ = tokio::time::sleep(delay) => {}
            }
            self.pump();
        }
        for (_, (_, c)) in self.tcp.drain() {
            let mut c = lock(&c);
            c.closed = true;
            c.rx_eof = true;
            c.wake_rx();
            c.wake_tx();
        }
    }

    fn packet(&mut self, p: Vec<u8>) {
        match parse(&p) {
            Parsed::Tcp { src, dst, syn } => {
                let key = (src, dst);
                if self.tcp.contains_key(&key) {
                    self.dev.rx.push_back(p);
                } else if syn {
                    if self.pending.insert(key) {
                        let req = TcpRequest { src, dst, syn: Some(p), cmd: self.cmd_tx.clone(), notify: self.notify.clone(), stage: self.cfg.tcp_stage };
                        if let Err(e) = self.flows.try_send(Flow::Tcp(req)) {
                            // overloaded: refused (on drop) rather than held
                            drop(e);
                        }
                    } // else a retransmitted SYN while the engine decides
                } else {
                    // no such connection: smoltcp answers with a reset
                    self.dev.rx.push_back(p);
                }
            }
            Parsed::Udp { src, dst, payload } => {
                let key = (src, dst);
                let data = p[payload].to_vec();
                if let Some(tx) = self.udp.get(&key) {
                    match tx.try_send(data) {
                        Ok(()) => (),
                        Err(mpsc::error::TrySendError::Full(_)) => (),
                        Err(mpsc::error::TrySendError::Closed(d)) => {
                            self.udp.remove(&key);
                            self.new_udp(key, d);
                        }
                    }
                } else {
                    self.new_udp(key, data);
                }
            }
            Parsed::Other => {}
        }
    }

    fn new_udp(&mut self, key: Key, first: Vec<u8>) {
        let (tx, rx) = mpsc::channel(self.cfg.udp_queue);
        let _ = tx.try_send(first);
        let f = UdpFlow { src: key.0, dst: key.1, rx, reply: UdpReply { from: key.1, to: key.0, out: self.out.clone() } };
        if self.flows.try_send(Flow::Udp(f)).is_ok() {
            self.udp.insert(key, tx);
        }
    }

    fn command(&mut self, c: Cmd) {
        match c {
            Cmd::Refuse { key, syn } => {
                self.pending.remove(&key);
                // no socket listens for it: smoltcp resets it
                self.dev.rx.push_back(syn);
            }
            Cmd::Accept { key, syn, conn } => {
                self.pending.remove(&key);
                // A listening socket takes any SYN to its address and port,
                // so nothing else may be queued when it gets this one.
                self.pump();
                let n = self.cfg.tcp_buffer;
                let mut s = tcp::Socket::new(tcp::SocketBuffer::new(vec![0u8; n]), tcp::SocketBuffer::new(vec![0u8; n]));
                s.set_nagle_enabled(false);
                // a program that vanished mid-connection is given up on
                s.set_timeout(Some(SmolDuration::from_secs(120)));
                s.set_keep_alive(Some(SmolDuration::from_secs(60)));
                if s.listen(key.1).is_err() {
                    lock(&conn).closed = true;
                    self.dev.rx.push_back(syn);
                    return;
                }
                let h = self.sockets.add(s);
                self.tcp.insert(key, (h, conn));
                self.dev.rx.push_back(syn);
            }
        }
    }

    /// Lets smoltcp process what came in, moves data between the sockets
    /// and their streams, and sends what smoltcp wrote.
    fn pump(&mut self) {
        let now = Instant::now();
        self.iface.poll(now, &mut self.dev, &mut self.sockets);
        if self.service() {
            self.iface.poll(Instant::now(), &mut self.dev, &mut self.sockets);
        }
        for p in self.dev.tx.drain(..) {
            // a full queue drops, as a busy link would; TCP sends again
            let _ = self.out.try_send(p);
        }
        if self.swept.elapsed() > Duration::from_secs(10) {
            self.swept = StdInstant::now();
            self.udp.retain(|_, tx| !tx.is_closed());
        }
    }

    /// Returns whether a socket was given data or closed (worth another
    /// poll).
    fn service(&mut self) -> bool {
        let mut more = false;
        let cap = self.cfg.tcp_stage;
        let linger = self.cfg.linger;
        let mut gone = Vec::new();
        for (key, (h, conn)) in self.tcp.iter() {
            let s = self.sockets.get_mut::<tcp::Socket>(*h);
            let mut c = lock(conn);
            // a socket closed now still has its RST to send at the next poll
            let was_closed = s.state() == tcp::State::Closed;
            if c.abort && s.state() != tcp::State::Closed {
                s.abort();
                c.reset = true;
                more = true;
            }
            if c.dropped.is_some_and(|t| t.elapsed() > linger) && s.state() != tcp::State::Closed {
                s.abort();
                more = true;
            }
            // from the program
            let mut woke = false;
            while s.can_recv() {
                let discard = c.dropped.is_some();
                let room = if discard { usize::MAX } else { cap.saturating_sub(c.rx.len()) };
                if room == 0 {
                    break;
                }
                let r = s.recv(|b| {
                    let n = b.len().min(room);
                    if !discard {
                        c.rx.extend(&b[..n]);
                    }
                    (n, n)
                });
                match r {
                    Ok(0) | Err(_) => break,
                    Ok(_) => woke = true,
                }
            }
            let st = s.state();
            if !s.may_recv() && !matches!(st, tcp::State::Listen | tcp::State::SynReceived | tcp::State::SynSent) && !c.rx_eof {
                c.rx_eof = true;
                woke = true;
            }
            if woke {
                c.wake_rx();
            }
            // to the program
            let mut sent = false;
            while s.can_send() && !c.tx.is_empty() {
                let r = s.send(|b| {
                    let n = b.len().min(c.tx.len());
                    let (x, y) = c.tx.as_slices();
                    let nx = n.min(x.len());
                    b[..nx].copy_from_slice(&x[..nx]);
                    b[nx..n].copy_from_slice(&y[..n - nx]);
                    c.tx.drain(..n);
                    (n, n)
                });
                match r {
                    Ok(0) | Err(_) => break,
                    Ok(_) => sent = true,
                }
            }
            if sent {
                more = true;
                c.wake_tx();
            }
            if (c.shut_wr || c.dropped.is_some()) && c.tx.is_empty() && !c.fin_sent && s.may_send() {
                s.close();
                c.fin_sent = true;
                more = true;
            }
            if s.state() == tcp::State::Closed {
                // closed without both FINs: a reset either way
                if !(c.rx_eof && c.fin_sent) {
                    c.reset = true;
                }
                c.closed = true;
                c.rx_eof = true;
                c.wake_rx();
                c.wake_tx();
                if was_closed {
                    gone.push(*key);
                } else {
                    more = true;
                }
            }
        }
        for k in gone {
            if let Some((h, _)) = self.tcp.remove(&k) {
                self.sockets.remove(h);
            }
        }
        more
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// A TCP/IP host on the other side of the adapter (the programs'
    /// Windows), on smoltcp too.
    pub(crate) struct Host {
        iface: Interface,
        dev: QueueDevice,
        pub sockets: SocketSet<'static>,
    }

    impl Host {
        pub(crate) fn new() -> Host {
            let mut dev = QueueDevice { rx: VecDeque::new(), tx: Vec::new(), mtu: 1500 };
            let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut dev, Instant::now());
            iface.update_ip_addrs(|a| {
                let _ = a.push(IpCidr::new(IpAddress::v4(10, 111, 222, 1), 24));
            });
            let _ = iface.routes_mut().add_default_ipv4_route(Ipv4Addr::new(10, 111, 222, 2));
            Host { iface, dev, sockets: SocketSet::new(vec![]) }
        }

        pub(crate) fn connect(&mut self, local: u16, remote: SocketAddr) -> SocketHandle {
            let mut s = tcp::Socket::new(tcp::SocketBuffer::new(vec![0u8; 65536]), tcp::SocketBuffer::new(vec![0u8; 65536]));
            s.connect(self.iface.context(), remote, (IpAddress::v4(10, 111, 222, 1), local)).unwrap();
            self.sockets.add(s)
        }

        pub(crate) fn tcp(&mut self, h: SocketHandle) -> &mut tcp::Socket<'static> {
            self.sockets.get_mut::<tcp::Socket>(h)
        }

        /// Polls; returns the packets it sent.
        pub(crate) fn poll(&mut self, input: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
            self.dev.rx.extend(input);
            self.iface.poll(Instant::now(), &mut self.dev, &mut self.sockets);
            std::mem::take(&mut self.dev.tx)
        }
    }

    /// Runs the host against the stack until done says so or 5 s pass.
    pub(crate) async fn drive(host: &mut Host, to_stack: &mpsc::Sender<Vec<u8>>, from_stack: &mut mpsc::Receiver<Vec<u8>>, mut done: impl FnMut(&mut Host) -> bool) {
        let end = StdInstant::now() + Duration::from_secs(5);
        let mut input = Vec::new();
        loop {
            for p in host.poll(std::mem::take(&mut input)) {
                to_stack.send(p).await.unwrap();
            }
            if done(host) {
                return;
            }
            assert!(StdInstant::now() < end, "timed out");
            match tokio::time::timeout(Duration::from_millis(10), from_stack.recv()).await {
                Ok(Some(p)) => {
                    input.push(p);
                    while let Ok(p) = from_stack.try_recv() {
                        input.push(p);
                    }
                }
                Ok(None) => panic!("stack stopped"),
                Err(_) => {}
            }
        }
    }

    fn start(cfg: StackConfig) -> (mpsc::Sender<Vec<u8>>, StackIo) {
        let (st, io) = Stack::new(cfg);
        let (tx, rx) = mpsc::channel(1024);
        tokio::spawn(st.run(rx));
        (tx, io)
    }

    #[test]
    fn udp_packets_round_trip() {
        let p = build_udp(sa("10.111.222.1:5000"), sa("1.2.3.4:53"), b"hello").unwrap();
        assert_eq!(p.len(), 20 + 8 + 5);
        match parse(&p) {
            Parsed::Udp { src, dst, payload } => {
                assert_eq!((src, dst), (sa("10.111.222.1:5000"), sa("1.2.3.4:53")));
                assert_eq!(&p[payload], b"hello");
            }
            o => panic!("{o:?}"),
        }
        let mut bad = p.clone();
        bad[30] ^= 1; // payload changed, checksum not
        assert_eq!(parse(&bad), Parsed::Other);
        let p6 = build_udp(sa("[fd00::1]:5000"), sa("[2001:db8::1]:443"), b"x").unwrap();
        assert!(matches!(parse(&p6), Parsed::Udp { .. }));
        assert_eq!(build_udp(sa("10.0.0.1:1"), sa("[::1]:1"), b""), None);
        assert_eq!(parse(&[0x45, 0]), Parsed::Other);
        assert_eq!(parse(&[]), Parsed::Other);
    }

    #[tokio::test]
    async fn tcp_accepted_flow_carries_data_both_ways() {
        let (to_stack, mut io) = start(StackConfig::default());
        let mut host = Host::new();
        let dst = sa("198.51.100.7:80");
        let h = host.connect(40000, dst);
        // the SYN goes in; the stack holds it and hands out the request
        for p in host.poll(vec![]) {
            to_stack.send(p).await.unwrap();
        }
        let Some(Flow::Tcp(req)) = io.flows.recv().await else { panic!("no tcp flow") };
        assert_eq!((req.src, req.dst), (sa("10.111.222.1:40000"), dst));
        // a retransmitted SYN while undecided makes no second request
        assert!(io.flows.try_recv().is_err());
        let mut flow = req.accept();
        drive(&mut host, &to_stack, &mut io.out, |h2| h2.tcp(h).may_send()).await;
        host.tcp(h).send_slice(b"ping").unwrap();
        let reader = tokio::spawn(async move {
            let mut b = [0u8; 4];
            flow.read_exact(&mut b).await.unwrap();
            assert_eq!(&b, b"ping");
            flow.write_all(b"pong!").await.unwrap();
            flow.shutdown().await.unwrap();
            flow
        });
        let mut got = Vec::new();
        drive(&mut host, &to_stack, &mut io.out, |h2| {
            let s = h2.tcp(h);
            while s.can_recv() {
                let mut b = [0u8; 64];
                let n = s.recv_slice(&mut b).unwrap();
                got.extend_from_slice(&b[..n]);
            }
            !s.may_recv() && got.len() == 5
        })
        .await;
        assert_eq!(got, b"pong!");
        let flow = reader.await.unwrap();
        host.tcp(h).close();
        let mut flow = flow;
        drive(&mut host, &to_stack, &mut io.out, |h2| matches!(h2.tcp(h).state(), tcp::State::TimeWait | tcp::State::Closed)).await;
        let mut b = [0u8; 1];
        assert_eq!(tokio::time::timeout(Duration::from_secs(2), flow.read(&mut b)).await.unwrap().unwrap(), 0);
    }

    #[tokio::test]
    async fn tcp_refused_flow_is_reset() {
        let (to_stack, mut io) = start(StackConfig::default());
        let mut host = Host::new();
        let h = host.connect(40001, sa("198.51.100.8:443"));
        for p in host.poll(vec![]) {
            to_stack.send(p).await.unwrap();
        }
        let Some(Flow::Tcp(req)) = io.flows.recv().await else { panic!("no tcp flow") };
        drop(req); // undecided = refused
        drive(&mut host, &to_stack, &mut io.out, |h2| h2.tcp(h).state() == tcp::State::Closed).await;
    }

    #[tokio::test]
    async fn tcp_abort_resets_the_program() {
        let (to_stack, mut io) = start(StackConfig::default());
        let mut host = Host::new();
        let h = host.connect(40002, sa("198.51.100.9:22"));
        for p in host.poll(vec![]) {
            to_stack.send(p).await.unwrap();
        }
        let Some(Flow::Tcp(req)) = io.flows.recv().await else { panic!("no tcp flow") };
        let flow = req.accept();
        drive(&mut host, &to_stack, &mut io.out, |h2| h2.tcp(h).may_send()).await;
        flow.abort();
        drive(&mut host, &to_stack, &mut io.out, |h2| h2.tcp(h).state() == tcp::State::Closed).await;
        assert!(flow.was_reset());
    }

    #[tokio::test]
    async fn udp_flow_per_tuple_and_replies() {
        let (to_stack, mut io) = start(StackConfig::default());
        let (a, b) = (sa("10.111.222.1:5353"), sa("203.0.113.5:9999"));
        to_stack.send(build_udp(a, b, b"one").unwrap()).await.unwrap();
        to_stack.send(build_udp(a, b, b"two").unwrap()).await.unwrap();
        let Some(Flow::Udp(mut f)) = io.flows.recv().await else { panic!("no udp flow") };
        assert_eq!((f.src, f.dst), (a, b));
        assert_eq!(f.recv().await.unwrap(), b"one");
        assert_eq!(f.recv().await.unwrap(), b"two");
        assert!(f.reply().send(b"back"));
        let p = io.out.recv().await.unwrap();
        let Parsed::Udp { src, dst, payload } = parse(&p) else { panic!("not udp") };
        assert_eq!((src, dst, &p[payload]), (b, a, &b"back"[..]));
        // a dropped flow is forgotten: the next datagram is a new flow
        drop(f);
        to_stack.send(build_udp(a, b, b"three").unwrap()).await.unwrap();
        let Some(Flow::Udp(mut f)) = io.flows.recv().await else { panic!("no new udp flow") };
        assert_eq!(f.recv().await.unwrap(), b"three");
    }

    #[tokio::test]
    async fn stack_stops_with_the_adapter() {
        let (st, io) = Stack::new(StackConfig::default());
        let (tx, rx) = mpsc::channel(4);
        let t = tokio::spawn(st.run(rx));
        drop(tx);
        tokio::time::timeout(Duration::from_secs(2), t).await.unwrap().unwrap();
        drop(io);
    }
}
