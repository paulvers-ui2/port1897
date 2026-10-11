// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! What firestack's TCP and UDP handlers do with each flow the stack hands
//! out: find the program behind it, ask the engine (Preflow, Flow), then
//! refuse it, answer it here (DNS to 10.111.222.3:53), or dial out and copy
//! both ways; when it ends, the engine hears of it (OnSocketClosed) with the
//! bytes each way, as the journal and the traffic counters need.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, mpsc};

use super::dial::Dialer;
use super::stack::{Flow, TcpFlow, TcpRequest, UdpFlow};
use crate::dns::{BoxStream, Resolver, msg};
use crate::engine::{Closer, Engine, FAKEDNS4, Mark, Owners, SocketSummary, UNKNOWN_UID};
use crate::exit::{BASE, BLOCK};

/// How long a UDP flow may sit idle before it is closed (firestack's
/// default UDP timeout).
pub const UDP_IDLE: Duration = Duration::from_secs(120);
/// How long a DNS-over-TCP connection to our address may sit idle.
pub const DNS_TCP_IDLE: Duration = Duration::from_secs(10);
/// Remembered answers, at most; then the map starts afresh.
const MAX_DOMAINS: usize = 20_000;

/// The names DNS answers gave each address, so a flow to an address can be
/// matched against domain rules (firestack's per-IP domain cache).
#[derive(Default)]
pub struct DomainMap(Mutex<HashMap<IpAddr, Vec<String>>>);

impl DomainMap {
    /// Records an answer: every A/AAAA address in it maps to its name.
    pub fn record(&self, answer: &[u8]) {
        let Ok(m) = msg::parse(answer) else { return };
        let name = msg::qname(&m);
        let name = name.trim_end_matches('.');
        if name.is_empty() {
            return;
        }
        let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= MAX_DOMAINS {
            map.clear();
        }
        for ip in msg::ips(&m) {
            let v = map.entry(ip).or_default();
            // the latest name first, each once
            v.retain(|n| n != name);
            v.insert(0, name.to_string());
            v.truncate(8);
        }
    }

    /// The names of ip, as a csv; "" if none.
    pub fn get(&self, ip: IpAddr) -> String {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).get(&ip).map(|v| v.join(",")).unwrap_or_default()
    }
}

/// No owner tables (tests, and systems without them): every flow's
/// program is unknown.
pub struct NoOwners;

impl Owners for NoOwners {
    fn tcp4(&self, _: SocketAddr, _: SocketAddr) -> Result<u32, String> {
        Err("no owner tables".into())
    }
    fn udp4(&self, _: SocketAddr) -> Result<u32, String> {
        Err("no owner tables".into())
    }
    fn exe_path(&self, _: u32) -> Result<String, String> {
        Err("no owner tables".into())
    }
}

/// The handlers' shared state.
pub struct Forwarder {
    engine: Arc<Engine>,
    owners: Arc<dyn Owners>,
    /// Base: the physical interface
    direct: Arc<dyn Dialer>,
    /// the exits (and later the routes) by proxy id
    exits: Mutex<HashMap<String, Arc<dyn Dialer>>>,
    resolver: Arc<dyn Resolver>,
    pub domains: DomainMap,
    /// open connections by id, each with what ends it
    live: Mutex<HashMap<String, Arc<Notify>>>,
    pub udp_idle: Duration,
    fake_dns: SocketAddr,
}

impl Forwarder {
    pub fn new(engine: Arc<Engine>, owners: Arc<dyn Owners>, dialer: Arc<dyn Dialer>, resolver: Arc<dyn Resolver>) -> Forwarder {
        let fake_dns = SocketAddr::new(FAKEDNS4.parse().unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(10, 111, 222, 3))), 53);
        Forwarder {
            engine,
            owners,
            direct: dialer,
            exits: Mutex::new(HashMap::new()),
            resolver,
            domains: DomainMap::default(),
            live: Mutex::new(HashMap::new()),
            udp_idle: UDP_IDLE,
            fake_dns,
        }
    }

    /// Sends the flows the engine marks with proxy id through d.
    pub fn add_exit(&self, id: &str, d: Arc<dyn Dialer>) {
        self.exits.lock().unwrap_or_else(|e| e.into_inner()).insert(id.to_string(), d);
    }

    /// The dialer for a flow's proxy id; None for an exit that is not here.
    fn dialer(&self, pid: &str) -> Option<Arc<dyn Dialer>> {
        if pid == BASE {
            return Some(self.direct.clone());
        }
        self.exits.lock().unwrap_or_else(|e| e.into_inner()).get(pid).cloned()
    }

    /// The tunnel's CloseConns for the engine: closes the connections in a
    /// csv of ids and returns the csv of those that were open.
    pub fn closer(self: &Arc<Self>) -> Closer {
        let me = Arc::downgrade(self);
        Arc::new(move |csv: &str| match me.upgrade() {
            Some(f) => f.close_ids(csv),
            None => String::new(),
        })
    }

    pub fn close_ids(&self, csv: &str) -> String {
        let live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        let mut closed = Vec::new();
        for id in csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if let Some(n) = live.get(id) {
                n.notify_one();
                closed.push(id);
            }
        }
        closed.join(",")
    }

    /// Ends every open connection (the tunnel is going).
    pub fn close_all(&self) {
        for n in self.live.lock().unwrap_or_else(|e| e.into_inner()).values() {
            n.notify_one();
        }
    }

    /// How many connections are open.
    pub fn open(&self) -> usize {
        self.live.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Handles every flow until the stack stops.
    pub async fn run(self: Arc<Self>, mut flows: mpsc::Receiver<Flow>) {
        while let Some(f) = flows.recv().await {
            let me = self.clone();
            match f {
                Flow::Tcp(req) => tokio::spawn(me.tcp(req)),
                Flow::Udp(u) => tokio::spawn(me.udp(u)),
            };
        }
    }

    /// The uid of the program behind a flow, and whether it is the engine
    /// itself. The owner tables are read off the async workers.
    async fn owner(&self, proto: i32, src: SocketAddr, dst: SocketAddr) -> (i32, bool) {
        let (e, o) = (self.engine.clone(), self.owners.clone());
        let pre = tokio::task::spawn_blocking(move || e.preflow(o.as_ref(), proto, &src.to_string(), &dst.to_string())).await;
        match pre {
            Ok(p) => (p.uid.parse().unwrap_or(UNKNOWN_UID), p.is_uid_self),
            Err(_) => (UNKNOWN_UID, false),
        }
    }

    async fn decide(&self, proto: i32, src: SocketAddr, dst: SocketAddr) -> Mark {
        let (uid, is_self) = self.owner(proto, src, dst).await;
        let doms = self.domains.get(dst.ip());
        let mut m = self.engine.flow(proto, uid, &src.to_string(), &dst.to_string(), &doms, "");
        // the engine's own sockets never take the exit: that would loop
        if is_self && m.pid != BLOCK {
            m.pid = BASE.to_string();
        }
        m
    }

    fn track(&self, cid: &str) -> Arc<Notify> {
        let n = Arc::new(Notify::new());
        self.live.lock().unwrap_or_else(|e| e.into_inner()).insert(cid.to_string(), n.clone());
        n
    }

    fn untrack(&self, cid: &str) {
        self.live.lock().unwrap_or_else(|e| e.into_inner()).remove(cid);
    }

    fn closed(&self, proto: &str, m: &Mark, dst: SocketAddr, (rx, tx): (i64, i64), began: Instant, why: &str) {
        self.untrack(&m.cid);
        self.engine.on_socket_closed(&SocketSummary {
            proto: proto.to_string(),
            id: m.cid.clone(),
            pid: m.pid.clone(),
            uid: m.uid.clone(),
            target: dst.to_string(),
            rx,
            tx,
            duration: began.elapsed().as_millis() as i64,
            msg: why.to_string(),
        });
    }

    async fn tcp(self: Arc<Self>, req: TcpRequest) {
        let (src, dst) = (req.src, req.dst);
        let m = self.decide(6, src, dst).await;
        if m.pid == BLOCK {
            req.refuse();
            return;
        }
        if dst == self.fake_dns {
            self.dns_tcp(req.accept(), &m.uid).await;
            return;
        }
        let began = Instant::now();
        let Some(dialer) = self.dialer(&m.pid) else {
            req.refuse();
            self.closed("tcp", &m, dst, (0, 0), began, &format!("exit {} is not supported yet", m.pid));
            return;
        };
        let stop = self.track(&m.cid);
        let remote = tokio::select! {
            r = dialer.tcp(dst) => r,
            _ = stop.notified() => Err(io::Error::other("closed")),
        };
        let remote = match remote {
            Ok(r) => r,
            Err(e) => {
                req.refuse();
                self.closed("tcp", &m, dst, (0, 0), began, &e.to_string());
                return;
            }
        };
        let flow = req.accept();
        let (tx, rx) = (AtomicI64::new(0), AtomicI64::new(0));
        let why = relay(flow, remote, &stop, &tx, &rx).await;
        self.closed("tcp", &m, dst, (rx.load(Ordering::Relaxed), tx.load(Ordering::Relaxed)), began, &why);
    }

    async fn udp(self: Arc<Self>, mut f: UdpFlow) {
        let (src, dst) = (f.src, f.dst);
        let m = self.decide(17, src, dst).await;
        if dst == self.fake_dns && m.pid != BLOCK {
            self.dns_udp(f, &m.uid).await;
            return;
        }
        let began = Instant::now();
        if m.pid == BLOCK {
            // the tuple stays known, so its next datagrams are dropped
            // here instead of each making a new blocked flow
            while let Ok(Some(_)) = tokio::time::timeout(self.udp_idle, f.recv()).await {}
            return;
        }
        let Some(dialer) = self.dialer(&m.pid) else {
            self.closed("udp", &m, dst, (0, 0), began, &format!("exit {} is not supported yet", m.pid));
            return;
        };
        let stop = self.track(&m.cid);
        let sock = match dialer.udp(dst).await {
            Ok(s) => s,
            Err(e) => {
                self.closed("udp", &m, dst, (0, 0), began, &e.to_string());
                return;
            }
        };
        let reply = f.reply();
        let (mut tx, mut rx) = (0i64, 0i64);
        let mut buf = vec![0u8; 65536];
        let mut why = String::new();
        loop {
            let step = tokio::time::timeout(self.udp_idle, async {
                tokio::select! {
                    d = f.recv() => match d {
                        Some(d) => sock.send(&d).await.map(|n| (n as i64, 0i64)),
                        None => Err(io::Error::other("tunnel closed")),
                    },
                    r = sock.recv(&mut buf) => r.map(|n| {
                        // a full queue drops the datagram, as UDP may
                        let _ = reply.send(&buf[..n]);
                        (0, n as i64)
                    }),
                    _ = stop.notified() => Err(io::Error::other("closed")),
                }
            })
            .await;
            match step {
                Ok(Ok((t, r))) => {
                    tx += t;
                    rx += r;
                }
                Ok(Err(e)) => {
                    // a refused port (ICMP) ends nothing on its own in firestack
                    // either; only the stop, the tunnel and idleness do
                    if e.kind() == io::ErrorKind::ConnectionRefused || e.kind() == io::ErrorKind::ConnectionReset {
                        continue;
                    }
                    why = e.to_string();
                    break;
                }
                Err(_) => break, // idle
            }
        }
        self.closed("udp", &m, dst, (rx, tx), began, &why);
    }

    /// Answers DNS over UDP to our address, each query on its own task so a
    /// slow one holds up none behind it.
    async fn dns_udp(self: Arc<Self>, mut f: UdpFlow, uid: &str) {
        let reply = f.reply();
        while let Ok(Some(q)) = tokio::time::timeout(self.udp_idle, f.recv()).await {
            let (me, reply, uid) = (self.clone(), reply.clone(), uid.to_string());
            tokio::spawn(async move {
                if let Ok(a) = me.resolver.resolve(&uid, &q).await {
                    me.domains.record(&a);
                    let _ = reply.send(&a);
                }
            });
        }
    }

    /// Answers DNS over TCP to our address: length-prefixed messages, one
    /// after another, until the asker closes or goes quiet.
    async fn dns_tcp(&self, mut flow: TcpFlow, uid: &str) {
        loop {
            let mut len = [0u8; 2];
            match tokio::time::timeout(DNS_TCP_IDLE, flow.read_exact(&mut len)).await {
                Ok(Ok(_)) => {}
                _ => return,
            }
            let mut q = vec![0u8; usize::from(u16::from_be_bytes(len))];
            if flow.read_exact(&mut q).await.is_err() {
                return;
            }
            let Ok(a) = self.resolver.resolve(uid, &q).await else { return };
            self.domains.record(&a);
            let Ok(n) = u16::try_from(a.len()) else { return };
            let mut out = Vec::with_capacity(a.len() + 2);
            out.extend_from_slice(&n.to_be_bytes());
            out.extend_from_slice(&a);
            if flow.write_all(&out).await.is_err() {
                return;
            }
        }
    }
}

/// Copies one way until EOF, then passes the EOF on (a half close).
async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(mut r: R, mut w: W, n: &AtomicI64) -> io::Result<()> {
    let mut buf = vec![0u8; 32 << 10];
    loop {
        let k = r.read(&mut buf).await?;
        if k == 0 {
            let _ = w.shutdown().await;
            return Ok(());
        }
        w.write_all(&buf[..k]).await?;
        n.fetch_add(k as i64, Ordering::Relaxed);
    }
}

/// Copies a program's connection and the remote one both ways until both
/// are done, one fails (the program then gets a reset, as from firestack),
/// or stop says so. Returns why it ended early, "" if it did not.
async fn relay(flow: TcpFlow, remote: BoxStream, stop: &Notify, tx: &AtomicI64, rx: &AtomicI64) -> String {
    let aborter = flow.aborter();
    let (fr, fw) = tokio::io::split(flow);
    let (rr, rw) = tokio::io::split(remote);
    let both = async { tokio::try_join!(pump(fr, rw, tx), pump(rr, fw, rx)) };
    let why = tokio::select! {
        r = both => match r {
            Ok(_) => String::new(),
            Err(e) => e.to_string(),
        },
        _ = stop.notified() => "closed".to_string(),
    };
    if !why.is_empty() {
        aborter.abort();
    }
    why
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{BoxFuture, QueryError};
    use crate::net::dial::Direct;
    use crate::net::stack::tests::{Host, drive};
    use crate::net::stack::{Stack, StackConfig, build_udp, parse, Parsed};
    use smoltcp::socket::tcp;

    /// Answers every query with the query itself, flagged as a response.
    struct Echo;
    impl Resolver for Echo {
        fn resolve<'a>(&'a self, _uid: &'a str, q: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>, QueryError>> {
            Box::pin(async move {
                let mut a = q.to_vec();
                if a.len() > 2 {
                    a[2] |= 0x80;
                }
                Ok(a)
            })
        }
    }

    fn engine() -> Arc<Engine> {
        Arc::new(Engine::with_self(None, "", "C:\\fswin.exe", Box::new(|_| {})))
    }

    fn start(e: Arc<Engine>) -> (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>, Arc<Forwarder>) {
        let (st, io) = Stack::new(StackConfig::default());
        let (tx, rx) = mpsc::channel(1024);
        tokio::spawn(st.run(rx));
        let f = Arc::new(Forwarder::new(e.clone(), Arc::new(NoOwners), Arc::new(Direct::new(None)), Arc::new(Echo)));
        e.set_closer(f.closer());
        tokio::spawn(f.clone().run(io.flows));
        (tx, io.out, f)
    }

    async fn wait_for(mut ok: impl FnMut() -> bool) {
        for _ in 0..500 {
            if ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out");
    }

    /// A program's TCP connection through the stack reaches a real echo
    /// server on 127.0.0.1 and back; the close is journaled with its bytes.
    #[tokio::test]
    async fn tcp_relays_to_echo_server_and_records_the_close() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut c, _) = l.accept().await.unwrap();
            let (mut r, mut w) = c.split();
            tokio::io::copy(&mut r, &mut w).await.unwrap();
            w.shutdown().await.unwrap();
        });
        let e = engine();
        let (to_stack, mut from_stack, f) = start(e.clone());
        let mut host = Host::new();
        let h = host.connect(41000, echo);
        drive(&mut host, &to_stack, &mut from_stack, |h2| h2.tcp(h).may_send()).await;
        host.tcp(h).send_slice(b"hello, world").unwrap();
        let mut got = Vec::new();
        drive(&mut host, &to_stack, &mut from_stack, |h2| {
            let s = h2.tcp(h);
            while s.can_recv() {
                let mut b = [0u8; 64];
                let n = s.recv_slice(&mut b).unwrap();
                got.extend_from_slice(&b[..n]);
            }
            got.len() == 12
        })
        .await;
        assert_eq!(got, b"hello, world");
        assert_eq!(f.open(), 1);
        assert_eq!(e.conns.len(), 1);
        host.tcp(h).close();
        drive(&mut host, &to_stack, &mut from_stack, |h2| !h2.tcp(h).may_recv()).await;
        wait_for(|| f.open() == 0).await;
        let ev = e.log.since(0, 100);
        let flow = ev.iter().find(|v| v.kind == "flow").expect("flow event");
        assert_eq!((flow.dst.as_str(), flow.proto.as_str(), flow.via.as_str()), (echo.to_string().as_str(), "tcp", "direct"));
        let close = ev.iter().find(|v| v.kind == "close").expect("close event");
        assert_eq!((close.tx, close.rx, close.cid.as_str()), (12, 12, flow.cid.as_str()));
        assert_eq!(crate::events::Journal::get(&e.log.tx), 12);
        assert!(e.conns.is_empty());
    }

    /// A connection nothing listens at is refused with a reset, and its
    /// failure is journaled.
    #[tokio::test]
    async fn tcp_dial_failure_resets_the_program() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead = l.local_addr().unwrap();
        drop(l);
        let e = engine();
        let (to_stack, mut from_stack, _f) = start(e.clone());
        let mut host = Host::new();
        let h = host.connect(41001, dead);
        drive(&mut host, &to_stack, &mut from_stack, |h2| h2.tcp(h).state() == tcp::State::Closed).await;
        wait_for(|| e.log.since(0, 100).iter().any(|v| v.kind == "close")).await;
    }

    /// Closing by id (a rule change) resets the program's connection.
    #[tokio::test]
    async fn closer_resets_open_connections() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (c, _) = l.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
            drop(c);
        });
        let e = engine();
        let (to_stack, mut from_stack, f) = start(e.clone());
        let mut host = Host::new();
        let h = host.connect(41002, a);
        drive(&mut host, &to_stack, &mut from_stack, |h2| h2.tcp(h).may_send()).await;
        wait_for(|| f.open() == 1).await;
        let cid = e.log.since(0, 10).iter().find(|v| v.kind == "flow").unwrap().cid.clone();
        assert_eq!(f.close_ids(&format!("nope,{cid}")), cid);
        drive(&mut host, &to_stack, &mut from_stack, |h2| h2.tcp(h).state() == tcp::State::Closed).await;
        wait_for(|| f.open() == 0).await;
    }

    /// UDP to a real socket and back, counted on close.
    #[tokio::test]
    async fn udp_relays_and_counts() {
        let u = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ua = u.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 64];
            let (n, from) = u.recv_from(&mut b).await.unwrap();
            u.send_to(&b[..n], from).await.unwrap();
        });
        let e = engine();
        let (to_stack, mut from_stack, f) = start(e.clone());
        let me: SocketAddr = "10.111.222.1:5000".parse().unwrap();
        to_stack.send(build_udp(me, ua, b"ping").unwrap()).await.unwrap();
        let p = tokio::time::timeout(Duration::from_secs(5), from_stack.recv()).await.unwrap().unwrap();
        let Parsed::Udp { src, dst, payload } = parse(&p) else { panic!("not udp") };
        assert_eq!((src, dst, &p[payload]), (ua, me, &b"ping"[..]));
        f.close_all();
        wait_for(|| e.log.since(0, 10).iter().any(|v| v.kind == "close")).await;
        let close = e.log.since(0, 10).into_iter().find(|v| v.kind == "close").unwrap();
        assert_eq!((close.tx, close.rx, close.proto.as_str()), (4, 4, "udp"));
    }

    /// Port 53 at our address goes to the resolver, over UDP and TCP, and
    /// shows in no flow event.
    #[tokio::test]
    async fn dns_trap_answers_udp_and_tcp() {
        let e = engine();
        let (to_stack, mut from_stack, _f) = start(e.clone());
        let dns: SocketAddr = "10.111.222.3:53".parse().unwrap();
        let me: SocketAddr = "10.111.222.1:5001".parse().unwrap();
        let q = [0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        to_stack.send(build_udp(me, dns, &q).unwrap()).await.unwrap();
        let p = tokio::time::timeout(Duration::from_secs(5), from_stack.recv()).await.unwrap().unwrap();
        let Parsed::Udp { src, payload, .. } = parse(&p) else { panic!("not udp") };
        assert_eq!(src, dns);
        assert_eq!(p[payload][2], 0x81);

        let mut host = Host::new();
        let h = host.connect(41003, dns);
        drive(&mut host, &to_stack, &mut from_stack, |h2| h2.tcp(h).may_send()).await;
        let mut framed = vec![0, q.len() as u8];
        framed.extend_from_slice(&q);
        host.tcp(h).send_slice(&framed).unwrap();
        let mut got = Vec::new();
        drive(&mut host, &to_stack, &mut from_stack, |h2| {
            let s = h2.tcp(h);
            while s.can_recv() {
                let mut b = [0u8; 64];
                let n = s.recv_slice(&mut b).unwrap();
                got.extend_from_slice(&b[..n]);
            }
            got.len() == framed.len()
        })
        .await;
        assert_eq!((got[0], got[1], got[4]), (0, 12, 0x81));
        assert!(e.log.since(0, 10).iter().all(|v| v.kind != "flow"));
    }

    #[test]
    fn domain_map_from_answers() {
        use hickory_proto::rr::{Name, RData, Record, RecordType, rdata::A};
        let mut m = msg::test_query("example.com.", RecordType::A);
        m.add_answer(Record::from_rdata(Name::from_ascii("example.com.").unwrap(), 60, RData::A(A::new(93, 184, 215, 14))));
        let d = DomainMap::default();
        d.record(&msg::pack(&m).unwrap());
        assert_eq!(d.get("93.184.215.14".parse().unwrap()), "example.com");
        assert_eq!(d.get("1.1.1.1".parse().unwrap()), "");
        d.record(b"junk");
    }
}
