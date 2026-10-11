// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The "direct" exit (firestack's Base): real sockets for the flows the
//! engine lets out, and for its own DNS transports. With all traffic routed
//! into the tunnel, a socket left to the routing table would come straight
//! back in; each is pinned to the physical interface (win/ifbind) before it
//! connects, unless its destination is on this PC or an attached network.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpSocket, TcpStream, UdpSocket};

use crate::dns::{self, BoxFuture, BoxStream};
use crate::exit::BASE;

/// How long a connect may take: a dial that never answers would hold the
/// program's SYN as long.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(20);

/// Keeps a socket out of the tunnel (Go: protect.Controller).
pub trait Protect: Send + Sync {
    /// Pins the raw socket s, about to connect to dst, to the physical
    /// interface; nothing to do for destinations that never take the
    /// default route.
    fn protect(&self, dst: IpAddr, s: u64) -> Result<(), String>;
}

/// Opens the sockets of the flows the engine allows.
pub trait Dialer: Send + Sync {
    fn tcp(&self, dst: SocketAddr) -> BoxFuture<'_, io::Result<TcpStream>>;
    /// A UDP socket connected to dst.
    fn udp(&self, dst: SocketAddr) -> BoxFuture<'_, io::Result<UdpSocket>>;
}

/// Sockets on the physical interface; without a Protect, plain ones (DNS
/// only mode, tests).
#[derive(Clone)]
pub struct Direct {
    pub protect: Option<Arc<dyn Protect>>,
    pub timeout: Duration,
}

impl Direct {
    pub fn new(protect: Option<Arc<dyn Protect>>) -> Direct {
        Direct { protect, timeout: DIAL_TIMEOUT }
    }

    fn pin(&self, dst: IpAddr, s: u64) -> io::Result<()> {
        match &self.protect {
            Some(p) => p.protect(dst, s).map_err(io::Error::other),
            None => Ok(()),
        }
    }

    pub async fn connect_tcp(&self, dst: SocketAddr) -> io::Result<TcpStream> {
        let s = if dst.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
        self.pin(dst.ip(), raw(&s))?;
        let c = tokio::time::timeout(self.timeout, s.connect(dst)).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("dial {dst}: timed out")))??;
        let _ = c.set_nodelay(true);
        Ok(c)
    }

    pub async fn connect_udp(&self, dst: SocketAddr) -> io::Result<UdpSocket> {
        let any: SocketAddr = if dst.is_ipv4() { "0.0.0.0:0".parse().unwrap_or(dst) } else { "[::]:0".parse().unwrap_or(dst) };
        let s = std::net::UdpSocket::bind(any)?;
        self.pin(dst.ip(), raw(&s))?;
        s.connect(dst)?;
        s.set_nonblocking(true)?;
        UdpSocket::from_std(s)
    }
}

#[cfg(windows)]
fn raw<S: std::os::windows::io::AsRawSocket>(s: &S) -> u64 {
    s.as_raw_socket()
}

#[cfg(not(windows))]
fn raw<S: std::os::fd::AsRawFd>(s: &S) -> u64 {
    s.as_raw_fd() as u64
}

impl Dialer for Direct {
    fn tcp(&self, dst: SocketAddr) -> BoxFuture<'_, io::Result<TcpStream>> {
        Box::pin(self.connect_tcp(dst))
    }

    fn udp(&self, dst: SocketAddr) -> BoxFuture<'_, io::Result<UdpSocket>> {
        Box::pin(self.connect_udp(dst))
    }
}

/// The DNS transports' connections: only the direct exit is here yet.
impl dns::Dialer for Direct {
    fn dial_tcp<'a>(&'a self, pid: &'a str, addr: SocketAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            if !pid.is_empty() && pid != BASE {
                return Err(io::Error::other(format!("dial {addr}: exit {pid} is not supported yet")));
            }
            Ok(Box::new(self.connect_tcp(addr).await?) as BoxStream)
        })
    }

    fn dial_udp<'a>(&'a self, pid: &'a str, addr: SocketAddr) -> BoxFuture<'a, io::Result<UdpSocket>> {
        Box::pin(async move {
            if !pid.is_empty() && pid != BASE {
                return Err(io::Error::other(format!("dial {addr}: exit {pid} is not supported yet")));
            }
            self.connect_udp(addr).await
        })
    }
}

/// Pins sockets with win/ifbind's Binder, as Go's protect.SkipBind and
/// Binder.Protect together.
#[cfg(windows)]
pub struct BinderProtect(pub Arc<crate::win::ifbind::Binder>);

#[cfg(windows)]
impl Protect for BinderProtect {
    fn protect(&self, dst: IpAddr, s: u64) -> Result<(), String> {
        if self.0.on_link(dst) {
            return Ok(());
        }
        let s = s as usize;
        match dst {
            IpAddr::V4(_) => self.0.bind4(s),
            IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some() => self.0.bind4(s),
            IpAddr::V6(_) => self.0.bind6(s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Default)]
    struct Seen(Mutex<Vec<IpAddr>>);

    impl Protect for Seen {
        fn protect(&self, dst: IpAddr, _s: u64) -> Result<(), String> {
            self.0.lock().unwrap().push(dst);
            if dst.is_unspecified() { Err("no".into()) } else { Ok(()) }
        }
    }

    #[tokio::test]
    async fn tcp_and_udp_are_protected_then_connected() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut c, _) = l.accept().await.unwrap();
            c.write_all(b"hi").await.unwrap();
        });
        let seen = Arc::new(Seen::default());
        let d = Direct::new(Some(seen.clone()));
        let mut c = d.tcp(a).await.unwrap();
        let mut b = [0u8; 2];
        c.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"hi");

        let u = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ua = u.local_addr().unwrap();
        let s = d.udp(ua).await.unwrap();
        s.send(b"x").await.unwrap();
        let (n, from) = u.recv_from(&mut b).await.unwrap();
        assert_eq!((n, from), (1, s.local_addr().unwrap()));
        assert_eq!(*seen.0.lock().unwrap(), [a.ip(), ua.ip()]);

        // a socket that cannot be kept out of the tunnel is not used
        assert!(d.tcp("0.0.0.0:9".parse().unwrap()).await.is_err());
        let e = dns::Dialer::dial_tcp(&d, "wg0", a).await.err().unwrap();
        assert!(e.to_string().contains("not supported"), "{e}");
    }
}
