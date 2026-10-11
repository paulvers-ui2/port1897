// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The tunnel: the adapter's packets into the stack, the stack's packets
//! back out, and the stack's flows to the forwarder (firestack's
//! intra.Connect and Disconnect). The adapter is a `Device`, so the whole
//! path runs in tests on a device in memory.

use std::io;
use std::sync::Arc;
use std::thread::JoinHandle;

use tokio::sync::mpsc;

use super::forward::Forwarder;
use super::stack::{Stack, StackConfig};

/// The adapter's packet interface (a Wintun session).
pub trait Device: Send + Sync + 'static {
    /// Blocks for the next IP packet; an error once the device is closed.
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;
    /// Writes an IP packet.
    fn send(&self, p: &[u8]) -> io::Result<()>;
}

/// A running tunnel.
pub struct Tunnel {
    pub forwarder: Arc<Forwarder>,
    reader: Option<JoinHandle<()>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Tunnel {
    /// Starts the stack on dev; flows go to fwd. Must run in a tokio
    /// runtime.
    pub fn start(dev: Arc<dyn Device>, cfg: StackConfig, fwd: Arc<Forwarder>) -> Tunnel {
        let mtu = cfg.mtu;
        let (stack, io) = Stack::new(cfg);
        let (tx, rx) = mpsc::channel(1024);
        // Wintun's receive blocks: a thread of its own, not a tokio worker
        let rdev = dev.clone();
        let reader = std::thread::Builder::new()
            .name("tun-read".into())
            .spawn(move || {
                let mut buf = vec![0u8; mtu.max(1500) + 64];
                while let Ok(n) = rdev.recv(&mut buf) {
                    if n > 0 && tx.blocking_send(buf[..n].to_vec()).is_err() {
                        return;
                    }
                }
            })
            .ok();
        let mut out = io.out;
        let writer = tokio::spawn(async move {
            while let Some(p) = out.recv().await {
                // a packet the adapter will not take is lost, as on a wire
                let _ = dev.send(&p);
            }
        });
        let tasks = vec![tokio::spawn(stack.run(rx)), writer, tokio::spawn(fwd.clone().run(io.flows))];
        Tunnel { forwarder: fwd, reader, tasks }
    }

    /// Stops the tunnel (firestack's Disconnect): every connection ends,
    /// then the stack. close_device ends the adapter's session, which lets
    /// the reading thread go; that is waited for.
    pub async fn stop(mut self, close_device: impl FnOnce() + Send + 'static) {
        self.forwarder.close_all();
        for t in self.tasks.drain(..) {
            t.abort();
        }
        let reader = self.reader.take();
        let _ = tokio::task::spawn_blocking(move || {
            close_device();
            if let Some(r) = reader {
                let _ = r.join();
            }
        })
        .await;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::mpsc as smpsc;
    use std::time::Duration;

    /// A device in memory: what the "programs" send comes from a channel,
    /// what the tunnel writes goes to another.
    pub(crate) struct MemDevice {
        input: Mutex<smpsc::Receiver<Vec<u8>>>,
        output: mpsc::UnboundedSender<Vec<u8>>,
    }

    impl MemDevice {
        pub(crate) fn new() -> (Arc<MemDevice>, smpsc::Sender<Vec<u8>>, mpsc::UnboundedReceiver<Vec<u8>>) {
            let (itx, irx) = smpsc::channel();
            let (otx, orx) = mpsc::unbounded_channel();
            (Arc::new(MemDevice { input: Mutex::new(irx), output: otx }), itx, orx)
        }
    }

    impl Device for MemDevice {
        fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            let p = self.input.lock().unwrap().recv().map_err(|_| io::Error::other("closed"))?;
            buf[..p.len()].copy_from_slice(&p);
            Ok(p.len())
        }
        fn send(&self, p: &[u8]) -> io::Result<()> {
            self.output.send(p.to_vec()).map_err(|_| io::Error::other("closed"))
        }
    }

    #[tokio::test]
    async fn packets_flow_through_the_device_and_stop_ends_it() {
        use crate::net::stack::{Parsed, build_udp, parse};
        let u = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ua = u.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 64];
            let (n, from) = u.recv_from(&mut b).await.unwrap();
            u.send_to(&b[..n], from).await.unwrap();
        });
        let e = Arc::new(crate::engine::Engine::with_self(None, "", "C:\\fswin.exe", Box::new(|_| {})));
        let fwd = Arc::new(Forwarder::new(e, Arc::new(crate::net::forward::NoOwners), Arc::new(crate::net::dial::Direct::new(None)), Arc::new(crate::dns::FakeDns::new(Arc::new(crate::engine::Engine::with_self(None, "", "x", Box::new(|_| {})))))));
        let (dev, input, mut output) = MemDevice::new();
        let t = Tunnel::start(dev, StackConfig::default(), fwd);
        let me = "10.111.222.1:6000".parse().unwrap();
        input.send(build_udp(me, ua, b"hey").unwrap()).unwrap();
        let p = tokio::time::timeout(Duration::from_secs(5), output.recv()).await.unwrap().unwrap();
        let Parsed::Udp { payload, .. } = parse(&p) else { panic!("not udp") };
        assert_eq!(&p[payload], b"hey");
        tokio::time::timeout(Duration::from_secs(5), t.stop(move || drop(input))).await.unwrap();
    }
}
