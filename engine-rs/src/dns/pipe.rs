// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! An in-memory dialer for the DoH and DoT tests.
//!
//! The transport tests must not open a real TLS connection, not even to
//! 127.0.0.1. An antivirus that inspects TLS re-signs the server's
//! certificate with a root of its own and the handshake then fails with
//! `UnknownIssuer` however correct the test CA is. On this machine
//! Avast's Web/Mail Shield does exactly that to a loopback connection:
//! it hands the client a certificate with our subject and our SANs, but
//! issued by "Avast Web/Mail Shield Untrusted Root".
//!
//! The transports reach their servers through a [`Dialer`] anyway (the
//! real one binds its sockets to the physical interface), so the tests
//! hand them one that dials a `tokio::io::duplex` pipe straight to the
//! test server. Nothing reaches the network stack, and the tests are
//! faster for it.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::DuplexStream;
use tokio::sync::mpsc::UnboundedSender;

use super::{BoxFuture, BoxStream, Dialer};

/// How much a pipe holds before a write waits.
const BUF: usize = 64 * 1024;

/// Hands every dial to the test server over a pipe.
pub struct PipeDialer {
    tx: UnboundedSender<DuplexStream>,
    /// addresses that answer as a closed port does
    closed: Vec<SocketAddr>,
}

impl PipeDialer {
    pub fn new(tx: UnboundedSender<DuplexStream>) -> Arc<PipeDialer> {
        Arc::new(PipeDialer { tx, closed: Vec::new() })
    }

    /// The same server, reached by a dialer that refuses `closed`.
    pub fn refusing(&self, closed: &[SocketAddr]) -> Arc<PipeDialer> {
        Arc::new(PipeDialer { tx: self.tx.clone(), closed: closed.to_vec() })
    }
}

impl Dialer for PipeDialer {
    fn dial_tcp<'a>(&'a self, _pid: &'a str, addr: SocketAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            if self.closed.contains(&addr) {
                // the wording Windows uses, as the journal shows it
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "No connection could be made because the target machine actively refused it.",
                ));
            }
            let (client, server) = tokio::io::duplex(BUF);
            self.tx.send(server).map_err(|_| io::Error::new(io::ErrorKind::NotConnected, "the test server is gone"))?;
            Ok(Box::new(client) as BoxStream)
        })
    }
}
