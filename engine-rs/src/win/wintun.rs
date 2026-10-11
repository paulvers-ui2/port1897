// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The Wintun adapter, as wireguard-go's tun.CreateTUN makes it for the Go
//! engine: wintun.dll from next to the engine (never found through PATH),
//! the tunnel type "AuroraVPN", an 8 MiB ring, and the adapter removed on
//! close. Over wintun-bindings (MIT); its netsh helpers (found through
//! PATH) are not used: win/ipconf configures the adapter.

use std::sync::Arc;

use wintun_bindings::{Adapter, Session, Wintun};

/// The tunnel type Windows shows for the adapter (Go: tun.WintunTunnelType).
pub const TUNNEL_TYPE: &str = "AuroraVPN";
/// wireguard-go's ring capacity.
pub const RING_CAPACITY: u32 = 0x80_0000;

/// wintun.dll in dir, the engine's folder.
pub fn dll_path(dir: &str) -> String {
    crate::usque::join(dir, "wintun.dll")
}

/// Loads wintun.dll by its full path.
pub fn load(dir: &str) -> Result<Wintun, String> {
    let path = dll_path(dir);
    // SAFETY: a full path to the wintun.dll shipped next to the engine, in
    // a folder only administrators write (the service locks it down); its
    // exports have the signatures the bindings expect
    unsafe { wintun_bindings::load_from_path(&path) }.map_err(|e| format!("load {path}: {e}"))
}

/// A Wintun adapter with its session; closing removes the adapter.
pub struct Tun {
    pub name: String,
    adapter: Arc<Adapter>,
    session: Arc<Session>,
}

impl Tun {
    /// Creates the adapter name (reusing one of that name, as Wintun does)
    /// and starts its session.
    pub fn create(wintun: &Wintun, name: &str) -> Result<Tun, String> {
        let adapter = Adapter::create(wintun, name, TUNNEL_TYPE, None).map_err(|e| format!("Error creating interface: {e}"))?;
        let session = adapter.start_session(RING_CAPACITY).map_err(|e| format!("Error starting session: {e}"))?;
        Ok(Tun { name: name.to_string(), adapter, session })
    }

    /// The adapter's LUID, for IP Helper and the kill switch.
    pub fn luid(&self) -> u64 {
        // SAFETY: NET_LUID_LH is a u64 seen whole or as bit fields
        unsafe { self.adapter.get_luid().Value }
    }

    /// The adapter's interface index.
    pub fn index(&self) -> Result<u32, String> {
        self.adapter.get_adapter_index().map_err(|e| e.to_string())
    }

    /// The packet session, for the network stack.
    pub fn session(&self) -> Arc<Session> {
        self.session.clone()
    }

    /// Ends the session and removes the adapter.
    pub fn close(self) {
        let _ = self.session.shutdown();
        // the adapter goes when its last reference does; the session holds one
        drop(self.session);
        drop(self.adapter);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dll_is_looked_up_by_full_path() {
        assert_eq!(dll_path(r"C:\Program Files\AuroraVPN\resources\engine"), r"C:\Program Files\AuroraVPN\resources\engine\wintun.dll");
        let e = load(r"C:\nope-fswin-rs").err().unwrap();
        assert!(e.starts_with(r"load C:\nope-fswin-rs\wintun.dll: "), "{e}");
    }

    /// Creates and removes an adapter: admin, and wintun.dll in
    /// FSWIN_WINTUN_DIR (the CI job downloads the pinned one).
    #[test]
    #[ignore = "creates a Wintun adapter (admin, wintun.dll): CI runner only"]
    fn create_and_close() {
        let Ok(dir) = std::env::var("FSWIN_WINTUN_DIR") else {
            eprintln!("FSWIN_WINTUN_DIR not set: no wintun.dll");
            return;
        };
        let w = load(&dir).unwrap();
        let t = Tun::create(&w, "AuroraVPNTest").unwrap();
        assert!(t.luid() != 0);
        assert!(t.index().unwrap() != 0);
        t.close();
    }
}
