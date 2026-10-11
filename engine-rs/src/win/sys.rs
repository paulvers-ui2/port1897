// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The run's system on Windows: the Win32 backends in this folder behind
//! run.rs's `Sys`, with Go's fallbacks (netsh when IP Helper fails) and
//! wording.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use wintun_bindings::Wintun;

use super::ifbind::{self, Binder};
use super::owner::WinOwners;
use super::registry::{self, WinRegistry};
use super::wfp::Wfp;
use super::wintun::{self, SessionDevice, Tun};
use super::ipconf;
use crate::engine::{FAKEDNS4, IFADDR4, Owners};
use crate::killswitch::Firewall;
use crate::net::dial::{BinderProtect, Protect};
use crate::net::tunnel::Device;
use crate::nrpt::Nrpt;
use crate::run::{Adapter, Phys, Sys};

/// Reads a file of the app's. The service's user-token reader replaces
/// this once the engine runs as SYSTEM for a user (asuser).
pub type FileReader = Box<dyn Fn(&str) -> Result<Vec<u8>, String> + Send + Sync>;

pub struct WinSys {
    /// the engine's folder: wintun.dll is loaded from there only
    pub dir: String,
    fw: Arc<Wfp>,
    reader: FileReader,
}

impl WinSys {
    pub fn new(dir: &str, reader: FileReader) -> WinSys {
        WinSys { dir: dir.to_string(), fw: Arc::new(Wfp::new()), reader }
    }

    /// The NRPT with the nudge left to the caller: Go adds the rule early
    /// and nudges once DNS is set up, as nudging at once slowed starts.
    fn nrpt(&self) -> Nrpt<WinRegistry> {
        Nrpt::new(WinRegistry::local_machine(), Box::new(|_| Ok(())))
    }
}

fn fake_dns4() -> Ipv4Addr {
    FAKEDNS4.parse().unwrap_or(Ipv4Addr::new(10, 111, 222, 3))
}

struct WinAdapter {
    tun: Mutex<Option<Tun>>,
    name: String,
    luid: u64,
    index: u32,
    dev: Arc<SessionDevice>,
    /// the DLL stays loaded while the adapter lives
    _wintun: Wintun,
}

impl Adapter for WinAdapter {
    fn name(&self) -> String {
        self.name.clone()
    }
    fn luid(&self) -> u64 {
        self.luid
    }
    fn index(&self) -> u32 {
        self.index
    }
    fn device(&self) -> Arc<dyn Device> {
        self.dev.clone()
    }
    fn close(self: Box<Self>) {
        if let Some(t) = self.tun.lock().unwrap_or_else(|e| e.into_inner()).take() {
            t.close();
        }
    }
}

struct WinPhys(Arc<Binder>);

impl Phys for WinPhys {
    fn indexes(&self) -> (u32, u32) {
        self.0.indexes()
    }
    fn protect(&self) -> Option<Arc<dyn Protect>> {
        Some(Arc::new(BinderProtect(self.0.clone())))
    }
    fn dns_servers(&self) -> Vec<Ipv4Addr> {
        self.0.dns_servers()
    }
}

impl Sys for WinSys {
    fn say(&self, line: &str) {
        println!("{line}");
    }

    fn warn(&self, line: &str) {
        eprintln!("{line}");
    }

    fn default_route4(&self) -> u32 {
        ifbind::link_mtu(0).1
    }

    fn link_mtu(&self) -> (i64, String) {
        let (m, idx) = ifbind::link_mtu(0);
        let (name, _, _) = ifbind::describe(idx);
        crate::mtu::link_mtu(m, &name)
    }

    fn create_adapter(&self, name: &str) -> Result<Box<dyn Adapter>, String> {
        let w = wintun::load(&self.dir)?;
        let t = Tun::create(&w, name)?;
        let (luid, index) = (t.luid(), t.index()?);
        let dev = Arc::new(SessionDevice(t.session()));
        Ok(Box::new(WinAdapter { name: t.name.clone(), luid, index, dev, tun: Mutex::new(Some(t)), _wintun: w }))
    }

    fn nrpt_add(&self) -> Result<(), String> {
        self.nrpt().add(IpAddr::V4(fake_dns4())).map_err(|e| e.to_string())?;
        // as Go's dnspolicy.Add: no answer from before the rule is used after it
        registry::flush_dns_cache();
        Ok(())
    }

    fn nrpt_drop(&self) -> Result<(), String> {
        let r = self.nrpt().remove();
        // the nudge runs on by itself; waiting for it held every stop up
        let n = registry::nudge(false);
        r.and(n)
    }

    fn nrpt_nudge(&self) -> Result<(), String> {
        registry::nudge(false)
    }

    fn nrpt_others(&self) -> Vec<String> {
        self.nrpt().others().unwrap_or_default()
    }

    fn configure(&self, name: &str, luid: u64, set_dns: bool) -> Result<(), String> {
        if luid != 0 {
            let ifaddr: Ipv4Addr = IFADDR4.parse().unwrap_or(Ipv4Addr::new(10, 111, 222, 1));
            let mut r = ipconf::set_address(luid, ifaddr, 24);
            if r.is_ok() && set_dns {
                let errs: Vec<String> = [ipconf::set_dns(luid, fake_dns4()), ipconf::set_metric(luid, 1)].into_iter().filter_map(Result::err).collect();
                if !errs.is_empty() {
                    r = Err(errs.join("\n"));
                }
            }
            match r {
                Ok(()) => return Ok(()),
                Err(e) => println!("fswin: configuring the adapter directly failed; using netsh: {e}"),
            }
        }
        ipconf::netsh(&ipconf::netsh_configure(name, set_dns))
    }

    fn clear_dns(&self, luid: u64) -> Result<(), String> {
        ipconf::clear_dns(luid)
    }

    fn add_routes(&self, name: &str, luid: u64) -> Result<(), String> {
        if luid != 0 {
            let errs: Vec<String> = [ipconf::add_route(luid, Ipv4Addr::new(0, 0, 0, 0), 1, 0), ipconf::add_route(luid, Ipv4Addr::new(128, 0, 0, 0), 1, 0)]
                .into_iter()
                .filter_map(Result::err)
                .collect();
            if errs.is_empty() {
                return Ok(());
            }
            println!("fswin: adding the routes directly failed; using netsh: {}", errs.join("\n"));
        }
        ipconf::netsh(&ipconf::netsh_routes(name))
    }

    fn phys(&self, tun_index: u32) -> Arc<dyn Phys> {
        Arc::new(WinPhys(Arc::new(Binder::new(tun_index))))
    }

    fn firewall(&self) -> Arc<dyn Firewall> {
        self.fw.clone()
    }

    fn owners(&self) -> Arc<dyn Owners> {
        Arc::new(WinOwners::new())
    }

    fn describe(&self, idx: u32) -> (String, String, bool) {
        ifbind::describe(idx)
    }

    fn cleanup(&self) -> Result<(), String> {
        // the stop waits for the DNS Client here: nothing runs after it
        let n = Nrpt::new(WinRegistry::local_machine(), Box::new(registry::nudge));
        let errs: Vec<String> = [n.remove(), self.fw.disable()].into_iter().filter_map(Result::err).collect();
        if errs.is_empty() { Ok(()) } else { Err(errs.join("\n")) }
    }

    fn read_user_file(&self, path: &str) -> Result<Vec<u8>, String> {
        (self.reader)(path)
    }
}
