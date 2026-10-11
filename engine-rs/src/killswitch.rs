// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The kill switch (a port of killswitch_windows.go): turned on at start
//! for -killswitch, and later from the app's button (POST /api/killswitch).
//! The WFP calls sit behind the `Firewall` trait, so the state machine is
//! tested here with a fake and the real backend stays small.

use std::fmt;
use std::sync::{Arc, Mutex};

/// What `Firewall::enable` installs (win/wfp's Options).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WfpOptions {
    /// the tunnel adapter, through which everything may pass
    pub tun_luid: u64,
    /// more programs (full paths) that may connect directly, besides the
    /// engine itself; e.g. usque.exe
    pub allow: Vec<String>,
    /// keep the block in place if the engine dies, until `disable` runs
    /// (from a later start or -cleanup)
    pub persistent: bool,
    /// let private, link-local and multicast addresses through
    pub allow_lan: bool,
}

/// The system firewall: WFP on Windows, a fake in tests.
pub trait Firewall: Send + Sync {
    /// Blocks all traffic except what `o` allows. It first removes any
    /// rules left by an earlier run, ours or the Go engine's.
    fn enable(&self, o: &WfpOptions) -> Result<(), String>;
    /// Removes the kill switch, including rules left by a crashed run.
    fn disable(&self) -> Result<(), String>;
    /// Whether kill-switch rules are installed.
    fn active(&self) -> Result<bool, String>;
}

/// Why the kill switch did not change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KillError {
    /// only DNS goes through the tunnel: everything else would be cut off
    NeedsFull,
    /// the tunnel is not a Wintun adapter
    NoKillSwitch,
    /// the firewall refused
    Firewall(String),
}

impl fmt::Display for KillError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KillError::NeedsFull => f.write_str("the kill switch needs all traffic in the tunnel; restart protection with the firewall on"),
            KillError::NoKillSwitch => f.write_str("no kill switch: the tunnel is not a Wintun adapter"),
            KillError::Firewall(e) => f.write_str(e),
        }
    }
}

impl std::error::Error for KillError {}

impl KillError {
    /// The app asked for something that cannot be done now (HTTP 409),
    /// rather than something that failed (500).
    pub fn is_conflict(&self) -> bool {
        matches!(self, KillError::NeedsFull | KillError::NoKillSwitch)
    }
}

struct State {
    on: bool,
    opts: WfpOptions,
    /// all IPv4 traffic goes through the tunnel
    full: bool,
    /// the last change's failure, for the status; None after a success
    err: Option<KillError>,
}

/// Turns the kill switch on and off while the engine runs.
pub struct KillSwitch {
    fw: Arc<dyn Firewall>,
    m: Mutex<State>,
}

impl KillSwitch {
    pub fn new(fw: Arc<dyn Firewall>, opts: WfpOptions, full: bool) -> KillSwitch {
        KillSwitch { fw, m: Mutex::new(State { on: false, opts, full, err: None }) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.m.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Turns the kill switch on (letting LAN traffic through if allow_lan)
    /// or off. Turning it on again applies a new allow_lan.
    pub fn set(&self, on: bool, allow_lan: bool) -> Result<(), KillError> {
        let mut s = self.lock();
        let r = self.set_locked(&mut s, on, allow_lan);
        s.err = r.as_ref().err().cloned();
        r
    }

    fn set_locked(&self, s: &mut State, on: bool, allow_lan: bool) -> Result<(), KillError> {
        if !on {
            if !s.on {
                return Ok(());
            }
            self.fw.disable().map_err(KillError::Firewall)?;
            s.on = false;
            return Ok(());
        }
        if !s.full {
            return Err(KillError::NeedsFull);
        }
        let o = WfpOptions { allow_lan, ..s.opts.clone() };
        // enable replaces the rules if already on; when it fails it has
        // removed the old ones
        if let Err(e) = self.fw.enable(&o) {
            s.on = false;
            return Err(KillError::Firewall(e));
        }
        s.on = true;
        s.opts = o;
        Ok(())
    }

    /// Records that all IPv4 traffic goes through the tunnel, as per-app
    /// routes make it after the kill switch was set up.
    pub fn set_full(&self, full: bool) {
        self.lock().full = full;
    }

    /// Why the kill switch last failed to change, or "".
    pub fn last_error(&self) -> String {
        self.lock().err.as_ref().map(|e| e.to_string()).unwrap_or_default()
    }

    pub fn is_on(&self) -> bool {
        self.lock().on
    }

    /// The options in force (or to be used when it goes on).
    pub fn options(&self) -> WfpOptions {
        self.lock().opts.clone()
    }
}

/// `KillSwitch::set` for an engine that may have no kill switch.
pub fn set(k: Option<&KillSwitch>, on: bool, allow_lan: bool) -> Result<(), KillError> {
    match k {
        Some(k) => k.set(on, allow_lan),
        None => Err(KillError::NoKillSwitch),
    }
}

/// A firewall that only records what it is asked, for tests.
#[derive(Default)]
pub struct FakeFirewall {
    pub calls: Mutex<Vec<String>>,
    /// installed rules, as the options they were installed with
    pub rules: Mutex<Option<WfpOptions>>,
    /// make the next enable fail with this
    pub fail_enable: Mutex<Option<String>>,
    pub fail_disable: Mutex<Option<String>>,
}

impl Firewall for FakeFirewall {
    fn enable(&self, o: &WfpOptions) -> Result<(), String> {
        self.calls.lock().unwrap().push(format!("enable lan={}", o.allow_lan));
        // as WFP's Enable: old rules go first, whatever happens next
        *self.rules.lock().unwrap() = None;
        if let Some(e) = self.fail_enable.lock().unwrap().take() {
            return Err(e);
        }
        *self.rules.lock().unwrap() = Some(o.clone());
        Ok(())
    }

    fn disable(&self) -> Result<(), String> {
        self.calls.lock().unwrap().push("disable".into());
        if let Some(e) = self.fail_disable.lock().unwrap().take() {
            return Err(e);
        }
        *self.rules.lock().unwrap() = None;
        Ok(())
    }

    fn active(&self) -> Result<bool, String> {
        Ok(self.rules.lock().unwrap().is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ks(full: bool) -> (Arc<FakeFirewall>, KillSwitch) {
        let fw = Arc::new(FakeFirewall::default());
        let o = WfpOptions { tun_luid: 7, allow: vec![r"C:\x\usque.exe".into()], persistent: true, allow_lan: false };
        (fw.clone(), KillSwitch::new(fw, o, full))
    }

    #[test]
    fn on_off_and_lan() {
        let (fw, k) = ks(true);
        assert!(!k.is_on());
        k.set(false, false).unwrap(); // off when off: nothing to do
        assert!(fw.calls.lock().unwrap().is_empty());
        k.set(true, false).unwrap();
        assert!(k.is_on() && fw.active().unwrap());
        k.set(true, true).unwrap(); // again, with the LAN: the rules are replaced
        let r = fw.rules.lock().unwrap().clone().unwrap();
        assert!(r.allow_lan && r.persistent && r.tun_luid == 7 && r.allow.len() == 1);
        assert!(k.options().allow_lan);
        k.set(false, false).unwrap();
        assert!(!k.is_on() && !fw.active().unwrap());
        assert_eq!(*fw.calls.lock().unwrap(), ["enable lan=false", "enable lan=true", "disable"]);
        assert_eq!(k.last_error(), "");
    }

    #[test]
    fn needs_full_and_failures() {
        let (fw, k) = ks(false);
        let e = k.set(true, false).unwrap_err();
        assert_eq!(e, KillError::NeedsFull);
        assert!(e.is_conflict());
        assert_eq!(k.last_error(), "the kill switch needs all traffic in the tunnel; restart protection with the firewall on");
        assert!(fw.calls.lock().unwrap().is_empty());
        k.set_full(true);
        k.set(true, false).unwrap();
        assert_eq!(k.last_error(), "", "a success clears the error");

        // a failed enable leaves it off: the old rules are gone
        *fw.fail_enable.lock().unwrap() = Some("wfp: enable: boom".into());
        let e = k.set(true, true).unwrap_err();
        assert!(!e.is_conflict());
        assert!(!k.is_on() && !fw.active().unwrap());
        assert_eq!(k.last_error(), "wfp: enable: boom");

        // a failed disable leaves it on
        k.set(true, false).unwrap();
        *fw.fail_disable.lock().unwrap() = Some("wfp: delete filter 3: 0x80320001".into());
        assert!(k.set(false, false).is_err());
        assert!(k.is_on());
        assert_eq!(set(None, true, false).unwrap_err(), KillError::NoKillSwitch);
        assert_eq!(KillError::NoKillSwitch.to_string(), "no kill switch: the tunnel is not a Wintun adapter");
    }
}
