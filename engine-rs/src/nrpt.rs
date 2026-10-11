// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The NRPT rule (a port of win/dnspolicy): one registry key per rule, as
//! Tailscale writes them, under a fixed key so that a rule left by a crash,
//! of either engine, is found and replaced. The registry sits behind the
//! `Registry` trait and the DNS Client's reload ("nudge": ipconfig
//! /registerdns and a cache flush) behind a function, so the logic is
//! tested here with a fake registry.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

use crate::golike;

/// Rules this PC sets (Add-DnsClientNrptRule's, and ours), under HKLM.
pub const LOCAL_RULES: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
/// Rules from group policy (read only), under HKLM.
pub const POLICY_RULES: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig";
/// Our rule's key: one fixed id, shared with the Go engine.
pub const RULE_KEY: &str = "{4A0F3C2E-8B71-4D5A-9E26-AF1D7C3B5E90}";
pub const TAG: &str = "AuroraVPN";
/// The app's name before 0.3, in rules PowerShell made.
pub const OLD_TAG: &str = "port1897";
/// ConfigOptions 0x8: answer from GenericDNSServers.
pub const CONFIG_GENERIC_SERVERS: u32 = 0x8;
/// What Add-DnsClientNrptRule writes.
pub const RULE_VERSION: u32 = 2;

/// A registry value of the types the rules use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegValue {
    Dword(u32),
    Sz(String),
    ExpandSz(String),
    MultiSz(Vec<String>),
}

/// Why a registry call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegError {
    /// the key does not exist
    NotExist,
    Other(String),
}

impl fmt::Display for RegError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegError::NotExist => f.write_str("The system cannot find the file specified."),
            RegError::Other(e) => f.write_str(e),
        }
    }
}

/// The registry under one root (HKLM for the engine), by key path.
pub trait Registry: Send + Sync {
    /// The names of path's subkeys, in the registry's order.
    fn subkeys(&self, path: &str) -> Result<Vec<String>, RegError>;
    /// A value; None when the key or value is missing or unreadable.
    fn value(&self, path: &str, name: &str) -> Option<RegValue>;
    /// Creates path (and its parents) if missing.
    fn create(&self, path: &str) -> Result<(), RegError>;
    fn set(&self, path: &str, name: &str, v: RegValue) -> Result<(), RegError>;
    /// Deletes a key that has no subkeys.
    fn delete(&self, path: &str) -> Result<(), RegError>;
}

/// Why add did not end with the rule in force.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NrptError {
    /// the rule is written, but the DNS Client did not confirm it took it
    /// in; protection can go on
    NotApplied(String),
    Failed(String),
}

impl fmt::Display for NrptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NrptError::NotApplied(e) => write!(f, "dnspolicy: the DNS Client did not confirm the change: {e}"),
            NrptError::Failed(e) => f.write_str(e),
        }
    }
}

/// Has the DNS Client take a rule change in: wait is true at a stop (at
/// most 5 s there), false at a start. An error means "not applied".
pub type Nudge = Box<dyn Fn(bool) -> Result<(), String> + Send + Sync>;

/// One NRPT rule as read back.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Rule {
    key: String,
    /// namespaces: "." for all names
    names: Vec<String>,
    comment: String,
    display: String,
}

/// Our rules: the fixed key, or the comment or name of one that PowerShell
/// made, now or under the old name.
fn ours(r: &Rule) -> bool {
    golike::equal_fold(&r.key, RULE_KEY) || r.comment == TAG || r.comment == OLD_TAG || r.display == TAG || r.display == OLD_TAG
}

/// The NRPT over a registry.
pub struct Nrpt<R: Registry> {
    pub reg: R,
    pub local: String,
    pub policy: String,
    nudge: Nudge,
}

impl<R: Registry> Nrpt<R> {
    pub fn new(reg: R, nudge: Nudge) -> Nrpt<R> {
        Nrpt { reg, local: LOCAL_RULES.into(), policy: POLICY_RULES.into(), nudge }
    }

    /// Replaces any of our rules with one sending all names (".") to
    /// server. If the engine dies without remove, the rule stays and DNS
    /// fails until remove (or add) runs again.
    pub fn add(&self, server: std::net::IpAddr) -> Result<(), NrptError> {
        self.remove_ours().map_err(NrptError::Failed)?;
        let path = format!(r"{}\{RULE_KEY}", self.local);
        let failed = |e: RegError| NrptError::Failed(format!("dnspolicy: add: {e}"));
        self.reg.create(&path).map_err(failed)?;
        let values = [
            ("Version", RegValue::Dword(RULE_VERSION)),
            ("Name", RegValue::MultiSz(vec![".".into()])),
            ("GenericDNSServers", RegValue::Sz(server.to_string())),
            ("ConfigOptions", RegValue::Dword(CONFIG_GENERIC_SERVERS)),
            ("Comment", RegValue::Sz(TAG.into())),
            ("DisplayName", RegValue::Sz(TAG.into())),
            ("IPSECCARestriction", RegValue::Sz(String::new())),
        ];
        // all are tried, as Go's errors.Join of the calls
        let errs: Vec<String> = values.into_iter().filter_map(|(n, v)| self.reg.set(&path, n, v).err()).map(|e| e.to_string()).collect();
        if !errs.is_empty() {
            let _ = self.reg.delete(&path);
            return Err(NrptError::Failed(format!("dnspolicy: add: {}", errs.join("\n"))));
        }
        (self.nudge)(false).map_err(NrptError::NotApplied)
    }

    /// Deletes our rules and has the DNS Client drop them: a rule left in
    /// force after the engine stops would send every lookup to an address
    /// no one answers.
    pub fn remove(&self) -> Result<(), String> {
        let errs: Vec<String> = [self.remove_ours(), (self.nudge)(true)].into_iter().filter_map(Result::err).collect();
        if errs.is_empty() { Ok(()) } else { Err(errs.join("\n")) }
    }

    /// Catch-all (".") rules that are not ours, such as another VPN's, as
    /// "DisplayName (Comment)": they compete with ours for every query.
    pub fn others(&self) -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        for path in [&self.local, &self.policy] {
            for r in self.list(path)? {
                if !ours(&r) && r.names.iter().any(|n| n == ".") {
                    out.push(format!("{} ({})", r.display, r.comment));
                }
            }
        }
        Ok(out)
    }

    fn remove_ours(&self) -> Result<(), String> {
        let mut errs = Vec::new();
        for r in self.list(&self.local)? {
            if !ours(&r) {
                continue;
            }
            match self.reg.delete(&format!(r"{}\{}", self.local, r.key)) {
                Ok(()) | Err(RegError::NotExist) => {}
                Err(e) => errs.push(format!("dnspolicy: remove {}: {e}", r.key)),
            }
        }
        if errs.is_empty() { Ok(()) } else { Err(errs.join("\n")) }
    }

    /// The rules under path; none when the key does not exist.
    fn list(&self, path: &str) -> Result<Vec<Rule>, String> {
        let keys = match self.reg.subkeys(path) {
            Ok(k) => k,
            Err(RegError::NotExist) => return Ok(Vec::new()),
            Err(e) => return Err(format!("dnspolicy: {path}: {e}")),
        };
        let mut rules = Vec::new();
        for key in keys {
            let rp = format!(r"{path}\{key}");
            // a value of another type reads as none, as with Go's typed getters
            let names = match self.reg.value(&rp, "Name") {
                Some(RegValue::MultiSz(v)) => v,
                _ => Vec::new(),
            };
            let s = |name| match self.reg.value(&rp, name) {
                Some(RegValue::Sz(v) | RegValue::ExpandSz(v)) => v,
                _ => String::new(),
            };
            rules.push(Rule { comment: s("Comment"), display: s("DisplayName"), key, names });
        }
        Ok(rules)
    }
}

/// A fake key: its path as created, and its values.
type FakeKey = (String, BTreeMap<String, RegValue>);

/// An in-memory registry for tests: keys are case-insensitive, subkeys
/// listed in name order, as Windows lists them.
#[derive(Default)]
pub struct FakeRegistry {
    /// lowercased path -> (path as created, values)
    keys: Mutex<BTreeMap<String, FakeKey>>,
    /// paths whose writes fail
    pub deny: Mutex<Vec<String>>,
}

impl FakeRegistry {
    fn denied(&self, path: &str) -> bool {
        self.deny.lock().unwrap().iter().any(|d| golike::equal_fold(d, path))
    }

    /// The paths of all keys.
    pub fn paths(&self) -> Vec<String> {
        self.keys.lock().unwrap().values().map(|(p, _)| p.clone()).collect()
    }
}

impl Registry for FakeRegistry {
    fn subkeys(&self, path: &str) -> Result<Vec<String>, RegError> {
        let keys = self.keys.lock().unwrap();
        let lp = golike::to_lower(path);
        if !keys.contains_key(&lp) {
            return Err(RegError::NotExist);
        }
        let prefix = format!(r"{lp}\");
        Ok(keys
            .iter()
            .filter_map(|(k, (orig, _))| k.strip_prefix(&prefix).filter(|rest| !rest.contains('\\')).map(|_| orig[path.len() + 1..].to_string()))
            .collect())
    }

    fn value(&self, path: &str, name: &str) -> Option<RegValue> {
        let keys = self.keys.lock().unwrap();
        let (_, vals) = keys.get(&golike::to_lower(path))?;
        vals.iter().find(|(k, _)| golike::equal_fold(k, name)).map(|(_, v)| v.clone())
    }

    fn create(&self, path: &str) -> Result<(), RegError> {
        if self.denied(path) {
            return Err(RegError::Other("Access is denied.".into()));
        }
        let mut keys = self.keys.lock().unwrap();
        let mut at = String::new();
        for part in path.split('\\') {
            if !at.is_empty() {
                at.push('\\');
            }
            at.push_str(part);
            keys.entry(golike::to_lower(&at)).or_insert_with(|| (at.clone(), BTreeMap::new()));
        }
        Ok(())
    }

    fn set(&self, path: &str, name: &str, v: RegValue) -> Result<(), RegError> {
        let mut keys = self.keys.lock().unwrap();
        let (_, vals) = keys.get_mut(&golike::to_lower(path)).ok_or(RegError::NotExist)?;
        vals.insert(name.to_string(), v);
        Ok(())
    }

    fn delete(&self, path: &str) -> Result<(), RegError> {
        if self.denied(path) {
            return Err(RegError::Other("Access is denied.".into()));
        }
        let mut keys = self.keys.lock().unwrap();
        let lp = golike::to_lower(path);
        if !keys.contains_key(&lp) {
            return Err(RegError::NotExist);
        }
        let prefix = format!(r"{lp}\");
        if keys.keys().any(|k| k.starts_with(&prefix)) {
            return Err(RegError::Other("Access is denied.".into()));
        }
        keys.remove(&lp);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn nrpt() -> (Nrpt<FakeRegistry>, Arc<Mutex<Vec<bool>>>) {
        let nudges = Arc::new(Mutex::new(Vec::new()));
        let n2 = nudges.clone();
        let n = Nrpt::new(
            FakeRegistry::default(),
            Box::new(move |wait| {
                n2.lock().unwrap().push(wait);
                Ok(())
            }),
        );
        (n, nudges)
    }

    /// A rule as PowerShell's Add-DnsClientNrptRule writes it.
    fn another(reg: &FakeRegistry, path: &str, key: &str, display: &str, comment: &str, names: &[&str]) {
        let p = format!(r"{path}\{key}");
        reg.create(&p).unwrap();
        reg.set(&p, "Name", RegValue::MultiSz(names.iter().map(|s| s.to_string()).collect())).unwrap();
        reg.set(&p, "DisplayName", RegValue::Sz(display.into())).unwrap();
        reg.set(&p, "Comment", RegValue::Sz(comment.into())).unwrap();
        reg.set(&p, "GenericDNSServers", RegValue::Sz("10.2.0.1".into())).unwrap();
        reg.set(&p, "ConfigOptions", RegValue::Dword(8)).unwrap();
        reg.set(&p, "Version", RegValue::Dword(2)).unwrap();
    }

    #[test]
    fn add_writes_the_rule_as_windows_reads_it() {
        let (n, nudges) = nrpt();
        n.add("10.111.222.3".parse().unwrap()).unwrap();
        let p = format!(r"{LOCAL_RULES}\{RULE_KEY}");
        let get = |name| n.reg.value(&p, name).unwrap();
        assert_eq!(get("Name"), RegValue::MultiSz(vec![".".into()]));
        assert_eq!(get("GenericDNSServers"), RegValue::Sz("10.111.222.3".into()));
        assert_eq!(get("ConfigOptions"), RegValue::Dword(8));
        assert_eq!(get("Version"), RegValue::Dword(2));
        assert_eq!(get("Comment"), RegValue::Sz(TAG.into()));
        assert_eq!(get("DisplayName"), RegValue::Sz(TAG.into()));
        assert_eq!(get("IPSECCARestriction"), RegValue::Sz(String::new()));
        // at a start the nudge is not waited for
        assert_eq!(*nudges.lock().unwrap(), [false]);
        // again: replaced, not doubled
        n.add("10.111.222.3".parse().unwrap()).unwrap();
        assert_eq!(n.reg.subkeys(LOCAL_RULES).unwrap(), [RULE_KEY]);
    }

    #[test]
    fn others_and_remove() {
        let (n, nudges) = nrpt();
        // another VPN's catch-all rule, a split rule, and two of ours left
        // over (one from the old PowerShell days, one in other case)
        another(&n.reg, LOCAL_RULES, "{11111111-1111-1111-1111-111111111111}", "", "Force all DNS requests via Proton VPN", &["."]);
        another(&n.reg, LOCAL_RULES, "{22222222-2222-2222-2222-222222222222}", "corp", "", &[".corp.example"]);
        another(&n.reg, LOCAL_RULES, "{33333333-3333-3333-3333-333333333333}", "", "port1897", &["."]);
        another(&n.reg, POLICY_RULES, "{44444444-4444-4444-4444-444444444444}", "GP VPN", "from policy", &["."]);
        n.add("10.111.222.3".parse().unwrap()).unwrap();
        another(&n.reg, LOCAL_RULES, &RULE_KEY.to_lowercase().replace("4a0f", "4A0F"), "x", "y", &["."]);

        assert_eq!(n.others().unwrap(), [" (Force all DNS requests via Proton VPN)", "GP VPN (from policy)"]);
        n.remove().unwrap();
        assert_eq!(n.reg.subkeys(LOCAL_RULES).unwrap(), ["{11111111-1111-1111-1111-111111111111}", "{22222222-2222-2222-2222-222222222222}"]);
        // at a stop the nudge is waited for
        assert_eq!(*nudges.lock().unwrap(), [false, true]);
    }

    #[test]
    fn no_rules_key() {
        let (n, _) = nrpt();
        assert!(n.others().unwrap().is_empty());
        n.remove().unwrap();
    }

    #[test]
    fn our_rule_detection() {
        let r = |key: &str, comment: &str, display: &str| Rule { key: key.into(), comment: comment.into(), display: display.into(), names: vec![] };
        assert!(ours(&r(&RULE_KEY.to_lowercase(), "", "")));
        assert!(ours(&r("{x}", "AuroraVPN", "")));
        assert!(ours(&r("{x}", "", "port1897")));
        assert!(!ours(&r("{x}", "auroravpn", "")), "comments match exactly");
        assert!(!ours(&r("{x}", "Proton", "Proton")));
    }

    #[test]
    fn failures() {
        let tries = Arc::new(AtomicUsize::new(0));
        let t2 = tries.clone();
        let n = Nrpt::new(
            FakeRegistry::default(),
            Box::new(move |_| {
                t2.fetch_add(1, Ordering::SeqCst);
                Err("ipconfig /registerdns: The system cannot find the file specified.".into())
            }),
        );
        // the rule is in, the reload not confirmed: protection goes on
        let e = n.add("10.111.222.3".parse().unwrap()).unwrap_err();
        assert!(matches!(e, NrptError::NotApplied(_)));
        assert_eq!(e.to_string(), "dnspolicy: the DNS Client did not confirm the change: ipconfig /registerdns: The system cannot find the file specified.");
        assert_eq!(n.reg.subkeys(LOCAL_RULES).unwrap(), [RULE_KEY]);
        // remove deletes the rule and reports the nudge's failure
        assert!(n.remove().unwrap_err().contains("registerdns"));
        assert!(n.reg.subkeys(LOCAL_RULES).unwrap().is_empty());
        assert_eq!(tries.load(Ordering::SeqCst), 2);

        let (n, nudges) = nrpt();
        n.reg.deny.lock().unwrap().push(format!(r"{LOCAL_RULES}\{RULE_KEY}"));
        let e = n.add("10.111.222.3".parse().unwrap()).unwrap_err();
        assert_eq!(e, NrptError::Failed("dnspolicy: add: Access is denied.".into()));
        assert!(nudges.lock().unwrap().is_empty());
        another(&n.reg, LOCAL_RULES, "{55555555-5555-5555-5555-555555555555}", TAG, "", &["."]);
        n.reg.deny.lock().unwrap().push(format!(r"{LOCAL_RULES}\{{55555555-5555-5555-5555-555555555555}}"));
        assert_eq!(n.remove().unwrap_err(), "dnspolicy: remove {55555555-5555-5555-5555-555555555555}: Access is denied.");
    }
}
