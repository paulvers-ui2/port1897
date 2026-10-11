// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2020 RethinkDNS and its authors
//     Licensed under the Apache License, Version 2.0
//     (the firewall in BraveVPNService.kt of the Rethink Android app)

//! The firewall rules of the Android app, for Windows (a port of
//! cmd/fswin/rules_windows.go): a mode per app, IP and domain rules (for one
//! app or all of them), the universal rules, allowed DNS query types and
//! pause. The app window owns the rules; it hands the engine the whole set
//! at start (-rules file) and on every change (POST /api/rules).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

use crate::gojson::{self, JValue, Obj};
use crate::golike::{self, quote};
use crate::netaddr::{self, Prefix};

// App modes, as on the Android app's App info screen.
pub const MODE_NONE: &str = "";
pub const MODE_ALLOW: &str = "allow";
pub const MODE_BLOCK: &str = "block";
/// block all but trusted IPs and domains
pub const MODE_ISOLATE: &str = "isolate";
/// "Bypass DNS & Firewall"
pub const MODE_BYPASS: &str = "bypass";
/// skip the universal rules only
pub const MODE_BYPASS_UNIVERSAL: &str = "bypassUniversal";
/// not firewalled, never proxied
pub const MODE_EXCLUDE: &str = "exclude";

/// The reason given for flows "Allow outgoing only" lets through; the app
/// window whitelists their programs when it sees it.
pub const RULE_OUTGOING_ALLOWED: &str = "universal: outgoing allowed";

// Rule actions.
pub const ACT_BLOCK: &str = "block";
/// allow, skipping every later rule
pub const ACT_TRUST: &str = "trust";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppRule {
    pub mode: String,
    /// unix millis: "Allow for 15 minutes"
    pub allow_until: i64,
    /// "Bypass app from all proxies"
    pub no_proxy: bool,
    /// a per-app route (routes_windows.go) instead of the exit
    pub route: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpRule {
    /// exe name or path; "" for all apps
    pub app: String,
    /// 1.2.3.4, 1.2.3.0/24, 1.2.3.*, or * for any
    pub ip: String,
    pub port: i64,
    pub action: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainRule {
    pub app: String,
    /// example.com, or *.example.com for it and its subdomains
    pub domain: String,
    pub action: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UniversalRules {
    /// block UDP except DNS (53) and NTP (123)
    pub udp: bool,
    /// block ping
    pub icmp: bool,
    /// block TCP port 80
    pub http: bool,
    /// block when the program is unknown
    pub unknown: bool,
    /// block IPs that were not looked up through the app
    pub dns_bypass: bool,
    /// block programs not seen before
    pub new_apps: bool,
    /// block everything while Windows is locked
    pub locked: bool,
    /// block all but bypassed apps and trusted IPs
    pub lockdown: bool,
    /// allows every outgoing connection the rules above it do not block,
    /// and blocks incoming ones; the app window then sets each program it
    /// allowed to Bypass Universal, so it stays allowed
    pub outgoing_only: bool,
}

/// The JSON the app sends.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleSet {
    pub apps: HashMap<String, AppRule>,
    pub ips: Vec<IpRule>,
    pub domains: Vec<DomainRule>,
    pub universal: UniversalRules,
    /// programs seen before, for NewApps
    pub known: Vec<String>,
    /// allowed DNS query types; empty: all
    pub dns_types: Vec<i64>,
    pub paused_until: i64,
    pub screen_locked: bool,
}

impl RuleSet {
    /// Reads the rule set from JSON as Go's json package fills ruleSet.
    pub fn from_json(v: &JValue) -> Result<RuleSet, String> {
        let mut rs = RuleSet::default();
        let Some(o) = Obj::of(v, "ruleSet")? else {
            return Ok(rs);
        };
        for (k, v) in o.map("apps", "map[string]main.appRule")? {
            let mut a = AppRule::default();
            if let Some(ao) = o.elem("apps", v, "main.appRule")? {
                a.mode = ao.string("mode")?;
                a.allow_until = ao.int("allowUntil")?;
                a.no_proxy = ao.bool("noProxy")?;
                a.route = ao.string("route")?;
            }
            rs.apps.insert(k.clone(), a);
        }
        for v in o.array("ips", "[]main.ipRule")? {
            let mut r = IpRule::default();
            if let Some(io) = o.elem("ips", v, "main.ipRule")? {
                r.app = io.string("app")?;
                r.ip = io.string("ip")?;
                r.port = io.int("port")?;
                r.action = io.string("action")?;
            }
            rs.ips.push(r);
        }
        for v in o.array("domains", "[]main.domainRule")? {
            let mut r = DomainRule::default();
            if let Some(dobj) = o.elem("domains", v, "main.domainRule")? {
                r.app = dobj.string("app")?;
                r.domain = dobj.string("domain")?;
                r.action = dobj.string("action")?;
            }
            rs.domains.push(r);
        }
        if let Some(u) = o.obj("universal", "main.universalRules")? {
            rs.universal = UniversalRules {
                udp: u.bool("udp")?,
                icmp: u.bool("icmp")?,
                http: u.bool("http")?,
                unknown: u.bool("unknown")?,
                dns_bypass: u.bool("dnsBypass")?,
                new_apps: u.bool("newApps")?,
                locked: u.bool("locked")?,
                lockdown: u.bool("lockdown")?,
                outgoing_only: u.bool("outgoingOnly")?,
            };
        }
        for v in o.array("known", "[]string")? {
            rs.known.push(o.elem_string("known", v)?);
        }
        for v in o.array("dnsTypes", "[]int")? {
            rs.dns_types.push(o.elem_int("dnsTypes", v)?);
        }
        rs.paused_until = o.int("pausedUntil")?;
        rs.screen_locked = o.bool("screenLocked")?;
        Ok(rs)
    }
}

#[derive(Debug, Clone)]
struct CIpRule {
    /// lowercased; "" for all
    app: String,
    any: bool,
    pfx: Option<Prefix>,
    port: u16,
    block: bool,
    text: String,
}

#[derive(Debug, Clone)]
struct CDomainRule {
    app: String,
    /// lowercased, no trailing dot or "*."
    name: String,
    /// also matches subdomains
    wild: bool,
    block: bool,
    text: String,
}

impl CDomainRule {
    fn matches(&self, d: &str) -> bool {
        if d == self.name {
            return true;
        }
        self.wild && d.len() > self.name.len() && d.ends_with(&self.name) && d.as_bytes()[d.len() - self.name.len() - 1] == b'.'
    }
}

/// A rule set compiled for matching. It is never changed once built;
/// updates swap in a new one.
#[derive(Debug, Clone)]
pub struct Rules {
    src: RuleSet,
    /// lowercased exe name or full path
    apps: HashMap<String, AppRule>,
    ips: Vec<CIpRule>,
    domains: Vec<CDomainRule>,
    u: UniversalRules,
    known: HashSet<String>,
    dns_types: HashSet<i64>,
    paused: i64,
    locked: bool,
}

impl Default for Rules {
    fn default() -> Self {
        compile(RuleSet::default()).0
    }
}

/// Compiles rs. Rules that do not parse are skipped; the second value then
/// says why, one line per rule (Go's errors.Join).
pub fn compile(rs: RuleSet) -> (Rules, Option<String>) {
    let mut r = Rules {
        src: RuleSet::default(),
        apps: HashMap::new(),
        ips: Vec::new(),
        domains: Vec::new(),
        u: rs.universal,
        known: HashSet::new(),
        dns_types: HashSet::new(),
        paused: rs.paused_until,
        locked: rs.screen_locked,
    };
    let mut errs: Vec<String> = Vec::new();
    for (k, v) in &rs.apps {
        let k = golike::to_lower(golike::trim_space(k));
        if !k.is_empty() {
            r.apps.insert(k, v.clone());
        }
    }
    for k in &rs.known {
        r.known.insert(golike::to_lower(golike::trim_space(k)));
    }
    r.dns_types.extend(rs.dns_types.iter().copied());
    for ir in &rs.ips {
        match compile_ip_rule(ir) {
            Ok(c) => r.ips.push(c),
            Err(e) => errs.push(e),
        }
    }
    for dr in &rs.domains {
        let name = golike::to_lower(golike::trim_suffix(golike::trim_space(&dr.domain), "."));
        let wild = name.starts_with("*.");
        let name = golike::trim_prefix(&name, "*.").to_string();
        if name.is_empty() || name.contains([' ', '/', ':', '*']) {
            errs.push(format!("domain rule {}: not a domain", quote(&dr.domain)));
            continue;
        }
        r.domains.push(CDomainRule {
            app: golike::to_lower(golike::trim_space(&dr.app)),
            name,
            wild,
            block: dr.action == ACT_BLOCK,
            text: dr.domain.clone(),
        });
    }
    r.src = rs;
    let err = (!errs.is_empty()).then(|| errs.join("\n"));
    (r, err)
}

/// Accepts an address, a CIDR, octet wildcards like 10.1.*.* (or 10.1.*)
/// or * for any address.
fn compile_ip_rule(ir: &IpRule) -> Result<CIpRule, String> {
    let mut c = CIpRule {
        app: golike::to_lower(golike::trim_space(&ir.app)),
        any: false,
        pfx: None,
        port: 0,
        block: ir.action == ACT_BLOCK,
        text: ir.ip.clone(),
    };
    if ir.port < 0 || ir.port > 65535 {
        return Err(format!("ip rule {}: bad port {}", quote(&ir.ip), ir.port));
    }
    c.port = ir.port as u16;
    let mut s = golike::trim_space(&ir.ip).to_string();
    if s.is_empty() || s == "*" || s == "*.*" || s == "*.*.*.*" {
        c.any = true;
        if c.port == 0 {
            return Err("ip rule: any address needs a port".to_string());
        }
        return Ok(c);
    }
    if s.contains('*') {
        let parts: Vec<&str> = s.split('.').collect();
        let mut fixed: Vec<&str> = parts.iter().copied().take_while(|p| *p != "*").collect();
        if parts.len() > 4 || fixed.is_empty() {
            return Err(format!("ip rule {}: bad wildcard", quote(&ir.ip)));
        }
        let bits = 8 * fixed.len();
        while fixed.len() < 4 {
            fixed.push("0");
        }
        s = format!("{}/{bits}", fixed.join("."));
    }
    if s.contains('/') {
        let p = Prefix::parse(&s).map_err(|e| format!("ip rule {}: {e}", quote(&ir.ip)))?;
        c.pfx = Some(p.masked());
    } else {
        let Some(ip) = netaddr::parse_addr(&s) else {
            return Err(format!("ip rule {}: ParseAddr({}): unable to parse IP", quote(&ir.ip), quote(&s)));
        };
        let ip = netaddr::unmap(ip);
        // [::]:80 or 0.0.0.0:80: any address of that family
        let bits = if ip.is_unspecified() { 0 } else { netaddr::bit_len(ip) };
        c.pfx = Prefix::new(ip, bits);
    }
    Ok(c)
}

/// Reads a rules file: an error if it is not a rule set at all; else the
/// rules, and why some were skipped.
pub fn load(data: &[u8]) -> Result<(Rules, Option<String>), String> {
    let v = gojson::unmarshal(data)?;
    let rs = RuleSet::from_json(&v)?;
    Ok(compile(rs))
}

/// The keys an app's rules may be stored under: the full path and the exe
/// name, lowercased.
pub fn app_keys(path: &str) -> (String, String) {
    (golike::to_lower(path), golike::to_lower(&golike::base(path)))
}

fn rule_applies(rule_app: &str, full: &str, exe: &str) -> bool {
    rule_app == full || rule_app == exe
}

/// What the rules say about one flow.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Decision {
    pub block: bool,
    /// leave directly, not through the VPN exit
    pub no_proxy: bool,
    /// leave through this per-app route, if loaded
    pub route: String,
    /// the rule that decided, for the logs
    pub why: String,
}

/// LAN, loopback, link-local and multicast addresses, which never come from
/// DNS lookups.
pub fn is_local_addr(ip: Option<IpAddr>) -> bool {
    let Some(ip) = ip else { return false };
    let ip = netaddr::unmap(ip);
    netaddr::is_private(ip)
        || netaddr::is_loopback(ip)
        || netaddr::is_link_local_unicast(ip)
        || netaddr::is_link_local_multicast(ip)
        || netaddr::is_multicast(ip)
        || netaddr::is_unspecified(ip)
}

impl Rules {
    /// The rule set these were compiled from.
    pub fn source(&self) -> &RuleSet {
        &self.src
    }

    /// The compiled app rules, by lowercased exe name or path.
    pub fn apps(&self) -> &HashMap<String, AppRule> {
        &self.apps
    }

    /// The app's own rule: by full path first, then by exe name.
    pub fn app(&self, path: &str) -> AppRule {
        if path.is_empty() {
            return AppRule::default();
        }
        let (full, exe) = app_keys(path);
        if let Some(a) = self.apps.get(&full) {
            return a.clone();
        }
        self.apps.get(&exe).cloned().unwrap_or_default()
    }

    pub fn is_paused(&self, now_ms: i64) -> bool {
        self.paused > now_ms
    }

    /// Until when protection is paused (unix millis), as given.
    pub fn paused_until(&self) -> i64 {
        self.paused
    }

    /// Whether connections coming in through the tunnel are refused: "Allow
    /// outgoing only", unless protection is paused.
    pub fn blocks_incoming(&self, now_ms: i64) -> bool {
        self.u.outgoing_only && !self.is_paused(now_ms)
    }

    /// The first IP rule for the app (for_app) or for all apps that matches
    /// dst: (block, found, the rule's text).
    fn ip_verdict(&self, for_app: bool, full: &str, exe: &str, dst: Option<SocketAddr>) -> (bool, bool, String) {
        let ip = dst.map(|d| netaddr::unmap(d.ip()));
        let port = dst.map(|d| d.port()).unwrap_or(0);
        for c in &self.ips {
            if for_app {
                if c.app.is_empty() || !rule_applies(&c.app, full, exe) {
                    continue;
                }
            } else if !c.app.is_empty() {
                continue;
            }
            if c.port != 0 && c.port != port {
                continue;
            }
            if !c.any {
                let inside = match (c.pfx, ip) {
                    (Some(p), Some(ip)) => p.contains(ip),
                    _ => false,
                };
                if !inside {
                    continue;
                }
            }
            return (c.block, true, c.text.clone());
        }
        (false, false, String::new())
    }

    /// ip_verdict for domain rules; block rules win over trust rules when
    /// several domains match.
    fn domain_verdict(&self, for_app: bool, full: &str, exe: &str, domains: &[String]) -> (bool, bool, String) {
        let (mut found, mut why) = (false, String::new());
        for c in &self.domains {
            if for_app {
                if c.app.is_empty() || !rule_applies(&c.app, full, exe) {
                    continue;
                }
            } else if !c.app.is_empty() {
                continue;
            }
            for d in domains {
                if !c.matches(d) {
                    continue;
                }
                if c.block {
                    return (true, true, c.text.clone());
                }
                found = true;
                why = c.text.clone();
            }
        }
        (false, found, why)
    }

    /// The rules for all apps applied to a DNS query: blocked query types
    /// and blocked domains are answered by BlockAll; trusted domains skip
    /// on-device blocklists. Returns (block, trust, why).
    pub fn dns_verdict(&self, domain: &str, qtype: i64, now_ms: i64) -> (bool, bool, String) {
        if self.is_paused(now_ms) {
            return (false, false, String::new());
        }
        if !self.dns_types.is_empty() && !self.dns_types.contains(&qtype) {
            return (true, false, format!("query type {qtype} not allowed"));
        }
        let d = golike::to_lower(golike::trim_suffix(domain, "."));
        let (block, found, rule) = self.domain_verdict(false, "", "", &[d]);
        if !found {
            return (false, false, String::new());
        }
        if block {
            return (true, false, format!("domain rule {rule}"));
        }
        (false, true, format!("trusted {rule}"))
    }

    /// The Android app's firewall order: exclusions and bypasses, pause, the
    /// app's own IP and domain rules, isolation, the global domain and IP
    /// rules, the app's block, and last the universal rules.
    pub fn decide(
        &self,
        protocol: i32,
        path: &str,
        known: bool,
        dst: Option<SocketAddr>,
        domains: &[String],
        now_ms: i64,
    ) -> Decision {
        let (full, exe) = app_keys(path);
        let a = self.app(path);
        let temp_allowed = a.allow_until > now_ms;

        match a.mode.as_str() {
            MODE_EXCLUDE => return Decision { no_proxy: true, why: "app excluded".into(), ..Default::default() },
            MODE_BYPASS => {
                return Decision {
                    no_proxy: a.no_proxy,
                    route: a.route.clone(),
                    why: "app bypasses DNS & firewall".into(),
                    ..Default::default()
                };
            }
            _ => {}
        }
        let allow = |why: String| Decision { no_proxy: a.no_proxy, route: a.route.clone(), why, block: false };
        let blocked = |why: String| Decision { block: true, why, ..Default::default() };

        if self.is_paused(now_ms) {
            if a.mode == MODE_BLOCK && !temp_allowed {
                return blocked("app blocked (paused)".into());
            }
            return allow("paused".into());
        }

        if !path.is_empty() {
            let (block, found, rule) = self.ip_verdict(true, &full, &exe, dst);
            if found {
                return if block { blocked(format!("app IP rule {rule}")) } else { allow(format!("app trusts IP {rule}")) };
            }
            let (block, found, rule) = self.domain_verdict(true, &full, &exe, domains);
            if found {
                return if block {
                    blocked(format!("app domain rule {rule}"))
                } else {
                    allow(format!("app trusts domain {rule}"))
                };
            }
        }
        if a.mode == MODE_ISOLATE && !temp_allowed {
            return blocked("app isolated".into());
        }
        let (block, found, rule) = self.domain_verdict(false, "", "", domains);
        if found {
            return if block { blocked(format!("domain rule {rule}")) } else { allow(format!("trusted domain {rule}")) };
        }
        let (block, found, rule) = self.ip_verdict(false, "", "", dst);
        if found {
            return if block { blocked(format!("IP rule {rule}")) } else { allow(format!("trusted IP {rule}")) };
        }
        if a.mode == MODE_BLOCK && !temp_allowed {
            return blocked("app blocked".into());
        }
        if a.mode == MODE_BYPASS_UNIVERSAL {
            return allow("app bypasses universal rules".into());
        }

        let u = &self.u;
        let port = dst.map(|d| d.port()).unwrap_or(0);
        if u.lockdown {
            return blocked("universal: lockdown".into());
        }
        if u.locked && self.locked {
            return blocked("universal: PC locked".into());
        }
        if u.outgoing_only {
            // every program may connect out; the rules below would only block it
            return allow(RULE_OUTGOING_ALLOWED.into());
        }
        if u.unknown && path.is_empty() {
            return blocked("universal: unknown app".into());
        }
        if u.new_apps && !path.is_empty() && a.mode == MODE_NONE && !known {
            return blocked("universal: new app".into());
        }
        if u.icmp && (protocol == 1 || protocol == 58) {
            return blocked("universal: ICMP".into());
        }
        if u.udp && protocol == 17 && port != 53 && port != 123 {
            return blocked("universal: UDP".into());
        }
        if u.http && protocol == 6 && port == 80 {
            return blocked("universal: HTTP (port 80)".into());
        }
        if u.dns_bypass && domains.is_empty() && !is_local_addr(dst.map(|d| d.ip())) {
            return blocked("universal: DNS bypassed".into());
        }
        allow(String::new())
    }

    /// Whether a program was seen before, for "Block newly installed apps":
    /// listed in the app's known list.
    pub fn known_app(&self, path: &str) -> bool {
        let (full, exe) = app_keys(path);
        self.known.contains(&exe) || self.known.contains(&full)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: i32 = 6;
    const UDP: i32 = 17;
    const ICMP: i32 = 1;

    fn must_rules(rs: RuleSet) -> Rules {
        let (r, err) = compile(rs);
        assert_eq!(err, None, "compile");
        r
    }

    fn ap(s: &str) -> Option<SocketAddr> {
        Some(netaddr::parse_addr_port(s).unwrap())
    }

    fn now() -> i64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
    }

    fn apps(list: &[(&str, &str)]) -> HashMap<String, AppRule> {
        list.iter().map(|(k, m)| (k.to_string(), AppRule { mode: m.to_string(), ..Default::default() })).collect()
    }

    fn doms(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    // TestOutgoingOnly: "Allow outgoing only" lets every program connect
    // out, even with the universal rules that would block it, but never
    // overrides what the user chose for an app, the global IP and domain
    // rules, Lockdown or "PC locked".
    #[test]
    fn outgoing_only() {
        let now = now();
        let web = ap("93.184.215.14:443");
        let strict = UniversalRules {
            udp: true,
            icmp: true,
            http: true,
            unknown: true,
            dns_bypass: true,
            new_apps: true,
            outgoing_only: true,
            ..Default::default()
        };
        struct Case {
            name: &'static str,
            rs: RuleSet,
            protocol: i32,
            path: &'static str,
            dst: Option<SocketAddr>,
            domains: Vec<String>,
            want_block: bool,
            want_why: &'static str,
        }
        let rs = |u: UniversalRules| RuleSet { universal: u, ..Default::default() };
        let cases = vec![
            Case { name: "a new app, every universal block on", rs: rs(strict), protocol: TCP, path: r"C:\new\app.exe", dst: web, domains: vec![], want_block: false, want_why: RULE_OUTGOING_ALLOWED },
            Case { name: "an unknown program", rs: rs(strict), protocol: TCP, path: "", dst: web, domains: vec![], want_block: false, want_why: RULE_OUTGOING_ALLOWED },
            Case { name: "UDP, ping and port 80", rs: rs(strict), protocol: UDP, path: r"C:\a.exe", dst: ap("1.1.1.1:443"), domains: vec![], want_block: false, want_why: RULE_OUTGOING_ALLOWED },
            Case { name: "ping", rs: rs(strict), protocol: ICMP, path: r"C:\a.exe", dst: ap("1.1.1.1:0"), domains: vec![], want_block: false, want_why: RULE_OUTGOING_ALLOWED },
            Case { name: "an app the user blocked", rs: RuleSet { universal: strict, apps: apps(&[("app.exe", MODE_BLOCK)]), ..Default::default() }, protocol: TCP, path: r"C:\x\app.exe", dst: web, domains: vec![], want_block: true, want_why: "app blocked" },
            Case { name: "an isolated app", rs: RuleSet { universal: strict, apps: apps(&[("app.exe", MODE_ISOLATE)]), ..Default::default() }, protocol: TCP, path: r"C:\x\app.exe", dst: web, domains: vec![], want_block: true, want_why: "app isolated" },
            Case { name: "a blocked domain", rs: RuleSet { universal: strict, domains: vec![DomainRule { domain: "ads.example".into(), action: ACT_BLOCK.into(), ..Default::default() }], ..Default::default() }, protocol: TCP, path: r"C:\a.exe", dst: web, domains: doms(&["ads.example"]), want_block: true, want_why: "domain rule ads.example" },
            Case { name: "a blocked IP", rs: RuleSet { universal: strict, ips: vec![IpRule { ip: "93.184.215.14".into(), action: ACT_BLOCK.into(), ..Default::default() }], ..Default::default() }, protocol: TCP, path: r"C:\a.exe", dst: web, domains: vec![], want_block: true, want_why: "IP rule 93.184.215.14" },
            Case { name: "lockdown still wins", rs: rs(UniversalRules { outgoing_only: true, lockdown: true, ..Default::default() }), protocol: TCP, path: r"C:\a.exe", dst: web, domains: vec![], want_block: true, want_why: "universal: lockdown" },
            Case { name: "off: the universal rules apply again", rs: rs(UniversalRules { new_apps: true, ..Default::default() }), protocol: TCP, path: r"C:\new\app.exe", dst: web, domains: vec![], want_block: true, want_why: "universal: new app" },
        ];
        for c in cases {
            let r = must_rules(c.rs);
            let d = r.decide(c.protocol, c.path, false, c.dst, &c.domains, now);
            assert_eq!(d.block, c.want_block, "{}: block ({})", c.name, d.why);
            if !c.want_why.is_empty() {
                assert_eq!(d.why, c.want_why, "{}", c.name);
            }
        }

        // "PC locked" needs the screen locked too
        let r = must_rules(RuleSet {
            universal: UniversalRules { outgoing_only: true, locked: true, ..Default::default() },
            screen_locked: true,
            ..Default::default()
        });
        let d = r.decide(TCP, r"C:\a.exe", false, web, &[], now);
        assert!(d.block && d.why == "universal: PC locked", "{d:?}");
    }

    #[test]
    fn order_of_the_rules() {
        let now = now();
        let web = ap("93.184.215.14:443");
        let path = r"C:\Apps\Chrome.exe";
        let mut rs = RuleSet {
            apps: apps(&[("chrome.exe", MODE_BLOCK)]),
            ips: vec![
                IpRule { app: "CHROME.EXE".into(), ip: "93.184.215.0/24".into(), action: ACT_TRUST.into(), ..Default::default() },
                IpRule { ip: "93.184.215.14".into(), action: ACT_BLOCK.into(), ..Default::default() },
            ],
            ..Default::default()
        };
        // the app's own trust beats its block and the global IP block
        let d = must_rules(rs.clone()).decide(TCP, path, false, web, &[], now);
        assert_eq!((d.block, d.why.as_str()), (false, "app trusts IP 93.184.215.14".replace(".14", ".0/24").as_str()));

        // without it, the global IP rule decides before the app's block
        rs.ips.remove(0);
        let d = must_rules(rs.clone()).decide(TCP, path, false, web, &[], now);
        assert_eq!((d.block, d.why.as_str()), (true, "IP rule 93.184.215.14"));

        // and without that, the app's block
        rs.ips.clear();
        let d = must_rules(rs.clone()).decide(TCP, path, false, web, &[], now);
        assert_eq!((d.block, d.why.as_str()), (true, "app blocked"));

        // "Allow for 15 minutes" lifts the block
        rs.apps.get_mut("chrome.exe").unwrap().allow_until = now + 60_000;
        let d = must_rules(rs.clone()).decide(TCP, path, false, web, &[], now);
        assert!(!d.block, "{d:?}");

        // a full-path rule beats the exe name's
        rs.apps.insert(r"c:\apps\chrome.exe".into(), AppRule { mode: MODE_EXCLUDE.into(), ..Default::default() });
        let d = must_rules(rs.clone()).decide(TCP, path, false, web, &[], now);
        assert_eq!(d, Decision { no_proxy: true, why: "app excluded".into(), ..Default::default() });

        // bypass keeps the app's proxy choice and route
        let rs = RuleSet {
            apps: [("x.exe".to_string(), AppRule { mode: MODE_BYPASS.into(), no_proxy: true, route: "wgapp1".into(), ..Default::default() })].into(),
            universal: UniversalRules { lockdown: true, ..Default::default() },
            ..Default::default()
        };
        let d = must_rules(rs).decide(TCP, r"C:\x.exe", false, web, &[], now);
        assert_eq!(d, Decision { no_proxy: true, route: "wgapp1".into(), why: "app bypasses DNS & firewall".into(), block: false });
    }

    #[test]
    fn pause() {
        let now = now();
        let rs = RuleSet {
            apps: apps(&[("bad.exe", MODE_BLOCK)]),
            universal: UniversalRules { lockdown: true, outgoing_only: true, ..Default::default() },
            domains: vec![DomainRule { domain: "ads.example".into(), action: ACT_BLOCK.into(), ..Default::default() }],
            dns_types: vec![1],
            paused_until: now + 3_600_000,
            ..Default::default()
        };
        let r = must_rules(rs);
        let web = ap("1.1.1.1:443");
        assert_eq!(r.decide(TCP, r"C:\ok.exe", false, web, &[], now).why, "paused");
        let d = r.decide(TCP, r"C:\bad.exe", false, web, &[], now);
        assert_eq!((d.block, d.why.as_str()), (true, "app blocked (paused)"));
        assert!(!r.blocks_incoming(now));
        assert_eq!(r.dns_verdict("ads.example.", 28, now), (false, false, String::new()));
        assert!(r.blocks_incoming(now + 3_600_001));
    }

    #[test]
    fn universal_rules() {
        let now = now();
        let u = UniversalRules { udp: true, icmp: true, http: true, unknown: true, dns_bypass: true, new_apps: true, ..Default::default() };
        let r = must_rules(RuleSet { universal: u, known: vec![r" C:\Known\App.exe ".into()], ..Default::default() });
        let why = |p: i32, path: &str, known: bool, dst: &str, d: &[&str]| {
            let d = r.decide(p, path, known, ap(dst), &doms(d), now);
            if d.block { d.why } else { String::from("allowed") }
        };
        assert_eq!(why(TCP, "", false, "1.1.1.1:443", &["a.com"]), "universal: unknown app");
        assert_eq!(why(TCP, r"C:\new.exe", false, "1.1.1.1:443", &["a.com"]), "universal: new app");
        assert!(r.known_app(r"c:\known\app.exe"));
        assert!(!r.known_app(r"C:\Other\App.exe"), "the known list holds a full path here");
        assert_eq!(why(ICMP, r"C:\k.exe", true, "1.1.1.1:0", &["a.com"]), "universal: ICMP");
        assert_eq!(why(58, r"C:\k.exe", true, "[2001:db8::1]:0", &["a.com"]), "universal: ICMP");
        assert_eq!(why(UDP, r"C:\k.exe", true, "1.1.1.1:443", &["a.com"]), "universal: UDP");
        assert_eq!(why(UDP, r"C:\k.exe", true, "1.1.1.1:53", &["a.com"]), "allowed");
        assert_eq!(why(UDP, r"C:\k.exe", true, "1.1.1.1:123", &["a.com"]), "allowed");
        assert_eq!(why(TCP, r"C:\k.exe", true, "1.1.1.1:80", &["a.com"]), "universal: HTTP (port 80)");
        assert_eq!(why(TCP, r"C:\k.exe", true, "1.1.1.1:443", &[]), "universal: DNS bypassed");
        assert_eq!(why(TCP, r"C:\k.exe", true, "192.168.1.10:443", &[]), "allowed");
        assert_eq!(why(TCP, r"C:\k.exe", true, "[::ffff:10.0.0.1]:443", &[]), "allowed");
        assert_eq!(why(TCP, r"C:\k.exe", true, "[ff02::fb]:5353", &[]), "allowed");
        // an unparsable destination is no local address
        assert!(r.decide(TCP, r"C:\k.exe", true, None, &[], now).block);
        // an app given any mode is not new
        let r2 = must_rules(RuleSet { universal: u, apps: apps(&[("new.exe", MODE_ALLOW)]), ..Default::default() });
        assert!(!r2.decide(TCP, r"C:\new.exe", false, ap("1.1.1.1:443"), &doms(&["a.com"]), now).block);
    }

    #[test]
    fn ip_rules_compile() {
        let (r, err) = compile(RuleSet {
            ips: vec![
                IpRule { ip: "10.1.*".into(), action: ACT_BLOCK.into(), ..Default::default() },
                IpRule { ip: "172.16.*.*".into(), action: ACT_BLOCK.into(), ..Default::default() },
                IpRule { ip: "*".into(), port: 8443, action: ACT_BLOCK.into(), ..Default::default() },
                IpRule { ip: "0.0.0.0".into(), port: 25, action: ACT_BLOCK.into(), ..Default::default() },
                IpRule { ip: "2001:db8::/32".into(), action: ACT_BLOCK.into(), ..Default::default() },
                IpRule { ip: "::ffff:9.9.9.9".into(), action: ACT_BLOCK.into(), ..Default::default() },
                IpRule { ip: "8.8.8.8".into(), port: 53, action: ACT_TRUST.into(), ..Default::default() },
                IpRule { ip: "8.8.8.0/24".into(), action: ACT_BLOCK.into(), ..Default::default() },
                // skipped:
                IpRule { ip: "*".into(), action: ACT_BLOCK.into(), ..Default::default() },
                IpRule { ip: "*.1".into(), action: ACT_BLOCK.into(), ..Default::default() },
                IpRule { ip: "1.2.3.4.*".into(), action: ACT_BLOCK.into(), ..Default::default() },
                IpRule { ip: "*.*.*".into(), action: ACT_BLOCK.into(), ..Default::default() },
                IpRule { ip: "1.2.3.4".into(), port: 70000, action: ACT_BLOCK.into(), ..Default::default() },
                IpRule { ip: "1.2.3.4/33".into(), action: ACT_BLOCK.into(), ..Default::default() },
                IpRule { ip: "example.com".into(), action: ACT_BLOCK.into(), ..Default::default() },
            ],
            ..Default::default()
        });
        let err = err.unwrap();
        let lines: Vec<&str> = err.lines().collect();
        assert_eq!(lines.len(), 7, "{err}");
        assert_eq!(lines[0], "ip rule: any address needs a port");
        assert_eq!(lines[1], "ip rule \"*.1\": bad wildcard");
        assert_eq!(lines[2], "ip rule \"1.2.3.4.*\": bad wildcard");
        assert_eq!(lines[3], "ip rule \"*.*.*\": bad wildcard");
        assert_eq!(lines[4], "ip rule \"1.2.3.4\": bad port 70000");
        assert!(lines[5].starts_with("ip rule \"1.2.3.4/33\": netip.ParsePrefix(\"1.2.3.4/33\"): prefix length out of range"), "{}", lines[5]);
        assert!(lines[6].starts_with("ip rule \"example.com\": "), "{}", lines[6]);

        let now = now();
        let why = |dst: &str| {
            let d = r.decide(TCP, r"C:\a.exe", true, ap(dst), &doms(&["x.com"]), now);
            (d.block, d.why)
        };
        assert_eq!(why("10.1.200.3:443"), (true, "IP rule 10.1.*".into()));
        assert_eq!(why("10.2.0.1:443"), (false, String::new()));
        assert_eq!(why("172.16.9.9:443"), (true, "IP rule 172.16.*.*".into()));
        assert_eq!(why("5.5.5.5:8443"), (true, "IP rule *".into()));
        assert_eq!(why("[2001:4860::1]:8443"), (true, "IP rule *".into()));
        assert_eq!(why("5.5.5.5:25"), (true, "IP rule 0.0.0.0".into()));
        assert_eq!(why("[2001:4860::1]:25"), (false, String::new()), "0.0.0.0 is IPv4 only");
        assert_eq!(why("[2001:db8:1::5]:443"), (true, "IP rule 2001:db8::/32".into()));
        assert_eq!(why("9.9.9.9:443"), (true, "IP rule ::ffff:9.9.9.9".into()));
        assert_eq!(why("[::ffff:9.9.9.9]:443"), (true, "IP rule ::ffff:9.9.9.9".into()));
        assert_eq!(why("8.8.8.8:53"), (false, "trusted IP 8.8.8.8".into()), "the first match decides");
        assert_eq!(why("8.8.8.8:443"), (true, "IP rule 8.8.8.0/24".into()));
    }

    #[test]
    fn domain_rules() {
        let now = now();
        let (r, err) = compile(RuleSet {
            domains: vec![
                DomainRule { domain: " *.Example.COM. ".into(), action: ACT_BLOCK.into(), ..Default::default() },
                DomainRule { domain: "safe.example.com".into(), action: ACT_TRUST.into(), ..Default::default() },
                DomainRule { domain: "trusted.org".into(), action: ACT_TRUST.into(), ..Default::default() },
                DomainRule { app: "mail.exe".into(), domain: "tracker.net".into(), action: ACT_BLOCK.into() },
                DomainRule { domain: "".into(), action: ACT_BLOCK.into(), ..Default::default() },
                DomainRule { domain: "*.".into(), action: ACT_BLOCK.into(), ..Default::default() },
                DomainRule { domain: "a b.com".into(), action: ACT_BLOCK.into(), ..Default::default() },
                DomainRule { domain: "x.*.com".into(), action: ACT_BLOCK.into(), ..Default::default() },
            ],
            dns_types: vec![1, 28],
            ..Default::default()
        });
        assert_eq!(err.unwrap().lines().count(), 4);
        // block beats trust when several match
        let d = r.decide(TCP, r"C:\a.exe", true, ap("1.1.1.1:443"), &doms(&["safe.example.com", "example.com"]), now);
        assert_eq!((d.block, d.why.as_str()), (true, "domain rule  *.Example.COM. "));
        let d = r.decide(TCP, r"C:\a.exe", true, ap("1.1.1.1:443"), &doms(&["notexample.com"]), now);
        assert!(!d.block);
        let d = r.decide(TCP, r"C:\a.exe", true, ap("1.1.1.1:443"), &doms(&["trusted.org"]), now);
        assert_eq!((d.block, d.why.as_str()), (false, "trusted domain trusted.org"));
        // app-only rules apply only to that app, and before isolation
        let d = r.decide(TCP, r"C:\Mail\MAIL.exe", true, ap("1.1.1.1:443"), &doms(&["tracker.net"]), now);
        assert_eq!((d.block, d.why.as_str()), (true, "app domain rule tracker.net"));
        let d = r.decide(TCP, r"C:\other.exe", true, ap("1.1.1.1:443"), &doms(&["tracker.net"]), now);
        assert!(!d.block);
        // DNS: types, then the rules for all apps
        assert_eq!(r.dns_verdict("Sub.Example.com.", 1, now), (true, false, "domain rule  *.Example.COM. ".into()));
        assert_eq!(r.dns_verdict("trusted.org", 28, now), (false, true, "trusted trusted.org".into()));
        assert_eq!(r.dns_verdict("tracker.net", 1, now), (false, false, String::new()));
        assert_eq!(r.dns_verdict("a.org", 65, now), (true, false, "query type 65 not allowed".into()));
    }

    #[test]
    fn rules_from_json_like_go() {
        let json = br#"{"apps":{"Chrome.exe":{"mode":"block"},"x.exe":null},
            "IPS":[{"app":"chrome.exe","ip":"1.2.3.0/24","port":443,"action":"block"},null],
            "domains":null,"universal":{"udp":true,"OutgoingOnly":true},
            "known":["C:\\a.exe",null],"dnsTypes":[1,28,null],"pausedUntil":1,"screenLocked":true,"other":[1,2]}"#;
        let (r, err) = load(json).unwrap();
        assert_eq!(err.unwrap(), "ip rule: any address needs a port", "the null rule is a zero rule");
        let src = r.source();
        assert_eq!(src.apps.len(), 2);
        assert_eq!(src.apps["x.exe"], AppRule::default());
        assert_eq!(src.ips.len(), 2);
        assert!(src.universal.udp && src.universal.outgoing_only);
        assert_eq!(src.known, vec![r"C:\a.exe".to_string(), String::new()]);
        assert_eq!(src.dns_types, vec![1, 28, 0]);
        assert_eq!(src.paused_until, 1);
        assert!(src.screen_locked);
        assert_eq!(r.app(r"D:\x\chrome.EXE").mode, MODE_BLOCK);

        assert!(load(b"{\"ips\":[{\"port\":\"443\"}]}").is_err());
        assert!(load(b"{\"apps\":[]}").is_err());
        assert!(load(b"[]").is_err());
        assert!(load(b"").is_err());
        let (r, err) = load(b"null").unwrap();
        assert!(err.is_none() && r.apps().is_empty());
    }

    // FuzzRules seeds: whatever arrives, deciding must not panic
    #[test]
    fn fuzz_seeds_do_not_panic() {
        let seeds: [(&[u8], &str, &str, &str, i64); 3] = [
            (b"{}", "chrome.exe", "1.2.3.4:443", "example.com", 1),
            (
                br#"{"apps":{"chrome.exe":{"mode":"block"}},"ips":[{"app":"chrome.exe","ip":"1.2.3.0/24","port":443,"action":"block"},{"ip":"*","action":"trust"},{"ip":"10.0.0.*","action":"block"}],"domains":[{"domain":"*.example.com","action":"block"},{"app":"x.exe","domain":"a.b","action":"trust"}],"universal":{"udp":true,"icmp":true,"http":true,"unknown":true,"dnsBypass":true,"newApps":true,"lockdown":true,"outgoingOnly":true},"known":["C:\\a.exe"],"dnsTypes":[1,28],"pausedUntil":1}"#,
                r"C:\Program Files\x.exe",
                "[2001:db8::1]:53",
                "sub.example.com.",
                28,
            ),
            (br#"{"ips":[{"ip":"::/0","port":-1,"action":"x"}],"domains":[{"domain":"*.","action":"block"},{"domain":"","action":"trust"}]}"#, "", "0.0.0.0:0", "*", 65535),
        ];
        for (raw, app, dst, domain, qtype) in seeds {
            let Ok((r, _)) = load(raw) else { continue };
            let d = netaddr::parse_addr_port(dst);
            let now = now();
            for p in [TCP, UDP, ICMP] {
                r.decide(p, app, true, d, &[domain.to_string()], now);
                r.decide(p, app, false, d, &[], now);
            }
            r.dns_verdict(domain, qtype, now);
            r.app(app);
            r.known_app(app);
        }
    }
}
