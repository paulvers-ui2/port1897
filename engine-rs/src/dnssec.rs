// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2025 RethinkDNS and its authors
//     Licensed under the Apache License, Version 2.0
//     (DnsSecGuard.kt in the Rethink / AuroraVPN Android app)

//! The DNSSEC switch (dnssec_windows.go), from the Android app's
//! DnsSecGuard: answers that put a public name on a bogon address are a
//! classic sign of DNS poisoning, and the way DNS rebinding attacks reach
//! local devices, so they are blocked. Answers without DNSSEC proof are only
//! marked: most domains are not signed.

use std::net::IpAddr;
use std::sync::OnceLock;

use crate::golike;
use crate::netaddr::{self, Prefix};

fn bogons() -> &'static [Prefix] {
    static B: OnceLock<Vec<Prefix>> = OnceLock::new();
    B.get_or_init(|| {
        [
            "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
            "172.16.0.0/12", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
            "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
            "::1/128", "fe80::/10", "fc00::/7", "2001:db8::/32", "2002::/16",
            "2001::/32", "ff00::/8",
        ]
        .iter()
        .map(|p| Prefix::parse(p).expect("bogon prefix"))
        .collect()
    })
}

/// Names that resolve to local addresses by design.
const LOCAL_SUFFIXES: &[&str] = &[
    ".lan", ".local", ".internal", ".home", ".home.arpa", ".localdomain",
    ".localhost", ".corp", ".intranet", ".private", ".arpa",
];

/// Names that may legitimately answer with private addresses: single-label
/// names and local or reverse-lookup zones.
pub fn is_local_name(qname: &str) -> bool {
    let n = golike::to_lower(golike::trim_suffix(qname, "."));
    if n.is_empty() || !n.contains('.') {
        return true;
    }
    LOCAL_SUFFIXES.iter().any(|s| n.ends_with(s))
}

/// The bogon addresses in a csv of answer IPs (bare or ip:port).
/// Unspecified addresses (0.0.0.0, ::) are how blocklists answer, not
/// poisoning.
pub fn bogons_in(csv: &str) -> Vec<String> {
    let mut out = Vec::new();
    for s in csv.split(',') {
        let mut s = s.trim().to_string();
        if s.is_empty() {
            continue;
        }
        if let Some(ap) = netaddr::parse_addr_port(&s) {
            s = ap.ip().to_string();
        }
        let Some(ip) = netaddr::parse_addr(s.trim_matches(|c| c == '[' || c == ']')) else {
            continue;
        };
        if ip.is_unspecified() {
            continue;
        }
        let ip: IpAddr = netaddr::unmap(ip);
        if bogons().iter().any(|p| p.contains(ip)) {
            out.push(ip.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_names() {
        for n in ["router", "router.", "nas.lan", "printer.LOCAL.", "x.home.arpa", "1.0.168.192.in-addr.arpa", ""] {
            assert!(is_local_name(n), "{n}");
        }
        for n in ["example.com", "lan.example.com", "evil.localhost.com"] {
            assert!(!is_local_name(n), "{n}");
        }
    }

    #[test]
    fn bogon_answers() {
        assert_eq!(bogons_in("93.184.215.14,192.168.1.1, 10.0.0.1"), vec!["192.168.1.1", "10.0.0.1"]);
        assert_eq!(bogons_in("0.0.0.0,::"), Vec::<String>::new());
        assert_eq!(bogons_in("::ffff:127.0.0.1"), vec!["127.0.0.1"]);
        assert_eq!(bogons_in("[fe80::1]:53,1.2.3.4:53,100.64.1.1:80"), vec!["fe80::1", "100.64.1.1"]);
        assert_eq!(bogons_in("cname.example.,2001:db8::5,240.0.0.1"), vec!["2001:db8::5", "240.0.0.1"]);
        assert!(bogons_in("8.8.8.8,2606:4700::1111").is_empty());
    }
}
