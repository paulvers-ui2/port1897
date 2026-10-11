// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The Android app's country database (cmd/fswin/geoip/README.md; geo-IP by
//! db-ip.com, CC BY 4.0), the same files the Go engine embeds: sorted
//! fixed-size records of a range's first address and its two-letter country
//! code, "ZZ" for private and unassigned ranges.

use std::net::IpAddr;

use crate::netaddr;

static GEO4: &[u8] = include_bytes!("../../cmd/fswin/geoip/dbip.v4");
static GEO6: &[u8] = include_bytes!("../../cmd/fswin/geoip/dbip.v6");

/// The two-letter code of the country ip is in, or "" for a private,
/// unassigned or missing address. As the Android app's CountryMap, it
/// looks for the last range that starts at or below ip.
pub fn country(ip: Option<IpAddr>) -> String {
    let Some(ip) = ip else { return String::new() };
    let (key, db): (Vec<u8>, &[u8]) = match netaddr::unmap(ip) {
        IpAddr::V4(a) => (a.octets().to_vec(), GEO4),
        IpAddr::V6(a) => (a.octets().to_vec(), GEO6),
    };
    lookup(db, &key)
}

fn lookup(db: &[u8], key: &[u8]) -> String {
    let size = key.len() + 2;
    let n = db.len() / size;
    // the first range that starts above ip; ip is in the one before it
    let i = partition_point(n, |i| &db[i * size..i * size + key.len()] <= key);
    if i == 0 {
        return String::new();
    }
    let cc = &db[i * size - 2..i * size];
    if !cc[0].is_ascii_uppercase() || !cc[1].is_ascii_uppercase() || cc == b"ZZ" {
        return String::new();
    }
    String::from_utf8_lossy(cc).into_owned()
}

/// The first index in 0..n for which pred is false (pred holds for a prefix).
fn partition_point(n: usize, pred: impl Fn(usize) -> bool) -> usize {
    let (mut lo, mut hi) = (0, n);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if pred(mid) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

/// The country of the first address in a DNS answer (a csv of rdata).
pub fn answer_country(rdata: &str) -> String {
    for a in rdata.split(',') {
        if let Some(ip) = netaddr::parse_addr(a.trim()) {
            if !ip.is_unspecified() {
                return country(Some(ip));
            }
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn countries() {
        for (ip, want) in [
            ("8.8.8.8", "US"),
            ("::ffff:8.8.8.8", "US"),
            ("95.173.136.70", "RU"),
            ("185.15.59.224", "NL"),
            ("2a00:1450:4001:80b::200e", "IE"),
            ("192.168.1.1", ""),
            ("10.111.222.1", ""),
            ("127.0.0.1", ""),
            ("0.0.0.0", ""),
            ("255.255.255.255", ""),
            ("::1", ""),
        ] {
            assert_eq!(country(netaddr::parse_addr(ip)), want, "{ip}");
        }
        assert_eq!(country(None), "");
    }

    #[test]
    fn database_is_whole() {
        for (name, data, key) in [("dbip.v4", GEO4, 4), ("dbip.v6", GEO6, 16)] {
            let size = key + 2;
            assert!(!data.is_empty() && data.len() % size == 0, "{name}");
            for i in (size..data.len()).step_by(size) {
                assert!(data[i - size..i - size + key] <= data[i..i + key], "{name}: record {} out of order", i / size);
            }
        }
    }

    #[test]
    fn answers() {
        for (rdata, want) in [
            ("8.8.8.8,8.8.4.4", "US"),
            ("0.0.0.0", ""),
            ("0.0.0.0,95.173.136.70", "RU"),
            ("cname.example.,8.8.8.8", "US"),
            ("", ""),
            ("2a00:1450:4001:80b::200e", "IE"),
            ("not an address", ""),
        ] {
            assert_eq!(answer_country(rdata), want, "{rdata}");
        }
    }

    // FuzzCountry: any address gives "" or two capital letters
    #[test]
    fn any_address() {
        let mut x: u128 = 0x1234_5678_9abc_def0_0fed_cba9_8765_4321;
        for _ in 0..20000 {
            x = x.wrapping_mul(0x2545_f491_4f6c_dd1d_9e37_79b9_7f4a_7c15).wrapping_add(1);
            for ip in [IpAddr::V6((x).into()), IpAddr::V4(((x >> 64) as u32).into())] {
                let c = country(Some(ip));
                assert!(c.is_empty() || (c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase())), "{ip}: {c}");
            }
        }
    }
}
