// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Addresses as Go's net/netip reads and prints them, for the firewall
//! rules and the API. The differences from Rust's std parsers that matter:
//! a port is decimal digits only (no '+'), an IPv6 address with a port must
//! be in brackets, and a prefix length has no leading zeros. IPv6 zones
//! (fe80::1%eth0) are not taken: flows from the tunnel never carry one.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// `netip.ParseAddr`, without zones.
pub fn parse_addr(s: &str) -> Option<IpAddr> {
    s.parse().ok()
}

/// `netip.ParseAddrPort`, without zones.
pub fn parse_addr_port(s: &str) -> Option<SocketAddr> {
    let colon = s.rfind(':')?;
    let (host, port) = (&s[..colon], &s[colon + 1..]);
    if port.is_empty() || !port.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let port: u16 = crate::golike::parse_uint(port, 10, 16).ok()? as u16;
    let ip = if let Some(inner) = host.strip_prefix('[') {
        let inner = inner.strip_suffix(']')?;
        match parse_addr(inner)? {
            IpAddr::V6(v6) => IpAddr::V6(v6),
            IpAddr::V4(_) => return None, // brackets are for IPv6 only
        }
    } else {
        match parse_addr(host)? {
            IpAddr::V4(v4) => IpAddr::V4(v4),
            IpAddr::V6(_) => return None, // IPv6 needs brackets
        }
    };
    Some(SocketAddr::new(ip, port))
}

/// `Addr.Unmap`: ::ffff:1.2.3.4 becomes 1.2.3.4.
pub fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        v4 => v4,
    }
}

/// `Addr.BitLen`.
pub fn bit_len(ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// An `AddrPort` as Go prints it; None is Go's zero AddrPort.
pub fn addr_port_string(ap: Option<SocketAddr>) -> String {
    match ap {
        Some(a) => a.to_string(),
        None => "invalid AddrPort".to_string(),
    }
}

/// A `netip.Prefix`: an address and how many leading bits count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    addr: IpAddr,
    bits: u8,
}

impl Prefix {
    /// `netip.PrefixFrom`; None if bits is too long for the family.
    pub fn new(addr: IpAddr, bits: u8) -> Option<Prefix> {
        (bits <= bit_len(addr)).then_some(Prefix { addr, bits })
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    pub fn bits(&self) -> u8 {
        self.bits
    }

    /// `netip.ParsePrefix`, with Go's error messages.
    pub fn parse(s: &str) -> Result<Prefix, String> {
        let err = |msg: &str| format!("netip.ParsePrefix({}): {msg}", crate::golike::quote(s));
        let Some(i) = s.rfind('/') else {
            return Err(err("no '/'"));
        };
        let Some(ip) = parse_addr(&s[..i]) else {
            return Err(err(&format!("ParseAddr({}): unable to parse IP", crate::golike::quote(&s[..i]))));
        };
        let bits_str = &s[i + 1..];
        let bad_bits = || err(&format!("bad bits after slash: {}", crate::golike::quote(bits_str)));
        // no sign and no leading zeros
        if bits_str.is_empty() || !bits_str.bytes().all(|c| c.is_ascii_digit()) {
            return Err(bad_bits());
        }
        if bits_str.len() > 1 && bits_str.as_bytes()[0] == b'0' {
            return Err(bad_bits());
        }
        // strconv.Atoi: too big for an int is "bad bits", not "out of range"
        let Ok(bits) = crate::golike::parse_int(bits_str, 10, 64) else {
            return Err(bad_bits());
        };
        if bits > bit_len(ip) as i64 {
            return Err(err("prefix length out of range"));
        }
        Ok(Prefix { addr: ip, bits: bits as u8 })
    }

    /// `Prefix.Masked`: the host bits cleared.
    pub fn masked(&self) -> Prefix {
        let addr = match self.addr {
            IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask32(self.bits))),
            IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask128(self.bits))),
        };
        Prefix { addr, bits: self.bits }
    }

    /// `Prefix.Contains`: same family only, as Go (an IPv4-mapped IPv6
    /// address is not in an IPv4 prefix).
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(p), IpAddr::V4(a)) => (u32::from(p) ^ u32::from(a)) & mask32(self.bits) == 0,
            (IpAddr::V6(p), IpAddr::V6(a)) => (u128::from(p) ^ u128::from(a)) & mask128(self.bits) == 0,
            _ => false,
        }
    }
}

fn mask32(bits: u8) -> u32 {
    if bits == 0 { 0 } else { u32::MAX << (32 - bits as u32) }
}

fn mask128(bits: u8) -> u128 {
    if bits == 0 { 0 } else { u128::MAX << (128 - bits as u32) }
}

/// `Addr.IsPrivate`: 10/8, 172.16/12, 192.168/16, fc00::/7.
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            o[0] == 10 || (o[0] == 172 && o[1] & 0xf0 == 16) || (o[0] == 192 && o[1] == 168)
        }
        IpAddr::V6(a) => a.octets()[0] & 0xfe == 0xfc,
    }
}

/// `Addr.IsLoopback`.
pub fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.octets()[0] == 127,
        IpAddr::V6(a) => a == Ipv6Addr::LOCALHOST,
    }
}

/// `Addr.IsLinkLocalUnicast`: 169.254/16, fe80::/10.
pub fn is_link_local_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            o[0] == 169 && o[1] == 254
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            s[0] & 0xffc0 == 0xfe80
        }
    }
}

/// `Addr.IsLinkLocalMulticast`: 224.0.0.0/24, ff02::/16.
pub fn is_link_local_multicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            o[0] == 224 && o[1] == 0 && o[2] == 0
        }
        IpAddr::V6(a) => a.segments()[0] == 0xff02,
    }
}

/// `Addr.IsMulticast`: 224/4, ff00::/8.
pub fn is_multicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.octets()[0] & 0xf0 == 0xe0,
        IpAddr::V6(a) => a.octets()[0] == 0xff,
    }
}

/// `Addr.IsUnspecified`.
pub fn is_unspecified(ip: IpAddr) -> bool {
    ip.is_unspecified()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_ports_like_netip() {
        let ok = |s: &str| parse_addr_port(s).unwrap_or_else(|| panic!("{s} refused"));
        assert_eq!(ok("1.2.3.4:443").to_string(), "1.2.3.4:443");
        assert_eq!(ok("[2001:db8::1]:53").to_string(), "[2001:db8::1]:53");
        assert_eq!(ok("1.2.3.4:0443").port(), 443);
        assert_eq!(ok("[::ffff:1.2.3.4]:80").to_string(), "[::ffff:1.2.3.4]:80");
        for bad in ["1.2.3.4", "1.2.3.4:", "1.2.3.4:+80", "1.2.3.4:65536", "2001:db8::1:53", "[1.2.3.4]:80", "[::1:80", "x:80", "01.2.3.4:80", ""] {
            assert_eq!(parse_addr_port(bad), None, "{bad} taken");
        }
        assert_eq!(addr_port_string(None), "invalid AddrPort");
    }

    #[test]
    fn prefixes_like_netip() {
        let p = Prefix::parse("10.1.2.3/8").unwrap();
        assert_eq!(p.masked(), Prefix::parse("10.0.0.0/8").unwrap());
        assert!(p.contains("10.200.0.1".parse().unwrap()));
        assert!(!p.contains("11.0.0.1".parse().unwrap()));
        assert!(!p.contains("::ffff:10.0.0.1".parse().unwrap()), "mapped is not v4");
        let any6 = Prefix::parse("::/0").unwrap();
        assert!(any6.contains("2001:db8::1".parse().unwrap()));
        assert!(!any6.contains("1.1.1.1".parse().unwrap()));
        assert!(Prefix::parse("0.0.0.0/0").unwrap().contains("255.255.255.255".parse().unwrap()));
        for (bad, why) in [
            ("10.0.0.0", "no '/'"),
            ("10.0.0.0/33", "prefix length out of range"),
            ("10.0.0.0/08", "bad bits after slash: \"08\""),
            ("10.0.0.0/+8", "bad bits after slash: \"+8\""),
            ("10.0.0.0/", "bad bits after slash: \"\""),
            ("::/129", "prefix length out of range"),
            ("x/8", "ParseAddr(\"x\"): unable to parse IP"),
        ] {
            let e = Prefix::parse(bad).unwrap_err();
            assert!(e.ends_with(why), "{bad}: {e}");
        }
        assert!(Prefix::parse("10.0.0.0/0").is_ok());
    }

    #[test]
    fn address_classes() {
        let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
        assert!(is_private(ip("172.31.255.255")) && !is_private(ip("172.32.0.0")));
        assert!(is_private(ip("fd00::1")) && !is_private(ip("fe00::1")));
        assert!(is_loopback(ip("127.255.0.1")) && is_loopback(ip("::1")));
        assert!(is_link_local_unicast(ip("169.254.1.1")) && is_link_local_unicast(ip("febf::1")));
        assert!(!is_link_local_unicast(ip("fec0::1")));
        assert!(is_link_local_multicast(ip("224.0.0.251")) && !is_link_local_multicast(ip("224.0.1.1")));
        assert!(is_link_local_multicast(ip("ff02::fb")));
        assert!(is_multicast(ip("239.1.1.1")) && is_multicast(ip("ff05::1")));
        assert_eq!(unmap(ip("::ffff:8.8.8.8")), ip("8.8.8.8"));
        assert_eq!(unmap(ip("::8.8.8.8")), ip("::8.8.8.8"));
    }
}
