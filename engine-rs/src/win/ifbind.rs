// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The engine's own sockets pinned to the physical interface (a port of
//! win/ifbind): with the two /1 routes in place, a socket left to the
//! routing table would loop back into the tunnel. IP_UNICAST_IF sends it
//! out of the interface of the cheapest default route other than the
//! tunnel's. Destinations on this PC or on a network attached to another
//! interface are not pinned: they never take the default route, and
//! pinning them breaks them (127.0.0.1 fails, a second NIC's host is sent
//! out the wrong one). Read only: its tests need no admin rights.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GAA_FLAG_SKIP_ANYCAST, GetAdaptersAddresses, GetIpForwardTable2, IP_ADAPTER_ADDRESSES_LH, MIB_IPFORWARD_TABLE2,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, setsockopt,
};

use super::{err_text, from_wide};

/// How long a looked-up default interface is reused.
const REFRESH: Duration = Duration::from_secs(5);

pub const NO_DEFAULT: &str = "ifbind: no default route outside the tunnel";

/// Prefixes shorter than these are not taken as on-link: an adapter that
/// claims 0.0.0.0/0 would otherwise turn all pinning off.
const MIN_ON_LINK4: u8 = 8;
const MIN_ON_LINK6: u8 = 16;

// from ipifcons.h
const IF_TYPE_PROP_VIRTUAL: u32 = 53;
const IF_TYPE_TUNNEL: u32 = 131;

/// A default-route candidate: (prefix length, interface index, route metric).
pub type RouteRow = (u8, u32, u32);

/// The interface of the cheapest default route (route metric + interface
/// metric) on an up interface (one in metrics) other than skip; 0 if none.
pub fn pick_default(rows: &[RouteRow], metrics: &HashMap<u32, u32>, skip: u32) -> u32 {
    let mut best = (0u32, u64::MAX);
    for &(bits, idx, metric) in rows {
        if bits != 0 || idx == skip {
            continue;
        }
        let Some(im) = metrics.get(&idx) else { continue };
        let m = u64::from(metric) + u64::from(*im);
        if m < best.1 {
            best = (idx, m);
        }
    }
    best.0
}

/// An IP prefix, masked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    pub addr: IpAddr,
    pub bits: u8,
}

impl Prefix {
    /// addr/bits masked, or None if bits is too long for the family.
    pub fn new(addr: IpAddr, bits: u8) -> Option<Prefix> {
        match addr {
            IpAddr::V4(a) if bits <= 32 => {
                let m = if bits == 0 { 0 } else { u32::MAX << (32 - u32::from(bits)) };
                Some(Prefix { addr: IpAddr::V4(Ipv4Addr::from(u32::from(a) & m)), bits })
            }
            IpAddr::V6(a) if bits <= 128 => {
                let m = if bits == 0 { 0 } else { u128::MAX << (128 - u32::from(bits)) };
                Some(Prefix { addr: IpAddr::V6(Ipv6Addr::from(u128::from(a) & m)), bits })
            }
            _ => None,
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        Prefix::new(ip, self.bits).is_some_and(|p| p.addr == self.addr)
    }
}

/// ip with an IPv4-mapped IPv6 address turned into IPv4, as Go's Unmap.
fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

fn is_link_local_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_link_local(),
        IpAddr::V6(a) => a.segments()[0] & 0xffc0 == 0xfe80,
    }
}

/// Whether ip is this machine or sits on one of the on-link prefixes of
/// the other interfaces (OnLink's decision, given those prefixes).
pub fn on_link_in(ip: IpAddr, prefixes: &[Prefix]) -> bool {
    let ip = unmap(ip);
    if ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    if ip.is_loopback() || is_link_local_unicast(ip) {
        return true;
    }
    prefixes.iter().any(|p| p.contains(ip))
}

/// The on-link prefix of one adapter address, if it is long enough to be
/// trusted.
pub fn on_link_prefix(ip: IpAddr, bits: u8) -> Option<Prefix> {
    let ip = unmap(ip);
    let min = if ip.is_ipv4() { MIN_ON_LINK4 } else { MIN_ON_LINK6 };
    if bits < min {
        return None;
    }
    Prefix::new(ip, bits)
}

/// Whether an adapter looks like another VPN's tunnel rather than Wi-Fi or
/// Ethernet.
pub fn looks_like_vpn(if_type: u32, desc: &str) -> bool {
    let d = desc.to_lowercase();
    if_type == IF_TYPE_PROP_VIRTUAL
        || if_type == IF_TYPE_TUNNEL
        || ["vpn", "tunnel", "wireguard", "wintun", "tap-"].iter().any(|w| d.contains(w))
}

/// IP_UNICAST_IF takes the index in network byte order.
pub fn htonl(v: u32) -> u32 {
    v.to_be()
}

/// Calls f with each adapter GetAdaptersAddresses reports for family, until
/// f returns false. The adapters point into the buffer, which lives while f
/// runs; f must not keep any of those pointers.
fn for_each_adapter(family: u16, mut f: impl FnMut(&IP_ADAPTER_ADDRESSES_LH) -> bool) -> Result<(), String> {
    let mut size: u32 = 15 << 10;
    for _ in 0..4 {
        // u64s: IP_ADAPTER_ADDRESSES needs 8-byte alignment
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        let first = buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        // SAFETY: buf is writable for size bytes, which is passed
        let r = unsafe { GetAdaptersAddresses(u32::from(family), GAA_FLAG_SKIP_ANYCAST, std::ptr::null(), first, &mut size) };
        if r == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if r != NO_ERROR {
            return Err(format!("ifbind: adapters: {}", err_text(r)));
        }
        let mut aa = first.cast_const();
        while !aa.is_null() {
            // SAFETY: Windows filled buf with a list of adapters, each
            // pointing at the next or null; buf outlives this loop
            let a = unsafe { &*aa };
            if !f(a) {
                break;
            }
            aa = a.Next;
        }
        drop(buf);
        return Ok(());
    }
    Err(format!("ifbind: adapters: {}", err_text(ERROR_BUFFER_OVERFLOW)))
}

fn if_index(a: &IP_ADAPTER_ADDRESSES_LH) -> u32 {
    // SAFETY: the union's IfIndex view is what Windows fills
    unsafe { a.Anonymous1.Anonymous.IfIndex }
}

/// The address a SOCKADDR points at, if IPv4 or IPv6.
///
/// # Safety
/// sa must be null or point at a SOCKADDR_IN or SOCKADDR_IN6 per its family.
unsafe fn sockaddr_ip(sa: *const SOCKADDR) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: the caller's promise
    unsafe {
        match (*sa).sa_family {
            AF_INET => {
                let s = &*sa.cast::<SOCKADDR_IN>();
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(s.sin_addr.S_un.S_addr))))
            }
            AF_INET6 => {
                let s = &*sa.cast::<SOCKADDR_IN6>();
                Some(IpAddr::V6(Ipv6Addr::from(s.sin6_addr.u.Byte)))
            }
            _ => None,
        }
    }
}

/// Every up interface's index and metric for family.
fn iface_metrics(family: u16) -> Result<HashMap<u32, u32>, String> {
    let mut out = HashMap::new();
    for_each_adapter(family, |a| {
        if a.OperStatus == IfOperStatusUp {
            if family == AF_INET6 {
                out.insert(a.Ipv6IfIndex, a.Ipv6Metric);
            } else {
                out.insert(if_index(a), a.Ipv4Metric);
            }
        }
        true
    })?;
    Ok(out)
}

/// The default routes of family as (prefix length, interface, metric).
fn route_rows(family: u16) -> Result<Vec<RouteRow>, String> {
    let mut t: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: t receives a table Windows allocates
    let r = unsafe { GetIpForwardTable2(family, &mut t) };
    if r != NO_ERROR {
        return Err(format!("ifbind: routes: {}", err_text(r)));
    }
    // SAFETY: t holds NumEntries rows, freed below
    let rows = unsafe {
        let n = (*t).NumEntries as usize;
        let first = std::ptr::addr_of!((*t).Table).cast::<windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPFORWARD_ROW2>();
        (0..n).map(|i| &*first.add(i)).map(|r| (r.DestinationPrefix.PrefixLength, r.InterfaceIndex, r.Metric)).collect()
    };
    // SAFETY: t came from GetIpForwardTable2
    unsafe { FreeMibTable(t.cast()) };
    Ok(rows)
}

/// The interface of the cheapest default route of family on an up
/// interface other than skip; 0 if none.
pub fn default_index(family: u16, skip: u32) -> u32 {
    let (Ok(m), Ok(rows)) = (iface_metrics(family), route_rows(family)) else {
        return 0;
    };
    pick_default(&rows, &m, skip)
}

fn on_link_prefixes(skip: u32) -> Vec<Prefix> {
    let mut out = Vec::new();
    let _ = for_each_adapter(AF_UNSPEC, |a| {
        if a.OperStatus != IfOperStatusUp || if_index(a) == skip || a.Ipv6IfIndex == skip {
            return true;
        }
        let mut u = a.FirstUnicastAddress.cast_const();
        while !u.is_null() {
            // SAFETY: a list in the adapters buffer, as for_each_adapter's
            let ua = unsafe { &*u };
            // SAFETY: Windows' address of the family it says
            if let Some(ip) = unsafe { sockaddr_ip(ua.Address.lpSockaddr) } {
                if let Some(p) = on_link_prefix(ip, ua.OnLinkPrefixLength) {
                    out.push(p);
                }
            }
            u = ua.Next;
        }
        true
    });
    out
}

#[derive(Default)]
struct Cache {
    idx: Option<(u32, u32, Instant)>,
    links: Option<(Vec<Prefix>, Instant)>,
}

/// Pins sockets to the interface of the default route, never the tunnel's.
/// Safe for concurrent use.
pub struct Binder {
    skip: u32,
    m: Mutex<Cache>,
}

impl Binder {
    /// A binder that never picks interface tun_index.
    pub fn new(tun_index: u32) -> Binder {
        Binder { skip: tun_index, m: Mutex::new(Cache::default()) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.m.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The current IPv4 and IPv6 default interfaces (0 if none).
    pub fn indexes(&self) -> (u32, u32) {
        let mut c = self.lock();
        if let Some((a, b, at)) = c.idx {
            if at.elapsed() < REFRESH {
                return (a, b);
            }
        }
        let (a, b) = (default_index(AF_INET, self.skip), default_index(AF_INET6, self.skip));
        c.idx = Some((a, b, Instant::now()));
        (a, b)
    }

    /// Whether ip is this PC or on a network attached to an interface
    /// other than the tunnel: not to be pinned.
    pub fn on_link(&self, ip: IpAddr) -> bool {
        let prefixes = {
            let mut c = self.lock();
            match &c.links {
                Some((p, at)) if at.elapsed() < REFRESH => p.clone(),
                _ => {
                    let p = on_link_prefixes(self.skip);
                    c.links = Some((p.clone(), Instant::now()));
                    p
                }
            }
        };
        on_link_in(ip, &prefixes)
    }

    /// Makes socket s send IPv4 out of the default physical interface.
    pub fn bind4(&self, s: usize) -> Result<(), String> {
        let (idx4, _) = self.indexes();
        if idx4 == 0 {
            return Err(NO_DEFAULT.into());
        }
        set_int(s, IPPROTO_IP, IP_UNICAST_IF, htonl(idx4))
    }

    /// Makes socket s send IPv6 out of the default physical interface.
    pub fn bind6(&self, s: usize) -> Result<(), String> {
        let (_, idx6) = self.indexes();
        if idx6 == 0 {
            return Err(NO_DEFAULT.into());
        }
        set_int(s, IPPROTO_IPV6, IPV6_UNICAST_IF, idx6)
    }

    /// The IPv4 DNS servers of the default interface outside the tunnel:
    /// the "System DNS" Windows would use without us.
    pub fn dns_servers(&self) -> Vec<Ipv4Addr> {
        let (idx4, _) = self.indexes();
        let mut out = Vec::new();
        if idx4 == 0 {
            return out;
        }
        let _ = for_each_adapter(AF_INET, |a| {
            if if_index(a) != idx4 {
                return true;
            }
            let mut d = a.FirstDnsServerAddress.cast_const();
            while !d.is_null() {
                // SAFETY: a list in the adapters buffer
                let da = unsafe { &*d };
                // SAFETY: Windows' address of the family it says
                if let Some(IpAddr::V4(ip)) = unsafe { sockaddr_ip(da.Address.lpSockaddr) }.map(unmap) {
                    out.push(ip);
                }
                d = da.Next;
            }
            false
        });
        out
    }
}

fn set_int(s: usize, level: i32, opt: i32, v: u32) -> Result<(), String> {
    let b = v.to_ne_bytes();
    // SAFETY: b is 4 readable bytes, the size passed
    if unsafe { setsockopt(s, level, opt, b.as_ptr(), 4) } != 0 {
        return Err(format!("ifbind: setsockopt: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// The IP MTU of the IPv4 default interface other than skip, and its
/// index; (0, 0) when there is none.
pub fn link_mtu(skip: u32) -> (u32, u32) {
    let idx = default_index(AF_INET, skip);
    if idx == 0 {
        return (0, 0);
    }
    let mut mtu = 0;
    let _ = for_each_adapter(AF_INET, |a| {
        if if_index(a) != idx {
            return true;
        }
        mtu = a.Mtu;
        false
    });
    (mtu, idx)
}

/// Interface idx's name and description, and whether it looks like another
/// VPN's tunnel: the engine's traffic through it depends on that VPN.
pub fn describe(idx: u32) -> (String, String, bool) {
    let mut out = (String::new(), String::new(), false);
    let _ = for_each_adapter(AF_INET, |a| {
        if if_index(a) != idx {
            return true;
        }
        // SAFETY: NUL-terminated strings in the adapters buffer
        let s = |p: *mut u16| if p.is_null() { String::new() } else { from_wide(unsafe { std::slice::from_raw_parts(p, wcslen(p)) }) };
        let (name, desc) = (s(a.FriendlyName), s(a.Description));
        let vpn = looks_like_vpn(a.IfType, &desc);
        out = (name, desc, vpn);
        false
    });
    out
}

fn wcslen(p: *const u16) -> usize {
    let mut n = 0;
    // SAFETY: p is NUL-terminated (describe's caller)
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn picks_the_cheapest_default_route_off_the_tunnel() {
        let m: HashMap<u32, u32> = [(3, 25), (7, 5), (9, 1)].into_iter().collect();
        // 9 is the tunnel; 12 is down (no metric); 3 has a /24 only
        let rows = [(0, 9, 0), (0, 12, 0), (24, 3, 0), (0, 3, 0), (0, 7, 30)];
        assert_eq!(pick_default(&rows, &m, 9), 3); // 25 < 35
        assert_eq!(pick_default(&rows, &m, 3), 9);
        assert_eq!(pick_default(&[(0, 9, 0)], &m, 9), 0);
        assert_eq!(pick_default(&[], &m, 0), 0);
    }

    #[test]
    fn on_link() {
        let p = [on_link_prefix(ip("192.168.1.20"), 24).unwrap(), on_link_prefix(ip("fd00::5"), 64).unwrap()];
        for (a, want) in [
            ("127.0.0.1", true),
            ("::1", true),
            ("169.254.3.4", true),
            ("fe80::1", true),
            ("192.168.1.1", true),
            ("::ffff:192.168.1.9", true),
            ("192.168.2.1", false),
            ("fd00::77", true),
            ("1.1.1.1", false),
            ("0.0.0.0", false),
            ("224.0.0.1", false),
        ] {
            assert_eq!(on_link_in(ip(a), &p), want, "{a}");
        }
        // too wide to trust: an adapter claiming everything
        assert_eq!(on_link_prefix(ip("10.0.0.1"), 7), None);
        assert_eq!(on_link_prefix(ip("2001::1"), 15), None);
        assert_eq!(Prefix::new(ip("10.1.2.3"), 33), None);
        assert_eq!(Prefix::new(ip("10.1.2.3"), 8).unwrap().addr, ip("10.0.0.0"));
        assert!(Prefix::new(ip("0.0.0.0"), 0).unwrap().contains(ip("8.8.8.8")));
    }

    #[test]
    fn helpers() {
        assert_eq!(htonl(0x0102_0304).to_ne_bytes(), [1, 2, 3, 4]);
        assert!(looks_like_vpn(IF_TYPE_TUNNEL, "x"));
        assert!(looks_like_vpn(6, "ProtonVPN TUN"));
        assert!(looks_like_vpn(6, "TAP-Windows Adapter V9"));
        assert!(!looks_like_vpn(6, "Intel(R) Wi-Fi 6 AX201"));
    }

    /// Read only: what this PC's tables say (no admin).
    #[test]
    fn live_tables() {
        let b = Binder::new(0);
        let (i4, _) = b.indexes();
        let (mtu, idx) = link_mtu(0);
        assert_eq!(idx, i4);
        if idx != 0 {
            assert!(mtu >= 576, "{mtu}");
            let (name, _, _) = describe(idx);
            assert!(!name.is_empty());
        }
        assert!(b.on_link(ip("127.0.0.1")));
        assert!(!b.on_link(ip("1.1.1.1")));
        let _ = b.dns_servers();
    }
}
