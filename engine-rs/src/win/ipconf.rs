// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The adapter's IPv4 configuration (a port of win/ipconf, and of the
//! netsh fallback in main_windows.go): address, DNS server, metric and the
//! two /1 routes, through IP Helper directly, in a few milliseconds; netsh
//! (a program per setting, about 0.2 s each) is the fallback.

use std::net::Ipv4Addr;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToGuid, CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DNS_INTERFACE_SETTINGS, DNS_SETTING_NAMESERVER,
    DNS_SETTING_REGISTER_ADAPTER_NAME, DNS_SETTING_REGISTRATION_ENABLED, GetIpInterfaceEntry, InitializeIpForwardEntry, InitializeUnicastIpAddressEntry,
    MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW, SetIpInterfaceEntry,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{AF_INET, IN_ADDR, IN_ADDR_0, IpDadStatePreferred, SOCKADDR_INET};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW};
use windows_sys::core::GUID;

use super::{err_text, wide};
use crate::engine::{FAKEDNS4, IFADDR4};

/// SetDNS on a Windows without SetInterfaceDnsSettings.
pub const NO_DNS_API: &str = "ipconf: SetInterfaceDnsSettings needs Windows 10 2004 or later";

fn sockaddr4(a: Ipv4Addr) -> SOCKADDR_INET {
    // SAFETY: zeroed is a valid SOCKADDR_INET
    let mut s: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    s.Ipv4.sin_family = AF_INET;
    s.Ipv4.sin_addr = IN_ADDR { S_un: IN_ADDR_0 { S_addr: u32::from_ne_bytes(a.octets()) } };
    s
}

fn luid(v: u64) -> NET_LUID_LH {
    NET_LUID_LH { Value: v }
}

/// The row for the adapter's address (luid, a/bits), preferred at once.
fn address_row(l: u64, a: Ipv4Addr, bits: u8) -> MIB_UNICASTIPADDRESS_ROW {
    // SAFETY: zeroed, then initialised by Windows with its defaults
    let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
    // SAFETY: row is writable
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceLuid = luid(l);
    row.Address = sockaddr4(a);
    row.OnLinkPrefixLength = bits;
    row.DadState = IpDadStatePreferred;
    row
}

/// The row for an on-link route to dst/bits on the adapter.
fn route_row(l: u64, dst: Ipv4Addr, bits: u8, metric: u32) -> MIB_IPFORWARD_ROW2 {
    // SAFETY: zeroed, then initialised by Windows with its defaults
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    // SAFETY: row is writable
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = luid(l);
    // the prefix's address, masked
    let masked = if bits == 0 { 0 } else { u32::from(dst) & (u32::MAX << (32 - bits as u32)) };
    row.DestinationPrefix.Prefix = sockaddr4(Ipv4Addr::from(masked));
    row.DestinationPrefix.PrefixLength = bits;
    row.NextHop = sockaddr4(Ipv4Addr::UNSPECIFIED);
    row.Metric = metric;
    row
}

/// Gives the adapter luid the IPv4 address a/bits, as netsh's "set address
/// source=static". Already there is fine.
pub fn set_address(l: u64, a: Ipv4Addr, bits: u8) -> Result<(), String> {
    let row = address_row(l, a, bits);
    // SAFETY: row is a valid, initialised row
    match unsafe { CreateUnicastIpAddressEntry(&row) } {
        NO_ERROR | ERROR_OBJECT_ALREADY_EXISTS => Ok(()),
        e => Err(format!("ipconf: address {a}/{bits}: {}", err_text(e))),
    }
}

/// Gives the adapter's IPv4 side a fixed metric, as netsh's "set interface
/// metric=": the lowest wins Windows' DNS and route choices.
pub fn set_metric(l: u64, metric: u32) -> Result<(), String> {
    // SAFETY: zeroed is a valid row; the key fields are set below
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    row.Family = AF_INET;
    row.InterfaceLuid = luid(l);
    // SAFETY: row is writable
    let r = unsafe { GetIpInterfaceEntry(&mut row) };
    if r != NO_ERROR {
        return Err(format!("ipconf: interface: {}", err_text(r)));
    }
    row.UseAutomaticMetric = false;
    row.Metric = metric;
    row.SitePrefixLength = 0; // SetIpInterfaceEntry refuses anything else for IPv4
    // SAFETY: as above
    let r = unsafe { SetIpInterfaceEntry(&mut row) };
    if r != NO_ERROR {
        return Err(format!("ipconf: metric: {}", err_text(r)));
    }
    Ok(())
}

/// Sends dst/bits to the adapter, on link, as netsh's "add route
/// nexthop=0.0.0.0 store=active": the route goes with the adapter.
pub fn add_route(l: u64, dst: Ipv4Addr, bits: u8, metric: u32) -> Result<(), String> {
    let row = route_row(l, dst, bits, metric);
    // SAFETY: row is a valid, initialised row
    match unsafe { CreateIpForwardEntry2(&row) } {
        NO_ERROR | ERROR_OBJECT_ALREADY_EXISTS => Ok(()),
        e => Err(format!("ipconf: route {dst}/{bits}: {}", err_text(e))),
    }
}

type SetDnsFn = unsafe extern "system" fn(GUID, *const DNS_INTERFACE_SETTINGS) -> u32;

/// SetInterfaceDnsSettings, looked up as Go does: a Windows before 10 2004
/// has none, and a static import would keep the engine from starting.
fn set_dns_fn() -> Option<SetDnsFn> {
    let lib = wide("iphlpapi.dll");
    // SAFETY: lib is NUL-terminated; System32 only
    let m = unsafe { LoadLibraryExW(lib.as_ptr(), null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if m.is_null() {
        return None;
    }
    // SAFETY: m is loaded; the name is NUL-terminated ASCII
    let f = unsafe { GetProcAddress(m, c"SetInterfaceDnsSettings".as_ptr().cast()) }?;
    // SAFETY: the documented signature of SetInterfaceDnsSettings
    Some(unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, SetDnsFn>(f) })
}

/// Points the adapter's IPv4 DNS at server and keeps the PC from
/// registering its name through it, as netsh's "set dnsservers
/// register=none".
pub fn set_dns(l: u64, server: Ipv4Addr) -> Result<(), String> {
    let f = set_dns_fn().ok_or(NO_DNS_API)?;
    let mut guid = GUID { data1: 0, data2: 0, data3: 0, data4: [0; 8] };
    // SAFETY: both point at valid values
    let r = unsafe { ConvertInterfaceLuidToGuid(&luid(l), &mut guid) };
    if r != NO_ERROR {
        return Err(format!("ipconf: interface guid: {}", err_text(r)));
    }
    let ns = wide(&server.to_string());
    // SAFETY: zeroed is valid: null strings, zero flags
    let mut s: DNS_INTERFACE_SETTINGS = unsafe { std::mem::zeroed() };
    s.Version = 1;
    s.Flags = (DNS_SETTING_NAMESERVER | DNS_SETTING_REGISTRATION_ENABLED | DNS_SETTING_REGISTER_ADAPTER_NAME) as u64;
    s.NameServer = ns.as_ptr() as *mut u16; // registration stays 0: off
    // SAFETY: s and ns live through the call
    let r = unsafe { f(guid, &s) };
    if r != NO_ERROR {
        return Err(format!("ipconf: dns: {}", err_text(r)));
    }
    Ok(())
}

/// netsh's arguments for the adapter's address and, with set_dns, its DNS
/// server and metric (configure's fallback).
pub fn netsh_configure(name: &str, set_dns: bool) -> Vec<Vec<String>> {
    let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<String>>();
    let mut cmds = vec![v(&["interface", "ipv4", "set", "address", &format!("name={name}"), "source=static", &format!("address={IFADDR4}"), "mask=255.255.255.0"])];
    if set_dns {
        cmds.push(v(&["interface", "ipv4", "set", "dnsservers", &format!("name={name}"), "source=static", &format!("address={FAKEDNS4}"), "register=none", "validate=no"]));
        cmds.push(v(&["interface", "ipv4", "set", "interface", &format!("interface={name}"), "metric=1"]));
    }
    cmds
}

/// netsh's arguments for the two /1 routes (fullTunnel's fallback).
pub fn netsh_routes(name: &str) -> Vec<Vec<String>> {
    ["0.0.0.0/1", "128.0.0.0/1"]
        .iter()
        .map(|p| {
            ["interface", "ipv4", "add", "route", &format!("prefix={p}"), &format!("interface={name}"), "nexthop=0.0.0.0", "metric=0", "store=active"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        })
        .collect()
}

/// Runs netsh (from System32, with plain arguments) for each command.
pub fn netsh(cmds: &[Vec<String>]) -> Result<(), String> {
    for args in cmds {
        let out = std::process::Command::new(super::system_tool("netsh.exe")).args(args).output().map_err(|e| e.to_string())?;
        if !out.status.success() {
            let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            return Err(format!("netsh {}: {}: {}", args.join(" "), out.status, text.trim()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows() {
        let r = address_row(0x1234, "10.111.222.1".parse().unwrap(), 24);
        // SAFETY: the union fields were set as IPv4
        unsafe {
            assert_eq!(r.InterfaceLuid.Value, 0x1234);
            assert_eq!(r.Address.Ipv4.sin_family, AF_INET);
            assert_eq!(r.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(), [10, 111, 222, 1]);
        }
        assert_eq!((r.OnLinkPrefixLength, r.DadState), (24, IpDadStatePreferred));
        let r = route_row(7, "128.9.9.9".parse().unwrap(), 1, 0);
        // SAFETY: as above
        unsafe {
            assert_eq!(r.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(), [128, 0, 0, 0]);
            assert_eq!(r.NextHop.Ipv4.sin_addr.S_un.S_addr, 0);
            assert_eq!(r.NextHop.Ipv4.sin_family, AF_INET);
        }
        assert_eq!((r.DestinationPrefix.PrefixLength, r.Metric), (1, 0));
        // this Windows has the DNS call (10 2004 or later)
        assert!(set_dns_fn().is_some());
    }

    #[test]
    fn netsh_fallback() {
        let c = netsh_configure("AuroraVPN", true);
        assert_eq!(c[0].join(" "), "interface ipv4 set address name=AuroraVPN source=static address=10.111.222.1 mask=255.255.255.0");
        assert_eq!(c[1].join(" "), "interface ipv4 set dnsservers name=AuroraVPN source=static address=10.111.222.3 register=none validate=no");
        assert_eq!(c[2].join(" "), "interface ipv4 set interface interface=AuroraVPN metric=1");
        assert_eq!(netsh_configure("x", false).len(), 1);
        assert_eq!(netsh_routes("AuroraVPN")[1].join(" "), "interface ipv4 add route prefix=128.0.0.0/1 interface=AuroraVPN nexthop=0.0.0.0 metric=0 store=active");
    }

    /// An adapter that does not exist: Windows refuses each call, which
    /// shows the calls are made and worded; needs no admin to fail.
    #[test]
    fn unknown_adapter_is_refused() {
        let nope = 0x00ff_ffff_ffff_fff0;
        assert!(set_metric(nope, 1).unwrap_err().starts_with("ipconf: interface: "));
        assert!(set_dns(nope, "10.111.222.3".parse().unwrap()).unwrap_err().starts_with("ipconf: "));
    }

    /// Configures a real adapter: needs admin and a Wintun adapter, which
    /// the e2e simulation on the CI runner has.
    #[test]
    #[ignore = "changes an adapter's address, DNS and routes (admin, Wintun): CI e2e only"]
    fn configure_adapter_from_env() {
        // the adapter's LUID, from a job that created one; skipped without
        let Ok(l) = std::env::var("FSWIN_TEST_LUID") else {
            eprintln!("FSWIN_TEST_LUID not set: no adapter to configure");
            return;
        };
        let l: u64 = l.parse().unwrap();
        set_address(l, "10.111.222.1".parse().unwrap(), 24).unwrap();
        set_dns(l, "10.111.222.3".parse().unwrap()).unwrap();
        set_metric(l, 1).unwrap();
        add_route(l, "0.0.0.0".parse().unwrap(), 1, 0).unwrap();
        add_route(l, "128.0.0.0".parse().unwrap(), 1, 0).unwrap();
    }
}
