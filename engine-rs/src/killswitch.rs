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

// The WFP filters (win/wfp, from wireguard-windows): what Enable installs,
// as data, so the Windows backend only executes it and the list is tested
// here. The keys are fixed and shared with the Go engine, so either engine
// removes what the other left after a crash.

/// A Windows GUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl fmt::Display for Guid {
    /// As windows.GUID.String: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d = self.data4;
        write!(
            f,
            "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            self.data1, self.data2, self.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
        )
    }
}

const fn guid(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Guid {
    Guid { data1, data2, data3, data4 }
}

pub const PROVIDER_KEY: Guid = guid(0x6b1c2a47, 0x5f2e, 0x4c8f, [0x9a, 0x51, 0x18, 0x97, 0xa0, 0xc0, 0xf0, 0x01]);
pub const SUBLAYER_KEY: Guid = guid(0x6b1c2a47, 0x5f2e, 0x4c8f, [0x9a, 0x51, 0x18, 0x97, 0xa0, 0xc0, 0xf0, 0x02]);
/// Filters get this with their index in the last two bytes.
pub const FILTER_KEY_BASE: Guid = guid(0x6b1c2a47, 0x5f2e, 0x4c8f, [0x9a, 0x51, 0x18, 0x97, 0xa0, 0xc1, 0x00, 0x00]);
/// Disable deletes filter keys 0 to this.
pub const MAX_FILTERS: usize = 160;

/// The key of the i-th filter added.
pub fn filter_key(i: usize) -> Guid {
    let mut k = FILTER_KEY_BASE;
    k.data4[6] = (i >> 8) as u8;
    k.data4[7] = i as u8;
    k
}

/// The WFP layers the filters sit in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    ConnectV4,
    RecvAcceptV4,
    ConnectV6,
    RecvAcceptV6,
}

impl Layer {
    pub fn key(self) -> Guid {
        match self {
            Layer::ConnectV4 => guid(0xc38d57d1, 0x05a7, 0x4c33, [0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82]),
            Layer::RecvAcceptV4 => guid(0xe1cd9fe7, 0xf4b5, 0x4273, [0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50]),
            Layer::ConnectV6 => guid(0x4a72393b, 0x319f, 0x44bc, [0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4]),
            Layer::RecvAcceptV6 => guid(0xa3b42c97, 0x9f04, 0x4672, [0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f]),
        }
    }
}

const ALL_LAYERS: [Layer; 4] = [Layer::ConnectV4, Layer::RecvAcceptV4, Layer::ConnectV6, Layer::RecvAcceptV6];

/// A filter condition. Conditions on the same field are ORed by WFP, the
/// rest ANDed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cond {
    /// the engine's own program; the backend adds its service SID (as
    /// ALE_USER_ID) when it has one, which it does not as fswin runs
    AppSelf,
    /// a program by its full path (FwpmGetAppIdFromFileName0)
    App(String),
    LocalInterface(u64),
    /// FWP_CONDITION_FLAG_IS_LOOPBACK set
    Loopback,
    Protocol(u8),
    LocalPort(u16),
    RemotePort(u16),
    /// an IPv4 address, in host order
    RemoteV4(u32),
    /// IPv4 address and mask, host order
    RemoteV4Mask(u32, u32),
    RemoteV6([u8; 16]),
    RemoteV6Prefix([u8; 16], u8),
    LocalV6Prefix([u8; 16], u8),
    IcmpType(u16),
    IcmpCode(u16),
}

/// One WFP filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterSpec {
    pub key: Guid,
    pub name: String,
    pub layer: Layer,
    pub weight: u8,
    pub permit: bool,
    /// FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT: lower sublayers cannot veto
    pub clear_action_right: bool,
    pub persistent: bool,
    pub conds: Vec<Cond>,
}

const UDP: u8 = 17;
const ICMPV6: u8 = 58;
const LINK_LOCAL: ([u8; 16], u8) = ([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 10);
const DHCP6_LINK_MULTICAST: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0x02];
const DHCP6_SITE_MULTICAST: [u8; 16] = [0xff, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0x03];
const ROUTER_MULTICAST: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];

/// What -allow-lan lets through.
const LAN4: [([u8; 4], u8); 6] = [([10, 0, 0, 0], 8), ([172, 16, 0, 0], 12), ([192, 168, 0, 0], 16), ([169, 254, 0, 0], 16), ([224, 0, 0, 0], 4), ([255, 255, 255, 255], 32)];
const LAN6: [([u8; 16], u8); 3] = [
    ([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 10),
    ([0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 7),
    ([0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 8),
];

/// The filters Enable adds for o, in order, with their keys: the engine
/// (15), allowed programs (15), loopback (13), the LAN (13), the tunnel
/// (12), DHCP and IPv6 neighbour discovery (12), and a block of the rest
/// (0).
pub fn plan(o: &WfpOptions) -> Result<Vec<FilterSpec>, String> {
    let out: std::cell::RefCell<Vec<FilterSpec>> = Default::default();
    // where each step starts, and how Go words a failure in it
    let mut steps: Vec<(usize, String)> = vec![(0, String::new())];
    let add = |name: &str, layer: Layer, weight: u8, permit: bool, clear: bool, conds: Vec<Cond>| {
        let mut out = out.borrow_mut();
        let key = filter_key(out.len());
        out.push(FilterSpec { key, name: name.into(), layer, weight, permit, clear_action_right: clear, persistent: o.persistent, conds });
    };
    let step = |steps: &mut Vec<(usize, String)>, what: String| steps.push((out.borrow().len(), what));
    use Layer::*;
    let dir = |l: Layer| match l {
        ConnectV4 => "outbound IPv4",
        RecvAcceptV4 => "inbound IPv4",
        ConnectV6 => "outbound IPv6",
        RecvAcceptV6 => "inbound IPv6",
    };
    let fam = |l: Layer| if matches!(l, ConnectV4 | RecvAcceptV4) { "IPv4" } else { "IPv6" };
    let way = |l: Layer| if matches!(l, ConnectV4 | ConnectV6) { "outbound" } else { "inbound" };

    for l in ALL_LAYERS {
        add(&format!("Permit unrestricted {} traffic for WireGuard service ({})", way(l), fam(l)), l, 15, true, true, vec![Cond::AppSelf]);
    }
    for p in &o.allow {
        step(&mut steps, format!("allow {p}: "));
        for l in ALL_LAYERS {
            add(&format!("Permit {p}"), l, 15, true, true, vec![Cond::App(p.clone())]);
        }
    }
    step(&mut steps, String::new());
    for l in ALL_LAYERS {
        add(&format!("Permit {} on loopback ({})", way(l), fam(l)), l, 13, true, false, vec![Cond::Loopback]);
    }
    if o.allow_lan {
        step(&mut steps, "allow LAN: ".into());
        let c4: Vec<Cond> = LAN4.iter().map(|(a, bits)| Cond::RemoteV4Mask(u32::from_be_bytes(*a), u32::MAX.checked_shl(32 - *bits as u32).unwrap_or(0))).collect();
        let c6: Vec<Cond> = LAN6.iter().map(|(a, bits)| Cond::RemoteV6Prefix(*a, *bits)).collect();
        add("Permit LAN (IPv4 out)", ConnectV4, 13, true, false, c4.clone());
        add("Permit LAN (IPv4 in)", RecvAcceptV4, 13, true, false, c4);
        add("Permit LAN (IPv6 out)", ConnectV6, 13, true, false, c6.clone());
        add("Permit LAN (IPv6 in)", RecvAcceptV6, 13, true, false, c6);
        step(&mut steps, String::new());
    }
    for l in ALL_LAYERS {
        add(&format!("Permit {} traffic on TUN", dir(l)), l, 12, true, false, vec![Cond::LocalInterface(o.tun_luid)]);
    }
    add("Permit outbound DHCP request (IPv4)", ConnectV4, 12, true, false, vec![Cond::Protocol(UDP), Cond::LocalPort(68), Cond::RemotePort(67), Cond::RemoteV4(0xffff_ffff)]);
    add("Permit inbound DHCP response (IPv4)", RecvAcceptV4, 12, true, false, vec![Cond::Protocol(UDP), Cond::LocalPort(68), Cond::RemotePort(67)]);
    add(
        "Permit outbound DHCP request (IPv6)",
        ConnectV6,
        12,
        true,
        false,
        vec![
            Cond::Protocol(UDP),
            Cond::RemoteV6(DHCP6_LINK_MULTICAST),
            Cond::RemoteV6(DHCP6_SITE_MULTICAST),
            Cond::RemotePort(547),
            Cond::LocalV6Prefix(LINK_LOCAL.0, LINK_LOCAL.1),
            Cond::LocalPort(546),
        ],
    );
    add(
        "Permit inbound DHCP response (IPv6)",
        RecvAcceptV6,
        12,
        true,
        false,
        vec![Cond::Protocol(UDP), Cond::RemoteV6Prefix(LINK_LOCAL.0, LINK_LOCAL.1), Cond::RemotePort(547), Cond::LocalV6Prefix(LINK_LOCAL.0, LINK_LOCAL.1), Cond::LocalPort(546)],
    );
    let icmp = |t: u16| vec![Cond::Protocol(ICMPV6), Cond::IcmpType(t), Cond::IcmpCode(0)];
    let with = |mut c: Vec<Cond>, extra: Cond| {
        c.push(extra);
        c
    };
    add("Permit NDP type 133", ConnectV6, 12, true, false, with(icmp(133), Cond::RemoteV6(ROUTER_MULTICAST)));
    add("Permit NDP type 134", RecvAcceptV6, 12, true, false, with(icmp(134), Cond::RemoteV6Prefix(LINK_LOCAL.0, LINK_LOCAL.1)));
    add("Permit NDP type 135", ConnectV6, 12, true, false, icmp(135));
    add("Permit NDP type 135", RecvAcceptV6, 12, true, false, icmp(135));
    add("Permit NDP type 136", ConnectV6, 12, true, false, icmp(136));
    add("Permit NDP type 136", RecvAcceptV6, 12, true, false, icmp(136));
    add("Permit NDP type 137", RecvAcceptV6, 12, true, false, with(icmp(137), Cond::RemoteV6Prefix(LINK_LOCAL.0, LINK_LOCAL.1)));
    for l in ALL_LAYERS {
        add(&format!("Block all {} ({})", way(l), fam(l)), l, 0, false, false, vec![]);
    }
    let out = out.into_inner();
    if out.len() > MAX_FILTERS {
        // Go stops at the first filter past the limit, inside its step
        let what = steps.iter().rev().find(|(at, _)| *at <= MAX_FILTERS).map(|(_, w)| w.as_str()).unwrap_or("");
        return Err(format!("wfp: enable: {what}wfp: too many filters"));
    }
    Ok(out)
}

/// WFP's "not found" results, which removing leftovers ignores.
pub const FWP_E_FILTER_NOT_FOUND: u32 = 0x8032_0003;
pub const FWP_E_PROVIDER_NOT_FOUND: u32 = 0x8032_0005;
pub const FWP_E_SUBLAYER_NOT_FOUND: u32 = 0x8032_0007;

/// What removing the kill switch deletes, by key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpObject {
    Filter,
    Sublayer,
    Provider,
}

/// Disable's deletions (in one transaction in the backend): every filter
/// key, then the sublayer and the provider. del returns the Win32 result
/// of the delete-by-key call.
pub fn remove_leftovers(mut del: impl FnMut(WfpObject, &Guid) -> u32) -> Result<(), String> {
    for i in 0..MAX_FILTERS {
        let r = del(WfpObject::Filter, &filter_key(i));
        if r != 0 && r != FWP_E_FILTER_NOT_FOUND {
            return Err(format!("wfp: delete filter {i}: 0x{r:08x}"));
        }
    }
    let r = del(WfpObject::Sublayer, &SUBLAYER_KEY);
    if r != 0 && r != FWP_E_SUBLAYER_NOT_FOUND {
        return Err(format!("wfp: delete sublayer: 0x{r:08x}"));
    }
    let r = del(WfpObject::Provider, &PROVIDER_KEY);
    if r != 0 && r != FWP_E_PROVIDER_NOT_FOUND {
        return Err(format!("wfp: delete provider: 0x{r:08x}"));
    }
    Ok(())
}

/// The display names WFP shows for our objects (netsh wfp show filters).
pub const SESSION_NAME: (&str, &str) = ("AuroraVPN", "AuroraVPN kill switch session");
pub const PROVIDER_NAME: (&str, &str) = ("AuroraVPN", "AuroraVPN kill switch");
pub const SUBLAYER_NAME: (&str, &str) = ("AuroraVPN filters", "Permit the tunnel and the engine, block the rest");
/// Our sublayer outranks every other.
pub const SUBLAYER_WEIGHT: u16 = 0xffff;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_keys() {
        assert_eq!(PROVIDER_KEY.to_string(), "{6B1C2A47-5F2E-4C8F-9A51-1897A0C0F001}");
        assert_eq!(SUBLAYER_KEY.to_string(), "{6B1C2A47-5F2E-4C8F-9A51-1897A0C0F002}");
        assert_eq!(filter_key(0).to_string(), "{6B1C2A47-5F2E-4C8F-9A51-1897A0C10000}");
        assert_eq!(filter_key(159).to_string(), "{6B1C2A47-5F2E-4C8F-9A51-1897A0C1009F}");
        assert_eq!(filter_key(300).to_string(), "{6B1C2A47-5F2E-4C8F-9A51-1897A0C1012C}");
        assert_eq!(Layer::ConnectV4.key().to_string(), "{C38D57D1-05A7-4C33-904F-7FBCEEE60E82}");
    }

    #[test]
    fn filter_plan() {
        let o = WfpOptions { tun_luid: 0x1234, allow: vec![r"C:\A\usque.exe".into()], persistent: true, allow_lan: false };
        let p = plan(&o).unwrap();
        // self 4, usque 4, loopback 4, tunnel 4, DHCP 4, NDP 7, block 4
        assert_eq!(p.len(), 31);
        for (i, f) in p.iter().enumerate() {
            assert_eq!(f.key, filter_key(i));
            assert!(f.persistent);
        }
        assert_eq!(p[0].name, "Permit unrestricted outbound traffic for WireGuard service (IPv4)");
        assert!(p[0].clear_action_right && p[0].weight == 15 && p[0].conds == [Cond::AppSelf]);
        assert_eq!(p[4].name, r"Permit C:\A\usque.exe");
        assert_eq!(p[7].layer, Layer::RecvAcceptV6);
        assert_eq!(p[8].name, "Permit outbound on loopback (IPv4)");
        assert_eq!(p[12].name, "Permit outbound IPv4 traffic on TUN");
        assert_eq!(p[12].conds, [Cond::LocalInterface(0x1234)]);
        assert_eq!(p[16].name, "Permit outbound DHCP request (IPv4)");
        assert_eq!(p[20].name, "Permit NDP type 133");
        assert_eq!(p[27].name, "Block all outbound (IPv4)");
        assert!(!p[30].permit && p[30].weight == 0 && p[30].conds.is_empty() && p[30].layer == Layer::RecvAcceptV6);

        let lan = plan(&WfpOptions { allow_lan: true, persistent: false, ..o.clone() }).unwrap();
        assert_eq!(lan.len(), 35);
        assert!(!lan[0].persistent);
        assert_eq!(lan[12].name, "Permit LAN (IPv4 out)");
        assert_eq!(lan[12].conds[0], Cond::RemoteV4Mask(0x0a00_0000, 0xff00_0000));
        assert_eq!(lan[12].conds[5], Cond::RemoteV4Mask(0xffff_ffff, 0xffff_ffff));
        assert_eq!(lan[15].conds[2], Cond::RemoteV6Prefix(LAN6[2].0, 8));

        // 160 keys at most: 32 programs allowed besides the engine is too many
        let apps = |n: usize, lan| WfpOptions { allow: (0..n).map(|i| format!(r"C:\{i}.exe")).collect(), allow_lan: lan, ..o.clone() };
        // 27 + 4 per program: 33 fit; Go fails on the 161st filter, and
        // says in which step
        assert_eq!(plan(&apps(33, false)).unwrap().len(), 159);
        assert_eq!(plan(&apps(34, false)).unwrap_err(), "wfp: enable: wfp: too many filters");
        assert_eq!(plan(&apps(40, false)).unwrap_err(), r"wfp: enable: allow C:\39.exe: wfp: too many filters");
        assert_eq!(plan(&apps(38, true)).unwrap_err(), "wfp: enable: allow LAN: wfp: too many filters");
    }

    #[test]
    fn leftovers() {
        let mut seen = Vec::new();
        remove_leftovers(|what, k| {
            seen.push((what, *k));
            // three filters left by a crash; the rest is gone already
            match what {
                WfpObject::Filter if k.data4[7] < 3 => 0,
                WfpObject::Filter => FWP_E_FILTER_NOT_FOUND,
                WfpObject::Sublayer => FWP_E_SUBLAYER_NOT_FOUND,
                WfpObject::Provider => FWP_E_PROVIDER_NOT_FOUND,
            }
        })
        .unwrap();
        assert_eq!(seen.len(), MAX_FILTERS + 2);
        assert_eq!(seen[MAX_FILTERS], (WfpObject::Sublayer, SUBLAYER_KEY));
        assert_eq!(seen[MAX_FILTERS + 1], (WfpObject::Provider, PROVIDER_KEY));
        let e = remove_leftovers(|what, k| if what == WfpObject::Filter && k.data4[7] == 5 { 5 } else { 0 }).unwrap_err();
        assert_eq!(e, "wfp: delete filter 5: 0x00000005");
        assert_eq!(remove_leftovers(|w, _| if w == WfpObject::Provider { 0x80320001 } else { 0 }).unwrap_err(), "wfp: delete provider: 0x80320001");
    }

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
