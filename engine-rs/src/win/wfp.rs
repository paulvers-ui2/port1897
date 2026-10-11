// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     SPDX-License-Identifier: MIT
//
//     Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.

//! The kill switch's WFP backend (win/wfp's Enable, Disable and Active):
//! it executes `killswitch::plan` in one transaction. With `persistent`
//! the objects outlive the engine until Disable (a later start or
//! -cleanup); without, they live in a dynamic session that closing
//! removes, as in Go.

use std::ptr::{null, null_mut};
use std::sync::Mutex;

use windows_sys::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows_sys::Win32::Security::{GetSecurityDescriptorLength, GetTokenInformation, PSECURITY_DESCRIPTOR, TOKEN_GROUPS, TOKEN_QUERY, TokenGroups};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, INFINITE, OpenProcessToken};
use windows_sys::core::GUID;

use super::{err_text, from_wide, last_error, wide};
use crate::killswitch::{
    self, Cond, FWP_E_PROVIDER_NOT_FOUND, FilterSpec, Firewall, Guid, PROVIDER_KEY, PROVIDER_NAME, SESSION_NAME, SUBLAYER_KEY, SUBLAYER_NAME, SUBLAYER_WEIGHT,
    WfpObject, WfpOptions,
};

fn g(k: &Guid) -> GUID {
    GUID { data1: k.data1, data2: k.data2, data3: k.data3, data4: k.data4 }
}

/// An open WFP engine session (a handle kept as an integer, so the
/// struct may move between threads; WFP sessions are not tied to one).
struct Session(usize);

impl Session {
    fn h(&self) -> HANDLE {
        self.0 as HANDLE
    }

    fn open(dynamic: bool) -> Result<Session, String> {
        let name = wide(SESSION_NAME.0);
        let desc = wide(SESSION_NAME.1);
        // SAFETY: zeroed is a valid FWPM_SESSION0 (integers, null pointers)
        let mut s: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
        s.displayData = FWPM_DISPLAY_DATA0 { name: name.as_ptr() as *mut u16, description: desc.as_ptr() as *mut u16 };
        s.flags = if dynamic { FWPM_SESSION_FLAG_DYNAMIC } else { 0 };
        s.txnWaitTimeoutInMSec = INFINITE;
        let mut h: HANDLE = null_mut();
        // SAFETY: s and the strings it points to live through the call
        let r = unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &s, &mut h) };
        if r != 0 {
            return Err(format!("wfp: open engine (run as admin?): {}", err_text(r)));
        }
        Ok(Session(h as usize))
    }

    /// Runs f in a transaction: committed if it succeeds, else aborted.
    fn transaction(&self, f: impl FnOnce(&Session) -> Result<(), String>) -> Result<(), String> {
        // SAFETY: the session handle is open
        let r = unsafe { FwpmTransactionBegin0(self.h(), 0) };
        if r != 0 {
            return Err(format!("Firewall error: {}", err_text(r)));
        }
        if let Err(e) = f(self) {
            // SAFETY: as above
            unsafe { FwpmTransactionAbort0(self.h()) };
            return Err(e);
        }
        // SAFETY: as above
        let r = unsafe { FwpmTransactionCommit0(self.h()) };
        if r != 0 {
            // SAFETY: as above
            unsafe { FwpmTransactionAbort0(self.h()) };
            return Err(format!("Firewall error: {}", err_text(r)));
        }
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: the handle is ours and closed once; for a dynamic session
        // this removes what it added
        unsafe { FwpmEngineClose0(self.h()) };
    }
}

/// The WFP kill switch; one per process, as Go keeps it in package state.
#[derive(Default)]
pub struct Wfp {
    /// the dynamic session of a non-persistent Enable
    dynamic: Mutex<Option<Session>>,
}

impl Wfp {
    pub fn new() -> Wfp {
        Wfp::default()
    }

    fn disable_locked(&self, dynamic: &mut Option<Session>) -> Result<(), String> {
        dynamic.take(); // closing it removes its objects
        let s = Session::open(false)?;
        s.transaction(|s| {
            killswitch::remove_leftovers(|what, key| {
                let k = g(key);
                // SAFETY: the session is open; k lives through the call
                unsafe {
                    match what {
                        WfpObject::Filter => FwpmFilterDeleteByKey0(s.h(), &k),
                        WfpObject::Sublayer => FwpmSubLayerDeleteByKey0(s.h(), &k),
                        WfpObject::Provider => FwpmProviderDeleteByKey0(s.h(), &k),
                    }
                }
            })
        })
    }
}

impl Firewall for Wfp {
    fn enable(&self, o: &WfpOptions) -> Result<(), String> {
        let mut dynamic = self.dynamic.lock().unwrap_or_else(|e| e.into_inner());
        self.disable_locked(&mut dynamic)?;
        let s = Session::open(!o.persistent)?;
        let r = killswitch::plan(o).and_then(|plan| s.transaction(|s| install(s, o.persistent, &plan)).map_err(|e| format!("wfp: enable: {e}")));
        r?;
        if !o.persistent {
            *dynamic = Some(s);
        }
        // a persistent session closes here: its objects stay
        Ok(())
    }

    fn disable(&self) -> Result<(), String> {
        let mut dynamic = self.dynamic.lock().unwrap_or_else(|e| e.into_inner());
        self.disable_locked(&mut dynamic)
    }

    fn active(&self) -> Result<bool, String> {
        let s = Session::open(false)?;
        let k = g(&PROVIDER_KEY);
        let mut p: *mut FWPM_PROVIDER0 = null_mut();
        // SAFETY: the session is open; p receives memory WFP allocates
        let r = unsafe { FwpmProviderGetByKey0(s.h(), &k, &mut p) };
        match r {
            0 => {
                // SAFETY: p was allocated by WFP and is freed once
                unsafe { FwpmFreeMemory0(&mut p as *mut _ as *mut *mut core::ffi::c_void) };
                Ok(true)
            }
            FWP_E_PROVIDER_NOT_FOUND => Ok(false),
            r => Err(format!("wfp: get provider: 0x{r:08x}")),
        }
    }
}

/// Registers our provider and sublayer under the fixed keys, then adds the
/// plan's filters.
fn install(s: &Session, persistent: bool, plan: &[FilterSpec]) -> Result<(), String> {
    let mut pk = g(&PROVIDER_KEY);
    let (pn, pd) = (wide(PROVIDER_NAME.0), wide(PROVIDER_NAME.1));
    // SAFETY: zeroed is a valid FWPM_PROVIDER0
    let mut provider: FWPM_PROVIDER0 = unsafe { std::mem::zeroed() };
    provider.providerKey = pk;
    provider.displayData = FWPM_DISPLAY_DATA0 { name: pn.as_ptr() as *mut u16, description: pd.as_ptr() as *mut u16 };
    provider.flags = if persistent { FWPM_PROVIDER_FLAG_PERSISTENT } else { 0 };
    // SAFETY: provider and its strings live through the call
    let r = unsafe { FwpmProviderAdd0(s.h(), &provider, null_mut()) };
    if r != 0 {
        return Err(format!("add provider: {}", err_text(r)));
    }
    let (sn, sd) = (wide(SUBLAYER_NAME.0), wide(SUBLAYER_NAME.1));
    // SAFETY: zeroed is a valid FWPM_SUBLAYER0
    let mut sub: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
    sub.subLayerKey = g(&SUBLAYER_KEY);
    sub.displayData = FWPM_DISPLAY_DATA0 { name: sn.as_ptr() as *mut u16, description: sd.as_ptr() as *mut u16 };
    sub.providerKey = &mut pk;
    sub.weight = SUBLAYER_WEIGHT;
    sub.flags = if persistent { FWPM_SUBLAYER_FLAG_PERSISTENT } else { 0 };
    // SAFETY: sub, pk and the strings live through the call
    let r = unsafe { FwpmSubLayerAdd0(s.h(), &sub, null_mut()) };
    if r != 0 {
        return Err(format!("add sublayer: {}", err_text(r)));
    }
    let me = AppSelf::new()?;
    for f in plan {
        add_filter(s, f, &mut pk, &me)?;
    }
    Ok(())
}

/// The engine's own app id, and its service SID's security descriptor
/// when it has one (it does when AuroraVPN Service started it).
struct AppSelf {
    app: AppId,
    sd: Option<Vec<u8>>,
}

impl AppSelf {
    fn new() -> Result<AppSelf, String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        Ok(AppSelf { app: AppId::of(&exe.to_string_lossy())?, sd: service_sid_sd()? })
    }
}

/// An app id from FwpmGetAppIdFromFileName0, freed on drop.
struct AppId(*mut FWP_BYTE_BLOB);

impl AppId {
    fn of(path: &str) -> Result<AppId, String> {
        let p = wide(path);
        let mut b: *mut FWP_BYTE_BLOB = null_mut();
        // SAFETY: p is NUL-terminated; b receives memory WFP allocates
        let r = unsafe { FwpmGetAppIdFromFileName0(p.as_ptr(), &mut b) };
        if r != 0 {
            return Err(err_text(r));
        }
        Ok(AppId(b))
    }
}

impl Drop for AppId {
    fn drop(&mut self) {
        // SAFETY: allocated by WFP, freed once
        unsafe { FwpmFreeMemory0(&mut self.0 as *mut _ as *mut *mut core::ffi::c_void) };
    }
}

/// Memory a filter's conditions point to, kept until it is added. Each
/// value is boxed so that its address stays put while the lists grow.
#[derive(Default)]
#[allow(clippy::vec_box)]
struct Arena {
    u64s: Vec<Box<u64>>,
    v4: Vec<Box<FWP_V4_ADDR_AND_MASK>>,
    v6: Vec<Box<FWP_V6_ADDR_AND_MASK>>,
    a16: Vec<Box<FWP_BYTE_ARRAY16>>,
    blobs: Vec<Box<FWP_BYTE_BLOB>>,
    apps: Vec<AppId>,
}

fn add_filter(s: &Session, f: &FilterSpec, pk: &mut GUID, me: &AppSelf) -> Result<(), String> {
    let mut arena = Arena::default();
    let mut conds: Vec<FWPM_FILTER_CONDITION0> = Vec::new();
    for c in &f.conds {
        conds.push(condition(c, &mut arena, me)?);
        if *c == Cond::AppSelf {
            if let Some(sd) = &me.sd {
                // a Windows service: its SID keeps other services in the
                // same exe from matching
                let mut sd_blob = Box::new(FWP_BYTE_BLOB { size: sd.len() as u32, data: sd.as_ptr() as *mut u8 });
                let mut v = cond_value(FWP_SECURITY_DESCRIPTOR_TYPE);
                v.Anonymous.sd = &mut *sd_blob;
                conds.push(FWPM_FILTER_CONDITION0 { fieldKey: FWPM_CONDITION_ALE_USER_ID, matchType: FWP_MATCH_EQUAL, conditionValue: v });
                arena.blobs.push(sd_blob);
            }
        }
    }
    let name = wide(&f.name);
    let desc = wide("");
    // SAFETY: zeroed is a valid FWPM_FILTER0
    let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
    filter.filterKey = g(&f.key);
    filter.displayData = FWPM_DISPLAY_DATA0 { name: name.as_ptr() as *mut u16, description: desc.as_ptr() as *mut u16 };
    filter.flags = (if f.persistent { FWPM_FILTER_FLAG_PERSISTENT } else { 0 }) | (if f.clear_action_right { FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT } else { 0 });
    filter.providerKey = pk;
    filter.layerKey = g(&f.layer.key());
    filter.subLayerKey = g(&SUBLAYER_KEY);
    filter.weight.r#type = FWP_UINT8;
    filter.weight.Anonymous.uint8 = f.weight;
    filter.numFilterConditions = conds.len() as u32;
    filter.filterCondition = if conds.is_empty() { null_mut() } else { conds.as_mut_ptr() };
    filter.action.r#type = if f.permit { FWP_ACTION_PERMIT } else { FWP_ACTION_BLOCK };
    let mut id = 0u64;
    // SAFETY: filter, its conditions and everything they point to (arena,
    // name, me) live through the call
    let r = unsafe { FwpmFilterAdd0(s.h(), &filter, null_mut(), &mut id) };
    drop(arena);
    if r != 0 {
        return Err(format!("Firewall error: {}", err_text(r)));
    }
    Ok(())
}

fn cond_value(t: FWP_DATA_TYPE) -> FWP_CONDITION_VALUE0 {
    // SAFETY: zeroed is a valid value of the union
    let mut v: FWP_CONDITION_VALUE0 = unsafe { std::mem::zeroed() };
    v.r#type = t;
    v
}

/// One condition; pointers go into arena.
fn condition(c: &Cond, arena: &mut Arena, me: &AppSelf) -> Result<FWPM_FILTER_CONDITION0, String> {
    let (field, matching, value) = match c {
        Cond::AppSelf | Cond::App(_) => {
            let blob = match c {
                Cond::App(p) => {
                    let a = AppId::of(p).map_err(|e| format!("allow {p}: {e}"))?;
                    let b = a.0;
                    arena.apps.push(a);
                    b
                }
                _ => me.app.0,
            };
            let mut v = cond_value(FWP_BYTE_BLOB_TYPE);
            v.Anonymous.byteBlob = blob;
            (FWPM_CONDITION_ALE_APP_ID, FWP_MATCH_EQUAL, v)
        }
        Cond::LocalInterface(luid) => {
            let mut b = Box::new(*luid);
            let mut v = cond_value(FWP_UINT64);
            v.Anonymous.uint64 = &mut *b;
            arena.u64s.push(b);
            (FWPM_CONDITION_IP_LOCAL_INTERFACE, FWP_MATCH_EQUAL, v)
        }
        Cond::Loopback => {
            let mut v = cond_value(FWP_UINT32);
            v.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
            (FWPM_CONDITION_FLAGS, FWP_MATCH_FLAGS_ALL_SET, v)
        }
        Cond::Protocol(p) => {
            let mut v = cond_value(FWP_UINT8);
            v.Anonymous.uint8 = *p;
            (FWPM_CONDITION_IP_PROTOCOL, FWP_MATCH_EQUAL, v)
        }
        // the ICMP type and code share the port fields
        Cond::LocalPort(p) | Cond::IcmpType(p) => {
            let mut v = cond_value(FWP_UINT16);
            v.Anonymous.uint16 = *p;
            (FWPM_CONDITION_IP_LOCAL_PORT, FWP_MATCH_EQUAL, v)
        }
        Cond::RemotePort(p) | Cond::IcmpCode(p) => {
            let mut v = cond_value(FWP_UINT16);
            v.Anonymous.uint16 = *p;
            (FWPM_CONDITION_IP_REMOTE_PORT, FWP_MATCH_EQUAL, v)
        }
        Cond::RemoteV4(a) => {
            let mut v = cond_value(FWP_UINT32);
            v.Anonymous.uint32 = *a;
            (FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_MATCH_EQUAL, v)
        }
        Cond::RemoteV4Mask(addr, mask) => {
            let mut b = Box::new(FWP_V4_ADDR_AND_MASK { addr: *addr, mask: *mask });
            let mut v = cond_value(FWP_V4_ADDR_MASK);
            v.Anonymous.v4AddrMask = &mut *b;
            arena.v4.push(b);
            (FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_MATCH_EQUAL, v)
        }
        Cond::RemoteV6(a) => {
            let mut b = Box::new(FWP_BYTE_ARRAY16 { byteArray16: *a });
            let mut v = cond_value(FWP_BYTE_ARRAY16_TYPE);
            v.Anonymous.byteArray16 = &mut *b;
            arena.a16.push(b);
            (FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_MATCH_EQUAL, v)
        }
        Cond::RemoteV6Prefix(a, n) | Cond::LocalV6Prefix(a, n) => {
            let mut b = Box::new(FWP_V6_ADDR_AND_MASK { addr: *a, prefixLength: *n });
            let mut v = cond_value(FWP_V6_ADDR_MASK);
            v.Anonymous.v6AddrMask = &mut *b;
            arena.v6.push(b);
            let field = if matches!(c, Cond::LocalV6Prefix(..)) { FWPM_CONDITION_IP_LOCAL_ADDRESS } else { FWPM_CONDITION_IP_REMOTE_ADDRESS };
            (field, FWP_MATCH_EQUAL, v)
        }
    };
    Ok(FWPM_FILTER_CONDITION0 { fieldKey: field, matchType: matching, conditionValue: value })
}

/// Whether a SID string is a service SID (S-1-5-80-...).
fn is_service_sid(s: &str) -> bool {
    let p: Vec<&str> = s.split('-').collect();
    p.len() >= 3 + 6 && p[0] == "S" && p[1] == "1" && p[2] == "5" && p[3] == "80"
}

/// The engine's service SID (enabled, by default, owner), as a
/// self-relative security descriptor granting it FWP_ACTRL_MATCH_FILTER;
/// None when it has none, as a program started by hand.
fn service_sid_sd() -> Result<Option<Vec<u8>>, String> {
    let mut tok: HANDLE = null_mut();
    // SAFETY: the current-process pseudo handle; tok receives a handle
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) } == 0 {
        return Err(last_error());
    }
    let tok = super::OwnedHandle(tok);
    let mut n = 0u32;
    // SAFETY: a size query
    unsafe { GetTokenInformation(tok.0, TokenGroups, null_mut(), 0, &mut n) };
    // u64s keep TOKEN_GROUPS aligned
    let mut buf = vec![0u64; (n as usize).div_ceil(8)];
    // SAFETY: buf holds n bytes
    if unsafe { GetTokenInformation(tok.0, TokenGroups, buf.as_mut_ptr().cast(), n, &mut n) } == 0 {
        return Err(last_error());
    }
    // SAFETY: buf now holds a TOKEN_GROUPS with GroupCount entries
    let groups = unsafe {
        let tg = &*(buf.as_ptr() as *const TOKEN_GROUPS);
        std::slice::from_raw_parts(tg.Groups.as_ptr(), tg.GroupCount as usize)
    };
    const WANT: u32 = 0x4 | 0x2 | 0x8; // SE_GROUP_ENABLED | ENABLED_BY_DEFAULT | OWNER
    for grp in groups {
        if grp.Attributes != WANT {
            continue;
        }
        let mut s: *mut u16 = null_mut();
        // SAFETY: the SID is valid while buf lives; s is LocalAlloc'd
        if unsafe { ConvertSidToStringSidW(grp.Sid, &mut s) } == 0 {
            continue;
        }
        // SAFETY: s is a NUL-terminated string from the call above
        let sid = from_wide(unsafe { std::slice::from_raw_parts(s, wcslen(s)) });
        // SAFETY: allocated by ConvertSidToStringSidW
        unsafe { LocalFree(s as HLOCAL) };
        if is_service_sid(&sid) {
            return sd_for(&sid).map(Some);
        }
    }
    Ok(None)
}

/// The self-relative descriptor "D:(A;;0x1;;;sid)": the DACL Go builds
/// with ACLFromEntries for FWP_ACTRL_MATCH_FILTER.
fn sd_for(sid: &str) -> Result<Vec<u8>, String> {
    let sddl = wide(&format!("D:(A;;0x1;;;{sid})"));
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: sddl is NUL-terminated; sd is LocalAlloc'd by the call
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, null_mut()) } == 0 {
        return Err(last_error());
    }
    // SAFETY: sd is a valid self-relative descriptor of that length
    let out = unsafe { std::slice::from_raw_parts(sd as *const u8, GetSecurityDescriptorLength(sd) as usize).to_vec() };
    // SAFETY: allocated by the conversion
    unsafe { LocalFree(sd as HLOCAL) };
    Ok(out)
}

/// The length of a NUL-terminated UTF-16 string.
///
/// # Safety
/// p must point to a NUL-terminated string.
unsafe fn wcslen(p: *const u16) -> usize {
    let mut n = 0;
    // SAFETY: the caller promises a terminating NUL
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::killswitch::{Layer, plan};

    fn same(a: &GUID, b: &GUID) -> bool {
        (a.data1, a.data2, a.data3, a.data4) == (b.data1, b.data2, b.data3, b.data4)
    }

    #[test]
    fn conditions_point_at_their_values() {
        // no WFP call: the app id needs fwpuclnt.dll only
        let me = AppSelf { app: AppId::of(&std::env::current_exe().unwrap().to_string_lossy()).unwrap(), sd: None };
        let mut arena = Arena::default();
        let c = condition(&Cond::LocalInterface(0xabcdef), &mut arena, &me).unwrap();
        assert_eq!(c.conditionValue.r#type, FWP_UINT64);
        // SAFETY: a u64 condition points at a boxed u64 in the arena
        assert_eq!(unsafe { *c.conditionValue.Anonymous.uint64 }, 0xabcdef);
        let c = condition(&Cond::IcmpType(133), &mut arena, &me).unwrap();
        assert!(same(&c.fieldKey, &FWPM_CONDITION_IP_LOCAL_PORT) && unsafe { c.conditionValue.Anonymous.uint16 } == 133);
        let c = condition(&Cond::RemoteV4Mask(0x0a00_0000, 0xff00_0000), &mut arena, &me).unwrap();
        // SAFETY: as above
        let m = unsafe { &*c.conditionValue.Anonymous.v4AddrMask };
        assert_eq!((m.addr, m.mask), (0x0a00_0000, 0xff00_0000));
        let c = condition(&Cond::AppSelf, &mut arena, &me).unwrap();
        // SAFETY: the blob is WFP's app id, alive in me
        assert!(unsafe { (*c.conditionValue.Anonymous.byteBlob).size } > 0);
        assert!(condition(&Cond::App(r"C:\nope\none.exe".into()), &mut arena, &me).err().unwrap().starts_with(r"allow C:\nope\none.exe: "));
        assert!(same(&g(&Layer::ConnectV4.key()), &FWPM_LAYER_ALE_AUTH_CONNECT_V4));
        assert!(same(&g(&Layer::RecvAcceptV6.key()), &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6));
    }

    #[test]
    fn service_sids() {
        assert!(is_service_sid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"));
        assert!(!is_service_sid("S-1-5-32-544"));
        assert!(!is_service_sid("S-1-5-80-0"));
        // a program started by hand has none; a CI runner's may differ
        service_sid_sd().unwrap();
        let sd = sd_for("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464").unwrap();
        assert!(sd.len() > 20 && sd[0] == 1, "revision 1");
    }

    /// Go's TestPermitSelfWithoutServiceSID, for the whole plan: every
    /// filter goes into a dynamic session, inside a transaction that is
    /// aborted, so nothing is ever blocked. Needs admin.
    #[test]
    #[ignore = "opens WFP with write access (admin); nothing is committed: CI runner only"]
    fn whole_plan_installs_in_an_aborted_transaction() {
        let s = Session::open(true).unwrap();
        let o = WfpOptions { tun_luid: 1, allow: vec![std::env::current_exe().unwrap().to_string_lossy().into()], persistent: false, allow_lan: true };
        let p = plan(&o).unwrap();
        // SAFETY: the session is open
        assert_eq!(unsafe { FwpmTransactionBegin0(s.h(), 0) }, 0);
        let r = install(&s, false, &p);
        // SAFETY: as above
        unsafe { FwpmTransactionAbort0(s.h()) };
        r.unwrap();
    }

    /// The kill switch's whole life on the CI runner: it blocks the
    /// runner's other traffic for a moment (the test program itself is let
    /// through).
    #[test]
    #[ignore = "turns a dynamic kill switch on and off (admin, blocks traffic briefly): CI runner only"]
    fn enable_disable_dynamic() {
        let w = Wfp::new();
        w.enable(&WfpOptions { tun_luid: 1, allow: vec![], persistent: false, allow_lan: true }).unwrap();
        assert!(w.active().unwrap());
        w.disable().unwrap();
        assert!(!w.active().unwrap());
    }
}
