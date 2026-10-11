// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The NRPT's Windows side: the registry (`nrpt::Registry` over HKLM, or
//! HKCU for tests, as x/sys/windows/registry reads and writes values), and
//! the nudge that has the DNS Client take a rule change in.

use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ,
    REG_OPTION_NON_VOLATILE, REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW,
    RegSetValueExW,
};

use super::{err_text, proc, system_tool, wide};
use crate::nrpt::{RegError, RegValue, Registry};

/// Which predefined key the paths are under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Root {
    LocalMachine,
    CurrentUser,
}

/// The Windows registry under one root.
pub struct WinRegistry {
    pub root: Root,
}

fn reg_err(code: u32) -> RegError {
    if code == ERROR_FILE_NOT_FOUND { RegError::NotExist } else { RegError::Other(err_text(code)) }
}

/// An open key, closed on drop.
struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the key was opened by us and is closed once
        unsafe { RegCloseKey(self.0) };
    }
}

impl WinRegistry {
    pub fn local_machine() -> WinRegistry {
        WinRegistry { root: Root::LocalMachine }
    }

    fn root(&self) -> HKEY {
        match self.root {
            Root::LocalMachine => HKEY_LOCAL_MACHINE,
            Root::CurrentUser => HKEY_CURRENT_USER,
        }
    }

    fn open(&self, path: &str, access: u32) -> Result<Key, RegError> {
        let p = wide(path);
        let mut k: HKEY = null_mut();
        // SAFETY: p is NUL-terminated; k receives the key
        let r = unsafe { RegOpenKeyExW(self.root(), p.as_ptr(), 0, access, &mut k) };
        if r != ERROR_SUCCESS {
            return Err(reg_err(r));
        }
        Ok(Key(k))
    }
}

impl Registry for WinRegistry {
    fn subkeys(&self, path: &str) -> Result<Vec<String>, RegError> {
        let k = self.open(path, KEY_ENUMERATE_SUB_KEYS)?;
        let mut out = Vec::new();
        for i in 0.. {
            // key names are 255 characters at most
            let mut buf = [0u16; 256];
            let mut n = buf.len() as u32;
            // SAFETY: buf holds n characters; the other outputs are unused
            let r = unsafe { RegEnumKeyExW(k.0, i, buf.as_mut_ptr(), &mut n, null_mut(), null_mut(), null_mut(), null_mut()) };
            match r {
                ERROR_SUCCESS => out.push(String::from_utf16_lossy(&buf[..n as usize])),
                ERROR_NO_MORE_ITEMS => break,
                e => return Err(reg_err(e)),
            }
        }
        Ok(out)
    }

    fn value(&self, path: &str, name: &str) -> Option<RegValue> {
        let k = self.open(path, KEY_QUERY_VALUE).ok()?;
        let n16 = wide(name);
        let mut buf: Vec<u8> = vec![0; 256];
        let mut typ: REG_VALUE_TYPE = 0;
        loop {
            let mut len = buf.len() as u32;
            // SAFETY: n16 is NUL-terminated; buf holds len bytes
            let r = unsafe { RegQueryValueExW(k.0, n16.as_ptr(), null_mut(), &mut typ, buf.as_mut_ptr(), &mut len) };
            match r {
                ERROR_SUCCESS => {
                    buf.truncate(len as usize);
                    break;
                }
                ERROR_MORE_DATA => buf.resize(len as usize, 0),
                _ => return None,
            }
        }
        let u16s: Vec<u16> = buf.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        match typ {
            REG_DWORD if buf.len() == 4 => Some(RegValue::Dword(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))),
            REG_SZ => Some(RegValue::Sz(super::from_wide(&u16s))),
            REG_EXPAND_SZ => Some(RegValue::ExpandSz(super::from_wide(&u16s))),
            REG_MULTI_SZ => Some(RegValue::MultiSz(multi_sz(&u16s))),
            _ => None,
        }
    }

    fn create(&self, path: &str) -> Result<(), RegError> {
        let p = wide(path);
        let mut k: HKEY = null_mut();
        // SAFETY: p is NUL-terminated; k receives the key; no class, no
        // security attributes, disposition not wanted
        let r = unsafe {
            RegCreateKeyExW(self.root(), p.as_ptr(), 0, std::ptr::null(), REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, std::ptr::null(), &mut k, null_mut())
        };
        if r != ERROR_SUCCESS {
            return Err(reg_err(r));
        }
        drop(Key(k));
        Ok(())
    }

    fn set(&self, path: &str, name: &str, v: RegValue) -> Result<(), RegError> {
        let k = self.open(path, KEY_SET_VALUE)?;
        let (typ, data): (REG_VALUE_TYPE, Vec<u8>) = match v {
            RegValue::Dword(d) => (REG_DWORD, d.to_le_bytes().to_vec()),
            RegValue::Sz(s) => (REG_SZ, utf16_bytes(&wide(&s))),
            RegValue::ExpandSz(s) => (REG_EXPAND_SZ, utf16_bytes(&wide(&s))),
            RegValue::MultiSz(list) => {
                // as Go's SetStringsValue: a NUL inside a string is refused
                if list.iter().any(|s| s.contains('\0')) {
                    return Err(RegError::Other("The parameter is incorrect.".into()));
                }
                let mut w: Vec<u16> = Vec::new();
                for s in &list {
                    w.extend(s.encode_utf16());
                    w.push(0);
                }
                w.push(0);
                (REG_MULTI_SZ, utf16_bytes(&w))
            }
        };
        let n16 = wide(name);
        // SAFETY: n16 is NUL-terminated; data holds data.len() bytes
        let r = unsafe { RegSetValueExW(k.0, n16.as_ptr(), 0, typ, data.as_ptr(), data.len() as u32) };
        if r != ERROR_SUCCESS {
            return Err(reg_err(r));
        }
        Ok(())
    }

    fn delete(&self, path: &str) -> Result<(), RegError> {
        let p = wide(path);
        // SAFETY: p is NUL-terminated
        let r = unsafe { RegDeleteKeyW(self.root(), p.as_ptr()) };
        if r != ERROR_SUCCESS {
            return Err(reg_err(r));
        }
        Ok(())
    }
}

fn utf16_bytes(w: &[u16]) -> Vec<u8> {
    w.iter().flat_map(|c| c.to_le_bytes()).collect()
}

/// A REG_MULTI_SZ as Go's GetStringsValue splits it: the terminating NUL
/// dropped, then a string per NUL.
fn multi_sz(p: &[u16]) -> Vec<String> {
    let p = match p.last() {
        Some(0) => &p[..p.len() - 1],
        _ => p,
    };
    let mut out = Vec::new();
    let mut from = 0;
    for (i, &c) in p.iter().enumerate() {
        if c == 0 {
            out.push(String::from_utf16_lossy(&p[from..i]));
            from = i + 1;
        }
    }
    out
}

/// Empties the DNS cache, as ipconfig /flushdns does, so no answer from
/// before a rule change is used after it. DnsFlushResolverCache is not
/// documented: looked up, and skipped if missing.
pub fn flush_dns_cache() {
    let lib = wide("dnsapi.dll");
    // SAFETY: lib is NUL-terminated; System32 only, so no planted DLL
    let m = unsafe { LoadLibraryExW(lib.as_ptr(), null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if m.is_null() {
        return;
    }
    // SAFETY: m is a loaded module; the name is NUL-terminated ASCII
    if let Some(f) = unsafe { GetProcAddress(m, c"DnsFlushResolverCache".as_ptr().cast()) } {
        // SAFETY: DnsFlushResolverCache takes no arguments and returns a
        // BOOL, which the transmuted signature matches
        let f: unsafe extern "system" fn() -> i32 = unsafe { std::mem::transmute(f) };
        // SAFETY: as above
        unsafe { f() };
    }
    // the module stays loaded: dnsapi.dll is in every process that resolves
}

/// Has the DNS Client take a rule change in, as win/dnspolicy's nudge:
/// ipconfig /registerdns (from System32) makes Windows notice changed DNS
/// settings. At a start (wait false) it is not waited for; at a stop it is,
/// at most 5 s. The cache is flushed before and after.
pub fn nudge(wait: bool) -> Result<(), String> {
    flush_dns_cache();
    let p = proc::start_hidden(&system_tool("ipconfig.exe"), &["/registerdns"]).map_err(|e| format!("ipconfig /registerdns: {e}"))?;
    if wait {
        p.wait(5000);
        flush_dns_cache();
        return Ok(());
    }
    std::thread::spawn(move || {
        p.wait_forever();
        flush_dns_cache(); // for answers cached meanwhile
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nrpt::{Nrpt, RULE_KEY};

    /// Rules under HKCU, as the Go tests' sandbox: nothing of this PC's DNS
    /// is read or changed.
    struct Sandbox {
        base: String,
    }

    impl Sandbox {
        fn new(name: &str) -> Sandbox {
            let s = Sandbox { base: format!(r"Software\AuroraVPNTest\Rust_{name}_{}", std::process::id()) };
            s.clean();
            s
        }

        fn clean(&self) {
            let r = WinRegistry { root: Root::CurrentUser };
            fn tree(r: &WinRegistry, p: &str) {
                for k in r.subkeys(p).unwrap_or_default() {
                    tree(r, &format!(r"{p}\{k}"));
                }
                let _ = r.delete(p);
            }
            tree(&r, &self.base);
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            self.clean();
            let _ = WinRegistry { root: Root::CurrentUser }.delete(r"Software\AuroraVPNTest");
        }
    }

    #[test]
    fn values_round_trip() {
        let sb = Sandbox::new("values");
        let r = WinRegistry { root: Root::CurrentUser };
        let p = format!(r"{}\k", sb.base);
        assert_eq!(r.subkeys(&p), Err(RegError::NotExist));
        assert_eq!(r.set(&p, "x", RegValue::Dword(1)), Err(RegError::NotExist));
        r.create(&p).unwrap();
        r.set(&p, "D", RegValue::Dword(0x8)).unwrap();
        r.set(&p, "S", RegValue::Sz("10.111.222.3".into())).unwrap();
        r.set(&p, "E", RegValue::ExpandSz("%SystemRoot%".into())).unwrap();
        r.set(&p, "M", RegValue::MultiSz(vec![".".into(), "".into(), "ä.corp".into()])).unwrap();
        r.set(&p, "Empty", RegValue::Sz(String::new())).unwrap();
        assert!(r.set(&p, "Bad", RegValue::MultiSz(vec!["a\0b".into()])).is_err());
        assert_eq!(r.value(&p, "d"), Some(RegValue::Dword(8)), "names are case-insensitive");
        assert_eq!(r.value(&p, "S"), Some(RegValue::Sz("10.111.222.3".into())));
        assert_eq!(r.value(&p, "E"), Some(RegValue::ExpandSz("%SystemRoot%".into())));
        assert_eq!(r.value(&p, "M"), Some(RegValue::MultiSz(vec![".".into(), "".into(), "ä.corp".into()])));
        assert_eq!(r.value(&p, "Empty"), Some(RegValue::Sz(String::new())));
        assert_eq!(r.value(&p, "missing"), None);
        assert_eq!(r.value(&format!(r"{p}\none"), "S"), None);
        // a key with a subkey cannot be deleted
        r.create(&format!(r"{p}\sub")).unwrap();
        assert_eq!(r.subkeys(&p).unwrap(), ["sub"]);
        assert!(matches!(r.delete(&p), Err(RegError::Other(_))));
        r.delete(&format!(r"{p}\sub")).unwrap();
        r.delete(&p).unwrap();
        assert_eq!(r.delete(&p), Err(RegError::NotExist));
        assert_eq!(multi_sz(&[97, 0, 0]), ["a"]);
        assert!(multi_sz(&[]).is_empty());
    }

    /// The NRPT logic on the real registry, under HKCU.
    #[test]
    fn nrpt_in_a_sandbox() {
        let sb = Sandbox::new("nrpt");
        let mut n = Nrpt::new(WinRegistry { root: Root::CurrentUser }, Box::new(|_| Ok(())));
        n.local = format!(r"{}\local", sb.base);
        n.policy = format!(r"{}\policy", sb.base);
        assert!(n.others().unwrap().is_empty());
        n.remove().unwrap();
        let other = format!(r"{}\{{11111111-1111-1111-1111-111111111111}}", n.local);
        n.reg.create(&other).unwrap();
        n.reg.set(&other, "Name", RegValue::MultiSz(vec![".".into()])).unwrap();
        n.reg.set(&other, "Comment", RegValue::Sz("Force all DNS requests via Proton VPN".into())).unwrap();
        n.add("10.111.222.3".parse().unwrap()).unwrap();
        let ours = format!(r"{}\{RULE_KEY}", n.local);
        assert_eq!(n.reg.value(&ours, "ConfigOptions"), Some(RegValue::Dword(8)));
        assert_eq!(n.reg.value(&ours, "Name"), Some(RegValue::MultiSz(vec![".".into()])));
        assert_eq!(n.others().unwrap(), [" (Force all DNS requests via Proton VPN)"]);
        n.remove().unwrap();
        assert_eq!(n.reg.subkeys(&n.local).unwrap(), ["{11111111-1111-1111-1111-111111111111}"]);
    }

    /// Runs ipconfig /registerdns and flushes this PC's DNS cache: harmless,
    /// but it touches the system's DNS client, so only on the CI runner.
    #[test]
    #[ignore = "nudges this PC's DNS Client (ipconfig /registerdns): CI runner only"]
    fn nudge_runs() {
        nudge(true).unwrap();
        nudge(false).unwrap();
    }

    /// Writes the real rule under HKLM, which needs admin and changes this
    /// PC's DNS: only on the CI runner, then removed.
    #[test]
    #[ignore = "writes the NRPT rule under HKLM (admin, changes DNS): CI runner only"]
    fn hklm_rule_add_remove() {
        let n = Nrpt::new(WinRegistry::local_machine(), Box::new(nudge));
        n.add("10.111.222.3".parse().unwrap()).unwrap();
        assert!(n.reg.subkeys(&n.local).unwrap().iter().any(|k| k == RULE_KEY));
        n.remove().unwrap();
        assert!(!n.reg.subkeys(&n.local).unwrap_or_default().iter().any(|k| k == RULE_KEY));
    }
}
