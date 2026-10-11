// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The Win32 backends behind the engine's traits: the registry (NRPT),
//! child processes, WFP (kill switch), IP Helper (adapter address, DNS,
//! routes; flow owners) and Wintun. Nearly every `unsafe` block of the
//! engine is in here (usque.rs has the random-bytes call), each with what
//! makes it sound.
//!
//! Tests that change the system (HKLM, WFP, the adapter) are #[ignore]d
//! with the reason: they run on the admin CI runner, never on a PC whose
//! VPN they could break.

pub mod proc;
pub mod registry;

/// s as a NUL-terminated UTF-16 string.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A UTF-16 buffer up to its first NUL, as Go's UTF16ToString.
pub fn from_wide(b: &[u16]) -> String {
    let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf16_lossy(&b[..n])
}

/// A Win32 error code in Windows' words, as Go's syscall.Errno prints it
/// ("Access is denied.").
pub fn err_text(code: u32) -> String {
    let s = std::io::Error::from_raw_os_error(code as i32).to_string();
    // Rust adds " (os error N)"; Go does not
    match s.rfind(" (os error ") {
        Some(i) => s[..i].to_string(),
        None => s,
    }
}

/// A program in System32, never one found through PATH, which the user's
/// environment sets.
pub fn system_tool(name: &str) -> String {
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    let mut buf = [0u16; 260];
    // SAFETY: buf is writable for its length, which is passed
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if n == 0 || n >= buf.len() {
        return name.to_string();
    }
    crate::usque::join(&String::from_utf16_lossy(&buf[..n]), name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(wide("ab"), [97, 98, 0]);
        assert_eq!(from_wide(&[97, 0, 98]), "a");
        assert_eq!(err_text(5), "Access is denied.");
        let t = system_tool("ipconfig.exe");
        assert!(crate::golike::equal_fold(&t, r"C:\Windows\System32\ipconfig.exe") || t.ends_with(r"\System32\ipconfig.exe"), "{t}");
    }
}
