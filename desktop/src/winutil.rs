// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Windows calls: the UAC prompt, whether a process still runs, the screen
//! lock, and start at login.

use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED, ERROR_CANCELLED, HWND, LPARAM, LRESULT, STILL_ACTIVE, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::RemoteDesktop::{NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification};
use windows::Win32::System::Threading::{GetExitCodeProcess, GetProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
use windows::Win32::UI::Shell::{SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, HWND_MESSAGE, MSG, RegisterClassW, SW_HIDE, WINDOW_EX_STYLE, WINDOW_STYLE, WM_WTSSESSION_CHANGE,
    WNDCLASSW,
};
use windows::core::{PCWSTR, w};

fn wide(s: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

/// Quotes one argument for the Windows command line (CommandLineToArgvW).
pub fn win_quote(arg: &str) -> String {
    if !arg.is_empty() && !arg.chars().any(|c| c.is_whitespace() || c == '"') {
        return arg.to_string();
    }
    let mut out = String::from("\"");
    let mut slashes = 0usize;
    for ch in arg.chars() {
        match ch {
            '\\' => slashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(slashes * 2 + 1));
                out.push('"');
                slashes = 0;
            }
            c => {
                out.push_str(&"\\".repeat(slashes));
                out.push(c);
                slashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(slashes * 2));
    out.push('"');
    out
}

/// Starts exe as admin (a UAC prompt), hidden, and returns its process id.
pub fn launch_elevated(exe: &Path, args: &[String]) -> Result<u32, String> {
    let file = wide(exe);
    let params = wide(args.iter().map(|a| win_quote(a)).collect::<Vec<_>>().join(" "));
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(params.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    // SAFETY: info and the strings it points at live through the call
    if let Err(e) = unsafe { ShellExecuteExW(&mut info) } {
        return Err(if e.code() == ERROR_CANCELLED.to_hresult() { "Admin permission was declined.".into() } else { e.message() });
    }
    if info.hProcess.is_invalid() {
        return Ok(0);
    }
    // SAFETY: hProcess is the process handle ShellExecuteExW gave us
    let pid = unsafe { GetProcessId(info.hProcess) };
    // SAFETY: closed once; alive() opens the process again by its id
    unsafe {
        let _ = CloseHandle(info.hProcess);
    }
    Ok(pid)
}

/// Whether process pid still runs. An elevated process may refuse to be
/// opened from here (access denied), which still means it exists.
pub fn alive(pid: u32) -> bool {
    if pid == 0 {
        return true; // unknown: rely on the API alone
    }
    // SAFETY: plain query access; the handle is closed below
    match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(h) => {
            let mut code = 0u32;
            // SAFETY: h is a valid process handle
            let ok = unsafe { GetExitCodeProcess(h, &mut code) }.is_ok();
            // SAFETY: h is ours
            unsafe {
                let _ = CloseHandle(h);
            }
            !ok || code == STILL_ACTIVE.0 as u32
        }
        Err(e) => e.code() == ERROR_ACCESS_DENIED.to_hresult(),
    }
}

// ---------- screen lock ----------

const WTS_SESSION_LOCK: usize = 0x7;
const WTS_SESSION_UNLOCK: usize = 0x8;

static ON_LOCK: std::sync::OnceLock<Box<dyn Fn(bool) + Send + Sync>> = std::sync::OnceLock::new();

extern "system" fn lock_wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if msg == WM_WTSSESSION_CHANGE
        && let Some(f) = ON_LOCK.get()
    {
        match wparam.0 {
            WTS_SESSION_LOCK => f(true),
            WTS_SESSION_UNLOCK => f(false),
            _ => {}
        }
    }
    // SAFETY: the default handling for every other message
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

/// Calls f(true) when this session's screen locks and f(false) when it
/// unlocks, from a thread of its own with a message-only window.
pub fn watch_lock(f: impl Fn(bool) + Send + Sync + 'static) {
    if ON_LOCK.set(Box::new(f)).is_err() {
        return;
    }
    std::thread::spawn(|| {
        // SAFETY: a message-only window owned by this thread, which runs its
        // message loop until the app ends
        unsafe {
            let Ok(module) = GetModuleHandleW(None) else { return };
            let class = w!("AuroraVPNLockWatch");
            let wc = WNDCLASSW { lpfnWndProc: Some(lock_wndproc), hInstance: module.into(), lpszClassName: class, ..Default::default() };
            RegisterClassW(&wc);
            let Ok(hwnd) = CreateWindowExW(WINDOW_EX_STYLE(0), class, w!(""), WINDOW_STYLE(0), 0, 0, 0, 0, Some(HWND_MESSAGE), None, Some(module.into()), None) else {
                return;
            };
            if WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION).is_err() {
                return;
            }
            let mut msg = MSG::default();
            while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                DispatchMessageW(&msg);
            }
        }
    });
}

// ---------- start at login ----------

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// Start at login, with --autostart. Entries left by the Electron app
/// (named after its app id) go: they point at its old program files.
pub fn set_autostart(on: bool) -> std::io::Result<()> {
    let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    let (key, _) = hkcu.create_subkey(RUN_KEY)?;
    for old in ["electron.app.port1897", "electron.app.AuroraVPN"] {
        let _ = key.delete_value(old);
    }
    if on {
        let exe = std::env::current_exe()?;
        key.set_value("AuroraVPN", &format!("\"{}\" --autostart", exe.display()))
    } else {
        match key.delete_value("AuroraVPN") {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_follows_commandlinetoargvw() {
        assert_eq!(win_quote("plain"), "plain");
        assert_eq!(win_quote(""), "\"\"");
        assert_eq!(win_quote(r"C:\Program Files\x"), r#""C:\Program Files\x""#);
        assert_eq!(win_quote(r#"a"b"#), r#""a\"b""#);
        assert_eq!(win_quote(r"dir with space\"), r#""dir with space\\""#);
    }

    #[test]
    fn this_process_is_alive_and_a_gone_one_is_not() {
        assert!(alive(std::process::id()));
        assert!(alive(0));
    }
}
