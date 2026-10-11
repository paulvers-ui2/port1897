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
/// The prompt waits for the user, so this runs on a thread of its own.
pub async fn launch_elevated(exe: &Path, args: &[String]) -> Result<u32, String> {
    // only a full path: a bare name would be looked up from the current
    // folder, which is no place to pick what runs as admin
    if !exe.is_absolute() {
        return Err(format!("Engine not found at {}", exe.display()));
    }
    let (exe, args) = (exe.to_path_buf(), args.to_vec());
    tokio::task::spawn_blocking(move || {
        use windows::Win32::System::Com::{COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize};
        // ShellExecuteEx wants COM on its thread (Microsoft's docs)
        // SAFETY: on this pool thread; a thread that has COM already gets
        // S_FALSE (counted, so undone below too) or RPC_E_CHANGED_MODE
        let com = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) }.is_ok();
        let r = launch_elevated_blocking(&exe, &args);
        if com {
            // SAFETY: pairs the successful CoInitializeEx above, so the pool
            // thread goes back without COM for whatever runs on it next
            unsafe { CoUninitialize() };
        }
        r
    })
    .await
    .map_err(|e| e.to_string())?
}

fn launch_elevated_blocking(exe: &Path, args: &[String]) -> Result<u32, String> {
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

/// Whether the server end of a named pipe runs in session 0, where services
/// run; programs of a signed-in user run in their own session.
pub fn pipe_server_is_service(pipe: &impl std::os::windows::io::AsRawHandle) -> bool {
    let mut session = u32::MAX;
    // SAFETY: the pipe handle is open for the duration of the call
    let ok = unsafe { windows::Win32::System::Pipes::GetNamedPipeServerSessionId(windows::Win32::Foundation::HANDLE(pipe.as_raw_handle()), &mut session) }.is_ok();
    ok && session == 0
}

// ---------- the window's WebView2 ----------

/// Locks the window's WebView2 down as the Electron app's window was: every
/// web permission request (camera, microphone, location, notifications...)
/// is refused, nothing typed into forms and no password is kept, and the
/// browser's own keys (F5 and Ctrl+R reload, Ctrl+P print, Ctrl+F find...)
/// do nothing, while editing keys (copy, paste, undo) and the page's own
/// keys still work. A release also has no devtools and no default context
/// menu; the packaged Electron window had neither. All but the autofill
/// settings apply from the next page load: call it before the first one.
pub fn lock_down_webview(controller: &webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Controller) -> windows::core::Result<()> {
    use webview2_com::Microsoft::Web::WebView2::Win32::{COREWEBVIEW2_PERMISSION_STATE_DENY, ICoreWebView2Settings3, ICoreWebView2Settings4};
    use windows::core::Interface;
    // SAFETY: COM calls on the window's thread, which owns the controller;
    // the handler is kept by WebView2 for the life of the webview
    unsafe {
        let wv = controller.CoreWebView2()?;
        let mut token = 0i64;
        wv.add_PermissionRequested(
            &webview2_com::PermissionRequestedEventHandler::create(Box::new(|_, args| {
                if let Some(args) = args {
                    args.SetState(COREWEBVIEW2_PERMISSION_STATE_DENY)?;
                }
                Ok(())
            })),
            &mut token,
        )?;
        let settings = wv.Settings()?;
        settings.cast::<ICoreWebView2Settings3>()?.SetAreBrowserAcceleratorKeysEnabled(false)?;
        let s4 = settings.cast::<ICoreWebView2Settings4>()?;
        s4.SetIsGeneralAutofillEnabled(false)?;
        s4.SetIsPasswordAutosaveEnabled(false)?;
        if !cfg!(debug_assertions) {
            settings.SetAreDevToolsEnabled(false)?;
            settings.SetAreDefaultContextMenusEnabled(false)?;
        }
    }
    Ok(())
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
