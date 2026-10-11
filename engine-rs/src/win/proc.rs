// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Child processes started as Go's startHidden does: CreateProcess with a
//! full path as the program, so there is no PATH lookup and no shell.

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CreateProcessW, GetExitCodeProcess, INFINITE, PROCESS_INFORMATION, STARTF_USESHOWWINDOW, STARTUPINFOW, WaitForSingleObject,
};

use super::{err_text, wide};
use crate::{golike, service};

/// A process handle, closed on drop.
pub struct Process {
    h: HANDLE,
    pub pid: u32,
}

// SAFETY: a process handle may be used and closed from any thread
unsafe impl Send for Process {}

impl Process {
    /// Waits up to ms (INFINITE for ever); whether it has ended.
    pub fn wait(&self, ms: u32) -> bool {
        // SAFETY: h is a process handle we own until drop
        unsafe { WaitForSingleObject(self.h, ms) == WAIT_OBJECT_0 }
    }

    pub fn wait_forever(&self) {
        self.wait(INFINITE);
    }

    /// Its exit code, once it has ended.
    pub fn exit_code(&self) -> Option<u32> {
        let mut c = 0u32;
        // SAFETY: h is valid; c is a writable u32
        (unsafe { GetExitCodeProcess(self.h, &mut c) } != 0).then_some(c)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // SAFETY: h is ours and closed once
        unsafe { CloseHandle(self.h) };
    }
}

/// Starts exe, a full path, with fixed args, hidden, inheriting nothing.
pub fn start_hidden(exe: &str, args: &[&str]) -> Result<Process, String> {
    if !golike::is_abs(exe) {
        return Err(format!("{exe}: not a full path"));
    }
    let mut argv = vec![golike::base(exe)];
    argv.extend(args.iter().map(|s| s.to_string()));
    let app = wide(exe);
    // CreateProcessW may write to the command line: a buffer of our own
    let mut line = wide(&service::compose_command_line(&argv));
    // SAFETY: zeroed is a valid STARTUPINFOW (all integers and null pointers)
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = 0; // SW_HIDE
    // SAFETY: as above
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: app and line are NUL-terminated and live through the call;
    // si and pi are valid for reads and writes
    let ok = unsafe {
        CreateProcessW(app.as_ptr(), line.as_mut_ptr(), std::ptr::null(), std::ptr::null(), 0, CREATE_NO_WINDOW, std::ptr::null(), std::ptr::null(), &si, &mut pi)
    };
    if ok == 0 {
        return Err(err_text(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32));
    }
    // SAFETY: the thread handle is ours and not used
    unsafe { CloseHandle(pi.hThread) };
    Ok(Process { h: pi.hProcess, pid: pi.dwProcessId })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::win::system_tool;

    #[test]
    fn runs_a_system_program_hidden() {
        // cmd's own exit code comes back: the arguments got through
        let p = start_hidden(&system_tool("cmd.exe"), &["/c", "exit 7"]).unwrap();
        assert!(p.wait(10_000));
        assert_eq!(p.exit_code(), Some(7));
        assert!(p.pid != 0);
        assert_eq!(start_hidden("cmd.exe", &[]).err().unwrap(), "cmd.exe: not a full path");
        assert_eq!(start_hidden(r"C:\nope\none.exe", &[]).err().unwrap(), "The system cannot find the path specified.");
    }
}
