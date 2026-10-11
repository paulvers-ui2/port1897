// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! -logfile and -stop-handle: the process's output into a file, for when
//! the app or the service starts the engine without a console, and the
//! service's stop event.

use std::os::windows::io::IntoRawHandle;

use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Console::{STD_ERROR_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle};
use windows_sys::Win32::System::Threading::{INFINITE, WaitForSingleObject};

/// Sends stdout and stderr to the -logfile, opened with the user's rights
/// (asuser), as Go's redirectOutput. Rust's stdout looks the handle up on
/// every write, so SetStdHandle is enough; the file stays open for the
/// process's life.
pub fn redirect_to(f: std::fs::File) -> Result<(), String> {
    let h = f.into_raw_handle() as HANDLE;
    // SAFETY: h is an open file handle we never close
    let ok = unsafe { SetStdHandle(STD_OUTPUT_HANDLE, h) != 0 && SetStdHandle(STD_ERROR_HANDLE, h) != 0 };
    if ok { Ok(()) } else { Err(super::last_error()) }
}

/// Waits until the inherited event h is set; false if the wait failed (a
/// bad handle), so no stop is made up.
pub fn wait_event(h: u64) -> bool {
    // SAFETY: an inherited handle value from the service; a bad one makes
    // the wait fail rather than misbehave
    unsafe { WaitForSingleObject(h as usize as HANDLE, INFINITE) == WAIT_OBJECT_0 }
}
