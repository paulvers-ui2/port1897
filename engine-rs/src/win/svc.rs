// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! AuroraVPN Service, the Windows side (a port of service_windows.go; the
//! pipe protocol and the checks are in service.rs). The service starts the
//! engine when the app turns protection on, so the app needs no UAC prompt
//! each time.
//!
//! It runs as LocalSystem from the per-machine install, which only
//! administrators can change, and listens on `\\.\pipe\AuroraVPN`: one
//! request per connection, each answered on its own thread. It answers only
//! local clients (the pipe refuses remote ones) running the AuroraVPN.exe
//! the service was installed for, whoever the user: the engine runs as
//! SYSTEM, which a VPN needs, and inherits the asking user's own token
//! (`-user-token`), with which it opens the user's files (asuser.rs).

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_PIPE_CONNECTED, ERROR_SERVICE_SPECIFIC_ERROR, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, NO_ERROR, SYSTEMTIME,
};
use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetNamedSecurityInfoW};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, DuplicateTokenEx, LookupAccountSidW, PROTECTED_DACL_SECURITY_INFORMATION, RevertToSelf, SECURITY_ATTRIBUTES, SecurityImpersonation,
    TOKEN_DUPLICATE, TOKEN_QUERY, TokenPrimary, TokenSessionId,
};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, ImpersonateNamedPipeClient, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ControlService, CreateServiceW, DeleteService, OpenSCManagerW, OpenServiceW, QueryServiceStatus,
    RegisterServiceCtrlHandlerExW, SC_ACTION, SC_ACTION_RESTART, SC_HANDLE, SC_MANAGER_ALL_ACCESS, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_ALL_ACCESS,
    SERVICE_AUTO_START, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, SERVICE_CONFIG_DESCRIPTION, SERVICE_CONFIG_FAILURE_ACTIONS, SERVICE_CONFIG_SERVICE_SID_INFO,
    SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_DELAYED_AUTO_START_INFO, SERVICE_DESCRIPTIONW, SERVICE_ERROR_NORMAL,
    SERVICE_FAILURE_ACTIONSW, SERVICE_RUNNING, SERVICE_SID_INFO, SERVICE_SID_TYPE_UNRESTRICTED, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE,
    SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW, StartServiceW,
};
use windows_sys::Win32::System::SystemInformation::GetSystemTime;
use windows_sys::Win32::System::SystemServices::MAXIMUM_ALLOWED;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CreateEventW, CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentThread, GetExitCodeProcess, INFINITE,
    InitializeProcThreadAttributeList, OpenProcess, OpenThreadToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW, STARTF_USESHOWWINDOW, STARTUPINFOEXW, STARTUPINFOW, SetEvent, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};
use windows_sys::Win32::System::Time::SystemTimeToTzSpecificLocalTime;

use super::asuser::{SecDesc, Token, token_info, token_user, user_sid};
use super::{err_text, last_error, wide};
use crate::golike;
use crate::service::{self, EngineControl, LOCKED_SDDL, MAX_REQUEST, PIPE_PATH, PIPE_REJECT_REMOTE_CLIENTS, PIPE_SDDL, PipeRequest, SERVICE_NAME};
use crate::usque::join;

/// Handles -service install, uninstall and run.
pub fn service_main(cmd: &str, app: &str, version: &str) -> Result<(), String> {
    match cmd {
        "install" => install_service(app),
        "uninstall" => uninstall_service(),
        "run" => run_service(app, version),
        _ => Err(format!("-service must be install, uninstall or run, not {}", golike::quote(cmd))),
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// os.Executable: this program's path.
fn executable() -> Result<String, String> {
    std::env::current_exe().map(|p| p.to_string_lossy().into_owned()).map_err(|e| e.to_string())
}

/// filepath.Abs.
fn abs(path: &str) -> Result<String, String> {
    if golike::is_abs(path) {
        return Ok(golike::clean(path));
    }
    let p = std::path::absolute(path).map_err(|e| e.to_string())?;
    Ok(golike::clean(&p.to_string_lossy()))
}

/// The folder the service runs code from (service::install_root), and for
/// an engine in `<install>\engine` beside AuroraVPN.exe, `<install>`.
fn install_root(exe: &str) -> String {
    let dir = golike::dir(exe);
    let root = service::install_root(exe);
    if root != dir || !golike::equal_fold(&golike::base(&dir), "engine") {
        return root;
    }
    let up = golike::dir(&dir);
    if std::fs::metadata(join(&up, "AuroraVPN.exe")).is_ok_and(|m| !m.is_dir()) {
        return up;
    }
    dir
}

// ---------- the service manager ----------

/// A service manager or service handle, closed on drop.
struct Sc(SC_HANDLE);

impl Drop for Sc {
    fn drop(&mut self) {
        // SAFETY: the handle is ours and closed once
        unsafe { CloseServiceHandle(self.0) };
    }
}

fn connect() -> Result<Sc, String> {
    // SAFETY: null machine and database: the local, active one
    let h = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_ALL_ACCESS) };
    if h.is_null() {
        return Err(last_error());
    }
    Ok(Sc(h))
}

fn open_service(m: &Sc) -> Option<Sc> {
    let name = wide(SERVICE_NAME);
    // SAFETY: m is open; name is NUL-terminated
    let h = unsafe { OpenServiceW(m.0, name.as_ptr(), SERVICE_ALL_ACCESS) };
    (!h.is_null()).then_some(Sc(h))
}

fn config2<T>(s: &Sc, level: u32, v: &T) -> Result<(), String> {
    // SAFETY: v is the struct level takes, with what it points at alive
    if unsafe { ChangeServiceConfig2W(s.0, level, (v as *const T).cast()) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

const DISPLAY_NAME: &str = "AuroraVPN Service";
const DESCRIPTION: &str = "Starts AuroraVPN's engine when you turn protection on, without asking for admin rights each time.";

fn set_sid_type(s: &Sc) -> Result<(), String> {
    config2(s, SERVICE_CONFIG_SERVICE_SID_INFO, &SERVICE_SID_INFO { dwServiceSidType: SERVICE_SID_TYPE_UNRESTRICTED })
}

fn set_description(s: &Sc) -> Result<(), String> {
    let mut d = wide(DESCRIPTION);
    config2(s, SERVICE_CONFIG_DESCRIPTION, &SERVICE_DESCRIPTIONW { lpDescription: d.as_mut_ptr() })
}

/// Installs (or updates) the service for the app at app, and starts it.
fn install_service(app: &str) -> Result<(), String> {
    if app.is_empty() {
        return Err("-service install needs -app, the path of AuroraVPN.exe".into());
    }
    let app = abs(app)?;
    if !std::fs::metadata(&app).is_ok_and(|m| !m.is_dir()) {
        return Err(format!("-app {app}: not a program"));
    }
    let exe = executable()?;
    // a LocalSystem service runs code only from where administrators write
    let root = install_root(&exe);
    lock_down(&root).map_err(|e| format!("protect {root}: {e}"))?;

    let m = connect()?;
    let argv = service::service_argv(&exe, &app);
    let display = wide(DISPLAY_NAME);
    let s = match open_service(&m) {
        Some(s) => {
            // an update: the same service, maybe from a new folder
            stop_service(&s);
            let bin = wide(&service::compose_command_line(&argv));
            // SAFETY: s is open; the strings are NUL-terminated; null keeps
            // the rest (LocalSystem, no group, no dependencies)
            let ok = unsafe {
                ChangeServiceConfigW(
                    s.0,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    bin.as_ptr(),
                    null(),
                    null_mut(),
                    null(),
                    null(),
                    null(),
                    display.as_ptr(),
                )
            };
            if ok == 0 {
                return Err(last_error());
            }
            set_sid_type(&s)?;
            config2(&s, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &SERVICE_DELAYED_AUTO_START_INFO { fDelayedAutostart: 0 })?;
            set_description(&s)?;
            s
        }
        None => {
            // mgr.CreateService escapes each argument, the program too
            let bin = wide(&argv.iter().map(|a| service::escape_arg(a)).collect::<Vec<_>>().join(" "));
            let name = wide(SERVICE_NAME);
            // SAFETY: m is open; the strings are NUL-terminated
            let h = unsafe {
                CreateServiceW(
                    m.0,
                    name.as_ptr(),
                    display.as_ptr(),
                    SERVICE_ALL_ACCESS,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    bin.as_ptr(),
                    null(),
                    null_mut(),
                    null(),
                    null(),
                    null(),
                )
            };
            if h.is_null() {
                return Err(last_error());
            }
            let s = Sc(h);
            if let Err(e) = set_sid_type(&s).and_then(|()| set_description(&s)) {
                // SAFETY: s is open
                unsafe { DeleteService(s.0) };
                return Err(e);
            }
            s
        }
    };
    // a crash restarts it; an engine it started keeps running meanwhile
    let mut actions = [2_000, 10_000, 60_000].map(|ms| SC_ACTION { Type: SC_ACTION_RESTART, Delay: ms });
    let fa = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: 24 * 3600,
        lpRebootMsg: null_mut(),
        lpCommand: null_mut(),
        cActions: actions.len() as u32,
        lpsaActions: actions.as_mut_ptr(),
    };
    let _ = config2(&s, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);
    // SAFETY: s is open; no arguments
    if unsafe { StartServiceW(s.0, 0, null()) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

/// Stops the service, which stops its engine, and removes it.
fn uninstall_service() -> Result<(), String> {
    let m = connect()?;
    let Some(s) = open_service(&m) else {
        return Ok(()); // not installed
    };
    stop_service(&s);
    // SAFETY: s is open
    if unsafe { DeleteService(s.0) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

fn service_state(s: &Sc) -> Option<u32> {
    let mut st = SERVICE_STATUS::default();
    // SAFETY: s is open; st is writable
    (unsafe { QueryServiceStatus(s.0, &mut st) } != 0).then_some(st.dwCurrentState)
}

/// Asks s to stop and waits for it, at most 30 s.
fn stop_service(s: &Sc) {
    if service_state(s).is_none_or(|st| st == SERVICE_STOPPED) {
        return;
    }
    let mut st = SERVICE_STATUS::default();
    // SAFETY: s is open; st is writable
    unsafe { ControlService(s.0, SERVICE_CONTROL_STOP, &mut st) };
    for _ in 0..60 {
        if service_state(s).is_none_or(|st| st == SERVICE_STOPPED) {
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Lets only SYSTEM and administrators change dir and everything in it;
/// users read and run. Program Files is like that already; a folder picked
/// elsewhere, such as C:\AuroraVPN, may let users write.
fn lock_down(dir: &str) -> Result<(), String> {
    let sd = SecDesc::from_sddl(LOCKED_SDDL)?;
    let dacl = sd.dacl()?;
    let d = wide(dir);
    // SAFETY: d is NUL-terminated; the DACL lives in sd through the call
    let r = unsafe { SetNamedSecurityInfoW(d.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, null_mut(), null_mut(), dacl, null()) };
    if r != NO_ERROR {
        return Err(err_text(r));
    }
    Ok(())
}

// ---------- running as the service ----------

/// The app and version for the service's main function, which Windows
/// calls with no context of ours.
static RUN: OnceLock<(String, String)> = OnceLock::new();
/// Where the control handler sends what the service manager asks.
static CONTROLS: Mutex<Option<Sender<u32>>> = Mutex::new(None);

fn run_service(app: &str, version: &str) -> Result<(), String> {
    let _ = RUN.set((app.to_string(), version.to_string()));
    let mut name = wide(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW { lpServiceName: name.as_mut_ptr(), lpServiceProc: Some(service_proc) },
        SERVICE_TABLE_ENTRYW { lpServiceName: null_mut(), lpServiceProc: None },
    ];
    // SAFETY: the table ends with a null entry and, with name, lives until
    // the dispatcher returns, after the service has stopped
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

unsafe extern "system" fn control_handler(ctl: u32, _event: u32, _data: *mut core::ffi::c_void, _ctx: *mut core::ffi::c_void) -> u32 {
    if let Some(tx) = lock(&CONTROLS).as_ref() {
        let _ = tx.send(ctl);
    }
    NO_ERROR
}

unsafe extern "system" fn service_proc(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
    let (app, version) = RUN.get().cloned().unwrap_or_default();
    let (tx, rx) = mpsc::channel();
    *lock(&CONTROLS) = Some(tx);
    let name = wide(SERVICE_NAME);
    // SAFETY: name is NUL-terminated; the handler is a plain function
    let h = unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control_handler), null()) };
    if h.is_null() {
        return;
    }
    execute(&Status(h), &app, &version, rx);
}

/// The status handle of the running service.
struct Status(SERVICE_STATUS_HANDLE);

impl Status {
    fn set(&self, state: u32, accepts: u32, exit: u32, specific: u32) {
        let st = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: accepts,
            dwWin32ExitCode: exit,
            dwServiceSpecificExitCode: specific,
            dwCheckPoint: 0,
            dwWaitHint: 0,
        };
        // SAFETY: the handle came from RegisterServiceCtrlHandlerExW
        unsafe { SetServiceStatus(self.0, &st) };
    }
}

/// The service from start to stop: a pipe server while it runs.
fn execute(status: &Status, app: &str, version: &str, controls: mpsc::Receiver<u32>) {
    status.set(SERVICE_START_PENDING, 0, NO_ERROR, 0);
    let exe = executable().unwrap_or_default();
    let log = Arc::new(ServiceLog::new(join(&install_root(&exe), "service.log")));
    let ps = match PipeServer::new(app, &exe, version, log.clone()) {
        Ok(ps) => Arc::new(ps),
        Err(e) => {
            log.logf(&format!("start: {e}"));
            status.set(SERVICE_STOPPED, 0, ERROR_SERVICE_SPECIFIC_ERROR, 1);
            return;
        }
    };
    let server = ps.clone();
    std::thread::spawn(move || server.serve());
    let accepts = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    status.set(SERVICE_RUNNING, accepts, NO_ERROR, 0);
    log.logf(&format!("running {version} for {app}"));
    for c in controls {
        match c {
            SERVICE_CONTROL_INTERROGATE => status.set(SERVICE_RUNNING, accepts, NO_ERROR, 0),
            SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
                status.set(SERVICE_STOP_PENDING, 0, NO_ERROR, 0);
                ps.close();
                log.logf("stopped");
                break;
            }
            _ => {}
        }
    }
    status.set(SERVICE_STOPPED, 0, NO_ERROR, 0);
}

// ---------- the service's log ----------

/// The service's log, appended to and started over past 1 MB. It sits in
/// the locked-down install folder, where only SYSTEM and administrators
/// write.
pub(crate) struct ServiceLog {
    path: String,
    mu: Mutex<()>,
}

impl ServiceLog {
    pub(crate) fn new(path: String) -> ServiceLog {
        ServiceLog { path, mu: Mutex::new(()) }
    }

    pub(crate) fn logf(&self, msg: &str) {
        let _g = lock(&self.mu);
        if std::fs::metadata(&self.path).is_ok_and(|m| m.len() > 1 << 20) {
            let _ = std::fs::rename(&self.path, format!("{}.old", self.path));
        }
        let Ok(mut f) = OpenOptions::new().create(true).append(true).open(golike::clean(&self.path)) else {
            return;
        };
        let _ = f.write_all(format!("{} {msg}\n", now_rfc3339()).as_bytes());
    }
}

/// Days from 1970-01-01 to y-m-d (proleptic Gregorian).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn st_secs(t: &SYSTEMTIME) -> i64 {
    days_from_civil(t.wYear.into(), t.wMonth.into(), t.wDay.into()) * 86_400 + i64::from(t.wHour) * 3600 + i64::from(t.wMinute) * 60 + i64::from(t.wSecond)
}

/// A local time as Go's time.RFC3339 writes it: 2026-10-11T17:05:09+02:00,
/// or Z for UTC.
fn format_rfc3339(t: &SYSTEMTIME, offset_min: i64) -> String {
    let mut s = format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
    if offset_min == 0 {
        s.push('Z');
    } else {
        let a = offset_min.abs();
        s.push_str(&format!("{}{:02}:{:02}", if offset_min < 0 { '-' } else { '+' }, a / 60, a % 60));
    }
    s
}

fn now_rfc3339() -> String {
    let mut utc = SYSTEMTIME::default();
    let mut local = SYSTEMTIME::default();
    // SAFETY: both are writable SYSTEMTIMEs; null: the current time zone
    let ok = unsafe {
        GetSystemTime(&mut utc);
        SystemTimeToTzSpecificLocalTime(null(), &utc, &mut local)
    };
    if ok == 0 {
        return format_rfc3339(&utc, 0);
    }
    // the same instant twice, so the difference is the zone's offset
    let off = (st_secs(&local) - st_secs(&utc)) / 60;
    format_rfc3339(&local, off)
}

// ---------- the pipe ----------

/// Whether buf holds a whole JSON value, or something that more bytes
/// cannot make one: either way, reading can stop (Go's json.Decoder reads
/// just as far).
fn value_complete(buf: &[u8]) -> bool {
    let text = String::from_utf8_lossy(buf);
    let mut it = serde_json::Deserializer::from_str(&text).into_iter::<serde::de::IgnoredAny>();
    match it.next() {
        None => false,
        Some(Ok(_)) => true,
        Some(Err(e)) => !e.is_eof(),
    }
}

/// The request on f, as Go's json.Decoder over an io.LimitReader reads it.
fn read_request(f: &mut File) -> Option<PipeRequest> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while buf.len() < MAX_REQUEST {
        match f.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
        if value_complete(&buf) {
            break;
        }
    }
    PipeRequest::decode(&buf)
}

struct PipeServer {
    /// the only program that may ask
    app: String,
    version: String,
    log: Arc<ServiceLog>,
    sd: SecDesc,
    first: Mutex<Option<Token>>,
    closed: AtomicBool,
    engines: Engines,
}

impl PipeServer {
    fn new(app: &str, engine: &str, version: &str, log: Arc<ServiceLog>) -> Result<PipeServer, String> {
        let sd = SecDesc::from_sddl(PIPE_SDDL)?;
        let mut ps = PipeServer {
            app: app.into(),
            version: version.into(),
            log: log.clone(),
            sd,
            first: Mutex::new(None),
            closed: AtomicBool::new(false),
            engines: Engines::new(engine, log),
        };
        // the first instance fails if another program already holds the name
        let first = ps.instance(true).map_err(|e| format!("pipe {PIPE_PATH}: {e}"))?;
        ps.first = Mutex::new(Some(first));
        Ok(ps)
    }

    fn instance(&self, first: bool) -> Result<Token, String> {
        let name = wide(PIPE_PATH);
        let mut flags = PIPE_ACCESS_DUPLEX;
        if first {
            flags |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        let mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
        let sa = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: self.sd.0, bInheritHandle: 0 };
        // SAFETY: name is NUL-terminated; sa and its descriptor live through the call
        let h = unsafe { CreateNamedPipeW(name.as_ptr(), flags, mode, PIPE_UNLIMITED_INSTANCES, 64 << 10, 64 << 10, 0, &sa) };
        if h == INVALID_HANDLE_VALUE {
            return Err(last_error());
        }
        Ok(Token(h))
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Takes clients until close, each answered on a thread of its own.
    fn serve(self: Arc<Self>) {
        let Some(mut h) = lock(&self.first).take() else {
            return;
        };
        loop {
            // SAFETY: h is a pipe instance of ours; no overlapped I/O
            let ok = unsafe { ConnectNamedPipe(h.0, null_mut()) } != 0;
            let code = if ok { 0 } else { std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32 };
            if self.is_closed() {
                return;
            }
            if ok || code == ERROR_PIPE_CONNECTED {
                let ps = self.clone();
                std::thread::spawn(move || ps.answer(h));
            } else {
                self.log.logf(&format!("connect: {}", err_text(code)));
                drop(h);
            }
            // the next client gets a new instance of the pipe
            h = loop {
                match self.instance(false) {
                    Ok(n) => break n,
                    Err(e) => {
                        self.log.logf(&format!("pipe: {e}"));
                        if self.is_closed() {
                            return;
                        }
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
            };
        }
    }

    /// Stops taking clients, and stops the engine.
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        // a connection of our own wakes serve, waiting for the next client
        let name = wide(PIPE_PATH);
        // SAFETY: name is NUL-terminated; the handle, if any, is closed at once
        unsafe {
            let h = CreateFileW(name.as_ptr(), GENERIC_READ | GENERIC_WRITE, 0, null(), OPEN_EXISTING, 0, null_mut());
            if h != INVALID_HANDLE_VALUE {
                CloseHandle(h);
            }
        }
        self.engines.stop(Duration::from_secs(15));
    }

    /// Serves one connection: who asks, what for, and the reply.
    fn answer(&self, h: Token) {
        // SAFETY: the pipe handle is ours; the File owns and closes it now
        let mut f = unsafe { File::from_raw_handle(h.into_raw()) };
        let Some(req) = read_request(&mut f) else {
            return;
        };
        let client = self.identify(f.as_raw_handle());
        let identified = client.as_ref().map(|_| ()).map_err(|e| e.clone());
        let mut ctl = Ctl { engines: &self.engines, client: client.as_ref().ok() };
        let reply = service::handle(identified, &req, &self.version, &mut ctl);
        if !reply.ok {
            self.log.logf(&format!("{}: {}", req.cmd, reply.error));
        }
        let _ = f.write_all(reply.encode().as_bytes());
    }

    fn identify(&self, h: HANDLE) -> Result<Client, String> {
        let mut pid = 0u32;
        // SAFETY: h is a connected pipe; pid is writable
        if unsafe { GetNamedPipeClientProcessId(h, &mut pid) } == 0 {
            return Err(last_error());
        }
        // a handle on the process keeps its id from going to another meanwhile
        // SAFETY: plain call; the handle is closed by Token
        let p = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE, 0, pid) };
        if p.is_null() {
            return Err(format!("client {pid}: {}", last_error()));
        }
        let p = Token(p);
        let exe = process_path(p.0).map_err(|e| format!("client {pid}: {e}"))?;
        if !service::same_path(&exe, &self.app) {
            return Err(format!("{exe} is not the AuroraVPN app"));
        }
        let tok = pipe_client_token(h).map_err(|e| format!("client {pid}: {e}"))?;
        let user = account_name(tok.0).unwrap_or_else(|| "?".into());
        let token = user_primary(tok.0).map_err(|e| format!("{user}: {e}"))?;
        Ok(Client { user, token })
    }
}

fn process_path(p: HANDLE) -> Result<String, String> {
    let mut buf = vec![0u16; 32768]; // MAX_LONG_PATH
    let mut n = buf.len() as u32;
    // SAFETY: buf holds n characters
    if unsafe { QueryFullProcessImageNameW(p, 0, buf.as_mut_ptr(), &mut n) } == 0 {
        return Err(last_error());
    }
    Ok(String::from_utf16_lossy(&buf[..n as usize]))
}

/// The token of the program at the other end of the pipe h. Impersonation
/// belongs to a thread: a thread of its own, which ends right after, so it
/// can never stay the client.
fn pipe_client_token(h: HANDLE) -> Result<Token, String> {
    let hv = h as usize;
    std::thread::spawn(move || {
        // SAFETY: hv is a connected pipe that outlives this thread (joined)
        if unsafe { ImpersonateNamedPipeClient(hv as HANDLE) } == 0 {
            return Err(format!("impersonate: {}", last_error()));
        }
        let mut t = null_mut();
        // SAFETY: the pseudo handle of this thread; t receives the token
        let r = if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_DUPLICATE, 1, &mut t) } == 0 { Err(last_error()) } else { Ok(Token(t)) };
        // SAFETY: no arguments
        unsafe { RevertToSelf() };
        r
    })
    .join()
    .unwrap_or_else(|p| std::panic::resume_unwind(p))
}

/// DOMAIN\name of t's user.
fn account_name(t: HANDLE) -> Option<String> {
    let user = token_user(t).ok()?;
    let (mut name, mut domain) = (vec![0u16; 512], vec![0u16; 512]);
    let (mut nn, mut dn) = (name.len() as u32, domain.len() as u32);
    let mut use_ = 0;
    // SAFETY: the SID is valid in user; the buffers hold nn and dn characters
    if unsafe { LookupAccountSidW(null(), user_sid(&user), name.as_mut_ptr(), &mut nn, domain.as_mut_ptr(), &mut dn, &mut use_) } == 0 {
        return None;
    }
    Some(format!("{}\\{}", String::from_utf16_lossy(&domain[..dn as usize]), String::from_utf16_lossy(&name[..nn as usize])))
}

/// A primary copy of t, the token of the program that asked, that the
/// engine can inherit. Only the handle list of its CreateProcess names it
/// to the child.
fn user_primary(t: HANDLE) -> Result<Token, String> {
    let sa = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: null_mut(), bInheritHandle: 1 };
    let mut dup = null_mut();
    // SAFETY: t is a valid token; sa is valid; dup receives the copy
    if unsafe { DuplicateTokenEx(t, MAXIMUM_ALLOWED, &sa, SecurityImpersonation, TokenPrimary, &mut dup) } == 0 {
        return Err(format!("the user's token: {}", last_error()));
    }
    Ok(Token(dup))
}

/// The Windows session (log-on) a token belongs to.
fn token_session(t: HANDLE) -> u32 {
    token_info(t, TokenSessionId).ok().and_then(|b| b.first().map(|&v| v as u32)).unwrap_or(0)
}

/// Who asks: any user, in the installed app.
struct Client {
    user: String,
    /// the user's own token, primary, inheritable
    token: Token,
}

/// What the service does for one identified client.
struct Ctl<'a> {
    engines: &'a Engines,
    client: Option<&'a Client>,
}

impl EngineControl for Ctl<'_> {
    fn start(&mut self, args: &[String]) -> Result<u32, String> {
        let c = self.client.ok_or("no client")?;
        self.engines.start(c, args)
    }

    fn stop(&mut self) {
        self.engines.stop(Duration::from_secs(15));
    }

    fn cleanup(&mut self) -> Result<(), String> {
        self.engines.cleanup()
    }
}

// ---------- the engine ----------

/// A process the service started: the engine, or fswin -cleanup.
///
/// The service lets go of it the moment it ends: holding the process handle
/// kept the ended engine's id in use, and the app, which may not open a
/// SYSTEM process, read the "access denied" as "still running".
struct EngineProc {
    pid: u32,
    /// closed by watch only, once the process has ended
    process: usize,
    /// an event: set, the engine stops as for the app
    stop: usize,
    /// the exit code, once the process has ended and both handles are
    /// closed; signal and kill touch the handles only while it is None
    code: Mutex<Option<u32>>,
    ended: Condvar,
}

impl EngineProc {
    fn new(pid: u32, process: HANDLE, stop: HANDLE) -> Arc<EngineProc> {
        let e = Arc::new(EngineProc { pid, process: process as usize, stop: stop as usize, code: Mutex::new(None), ended: Condvar::new() });
        let w = e.clone();
        std::thread::spawn(move || w.watch());
        e
    }

    fn watch(&self) {
        let p = self.process as HANDLE;
        // SAFETY: p stays open until this function closes it, below
        unsafe { WaitForSingleObject(p, INFINITE) };
        let mut code = lock(&self.code);
        let mut c = 0u32;
        // SAFETY: both handles are ours, closed here once, under the lock
        unsafe {
            GetExitCodeProcess(p, &mut c);
            CloseHandle(p);
            CloseHandle(self.stop as HANDLE);
        }
        *code = Some(c);
        drop(code);
        self.ended.notify_all();
    }

    /// Waits up to d for the process to end.
    fn exited(&self, d: Duration) -> bool {
        let g = lock(&self.code);
        if d.is_zero() {
            return g.is_some();
        }
        let (g, _) = self.ended.wait_timeout_while(g, d, |c| c.is_none()).unwrap_or_else(|e| e.into_inner());
        g.is_some()
    }

    /// Waits for the end; the exit code.
    fn wait(&self) -> u32 {
        let g = self.ended.wait_while(lock(&self.code), |c| c.is_none()).unwrap_or_else(|e| e.into_inner());
        g.unwrap_or(0)
    }

    fn code(&self) -> Option<u32> {
        *lock(&self.code)
    }

    /// Asks the engine to stop, as the app's stop button does.
    fn signal(&self) {
        let g = lock(&self.code);
        if g.is_none() {
            // SAFETY: still open: watch closes it only under this lock
            unsafe { SetEvent(self.stop as HANDLE) };
        }
    }

    /// Ends the process at once.
    fn kill(&self) {
        let g = lock(&self.code);
        if g.is_none() {
            // SAFETY: as in signal
            unsafe { TerminateProcess(self.process as HANDLE, 1) };
        }
    }
}

/// An exit code as Windows writes it: 1, or 0xC0000005 for a crash.
fn win_code(c: u32) -> String {
    if c >= 0x8000_0000 { format!("0x{c:08X}") } else { c.to_string() }
}

/// The engine the service runs, at most one.
struct Engines {
    /// fswin.exe: this same program
    exe: String,
    log: Arc<ServiceLog>,
    running: Mutex<Option<Arc<EngineProc>>>,
}

impl Engines {
    fn new(exe: &str, log: Arc<ServiceLog>) -> Engines {
        Engines { exe: exe.into(), log, running: Mutex::new(None) }
    }

    fn start(&self, c: &Client, args: &[String]) -> Result<u32, String> {
        service::check_engine_args(args)?;
        let mut running = lock(&self.running);
        if let Some(e) = running.take() {
            // The app starts only when the engine's API is gone, so one still
            // alive is ending: its API goes first, then it removes its DNS
            // rule and adapter. Wait for it, or end it.
            if !e.exited(Duration::from_secs(15)) {
                self.log.logf(&format!("engine {} still running at a new start; ending it", e.pid));
                e.signal();
                if !e.exited(Duration::from_secs(5)) {
                    e.kill();
                    e.exited(Duration::from_secs(5));
                }
            }
        }
        let e = launch(Some(c.token.0), &self.exe, args)?;
        *running = Some(e.clone());
        self.log.logf(&format!("engine {} started as SYSTEM for {} (session {})", e.pid, c.user, token_session(c.token.0)));
        let log = self.log.clone();
        let pid = e.pid;
        std::thread::spawn(move || {
            let code = e.wait();
            log.logf(&format!("engine {pid} ended (exit code {})", win_code(code)));
        });
        Ok(pid)
    }

    /// Asks the running engine to stop, as the app's stop button does, and
    /// ends it if it has not after d.
    fn stop(&self, d: Duration) {
        let Some(e) = lock(&self.running).take() else {
            return;
        };
        if e.exited(Duration::ZERO) {
            return;
        }
        e.signal();
        if !e.exited(d) {
            self.log.logf(&format!("engine {} did not stop in {}s; ending it", e.pid, d.as_secs()));
            e.kill();
        }
    }

    /// Runs fswin -cleanup: it removes a kill switch and DNS rule that a
    /// crashed engine left behind.
    fn cleanup(&self) -> Result<(), String> {
        // an engine the app has just stopped may still be ending (its API
        // goes first): give it a moment
        let running = lock(&self.running).as_ref().is_some_and(|e| !e.exited(Duration::from_secs(5)));
        if running {
            return Err("stop protection first".into());
        }
        let e = launch(None, &self.exe, &["-cleanup".to_string()])?;
        if !e.exited(Duration::from_secs(30)) {
            e.kill();
            return Err("cleanup did not finish in 30 s".into());
        }
        match e.code() {
            Some(0) | None => Ok(()),
            Some(c) => Err(format!("cleanup failed (exit code {})", win_code(c))),
        }
    }
}

/// A PROC_THREAD_ATTRIBUTE_LIST in a buffer of ours, deleted on drop.
struct AttrList {
    buf: Vec<u64>,
}

impl AttrList {
    fn new(count: u32) -> Result<AttrList, String> {
        let mut size = 0usize;
        // SAFETY: a size query: no list
        unsafe { InitializeProcThreadAttributeList(null_mut(), count, 0, &mut size) };
        let mut l = AttrList { buf: vec![0u64; size.div_ceil(8).max(1)] };
        // SAFETY: buf holds size bytes, aligned
        if unsafe { InitializeProcThreadAttributeList(l.ptr(), count, 0, &mut size) } == 0 {
            let e = last_error();
            l.buf.clear(); // nothing to delete
            return Err(e);
        }
        Ok(l)
    }

    fn ptr(&mut self) -> *mut core::ffi::c_void {
        self.buf.as_mut_ptr().cast()
    }
}

impl Drop for AttrList {
    fn drop(&mut self) {
        if !self.buf.is_empty() {
            // SAFETY: the list was initialized and is deleted once
            unsafe { DeleteProcThreadAttributeList(self.ptr()) };
        }
    }
}

/// Starts exe with args as SYSTEM, the service's own account, hidden. The
/// engine inherits only the stop event (-stop-handle) and, for a user, the
/// user's token (-user-token).
fn launch(user: Option<HANDLE>, exe: &str, args: &[String]) -> Result<Arc<EngineProc>, String> {
    let sa = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: null_mut(), bInheritHandle: 1 };
    // SAFETY: sa is valid; a manual-reset event, not set, with no name
    let stop = unsafe { CreateEventW(&sa, 1, 0, null()) };
    if stop.is_null() {
        return Err(last_error());
    }
    let stop = Token(stop);

    let argv = service::engine_argv(exe, args, stop.0 as usize as u64, user.map(|u| u as usize as u64));
    let mut handles = vec![stop.0];
    handles.extend(user);
    let app = wide(exe);
    // CreateProcessW may write to the command line: a buffer of our own
    let mut line = wide(&service::compose_command_line(&argv));
    let dir = wide(&golike::dir(exe));

    let mut attrs = AttrList::new(1)?;
    // SAFETY: handles outlives the CreateProcessW call below, and its size
    // in bytes is what is passed
    let ok = unsafe {
        UpdateProcThreadAttribute(
            attrs.ptr(),
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            handles.as_ptr().cast(),
            handles.len() * std::mem::size_of::<HANDLE>(),
            null_mut(),
            null(),
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    // SAFETY: zeroed is a valid STARTUPINFOEXW (integers and null pointers)
    let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow = 0; // SW_HIDE
    si.lpAttributeList = attrs.ptr();
    // SAFETY: as above
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: the strings are NUL-terminated and live through the call; si
    // (an extended STARTUPINFO, as the flag says) and its list are valid
    let ok = unsafe {
        CreateProcessW(
            app.as_ptr(),
            line.as_mut_ptr(),
            null(),
            null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
            null(),
            dir.as_ptr(),
            (&si as *const STARTUPINFOEXW).cast::<STARTUPINFOW>(),
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(format!("start the engine: {}", last_error()));
    }
    // SAFETY: the thread handle is ours and not used
    unsafe { CloseHandle(pi.hThread) };
    Ok(EngineProc::new(pi.dwProcessId, pi.hProcess, stop.into_raw()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::STILL_ACTIVE;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    #[test]
    fn modes() {
        assert_eq!(service_main("start", "", "").unwrap_err(), "-service must be install, uninstall or run, not \"start\"");
        assert_eq!(service_main("install", "", "").unwrap_err(), "-service install needs -app, the path of AuroraVPN.exe");
        let none = r"C:\no\such\AuroraVPN.exe";
        assert_eq!(service_main("install", none, "").unwrap_err(), format!("-app {none}: not a program"));
    }

    #[test]
    fn exit_codes() {
        assert_eq!(win_code(1), "1");
        assert_eq!(win_code(0xC000_0005), "0xC0000005");
    }

    #[test]
    fn log_times() {
        let t = SYSTEMTIME { wYear: 2026, wMonth: 3, wDay: 9, wHour: 7, wMinute: 5, wSecond: 4, ..Default::default() };
        assert_eq!(format_rfc3339(&t, 0), "2026-03-09T07:05:04Z");
        assert_eq!(format_rfc3339(&t, 120), "2026-03-09T07:05:04+02:00");
        assert_eq!(format_rfc3339(&t, -330), "2026-03-09T07:05:04-05:30");
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        let now = now_rfc3339();
        assert!(now.len() >= 20 && now.as_bytes()[10] == b'T', "{now}");
    }

    #[test]
    fn requests_end_where_json_values_do() {
        for done in [r#"{"cmd":"ping"}"#, "{\"cmd\":\"ping\"}\r\n", "{] junk", "x", r#"{"cmd":"ping"} {"#] {
            assert!(value_complete(done.as_bytes()), "{done}");
        }
        for more in ["", "  ", r#"{"cmd":"pi"#, r#"{"cmd":"ping","args":["#] {
            assert!(!value_complete(more.as_bytes()), "{more}");
        }
    }

    #[test]
    fn install_roots() {
        assert_eq!(install_root(r"C:\Program Files\AuroraVPN\resources\engine\fswin.exe"), r"C:\Program Files\AuroraVPN");
        assert_eq!(install_root(r"D:\a\port1897\dist\fswin.exe"), r"D:\a\port1897\dist");
        // the Tauri app: <install>\AuroraVPN.exe, <install>\engine\fswin.exe
        let root = std::env::temp_dir().join(format!("fswin-rs-root-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let root = root.to_string_lossy().into_owned();
        std::fs::write(join(&root, "AuroraVPN.exe"), b"").unwrap();
        assert_eq!(install_root(&join(&root, r"engine\fswin.exe")), golike::clean(&root));
        let _ = std::fs::remove_dir_all(&root);
        // ui\engine of a checkout has no app beside it
        assert_eq!(install_root(r"D:\a\port1897\ui\engine\fswin.exe"), r"D:\a\port1897\ui\engine");
    }

    // The token the service hands the engine: a primary copy of the asking
    // program's, which the engine turns into its user token.
    #[test]
    fn user_token_from_the_service() {
        let mut h = null_mut();
        // SAFETY: the pseudo handle of this process; h receives the token
        assert_ne!(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut h) }, 0);
        let me = Token(h);
        let ut = user_primary(me.0).unwrap();
        assert!(account_name(me.0).is_some_and(|n| n.contains('\\')));
        let u = super::super::asuser::UserToken::from_handle(ut.into_raw() as usize as u64).unwrap();
        assert!(u.env().is_some_and(|e| e.iter().any(|v| v.to_uppercase().starts_with("USERPROFILE="))));
    }

    /// This test program as a fake engine: run by launch with the arguments
    /// below, "exit" ends at once with exit code 5; "wait" ends with 0 once
    /// the event of -stop-handle is set (9 if it is not within 30 s). Run
    /// as a test, it does nothing.
    #[test]
    fn fake_engine() {
        let args: Vec<String> = std::env::args().collect();
        if args.iter().any(|a| a == "fake-mode-exit") {
            std::process::exit(5);
        }
        if args.iter().any(|a| a == "fake-mode-wait") {
            let i = args.iter().position(|a| a == "-stop-handle").expect("no -stop-handle");
            let h: u64 = args[i + 1].parse().unwrap();
            // SAFETY: the handle was inherited from the test that started us
            let r = unsafe { WaitForSingleObject(h as usize as HANDLE, 30_000) };
            std::process::exit(if r == 0 { 0 } else { 9 });
        }
    }

    fn fake(mode: &str) -> Arc<EngineProc> {
        let exe = executable().unwrap();
        // libtest takes what follows "--" as name filters: only fake_engine runs
        let args = ["--exact", "win::svc::tests::fake_engine", "--nocapture", "--", &format!("fake-mode-{mode}")].map(String::from);
        launch(None, &exe, &args).unwrap()
    }

    /// Whether pid no longer names the process that had it, as the app
    /// checks: an ended process whose handle someone still holds keeps its id.
    fn pid_gone(pid: u32) -> bool {
        // SAFETY: plain call; the handle is closed by Token
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h.is_null() {
            return true;
        }
        let h = Token(h);
        let mut code = 0u32;
        // SAFETY: h is valid; code is writable
        (unsafe { GetExitCodeProcess(h.0, &mut code) }) != 0 && code == STILL_ACTIVE as u32 // the id went to a new process
    }

    fn wait_pid_gone(pid: u32) {
        for _ in 0..100 {
            if pid_gone(pid) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("process {pid} ended, but its id stays taken: the app waits 15 s for it");
    }

    fn test_log(tag: &str) -> Arc<ServiceLog> {
        Arc::new(ServiceLog::new(std::env::temp_dir().join(format!("fswin-rs-svc-{tag}-{}.log", std::process::id())).to_string_lossy().into_owned()))
    }

    // An engine that ends lets go of its process id at once, and its exit
    // code is kept for the log.
    #[test]
    fn lets_go_of_an_ended_engine() {
        let e = fake("exit");
        if !e.exited(Duration::from_secs(10)) {
            e.kill();
            panic!("the fake engine did not end");
        }
        assert_eq!(e.code(), Some(5));
        wait_pid_gone(e.pid);
        e.signal(); // after the end: does nothing, rather than touch a closed handle
        e.kill();
    }

    #[test]
    fn stops_its_engine() {
        let e = fake("wait");
        let eng = Engines::new("", test_log("stop"));
        *lock(&eng.running) = Some(e.clone());
        let began = std::time::Instant::now();
        eng.stop(Duration::from_secs(10));
        assert!(e.exited(Duration::ZERO) && e.code() == Some(0), "not stopped by its event: {:?}", e.code());
        assert!(began.elapsed() < Duration::from_secs(5), "stop took {:?}", began.elapsed());
        assert!(lock(&eng.running).is_none(), "the service still counts it as running");
        wait_pid_gone(e.pid);
    }

    #[test]
    fn service_log() {
        let log = test_log("log");
        let _ = std::fs::remove_file(&log.path);
        log.logf("engine 1 ended (exit code 0)");
        let text = std::fs::read_to_string(&log.path).unwrap();
        assert!(text.ends_with(" engine 1 ended (exit code 0)\n"), "{text}");
        let _ = std::fs::remove_file(&log.path);
    }

    #[test]
    #[ignore = "admin: installs AuroraVPN Service; run tools/sim/service-windows.ps1 instead"]
    fn install_and_uninstall() {
        // the acceptance test drives the real service end to end; this only
        // checks that uninstall of a service that is not there is quiet
        uninstall_service().unwrap();
    }
}
