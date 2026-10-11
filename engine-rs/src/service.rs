// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! AuroraVPN Service's pure parts (a port of service_windows.go): the pipe
//! protocol, the checks on what a client may ask, the paths, and the
//! engine's command line. The service runs the same executable with
//! `-service run`, listens on `\\.\pipe\AuroraVPN` and starts the engine
//! for the installed app; the Win32 side (SCM, pipe, tokens,
//! CreateProcess) is to come, and sits behind `EngineControl` here.

use serde::Serialize;

use crate::gojson::{self, Obj};
use crate::golike;

pub const SERVICE_NAME: &str = "AuroraVPN";
pub const PIPE_PATH: &str = r"\\.\pipe\AuroraVPN";
/// CreateNamedPipe: refuse clients on other computers.
pub const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x8;
/// The pipe: SYSTEM and administrators fully, interactive users (the app
/// runs unelevated) may connect; nobody else.
pub const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";
/// A folder SYSTEM and administrators change, users read and run.
pub const LOCKED_SDDL: &str = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
/// A request is read up to this many bytes.
pub const MAX_REQUEST: usize = 1 << 20;

/// One request to the service.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PipeRequest {
    /// ping, start, stop or cleanup
    pub cmd: String,
    /// start: the engine's flags
    pub args: Vec<String>,
}

impl PipeRequest {
    /// The request as Go's json.Decoder reads it from the pipe: the first
    /// JSON value. None means no answer: the service closes the pipe.
    pub fn decode(data: &[u8]) -> Option<PipeRequest> {
        // io.LimitReader: what lies past the limit is never read
        let data = &data[..data.len().min(MAX_REQUEST)];
        let v = gojson::decode_first(data, MAX_REQUEST).ok()?;
        let Some(o) = Obj::of(&v, "main.pipeRequest").ok()? else {
            return Some(PipeRequest::default());
        };
        let args = o.array("args", "[]string").ok()?.iter().map(|a| o.elem_string("args", a)).collect::<Result<Vec<_>, _>>().ok()?;
        Some(PipeRequest { cmd: o.string("cmd").ok()?, args })
    }
}

/// The service's answer; field order and omitted empty fields as Go's.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PipeReply {
    pub ok: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// start: the engine's process
    #[serde(skip_serializing_if = "is_zero")]
    pub pid: u32,
    /// ping
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version: String,
}

fn is_zero(v: &u32) -> bool {
    *v == 0
}

impl PipeReply {
    pub fn err(e: impl Into<String>) -> PipeReply {
        PipeReply { error: e.into(), ..Default::default() }
    }

    /// The reply as Go's json.Encoder writes it, newline included.
    pub fn encode(&self) -> String {
        crate::api::go_json(self)
    }
}

/// What the service does for an identified client.
pub trait EngineControl {
    /// Starts the engine with args (checked already); its pid.
    fn start(&mut self, args: &[String]) -> Result<u32, String>;
    /// Stops the running engine, if any.
    fn stop(&mut self);
    /// Runs fswin -cleanup.
    fn cleanup(&mut self) -> Result<(), String>;
}

/// Answers req from a client that `identified` says is (or is not) the
/// installed app.
pub fn handle(identified: Result<(), String>, req: &PipeRequest, version: &str, ctl: &mut dyn EngineControl) -> PipeReply {
    if let Err(e) = identified {
        return PipeReply::err(e);
    }
    match req.cmd.as_str() {
        "ping" => PipeReply { ok: true, version: version.into(), ..Default::default() },
        "start" => {
            if let Err(e) = check_engine_args(&req.args) {
                return PipeReply::err(e);
            }
            match ctl.start(&req.args) {
                Ok(pid) => PipeReply { ok: true, pid, ..Default::default() },
                Err(e) => PipeReply::err(e),
            }
        }
        "stop" => {
            ctl.stop();
            PipeReply { ok: true, ..Default::default() }
        }
        "cleanup" => match ctl.cleanup() {
            Ok(()) => PipeReply { ok: true, ..Default::default() },
            Err(e) => PipeReply::err(e),
        },
        other => PipeReply::err(format!("unknown request {}", golike::quote(other))),
    }
}

/// Flags that pick a program for the engine to run, or one of its own
/// modes, not a setting.
const REFUSED_FLAGS: &[&str] = &["service", "app", "stop-handle", "user-token", "usque"];

/// Refuses the flags a client may not pass.
pub fn check_engine_args(args: &[String]) -> Result<(), String> {
    if args.len() > 256 {
        return Err("too many flags".into());
    }
    for a in args {
        if a.len() > 8192 || a.contains('\0') {
            return Err("a flag is too long".into());
        }
        if !a.starts_with('-') {
            continue;
        }
        let name = a.trim_start_matches('-');
        let name = name.split_once('=').map_or(name, |(n, _)| n);
        if REFUSED_FLAGS.contains(&golike::to_lower(name).as_str()) {
            return Err(format!("the flag -{name} is not allowed through the service"));
        }
    }
    Ok(())
}

/// Whether a and b name the same program, written differently.
pub fn same_path(a: &str, b: &str) -> bool {
    !a.is_empty() && golike::equal_fold(&golike::clean(a), &golike::clean(b))
}

/// The folder the service runs code from: the app's install folder when
/// the engine sits in it (`<install>\resources\engine`), else the
/// engine's own.
pub fn install_root(exe: &str) -> String {
    let dir = golike::dir(exe);
    if golike::equal_fold(&golike::base(&dir), "engine") && golike::equal_fold(&golike::base(&golike::dir(&dir)), "resources") {
        return golike::dir(&golike::dir(&dir));
    }
    dir
}

/// The service's log, in the locked-down install folder.
pub fn service_log_path(exe: &str) -> String {
    crate::usque::join(&install_root(exe), "service.log")
}

/// Keeps -name to what netsh takes as a plain name:
/// `^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`.
pub fn valid_adapter_name(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty() && b.len() <= 64 && b[0].is_ascii_alphanumeric() && b[1..].iter().all(|c| c.is_ascii_alphanumeric() || b" ._-".contains(c))
}

/// The engine's command line from the service: the client's flags, the
/// stop event and, for a user, the user's token (inherited handles).
pub fn engine_argv(exe: &str, args: &[String], stop_handle: u64, user_token: Option<u64>) -> Vec<String> {
    let mut argv = vec![exe.to_string()];
    argv.extend(args.iter().cloned());
    argv.extend(["-stop-handle".into(), stop_handle.to_string()]);
    if let Some(t) = user_token {
        argv.extend(["-user-token".into(), t.to_string()]);
    }
    argv
}

/// The service's registered command line, for -service install.
pub fn service_argv(exe: &str, app: &str) -> Vec<String> {
    vec![exe.into(), "-service".into(), "run".into(), "-app".into(), app.into()]
}

/// x/sys/windows.EscapeArg: one argument as CommandLineToArgvW reads it
/// back.
pub fn escape_arg(s: &str) -> String {
    if s.is_empty() {
        return "\"\"".into();
    }
    let needs_backslash = s.contains(['"', '\\']);
    let has_space = s.contains([' ', '\t']);
    if !needs_backslash && !has_space {
        return s.into();
    }
    if !needs_backslash {
        return format!("\"{s}\"");
    }
    let mut b = String::with_capacity(s.len() + 2);
    if has_space {
        b.push('"');
    }
    let mut slashes = 0;
    for c in s.chars() {
        match c {
            '\\' => slashes += 1,
            '"' => {
                b.extend(std::iter::repeat_n('\\', slashes + 1));
                slashes = 0;
            }
            _ => slashes = 0,
        }
        b.push(c);
    }
    if has_space {
        b.extend(std::iter::repeat_n('\\', slashes));
        b.push('"');
    }
    b
}

/// x/sys/windows.ComposeCommandLine.
pub fn compose_command_line(args: &[String]) -> String {
    let Some(prog) = args.first() else {
        return String::new();
    };
    // quotes for a program name with spaces or control characters; a quote
    // inside it cannot be escaped and is dropped
    let pb = prog.as_bytes();
    let must_quote = pb.is_empty() || pb.iter().enumerate().any(|(i, &c)| c <= b' ' || (c == b'"' && i == 0));
    let mut line = if must_quote { format!("\"{}\"", prog.replace('"', "")) } else { prog.clone() };
    for a in &args[1..] {
        line.push(' ');
        line.push_str(&escape_arg(a));
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    // The service passes the app's flags to the engine, but never those
    // that pick a program to run or one of fswin's own modes.
    #[test]
    fn engine_args() {
        for args in [
            v(&["-api", "127.0.0.1:47897", "-token-file", r"C:\Users\me\AppData\Roaming\AuroraVPN\api-token", "-full", "-masque"]),
            v(&["-doh", "https://dns.example/dns-query", "-usque-flags", "-s qq.com"]),
            vec![],
        ] {
            assert!(check_engine_args(&args).is_ok(), "{args:?}");
        }
        let long = "x".repeat(9000);
        for args in [
            v(&["-usque", r"C:\evil.exe"]),
            v(&[r"--usque=C:\evil.exe"]),
            v(&["-full", "-service", "install"]),
            v(&["-app", r"C:\evil.exe"]),
            v(&["-stop-handle", "4"]),
            v(&["-user-token", "8"]),
            v(&["--user-token=8"]),
            v(&["-USQUE", "x"]),
            v(&["-doh", "a\0b"]),
            v(&["-doh", &long]),
            vec![String::new(); 300],
        ] {
            assert!(check_engine_args(&args).is_err(), "{:.60?}", args);
        }
        assert_eq!(check_engine_args(&v(&["---App=x"])).unwrap_err(), "the flag -App is not allowed through the service");
        assert_eq!(check_engine_args(&v(&["-doh", "a\0b"])).unwrap_err(), "a flag is too long");
    }

    #[test]
    fn paths() {
        let app = r"C:\Program Files\AuroraVPN\AuroraVPN.exe";
        assert!(same_path(r"c:\program files\auroravpn\AURORAVPN.EXE", app));
        assert!(same_path(r"C:\Program Files\AuroraVPN\.\AuroraVPN.exe", app));
        assert!(!same_path(r"C:\Users\me\Downloads\AuroraVPN.exe", app));
        assert!(!same_path("", ""));
        assert_eq!(install_root(r"C:\Program Files\AuroraVPN\resources\engine\fswin.exe"), r"C:\Program Files\AuroraVPN");
        assert_eq!(install_root(r"D:\a\port1897\dist\fswin.exe"), r"D:\a\port1897\dist");
        assert_eq!(service_log_path(r"C:\P\AuroraVPN\Resources\ENGINE\fswin.exe"), r"C:\P\AuroraVPN\service.log");
    }

    #[test]
    fn adapter_names() {
        for n in ["AuroraVPN", "AuroraVPN 2", "port1897", "a.b_c-d", &"a".repeat(64)] {
            assert!(valid_adapter_name(n), "{n:?}");
        }
        for n in ["", " lead", r#"x" exec C:\evil.txt ""#, "a=b", &"a".repeat(65), "name\nx", "a\n", "é", "aé"] {
            assert!(!valid_adapter_name(n), "{n:?}");
        }
    }

    // Compared with x/sys/windows v0.48.0's ComposeCommandLine.
    #[test]
    fn command_lines() {
        assert_eq!(
            compose_command_line(&service_argv(r"C:\Program Files\AuroraVPN\fswin.exe", r"C:\Program Files\AuroraVPN\AuroraVPN.exe")),
            r#""C:\Program Files\AuroraVPN\fswin.exe" -service run -app "C:\Program Files\AuroraVPN\AuroraVPN.exe""#
        );
        assert_eq!(
            compose_command_line(&v(&[r"C:\x\fswin.exe", "", r#"a"b"#, r"a\b", r#"a\\"b c"#, r"tail\", r"sp ace\\", "tab\there", "\"", r"\\server\share\"])),
            "C:\\x\\fswin.exe \"\" a\\\"b a\\b \"a\\\\\\\\\\\"b c\" tail\\ \"sp ace\\\\\\\\\" \"tab\there\" \\\" \\\\server\\share\\"
        );
        assert_eq!(compose_command_line(&v(&["\"quoted\"prog", "x"])), "\"quotedprog\" x");
        assert_eq!(compose_command_line(&v(&[""])), "\"\"");
        assert_eq!(compose_command_line(&v(&["plain"])), "plain");
        assert_eq!(compose_command_line(&v(&["a\u{1}b", "y"])), "\"a\u{1}b\" y");
        assert_eq!(compose_command_line(&[]), "");
        assert_eq!(
            engine_argv(r"C:\e\fswin.exe", &v(&["-full"]), 812, Some(900)),
            v(&[r"C:\e\fswin.exe", "-full", "-stop-handle", "812", "-user-token", "900"])
        );
        assert_eq!(engine_argv("f", &[], 1, None), v(&["f", "-stop-handle", "1"]));
    }

    struct Fake {
        calls: Vec<String>,
    }
    impl EngineControl for Fake {
        fn start(&mut self, args: &[String]) -> Result<u32, String> {
            self.calls.push(format!("start {}", args.join(" ")));
            if args.is_empty() { Err("start the engine: boom".into()) } else { Ok(4242) }
        }
        fn stop(&mut self) {
            self.calls.push("stop".into());
        }
        fn cleanup(&mut self) -> Result<(), String> {
            self.calls.push("cleanup".into());
            Err("stop protection first".into())
        }
    }

    #[test]
    fn protocol() {
        let mut f = Fake { calls: vec![] };
        let req = |s: &str| PipeRequest::decode(s.as_bytes()).unwrap();
        let ping = handle(Ok(()), &req(r#"{"cmd":"ping"}"#), "abc", &mut f);
        assert_eq!(ping.encode(), "{\"ok\":true,\"version\":\"abc\"}\n");
        let start = handle(Ok(()), &req(r#"{"CMD":"start","args":["-full"]} junk"#), "abc", &mut f);
        assert_eq!(start.encode(), "{\"ok\":true,\"pid\":4242}\n");
        let refused = handle(Ok(()), &req(r#"{"cmd":"start","args":["-usque","x.exe"]}"#), "abc", &mut f);
        assert_eq!(refused.encode(), "{\"ok\":false,\"error\":\"the flag -usque is not allowed through the service\"}\n");
        assert_eq!(handle(Ok(()), &req(r#"{"cmd":"start"}"#), "", &mut f).error, "start the engine: boom");
        assert_eq!(handle(Ok(()), &req(r#"{"cmd":"stop"}"#), "", &mut f), PipeReply { ok: true, ..Default::default() });
        assert_eq!(handle(Ok(()), &req(r#"{"cmd":"cleanup"}"#), "", &mut f).error, "stop protection first");
        assert_eq!(handle(Ok(()), &req("null"), "", &mut f).error, "unknown request \"\"");
        let who = handle(Err(r"C:\Users\me\evil.exe is not the AuroraVPN app".into()), &req(r#"{"cmd":"stop"}"#), "", &mut f);
        assert_eq!(who.encode(), "{\"ok\":false,\"error\":\"C:\\\\Users\\\\me\\\\evil.exe is not the AuroraVPN app\"}\n");
        assert_eq!(f.calls, ["start -full", "start ", "stop", "cleanup"]);
        // no answer to what is not a request
        for bad in ["", "{", "[1]", r#"{"cmd":1}"#, r#"{"args":"x"}"#, r#"{"args":[1]}"#] {
            assert_eq!(PipeRequest::decode(bad.as_bytes()), None, "{bad}");
        }
        assert_eq!(req(r#"{"args":[null,"a"]}"#).args, ["", "a"]);
    }
}
