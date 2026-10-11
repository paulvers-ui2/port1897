// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Starting and stopping the engine (fswin.exe). It needs admin rights:
//! AuroraVPN Service starts it without a prompt for the installed app; the
//! portable app, a build from source, or a standard user get a UAC prompt.
//! One start or stop runs at a time (OP), so a double click, the tray and
//! the window cannot cross each other.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::settings::{self, S};
use crate::{api, applog, paths, rules, usque, wg, winutil};

/// One start or stop at a time.
pub static OP: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The app asked the engine to stop: its end is no surprise.
pub static EXPECTED_STOP: AtomicBool = AtomicBool::new(false);

/// The engine this app started, 0 if not known.
static ENGINE_PID: AtomicU32 = AtomicU32::new(0);

/// The engine's status names its exit as fswin's exitName does; "" is direct.
fn engine_exit(exit: &str) -> Option<&'static str> {
    Some(match exit {
        "none" | "" => "",
        "masque" => "Cloudflare WARP (MASQUE)",
        "chain" => "WARP chain",
        "warp" => "Cloudflare WARP",
        "wg" => "WireGuard",
        "socks" | "http" => "proxy",
        _ => return None,
    })
}

/// Whether a running engine's status st has the exit s asks for.
pub fn runs_exit(st: &Value, s: &S) -> bool {
    match engine_exit(settings::str(s, "exit")) {
        None => true,
        Some(want) => st.get("exit").and_then(Value::as_str).unwrap_or("") == want,
    }
}

fn split(t: &str) -> Vec<String> {
    t.split_whitespace().map(String::from).collect()
}

const DEFAULT_SNI: &str = "consumer-masque.cloudflareclient.com";

pub fn masque_flags(s: &S) -> String {
    let warp_sni = settings::str(s, "warpSni");
    let sni = if warp_sni.is_empty() { DEFAULT_SNI } else { warp_sni };
    let mut out = if warp_sni.is_empty() { vec![] } else { vec!["-s".to_string(), warp_sni.to_string()] };
    out.extend(split(&settings::str(s, "masqueFlags").replace("{sni}", sni)));
    out.join(" ")
}

pub fn chain_flags(s: &S) -> String {
    let warp_sni = settings::str(s, "warpSni");
    let exit_sni = settings::str(s, "exitSni");
    let sni = if warp_sni.is_empty() { DEFAULT_SNI } else { warp_sni };
    let xsni = if exit_sni.is_empty() { DEFAULT_SNI } else { exit_sni };
    let mut out = if warp_sni.is_empty() { vec![] } else { vec!["-s".to_string(), warp_sni.to_string()] };
    out.extend(split(&settings::str(s, "warp1Flags").replace("{sni}", sni)));
    out.extend(split(settings::str(s, "wgFlags")));
    if !exit_sni.is_empty() {
        out.extend(["--exit-sni".to_string(), exit_sni.to_string()]);
    }
    out.extend(split(&settings::str(s, "warp2Flags").replace("{exit_sni}", xsni)));
    out.join(" ")
}

fn p(path: std::path::PathBuf) -> String {
    path.to_string_lossy().into_owned()
}

/// fswin's command line for the settings s.
pub fn engine_args(s: &S) -> Vec<String> {
    let mut a: Vec<String> = vec![
        "-api".into(),
        format!("{}:{}", paths::API_HOST, paths::API_PORT),
        "-token-file".into(),
        p(paths::token_file()),
        "-logfile".into(),
        p(paths::log_file()),
        "-warp-file".into(),
        p(paths::warp_file()),
        "-log".into(),
        settings::number(settings::num(s, "logLevel")).to_string(),
        "-fallback-doh".into(),
        settings::str(s, "fallbackDoh").into(),
        "-fallback-ips".into(),
        settings::str(s, "fallbackIps").into(),
    ];
    let mtu = settings::num(s, "mtu");
    if (1280.0..=1500.0).contains(&mtu) {
        a.extend(["-mtu".into(), settings::number(mtu).to_string()]);
    }
    // Firewall mode leaves DNS to the network adapter's servers, as on Android
    let dns_type = settings::str(s, "dnsType");
    let t = if settings::str(s, "mode") == "firewall" {
        "system"
    } else if dns_type == "rdns" {
        "doh"
    } else {
        dns_type
    };
    a.extend(["-dns".into(), t.into()]);
    match t {
        "doh" => a.extend(["-doh".into(), settings::str(s, "doh").into(), "-doh-ips".into(), settings::str(s, "dohIps").into()]),
        "dot" => a.extend(["-dot".into(), settings::str(s, "dot").into()]),
        "dnscrypt" => {
            a.extend(["-dnscrypt".into(), settings::str(s, "dnscrypt").into()]);
            let relays: Vec<String> = settings::arr(s, "dnscryptRelays").iter().map(|v| v.as_str().map(String::from).unwrap_or_else(|| v.to_string())).collect();
            if !relays.is_empty() {
                a.extend(["-dnscrypt-relays".into(), relays.join(",")]);
            }
        }
        "odoh" => {
            a.extend(["-odoh".into(), settings::str(s, "odoh").into()]);
            if !settings::str(s, "odohRelay").is_empty() {
                a.extend(["-odoh-relay".into(), settings::str(s, "odohRelay").into()]);
            }
        }
        "proxy" => a.extend(["-dns-proxy".into(), settings::str(s, "dnsProxy").into()]),
        _ => {}
    }
    // on-device blocklists are not offered any more; the filetag names the
    // lists of RethinkDNS servers
    let filetag = paths::bl_dir().join("filetag.json");
    if filetag.exists() {
        a.extend(["-filetag".into(), p(filetag)]);
    }
    for (k, flag) in [("dnsDirect", "-dns-direct"), ("dnsCache", "-dns-cache"), ("dnssec", "-dnssec"), ("undelegated", "-undelegated"), ("dnsFallback", "-dns-fallback")] {
        if settings::bool(s, k) {
            a.push(flag.into());
        }
    }
    if settings::str(s, "mode") != "dns" {
        a.push("-full".into());
    }
    if settings::bool(s, "nrpt") {
        a.push("-nrpt".into());
    }
    if settings::bool(s, "killSwitch") {
        a.push("-killswitch".into());
        if settings::bool(s, "allowLan") {
            a.push("-allow-lan".into());
        }
    }
    match settings::str(s, "exit") {
        "masque" => {
            a.extend(["-masque".into(), "-usque-dir".into(), p(paths::usque_dir())]);
            let f = masque_flags(s);
            if !f.is_empty() {
                a.extend(["-usque-flags".into(), f]);
            }
        }
        "chain" => {
            a.extend(["-chain".into(), p(usque::wg0()), "-usque-dir".into(), p(paths::usque_dir())]);
            let f = chain_flags(s);
            if !f.is_empty() {
                a.extend(["-usque-flags".into(), f]);
            }
        }
        "warp" => a.push("-warp".into()),
        "wg" => {
            if let Some(f) = wg::file(settings::str(s, "wgActive")) {
                a.extend(["-wg".into(), p(f)]);
            }
        }
        kind @ ("socks" | "http") => {
            if let Some(px) = settings::obj(s, kind)
                && !px.get("host").and_then(Value::as_str).unwrap_or("").is_empty()
            {
                a.extend(["-proxy".into(), rules::proxy_url(kind, px)]);
            }
        }
        _ => {}
    }
    // written by start_once (rules::save_rules), from the newest settings
    a.extend(["-rules".into(), p(paths::rules_file())]);
    let routes = rules::routes_of(s);
    if !routes.is_empty() {
        let f = paths::routes_file();
        let _ = std::fs::write(&f, serde_json::to_string_pretty(&routes).unwrap_or_default());
        a.extend(["-routes".into(), p(f)]);
    }
    let dial = settings::str(s, "dialStrategy");
    a.extend(["-dial-strategy".into(), if dial.is_empty() { "never".into() } else { dial.into() }]);
    if !settings::str(s, "dialRetry").is_empty() {
        a.extend(["-dial-retry".into(), settings::str(s, "dialRetry").into()]);
    }
    let dt = settings::num(s, "dialTimeout");
    if dt > 0.0 {
        a.extend(["-dial-timeout".into(), settings::number(dt).to_string()]);
    }
    if settings::bool(s, "tcpKeepAlive") {
        a.push("-tcp-keepalive".into());
    }
    if settings::bool(s, "eim") {
        a.push("-eim".into());
    }
    if settings::bool(s, "pcap") {
        a.extend(["-pcap".into(), p(paths::pcap_file())]);
    }
    a
}

// ---------- AuroraVPN Service ----------

// The service (fswin -service, installed with the app) starts the engine for
// an administrator without a UAC prompt; its pipe answers only the installed
// AuroraVPN.exe. None when there is no service.
const SERVICE_PIPE: &str = r"\\.\pipe\AuroraVPN";
const ERROR_PIPE_BUSY: i32 = 231;
// The service impersonates the app to learn who asks and to start the
// engine with the app user's own token, which needs this level. tokio's
// default (identification) made every start fall back to a UAC prompt.
const SECURITY_IMPERSONATION: u32 = 2 << 16;

async fn service_call_once(req: &Value, timeout: Duration) -> Result<Option<Value>, bool> {
    use tokio::net::windows::named_pipe::ClientOptions;
    let mut pipe = match ClientOptions::new().security_qos_flags(SECURITY_IMPERSONATION).open(SERVICE_PIPE) {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => return Err(true),
        Err(e) => return Ok(Some(json!({ "ok": false, "error": format!("AuroraVPN Service: {e}") }))),
    };
    // services run in session 0; a pipe of that name made by a program in
    // the user's own session is not the service, and gets nothing from us
    if !winutil::pipe_server_is_service(&pipe) {
        crate::applog!("AuroraVPN Service: the pipe's server is not in session 0; not used");
        return Ok(Some(json!({ "ok": false, "error": "AuroraVPN Service: the pipe is not the service's" })));
    }
    let talk = async {
        pipe.write_all(format!("{req}\n").as_bytes()).await?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match pipe.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.len() > 1 << 16 {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => break,
                Err(e) => return Err(e),
            }
        }
        Ok::<_, std::io::Error>(buf)
    };
    match tokio::time::timeout(timeout, talk).await {
        Err(_) => Ok(Some(json!({ "ok": false, "error": "AuroraVPN Service did not answer." }))),
        Ok(Err(e)) => Ok(Some(json!({ "ok": false, "error": format!("AuroraVPN Service: {e}") }))),
        Ok(Ok(buf)) if buf.len() > 1 << 16 => Ok(Some(json!({ "ok": false, "error": "AuroraVPN Service: reply too long" }))),
        Ok(Ok(buf)) => Ok(Some(serde_json::from_slice(&buf).unwrap_or_else(|_| json!({ "ok": false, "error": "AuroraVPN Service gave no reply." })))),
    }
}

pub async fn service_call(req: &Value) -> Option<Value> {
    for i in 0.. {
        match service_call_once(req, Duration::from_secs(70)).await {
            Ok(r) => return r,
            Err(_busy) if i < 3 => tokio::time::sleep(Duration::from_millis(300)).await, // every pipe instance busy: a moment
            Err(_) => return Some(json!({ "ok": false, "error": "AuroraVPN Service is busy." })),
        }
    }
    None
}

// ---------- the engine's log ----------

/// The last n lines of engine.log, read from its end.
pub fn last_log_lines(n: usize) -> String {
    let text = crate::logs::read_tail(&paths::log_file(), 256 << 10).unwrap_or_default();
    let lines: Vec<&str> = text.trim().lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

/// The reason fswin gave for stopping: its last "fswin: ..." line that is
/// not a warning.
fn engine_failure() -> String {
    for l in last_log_lines(60).lines().rev() {
        if let Some(m) = l.trim().strip_prefix("fswin: ")
            && !m.starts_with("warning")
        {
            return m.to_string();
        }
    }
    String::new()
}

// ---------- start and stop ----------

fn fail(error: impl Into<String>) -> Value {
    json!({ "ok": false, "error": error.into() })
}

/// Starts the engine with the settings, and logs how it went.
pub async fn start() -> Value {
    let _g = OP.lock().await;
    start_locked().await
}

/// start, for a caller that holds OP.
pub async fn start_locked() -> Value {
    let s = settings::read();
    let r = start_once().await;
    let ok = r.get("ok").and_then(Value::as_bool) == Some(true);
    let what = if ok { "engine running".to_string() } else { format!("engine did not start: {}", r.get("error").and_then(Value::as_str).unwrap_or("")) };
    let log = r.get("log").and_then(Value::as_str).map(|l| format!("\n{l}")).unwrap_or_default();
    applog!(
        "{what} (mode {}, DNS {}, exit {}, kill switch {}){log}",
        settings::str(&s, "mode"),
        settings::str(&s, "dnsType"),
        settings::str(&s, "exit"),
        if settings::bool(&s, "killSwitch") { "on" } else { "off" }
    );
    r
}

async fn start_once() -> Value {
    // Start runs the engine with the settings: one already running with
    // another exit (Connect chain while protection is on) restarts
    if let Some(st) = api::status().await {
        if runs_exit(&st, &settings::read()) {
            return json!({ "ok": true });
        }
        let stop = stop_once(false).await;
        if stop.get("ok").and_then(Value::as_bool) != Some(true) {
            return stop;
        }
    }
    // a previous engine that is still ending (its DNS rule and adapter)
    // would answer the service in place of a new one
    engine_exited(Duration::from_secs(20)).await;

    let exe = paths::engine_path();
    if !exe.is_absolute() || !exe.exists() {
        return fail(format!("Engine not found at {}", exe.display()));
    }
    let s = settings::read();
    if settings::str(&s, "exit") == "chain" && !usque::wg0().exists() {
        return fail("Chain mode needs a wg0.conf (Proxy → Chain mode).");
    }
    if settings::str(&s, "exit") == "wg" && wg::file(settings::str(&s, "wgActive")).is_none() {
        return fail("Choose a WireGuard config first (Proxy → Setup WireGuard).");
    }
    if let Err(e) = api::ensure_token() {
        return fail(format!("The engine could not start: {e}"));
    }
    crate::logs::reset_offset();
    // the engine truncates its log; keep the last run's for the debug zip
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match std::fs::rename(paths::log_file(), paths::prev_log_file()) {
            Ok(()) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) if Instant::now() < deadline => tokio::time::sleep(Duration::from_millis(50)).await,
            Err(_) => break,
        }
    }
    rules::save_rules().await;
    let args = engine_args(&s);
    let pid = match service_call(&json!({ "cmd": "start", "args": args })).await {
        Some(r) if r.get("ok").and_then(Value::as_bool) == Some(true) => {
            let pid = r.get("pid").and_then(Value::as_u64).unwrap_or(0) as u32;
            applog!("engine {pid} started by AuroraVPN Service");
            pid
        }
        other => {
            if let Some(r) = other {
                applog!("AuroraVPN Service did not start the engine; asking through UAC: {}", r.get("error").and_then(Value::as_str).unwrap_or(""));
            }
            match winutil::launch_elevated(&exe, &args).await {
                Ok(id) => id,
                Err(e) => return fail(e),
            }
        }
    };
    ENGINE_PID.store(pid, Ordering::Relaxed);
    // WARP registration and the usque chain can take a while on first use;
    // an engine that exits instead is reported at once, with its own reason.
    // Quick looks first: the engine is usually up within a second or two.
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(60) {
        let wait = if started.elapsed() < Duration::from_secs(5) { 50 } else { 250 };
        tokio::time::sleep(Duration::from_millis(wait)).await;
        if api::status().await.is_some() {
            settings::update(|s| {
                s.insert("wasRunning".into(), json!(true));
            });
            return json!({ "ok": true });
        }
        if !winutil::alive(pid) {
            tokio::time::sleep(Duration::from_millis(300)).await; // its last log lines
            let why = engine_failure();
            let error = if why.is_empty() { "The engine stopped while starting.".to_string() } else { format!("The engine stopped: {why}") };
            return json!({ "ok": false, "error": error, "log": last_log_lines(15) });
        }
    }
    json!({ "ok": false, "error": "The engine did not start in 60 seconds.", "log": last_log_lines(15) })
}

/// Stops the engine, and logs how it went.
pub async fn stop(by_user: bool) -> Value {
    let _g = OP.lock().await;
    stop_locked(by_user).await
}

pub async fn stop_locked(by_user: bool) -> Value {
    let r = stop_once(by_user).await;
    if r.get("ok").and_then(Value::as_bool) == Some(true) {
        applog!("engine stopped{}", if by_user { " (by the user)" } else { "" });
    } else {
        applog!("engine did not stop: {}{}", r.get("error").and_then(Value::as_str).unwrap_or(""), if by_user { " (by the user)" } else { "" });
    }
    r
}

/// How long a stop waits for the engine to end once its API is gone, as the
/// Electron app did.
const ENDING: Duration = Duration::from_secs(15);

/// Asks the engine to stop and waits until it has ended. Its API goes first
/// (protection is off then); its cleanup (DNS rule, adapter) runs a moment
/// more, with its files (the blocklists, its log) still open. A stop is done
/// only then, so Cleanup or deleting the blocklists right after it finds
/// nothing in use. The wait sleeps on the timer and holds only OP.
async fn stop_once(by_user: bool) -> Value {
    EXPECTED_STOP.store(true, Ordering::Relaxed);
    if api::post("/api/stop", None).await.is_err() {
        return json!({ "ok": true }); // not running
    }
    if by_user {
        settings::update(|s| {
            s.insert("wasRunning".into(), json!(false));
        });
    }
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(10) {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if api::status().await.is_none() {
            engine_exited(ENDING).await;
            return json!({ "ok": true });
        }
    }
    fail("The engine is still running.")
}

/// Whether the engine this app started is known to have ended (false when
/// the app started none, or does not know its process).
pub fn started_engine_gone() -> bool {
    let pid = ENGINE_PID.load(Ordering::Relaxed);
    pid != 0 && !winutil::alive(pid)
}

/// For a caller that holds OP: waits up to 15 s for an engine this app
/// started that is still ending, so its work does not overlap the engine's
/// own teardown.
pub async fn wait_ended() -> bool {
    engine_exited(ENDING).await
}

/// Waits up to d for the engine this app started to end. Its API goes away
/// first; it then removes its DNS rule and adapter. A start meanwhile would
/// find it still alive: the service answered with the old engine, which
/// then ended, and a switch of exit (none → WireGuard) never started.
async fn engine_exited(d: Duration) -> bool {
    let pid = ENGINE_PID.load(Ordering::Relaxed);
    if pid == 0 {
        return true;
    }
    let t = Instant::now();
    while t.elapsed() < d {
        if !winutil::alive(pid) {
            ENGINE_PID.store(0, Ordering::Relaxed);
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    applog!("engine {pid} still ending after {} s", d.as_secs());
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: Value) -> S {
        let mut d = settings::defaults().clone();
        for (k, x) in v.as_object().unwrap() {
            d.insert(k.clone(), x.clone());
        }
        d
    }

    #[test]
    fn runs_exit_compares_the_engine_name() {
        let st = json!({ "exit": "" });
        assert!(runs_exit(&st, &s(json!({ "exit": "none" }))));
        assert!(!runs_exit(&st, &s(json!({ "exit": "chain" }))));
        assert!(runs_exit(&json!({ "exit": "WARP chain" }), &s(json!({ "exit": "chain" }))));
    }

    #[test]
    fn chain_flags_put_sni_and_the_exit_sni_in_order() {
        let x = s(json!({ "warpSni": "qq.com", "exitSni": "fb.com", "warp1Flags": "-m 1280 {sni}", "wgFlags": "--wg-mtu 0", "warp2Flags": "--x {exit_sni}" }));
        assert_eq!(chain_flags(&x), "-s qq.com -m 1280 qq.com --wg-mtu 0 --exit-sni fb.com --x fb.com");
        assert_eq!(masque_flags(&s(json!({}))), "");
    }
}
