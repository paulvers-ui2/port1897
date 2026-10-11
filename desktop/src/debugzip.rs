// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! "Save debug zip": logs, settings and a report of the PC's network, with
//! private keys, tokens and passwords replaced by "(hidden)".

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

use crate::{api, applog, logs, paths, usque, wg};

fn re(p: &'static str) -> Regex {
    Regex::new(p).expect("valid regex")
}

/// Keys whose values must never leave the PC: WireGuard and WARP private
/// keys, tokens, proxy passwords (socks.pass, http.pass). Not "dnsBypass".
fn secret_key(k: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| re(r"(?i)key|token|secret|^pass(word)?$|license|auth")).is_match(k)
}

/// Passwords inside URLs (socks5://user:pass@host), under any key and in logs.
pub fn redact_url_auth(t: &str) -> String {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| re(r#"(//[^/\s:@"']*):[^@/\s"']*@"#)).replace_all(t, "$1:(hidden)@").into_owned()
}

pub fn redact_json(v: &Value) -> Value {
    match v {
        Value::Array(a) => Value::Array(a.iter().map(redact_json).collect()),
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, x)| {
                    let hide = secret_key(k) && !x.is_object() && !x.is_array() && !x.is_null() && *x != Value::String(String::new());
                    (k.clone(), if hide { Value::String("(hidden)".into()) } else { redact_json(x) })
                })
                .collect(),
        ),
        Value::String(s) => Value::String(redact_url_auth(s)),
        _ => v.clone(),
    }
}

/// wg-quick configs keep their shape; only key lines are hidden.
pub fn redact_wg(text: &str) -> String {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| re(r"(?im)^(\s*(PrivateKey|PresharedKey)\s*=)[^\r\n]*")).replace_all(text, "$1 (hidden)").into_owned()
}

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Windows PowerShell from System32 (never a copy found elsewhere on PATH),
/// told to write UTF-8.
async fn ps(script: String) -> String {
    let exe = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows")).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let mut cmd = tokio::process::Command::new(exe);
    cmd.args(["-NoProfile", "-NonInteractive", "-Command"])
        .arg(format!("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; {script}"))
        .kill_on_drop(true)
        .creation_flags(CREATE_NO_WINDOW);
    match tokio::time::timeout(std::time::Duration::from_secs(30), cmd.output()).await {
        Ok(Ok(o)) => format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)),
        Ok(Err(e)) => e.to_string(),
        Err(_) => "timed out".into(),
    }
}

/// What the network looks like: adapters, routes, DNS servers and the NRPT
/// rules other VPNs add. These show at once when two VPNs fight.
async fn system_report(version: &str) -> String {
    let parts: [(&str, &str); 13] = [
        ("Windows", "[Environment]::OSVersion.VersionString; (Get-CimInstance Win32_OperatingSystem).Caption"),
        ("Adapters", "Get-NetAdapter | Format-Table -AutoSize ifIndex,Name,InterfaceDescription,Status,LinkSpeed | Out-String -Width 220"),
        ("IPv4 interfaces (metrics)", "Get-NetIPInterface -AddressFamily IPv4 | Format-Table -AutoSize ifIndex,InterfaceAlias,InterfaceMetric,ConnectionState | Out-String -Width 220"),
        ("IPv4 addresses", "Get-NetIPAddress -AddressFamily IPv4 | Format-Table -AutoSize ifIndex,InterfaceAlias,IPAddress,PrefixLength | Out-String -Width 220"),
        ("IPv4 routes", "Get-NetRoute -AddressFamily IPv4 | Format-Table -AutoSize ifIndex,DestinationPrefix,NextHop,RouteMetric | Out-String -Width 220"),
        ("DNS servers", "Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table -AutoSize InterfaceIndex,InterfaceAlias,ServerAddresses | Out-String -Width 220"),
        ("NRPT rules (catch-all \".\" rules take every lookup)", "Get-DnsClientNrptRule | Format-List Name,Namespace,NameServers,DisplayName,Comment | Out-String -Width 220"),
        ("NRPT policy in effect", "Get-DnsClientNrptPolicy | Format-List | Out-String -Width 220"),
        (
            "VPN and tunnel programs running",
            "Get-Process | Where-Object { $_.Name -match 'vpn|proton|warp|wireguard|nord|mullvad|openvpn|usque|fswin|tailscale|zerotier' } | Format-Table -AutoSize Id,Name,Path | Out-String -Width 220",
        ),
        ("Lookup of cloudflare.com by Windows", "Resolve-DnsName cloudflare.com -Type A -QuickTimeout -ErrorAction Continue | Out-String -Width 220"),
        ("Windows Firewall profiles", "Get-NetFirewallProfile | Format-Table -AutoSize Name,Enabled,DefaultInboundAction,DefaultOutboundAction | Out-String -Width 220"),
        (
            "Crashes of AuroraVPN, the engine, usque or Wintun (Application log, 7 days)",
            "Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Application Error','Application Hang','Windows Error Reporting'; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'fswin|auroravpn|port1897|usque|wintun' } | Select-Object -First 20 | Format-List TimeCreated,ProviderName,Id,Message | Out-String -Width 220",
        ),
        (
            "Wintun and network driver events (System log, 7 days)",
            "Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2,3; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 2000 -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -match 'wintun|Tcpip|Dnscache|NDIS|BFE' -or $_.Message -match 'wintun|auroravpn|port1897' } | Select-Object -First 30 | Format-List TimeCreated,ProviderName,Id,LevelDisplayName,Message | Out-String -Width 220",
        ),
    ];
    let engine = paths::engine_path();
    let mut out = vec![
        format!("AuroraVPN {version} debug report, {}", applog::now_iso()),
        format!(
            "Tauri {}, WebView2 {}; Windows; engine {}",
            tauri::VERSION,
            tauri::webview_version().unwrap_or_else(|_| "?".into()),
            if engine.exists() { engine.display().to_string() } else { "missing".into() }
        ),
        String::new(),
    ];
    // the parts run side by side: one slow part (the event logs) holds up no other
    let results = futures_join(parts.iter().map(|(_, cmd)| ps(cmd.to_string())).collect()).await;
    for ((title, _), text) in parts.iter().zip(results) {
        out.push(format!("===== {title} ====="));
        out.push(text.trim().to_string());
        out.push(String::new());
    }
    out.join("\r\n")
}

async fn futures_join(fs: Vec<impl std::future::Future<Output = String> + Send + 'static>) -> Vec<String> {
    let handles: Vec<_> = fs.into_iter().map(tokio::spawn).collect();
    let mut out = Vec::new();
    for h in handles {
        out.push(h.await.unwrap_or_default());
    }
    out
}

/// Crash dumps Windows keeps of the app, the engine or usque: names, sizes
/// and dates; the dumps hold memory, so they are not copied.
fn crash_dump_list() -> String {
    let dir = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_default().join("CrashDumps");
    let mut lines = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let low = name.to_lowercase();
            if !["auroravpn", "fswin", "usque"].iter().any(|w| low.contains(w)) {
                continue;
            }
            if let Ok(m) = e.metadata() {
                let when: chrono::DateTime<chrono::Utc> = m.modified().map(Into::into).unwrap_or_else(|_| chrono::Utc::now());
                lines.push(format!("{}  {:>10}  {name}", when.to_rfc3339_opts(chrono::SecondsFormat::Millis, true), m.len()));
            }
        }
    }
    if lines.is_empty() { format!("{}: none\r\n", dir.display()) } else { format!("{}\r\n{}\r\n", dir.display(), lines.join("\r\n")) }
}

/// At most max bytes from the end of f, noting what was left out.
fn read_tail_noted(f: &Path, max: u64) -> Option<String> {
    let size = std::fs::metadata(f).ok()?.len();
    let t = logs::read_tail(f, max)?;
    Some(if size > max { format!("(the oldest {} MB of this file left out)\n{t}", (size - max).div_ceil(1 << 20)) } else { t })
}

const README: &str = "AuroraVPN debug logs\r\n\r\nPrivate keys, tokens and passwords are replaced with \"(hidden)\".\r\nengine.log, engine.prev.log and history/ list the apps, domains and addresses this PC used; remove them before sharing if you prefer.\r\n\r\nengine.log: the engine (firestack, DNS, firewall, WireGuard, WARP). app.log: the app (starts, stops, errors, crashes).\r\nusque/: WARP over MASQUE. system.txt: adapters, routes, DNS, other VPNs, Windows Firewall and recent crashes. crash-dumps.txt: crash dumps on this PC (names only; the dumps themselves can hold private data and are left out).";

/// Writes the debug zip to dest.
pub async fn write(dest: &Path, version: &str) -> Result<(), String> {
    let mut files: Vec<(String, String)> = Vec::new();
    let mut put = |name: &str, text: String| files.push((name.to_string(), redact_url_auth(&text)));
    let file = |f: &Path| read_tail_noted(f, 64 << 20);
    let json_file = |f: &Path| {
        file(f).map(|t| match serde_json::from_str::<Value>(&t) {
            Ok(v) => serde_json::to_string_pretty(&redact_json(&v)).unwrap_or_default(),
            Err(_) => "(not valid JSON; left out)".into(),
        })
    };
    for (name, f) in [
        ("engine.log", paths::log_file()),
        ("engine.prev.log", paths::prev_log_file()),
        ("app.log", paths::app_log_file()),
        ("app.prev.log", paths::prev_app_log_file()),
        ("usque/usque.log", paths::usque_log()),
        ("wireguard/index.json", paths::wg_dir().join("index.json")),
    ] {
        if let Some(t) = file(&f) {
            put(name, t);
        }
    }
    put("crash-dumps.txt", crash_dump_list());
    for (name, f) in [
        ("settings.json", paths::settings_file()),
        ("rules.json", paths::rules_file()),
        ("warp.json", paths::warp_file()),
        ("usque/warp1.json", usque::file("warp1").unwrap_or_default()),
        ("usque/warp2.json", usque::file("warp2").unwrap_or_default()),
    ] {
        if let Some(t) = json_file(&f) {
            put(name, t);
        }
    }
    if let Some(t) = file(&usque::wg0()) {
        put("usque/wg0.conf", redact_wg(&t));
    }
    for e in wg::index() {
        if let Some(id) = e.get("id").and_then(Value::as_str)
            && let Some(f) = wg::file(id)
            && let Some(t) = file(&f)
        {
            put(&format!("wireguard/{id}.conf"), redact_wg(&t));
        }
    }
    // the last two days of activity, newest lines only
    for back in [1, 0] {
        let day = (chrono::Utc::now() - chrono::Duration::days(back)).format("%Y-%m-%d").to_string();
        if let Some(t) = logs::read_tail(&paths::hist_dir().join(format!("events-{day}.jsonl")), 16 << 20) {
            let lines: Vec<&str> = t.split('\n').collect();
            put(&format!("history/events-{day}.jsonl"), lines[lines.len().saturating_sub(20000)..].join("\n"));
        }
    }
    let status = api::status().await.unwrap_or_else(|| serde_json::json!({ "running": false }));
    put("status.json", serde_json::to_string_pretty(&status).unwrap_or_default());
    put("system.txt", system_report(version).await);
    put("README.txt", README.to_string());

    // written next to the chosen file, then moved over it: a failed zip
    // leaves the chosen file untouched
    let dest = dest.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let tmp = dest.with_extension("zip.part");
        let out = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
        let mut zip = zip::ZipWriter::new(out);
        let opts = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (name, text) in files {
            zip.start_file(name, opts).map_err(|e| e.to_string())?;
            zip.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
        }
        zip.finish().map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &dest).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            e.to_string()
        })
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn secrets_are_hidden() {
        let v = redact_json(&json!({ "private_key": "abc", "access_token": "t", "socks": { "pass": "p", "host": "h" }, "dnsBypass": false, "proxy": "socks5://u:pw@h:1080", "endpoint_pub_key": "" }));
        assert_eq!(v["private_key"], "(hidden)");
        assert_eq!(v["access_token"], "(hidden)");
        assert_eq!(v["socks"]["pass"], "(hidden)");
        assert_eq!(v["socks"]["host"], "h");
        assert_eq!(v["proxy"], "socks5://u:(hidden)@h:1080");
        assert_eq!(v["endpoint_pub_key"], "");
    }

    #[test]
    fn wireguard_keys_are_hidden() {
        let t = redact_wg("[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/32\n[Peer]\nPresharedKey=x\n");
        assert!(t.contains("PrivateKey = (hidden)"));
        assert!(t.contains("PresharedKey= (hidden)"));
        assert!(t.contains("Address = 10.0.0.2/32"));
    }
}
