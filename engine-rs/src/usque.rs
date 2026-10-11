// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! usque (WARP over MASQUE) as a child process: the pure parts of
//! usque_windows.go and supervise_windows.go. The engine runs usque.exe
//! serving SOCKS5 on loopback with a random port, user and password per
//! run, so other programs cannot use it to get around the firewall.
//!
//! ```text
//! masque: apps -> usque socks -> WARP (MASQUE) -> internet
//! chain:  apps -> usque chain -> WARP2 -> wg0 -> WARP1 -> internet
//! ```

use std::time::Duration;

use crate::golike;

/// What starting usque needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsqueSetup {
    /// usque.exe
    pub exe: String,
    /// where warp1.json / warp2.json live
    pub dir: String,
    /// wg-quick file for the chain's middle hop; "" for plain MASQUE
    pub chain_wg: String,
    /// more usque flags (SNI, MTU...), checked by usque_flags
    pub extra: Vec<String>,
    /// the network's MTU, for -i; 0 if unknown
    pub link: i64,
}

/// fswin's own usque flags: the proxy address and password, and the
/// identity and config files. Users may add any other usque flag.
const CORE_FLAGS: &[&str] = &[
    "-b",
    "--bind",
    "-p",
    "--port",
    "-u",
    "--username",
    "-w",
    "--password",
    "-c",
    "--config",
    "--wg",
    "--exit-config",
    // usque runs these paths as programs, as admin under the engine
    "--on-connect",
    "--on-disconnect",
];

/// Splits extra, space-separated usque flags and refuses the core ones and
/// subcommands, as the Android chain screen does.
pub fn usque_flags(s: &str) -> Result<Vec<String>, String> {
    let f: Vec<String> = s.split_whitespace().map(str::to_string).collect();
    for a in &f {
        let mut name = a.split_once('=').map_or(a.as_str(), |(n, _)| n).to_string();
        let b = name.as_bytes();
        if b.len() > 2 && b[0] == b'-' && b[1] != b'-' {
            // pflag reads -b0.0.0.0, and -6b 0.0.0.0 after bool shorthands,
            // as -b
            if let Some(i) = name[1..].find(['b', 'p', 'u', 'w', 'c']) {
                name = format!("-{}", &name[1 + i..2 + i]);
            }
        }
        if CORE_FLAGS.contains(&name.as_str()) || name.ends_with("-on-connect") || name.ends_with("-on-disconnect") {
            return Err(format!("usque flag {name} belongs to the fixed core"));
        }
        if matches!(a.as_str(), "socks" | "chain" | "register" | "nativetun" | "http-proxy" | "portfw") {
            return Err(format!("usque flags: leave out the {a} subcommand"));
        }
    }
    Ok(f)
}

/// The Android app's usque flags, for usque v0.0.4: how fast a dead tunnel
/// is noticed and rebuilt. The user's flags come after them and win.
///
/// - `-i 1350`: QUIC packets of 1350 bytes, as Cloudflare's own client
///   sends; less on a network that cannot carry 1350 + 28.
/// - `-k 10s`: keepalive, keeps NAT bindings open.
/// - `-r 1s`: a second between reconnect attempts.
/// - `--idle-timeout 25s`, `--stall-timeout 2s`: rebuild a silent tunnel.
///
/// WARP over MASQUE also gets `--always-reconnect`; the chain reconnects
/// always (usque sets it).
pub fn usque_defaults(chain: bool, link: i64) -> Vec<String> {
    let mut ips = 1350;
    if link > 0 {
        // 28: IPv4 and UDP headers; QUIC needs 1200
        ips = ips.min(link - 28).max(1200);
    }
    let mut f: Vec<String> =
        ["-i", &ips.to_string(), "-k", "10s", "-r", "1s", "--idle-timeout", "25s", "--stall-timeout", "2s"].iter().map(|s| s.to_string()).collect();
    if !chain {
        f.push("--always-reconnect".into());
    }
    f
}

/// Go's filepath.Join(dir, name) for the names joined here.
pub fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        return golike::clean(name);
    }
    // a bare drive is not a folder: "C:" + "x" is C:x, relative to that
    // drive's current folder
    if dir.len() == 2 && dir.as_bytes()[1] == b':' {
        return golike::clean(&format!("{dir}{name}"));
    }
    golike::clean(&format!("{dir}\\{name}"))
}

/// usque's arguments for a run with its SOCKS proxy on port, user and
/// password: the identities, the subcommand, the proxy, the defaults, and
/// last the user's flags (the last of a flag wins).
pub fn start_args(s: &UsqueSetup, port: u16, user: &str, pass: &str) -> Vec<String> {
    let mut args = vec!["-c".to_string(), join(&s.dir, "warp1.json")];
    if s.chain_wg.is_empty() {
        args.push("socks".into());
    } else {
        args.extend(["chain".into(), "--wg".into(), s.chain_wg.clone(), "--exit-config".into(), join(&s.dir, "warp2.json")]);
    }
    args.extend(["-b".into(), "127.0.0.1".into(), "-p".into(), port.to_string(), "-u".into(), user.into(), "-w".into(), pass.into()]);
    args.extend(usque_defaults(!s.chain_wg.is_empty(), s.link));
    args.extend(s.extra.iter().cloned());
    args
}

/// usque's arguments to register a free WARP identity in cfg.
pub fn register_args(cfg: &str) -> Vec<String> {
    vec!["-c".into(), cfg.into(), "register".into(), "--accept-tos".into()]
}

/// The exit's proxy address for a usque run.
pub fn socks_url(port: u16, user: &str, pass: &str) -> String {
    format!("socks5://{}:{}@127.0.0.1:{port}", userinfo_escape(user), userinfo_escape(pass))
}

/// url.UserPassword's escaping, for the characters a user name or password
/// may hold (ours are hex, which needs none).
fn userinfo_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.bytes() {
        if c.is_ascii_alphanumeric() || b"-._~$&'()*+,;=".contains(&c) {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{c:02X}"));
        }
    }
    out
}

/// n random bytes as hex, for usque's proxy user and password.
pub fn rand_hex(n: usize) -> std::io::Result<String> {
    let mut b = vec![0u8; n];
    getrandom(&mut b)?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

#[cfg(windows)]
fn getrandom(b: &mut [u8]) -> std::io::Result<()> {
    // the system's CSPRNG, as Go's crypto/rand on Windows
    #[link(name = "bcryptprimitives", kind = "raw-dylib")]
    unsafe extern "system" {
        fn ProcessPrng(pbdata: *mut u8, cbdata: usize) -> i32;
    }
    // SAFETY: b is valid for writes of b.len() bytes; ProcessPrng always
    // succeeds and returns TRUE
    unsafe { ProcessPrng(b.as_mut_ptr(), b.len()) };
    Ok(())
}

#[cfg(not(windows))]
fn getrandom(b: &mut [u8]) -> std::io::Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")?.read_exact(b)
}

/// An exit code as Windows writes it: 1, or 0xC0000142 for a program
/// Windows could not start; None ("?") when it is not known.
pub fn exit_code(code: Option<u32>) -> String {
    match code {
        None => "?".into(),
        Some(c) if c >= 0x8000_0000 => format!("0x{c:08X}"),
        Some(c) => c.to_string(),
    }
}

/// Whether a line of usque's output says its tunnel is down: the app then
/// shows Reconnecting at once instead of at the next probe.
pub fn says_tunnel_lost(line: &str) -> bool {
    line.contains("Tunnel connection lost") || line.contains("Failed to connect tunnel")
}

/// What the app shows while usque says its tunnel is down.
pub const LOST_ISSUE: &str = "the tunnel to Cloudflare is down; usque is reconnecting";

// The supervisor's timing (supervise_windows.go).
pub const RESTART_MIN: Duration = Duration::from_secs(1);
pub const RESTART_MAX: Duration = Duration::from_secs(60);
pub const PROBE_FAILURES: u32 = 3;
pub const PROBE_TARGET: &str = "1.1.1.1:80";
pub const PROBE_EVERY: Duration = Duration::from_secs(15);
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(8);
/// the SOCKS port opens before the hops carry traffic
pub const START_GRACE: Duration = Duration::from_secs(30);
/// while usque says the tunnel is down
pub const QUICK_PROBE: Duration = Duration::from_secs(3);
pub const NET_EVERY: Duration = Duration::from_secs(5);
pub const NET_SETTLE: Duration = Duration::from_secs(8);

/// The wait before the restart after one that waited `wait`: twice as
/// long, up to RESTART_MAX, until a probe passes.
pub fn next_wait(wait: Duration) -> Duration {
    (wait * 2).min(RESTART_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags() {
        assert_eq!(usque_flags("  -s qq.com\t-m 1300 --sni=a.b ").unwrap(), ["-s", "qq.com", "-m", "1300", "--sni=a.b"]);
        assert!(usque_flags("").unwrap().is_empty());
        for (s, name) in [
            ("-b 0.0.0.0", "-b"),
            ("--bind=0.0.0.0", "--bind"),
            ("-b0.0.0.0", "-b"),
            ("-6b 0.0.0.0", "-b"),
            ("-p 1", "-p"),
            ("-w x", "-w"),
            ("--password x", "--password"),
            ("-c x.json", "-c"),
            ("--config=x", "--config"),
            ("--wg a.conf", "--wg"),
            ("--exit-config b", "--exit-config"),
            ("--on-connect evil.exe", "--on-connect"),
            ("--exit-on-disconnect=evil.exe", "--exit-on-disconnect"),
            // the first of b p u w c after the dash counts, so Go refuses it too
            ("-sexample.com", "-p"),
        ] {
            assert_eq!(usque_flags(s).unwrap_err(), format!("usque flag {name} belongs to the fixed core"), "{s}");
        }
        assert_eq!(usque_flags("-m 1300 socks").unwrap_err(), "usque flags: leave out the socks subcommand");
        assert_eq!(usque_flags("register").unwrap_err(), "usque flags: leave out the register subcommand");
        assert!(usque_flags("-m socks5").is_ok());
        // Unicode white space splits too, as strings.Fields
        assert_eq!(usque_flags("-m\u{a0}1300").unwrap(), ["-m", "1300"]);
    }

    #[test]
    fn defaults() {
        let d = |chain, link| usque_defaults(chain, link).join(" ");
        assert_eq!(d(false, 0), "-i 1350 -k 10s -r 1s --idle-timeout 25s --stall-timeout 2s --always-reconnect");
        assert_eq!(d(true, 1500), "-i 1350 -k 10s -r 1s --idle-timeout 25s --stall-timeout 2s");
        assert!(d(false, 1300).starts_with("-i 1272 "));
        assert!(d(false, 1000).starts_with("-i 1200 "));
    }

    #[test]
    fn args() {
        let s = UsqueSetup { exe: r"C:\A\usque.exe".into(), dir: r"C:\A\".into(), extra: vec!["-m".into(), "1300".into()], link: 1492, ..Default::default() };
        assert_eq!(
            start_args(&s, 40000, "u1", "p1").join(" "),
            r"-c C:\A\warp1.json socks -b 127.0.0.1 -p 40000 -u u1 -w p1 -i 1350 -k 10s -r 1s --idle-timeout 25s --stall-timeout 2s --always-reconnect -m 1300"
        );
        let c = UsqueSetup { chain_wg: r"C:\cfg\wg0.conf".into(), dir: r"C:\A\.\B".into(), ..s };
        assert!(start_args(&c, 1, "u", "p").join(" ").starts_with(r"-c C:\A\B\warp1.json chain --wg C:\cfg\wg0.conf --exit-config C:\A\B\warp2.json -b"));
        assert_eq!(join("C:", "x.json"), "C:x.json");
        assert_eq!(join("", "x.json"), "x.json");
        assert_eq!(register_args("w.json"), ["-c", "w.json", "register", "--accept-tos"]);
        assert_eq!(socks_url(1080, "ab", "c:d"), "socks5://ab:c%3Ad@127.0.0.1:1080");
        let h = rand_hex(16).unwrap();
        assert!(h.len() == 32 && h.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(h, rand_hex(16).unwrap());
    }

    #[test]
    fn exits_and_timing() {
        assert_eq!(exit_code(None), "?");
        assert_eq!(exit_code(Some(1)), "1");
        assert_eq!(exit_code(Some(0xC000_0142)), "0xC0000142");
        assert!(says_tunnel_lost("2026/10/10 Tunnel connection lost: timeout"));
        assert!(!says_tunnel_lost("Connected to MASQUE server"));
        let mut w = RESTART_MIN;
        let mut seen = vec![];
        for _ in 0..8 {
            seen.push(w.as_secs());
            w = next_wait(w);
        }
        assert_eq!(seen, [1, 2, 4, 8, 16, 32, 60, 60]);
    }
}
