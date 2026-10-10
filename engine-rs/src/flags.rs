// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! fswin's command line, read exactly as Go's `flag` package reads it: the
//! app (`engineArgs` in ui/main.js) and AuroraVPN Service build these
//! command lines, so the Rust engine must take the same ones. That is not
//! GNU style: `-name value`, `-name=value` and `--name` all work, a bool
//! flag never takes the next argument as its value, and parsing stops at the
//! first argument that is not a flag, or after `--`.

use crate::golike;

/// The run options, as fswin's `options` struct; defaults as Go's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub name: String,
    pub mtu: i64,
    pub doh: String,
    pub doh_ips: String,
    pub set_dns: bool,
    pub full: bool,
    pub nrpt: bool,
    pub cleanup: bool,
    pub kill: bool,
    /// other VPNs that compete with ours, found at start
    pub conflicts: Vec<String>,
    pub block: String,
    pub wg: String,
    pub warp: bool,
    pub proxy: String,
    pub masque: bool,
    pub chain: String,
    pub usque_exe: String,
    pub usque_dir: String,
    pub warp_file: String,
    pub api: String,
    pub token_file: String,
    pub log_file: String,
    /// `-log` as Go keeps it: an int converted to int32
    pub golog: i32,

    pub dns_type: String,
    pub dot: String,
    pub dot_ips: String,
    pub dnscrypt: String,
    pub dns_direct: bool,
    pub dns_cache: bool,
    pub dnssec: bool,
    pub undelegated: bool,
    pub dns_fallback: bool,
    pub fallback_doh: String,
    pub fallback_ips: String,
    pub usque_flags: String,
    pub allow_lan: bool,

    pub dnscrypt_relays: String,
    pub odoh: String,
    pub odoh_relay: String,
    pub odoh_ips: String,
    pub dns_proxy: String,
    pub blocklist_dir: String,
    pub blocklist_stamp: String,
    pub filetag: String,

    pub rules_file: String,
    pub routes_file: String,
    pub pcap_file: String,
    pub dial_strategy: String,
    pub dial_retry: String,
    pub dial_timeout: i64,
    pub keep_alive: bool,
    pub eim: bool,

    pub service: String,
    pub service_app: String,
    pub stop_handle: u64,
    pub user_token: u64,

    pub show_version: bool,
}

/// DNS types for -dns, as in the Android app's DNS screen.
pub const DNS_DOH: &str = "doh";
pub const DNS_DOT: &str = "dot";
pub const DNS_DNSCRYPT: &str = "dnscrypt";
pub const DNS_ODOH: &str = "odoh";
pub const DNS_PROXY: &str = "proxy";
pub const DNS_SYSTEM: &str = "system";

/// Dial strategies for -dial-strategy.
pub const DIAL_NEVER: &str = "never";
pub const DIAL_AUTO: &str = "auto";
pub const DIAL_SPLIT_TCP: &str = "split-tcp";
pub const DIAL_SPLIT_TLS: &str = "split-tls";

impl Default for Options {
    fn default() -> Self {
        let mut o = Options {
            name: String::new(),
            mtu: 0,
            doh: String::new(),
            doh_ips: String::new(),
            set_dns: false,
            full: false,
            nrpt: false,
            cleanup: false,
            kill: false,
            conflicts: Vec::new(),
            block: String::new(),
            wg: String::new(),
            warp: false,
            proxy: String::new(),
            masque: false,
            chain: String::new(),
            usque_exe: String::new(),
            usque_dir: String::new(),
            warp_file: String::new(),
            api: String::new(),
            token_file: String::new(),
            log_file: String::new(),
            golog: 0,
            dns_type: String::new(),
            dot: String::new(),
            dot_ips: String::new(),
            dnscrypt: String::new(),
            dns_direct: false,
            dns_cache: false,
            dnssec: false,
            undelegated: false,
            dns_fallback: false,
            fallback_doh: String::new(),
            fallback_ips: String::new(),
            usque_flags: String::new(),
            allow_lan: false,
            dnscrypt_relays: String::new(),
            odoh: String::new(),
            odoh_relay: String::new(),
            odoh_ips: String::new(),
            dns_proxy: String::new(),
            blocklist_dir: String::new(),
            blocklist_stamp: String::new(),
            filetag: String::new(),
            rules_file: String::new(),
            routes_file: String::new(),
            pcap_file: String::new(),
            dial_strategy: String::new(),
            dial_retry: String::new(),
            dial_timeout: 0,
            keep_alive: false,
            eim: false,
            service: String::new(),
            service_app: String::new(),
            stop_handle: 0,
            user_token: 0,
            show_version: false,
        };
        // the declared defaults go through the same setter as the command line
        for d in DEFS {
            if !d.default.is_empty() {
                set(&mut o, d.name, d.default).expect("flag default parses");
            }
        }
        o
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Bool,
    Str,
    Int,
    Uint,
}

struct Def {
    name: &'static str,
    kind: Kind,
    /// the default as Go's DefValue string; "" for the zero value
    default: &'static str,
    usage: &'static str,
}

const fn def(name: &'static str, kind: Kind, default: &'static str, usage: &'static str) -> Def {
    Def { name, kind, default, usage }
}

use Kind::{Bool, Int, Str, Uint};

/// fswin's flags in declaration order (main_windows.go), word for word.
const DEFS: &[Def] = &[
    def("name", Str, "AuroraVPN", "Wintun adapter name"),
    def("mtu", Int, "", "adapter MTU, 1280 to 1500; 0: automatic, from the network and the exit (mtu_windows.go)"),
    def("doh", Str, "https://cloudflare-dns.com/dns-query", "DoH server URL"),
    def("doh-ips", Str, "1.1.1.1,1.0.0.1", "comma-separated IPs of the DoH server"),
    def("set-dns", Bool, "true", "point the adapter's DNS at the tunnel and give it the lowest metric"),
    def("full", Bool, "", "route all IPv4 traffic through the tunnel, not just DNS"),
    def("nrpt", Bool, "", "send every DNS query to the tunnel with an NRPT rule, whatever other adapters use; removed on exit"),
    def("killswitch", Bool, "", "block all traffic outside the tunnel, and keep blocking if fswin crashes until it starts again or -cleanup runs (implies -full)"),
    def("cleanup", Bool, "", "remove fswin's NRPT rule (left behind if fswin was killed) and exit"),
    def("block", Str, "", "comma-separated programs to block (exe names like chrome.exe, or full paths); needs -full"),
    def("wg", Str, "", "send all traffic through the WireGuard server in this wg-quick .conf file (implies -full)"),
    def("warp", Bool, "", "send all traffic through free Cloudflare WARP; registers on first use and saves fswin-warp.json next to fswin.exe (implies -full)"),
    def("proxy", Str, "", "send all traffic through this proxy: socks5://[user:pass@]host:port or http://... (implies -full)"),
    def("log", Int, "3", "firestack log level: 0 very verbose ... 5 errors, 8 none"),
    def("masque", Bool, "", "send all traffic through free Cloudflare WARP over MASQUE (HTTP/3, falls back to HTTP/2), using usque (implies -full)"),
    def("chain", Str, "", "send all traffic through WARP2 -> this WireGuard server -> WARP1, using usque chain; value is a wg-quick .conf (implies -full)"),
    def("usque", Str, "", "path to usque.exe (default: next to fswin.exe)"),
    def("usque-dir", Str, "", "where -masque and -chain keep their WARP identities (default: next to fswin.exe)"),
    def("warp-file", Str, "", "where -warp keeps its account (default: fswin-warp.json next to fswin.exe)"),
    def("api", Str, "", "serve the control API for the app window on this loopback address, e.g. 127.0.0.1:47897"),
    def("token-file", Str, "", "file holding the secret every -api request must present"),
    def("logfile", Str, "", "write output to this file instead of the console"),
    def("dns", Str, "doh", "DNS type: doh, dot, dnscrypt, odoh (Oblivious DoH), proxy (plain DNS to -dns-proxy) or system (the network adapter's own DNS servers)"),
    def("dot", Str, "", "DNS-over-TLS server for -dns dot, e.g. tls://dns.adguard-dns.com"),
    def("dot-ips", Str, "", "comma-separated IPs of the -dot server (optional)"),
    def("dnscrypt", Str, "", "DNSCrypt server stamp (sdns://...) for -dns dnscrypt"),
    def("dns-direct", Bool, "", "never send DNS through the VPN exit"),
    def("dns-cache", Bool, "", "DNS booster: answer repeat lookups from the cache"),
    def("dnssec", Bool, "", "block DNS answers that put public names on bogus (bogon) addresses, a sign of poisoning"),
    def("undelegated", Bool, "", "use System DNS for undelegated domains like .lan and .internal"),
    def("dns-fallback", Bool, "", "use the fallback DNS when the chosen DNS fails"),
    def("fallback-doh", Str, "", "fallback (bootstrap) DoH server URL (default: -doh)"),
    def("fallback-ips", Str, "", "comma-separated IPs of -fallback-doh (default: -doh-ips)"),
    def("usque-flags", Str, "", "extra usque flags for -masque or -chain, space-separated; core flags (-b -p -u -w -c --wg --exit-config) are refused"),
    def("allow-lan", Bool, "", "with -killswitch, let private and link-local addresses (printers, shares) through"),
    def("dnscrypt-relays", Str, "", "comma-separated DNSCrypt relay stamps (sdns://...) for -dns dnscrypt, to hide your IP from the resolver"),
    def("odoh", Str, "", "Oblivious DoH target for -dns odoh, e.g. https://odoh.cloudflare-dns.com/dns-query"),
    def("odoh-relay", Str, "", "Oblivious DoH relay (proxy) URL; without one, queries go to the target directly"),
    def("odoh-ips", Str, "", "comma-separated IPs of the ODoH relay or target (optional)"),
    def("dns-proxy", Str, "", "plain DNS server ip:port for -dns proxy, e.g. 9.9.9.9:53 or a local DNS forwarder like 127.0.0.1:5400"),
    def("blocklists", Str, "", "folder with the on-device RethinkDNS blocklists (td.txt, rd.txt, basicconfig.json, filetag.json)"),
    def("blocklist-stamp", Str, "", "RethinkDNS stamp of the on-device blocklists to block, e.g. 1-..."),
    def("filetag", Str, "", "filetag.json, to name the blocklists a RethinkDNS server blocked a domain by"),
    def("pcap", Str, "", "write a packet capture of the tunnel to this .pcap file (replaced at start)"),
    def("routes", Str, "", "per-app routes (JSON list of {id, name, kind: wg|proxy, file|url}): extra WireGuard tunnels or proxies that apps with a route rule use instead of the exit"),
    def("rules", Str, "", "firewall rules (JSON, as the app writes them) to start with; the app updates them through -api"),
    def("dial-strategy", Str, "never", "anti-censorship: never (connect as-is), auto, split-tcp (split the first TCP segment) or split-tls (fragment the TLS ClientHello)"),
    def("dial-retry", Str, "", "when a connection fails: never, split (retry with the split) or plain (retry as-is); default: never for -dial-strategy never, else plain"),
    def("dial-timeout", Int, "", "idle timeout for TCP and UDP sockets, in seconds; 0 for firestack's default"),
    def("tcp-keepalive", Bool, "", "shorter TCP keep alive: quickly close TCP sockets with no recent activity"),
    def("eim", Bool, "", "endpoint-independent mapping and filtering for UDP (fixed port for all destinations; helps games and calls)"),
    def("service", Str, "", "install, uninstall or run AuroraVPN Service, which starts the engine for the app without a UAC prompt"),
    def("app", Str, "", "with -service install: the path of AuroraVPN.exe, the only program the service answers"),
    def("stop-handle", Uint, "", "set by AuroraVPN Service: an inherited event that, once set, stops the engine"),
    def("user-token", Uint, "", "set by AuroraVPN Service, which runs the engine as SYSTEM: the inherited token of the user who asked; the user's files are opened, and usque started, with it"),
    def("version", Bool, "", "print the build and exit"),
];

/// The number of flags fswin defines.
pub fn count() -> usize {
    DEFS.len()
}

/// Stores one flag's value, parsed as Go's flag.Value.Set does. The error
/// is the reason only ("parse error", "value out of range").
fn set(o: &mut Options, name: &str, v: &str) -> Result<(), &'static str> {
    let b = || golike::parse_bool(v).ok_or("parse error");
    let i = || golike::parse_int_base0(v).map_err(|e| e.text());
    let u = || golike::parse_uint_base0(v).map_err(|e| e.text());
    let s = || v.to_string();
    match name {
        "name" => o.name = s(),
        "mtu" => o.mtu = i()?,
        "doh" => o.doh = s(),
        "doh-ips" => o.doh_ips = s(),
        "set-dns" => o.set_dns = b()?,
        "full" => o.full = b()?,
        "nrpt" => o.nrpt = b()?,
        "killswitch" => o.kill = b()?,
        "cleanup" => o.cleanup = b()?,
        "block" => o.block = s(),
        "wg" => o.wg = s(),
        "warp" => o.warp = b()?,
        "proxy" => o.proxy = s(),
        // Go keeps an int and converts it with int32(), which wraps
        "log" => o.golog = i()? as i32,
        "masque" => o.masque = b()?,
        "chain" => o.chain = s(),
        "usque" => o.usque_exe = s(),
        "usque-dir" => o.usque_dir = s(),
        "warp-file" => o.warp_file = s(),
        "api" => o.api = s(),
        "token-file" => o.token_file = s(),
        "logfile" => o.log_file = s(),
        "dns" => o.dns_type = s(),
        "dot" => o.dot = s(),
        "dot-ips" => o.dot_ips = s(),
        "dnscrypt" => o.dnscrypt = s(),
        "dns-direct" => o.dns_direct = b()?,
        "dns-cache" => o.dns_cache = b()?,
        "dnssec" => o.dnssec = b()?,
        "undelegated" => o.undelegated = b()?,
        "dns-fallback" => o.dns_fallback = b()?,
        "fallback-doh" => o.fallback_doh = s(),
        "fallback-ips" => o.fallback_ips = s(),
        "usque-flags" => o.usque_flags = s(),
        "allow-lan" => o.allow_lan = b()?,
        "dnscrypt-relays" => o.dnscrypt_relays = s(),
        "odoh" => o.odoh = s(),
        "odoh-relay" => o.odoh_relay = s(),
        "odoh-ips" => o.odoh_ips = s(),
        "dns-proxy" => o.dns_proxy = s(),
        "blocklists" => o.blocklist_dir = s(),
        "blocklist-stamp" => o.blocklist_stamp = s(),
        "filetag" => o.filetag = s(),
        "pcap" => o.pcap_file = s(),
        "routes" => o.routes_file = s(),
        "rules" => o.rules_file = s(),
        "dial-strategy" => o.dial_strategy = s(),
        "dial-retry" => o.dial_retry = s(),
        "dial-timeout" => o.dial_timeout = i()?,
        "tcp-keepalive" => o.keep_alive = b()?,
        "eim" => o.eim = b()?,
        "service" => o.service = s(),
        "app" => o.service_app = s(),
        "stop-handle" => o.stop_handle = u()?,
        "user-token" => o.user_token = u()?,
        "version" => o.show_version = b()?,
        _ => return Err("not defined"),
    }
    Ok(())
}

/// What went wrong reading the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlagError {
    /// -h or -help: print the usage and exit 0
    Help,
    /// print this, then the usage, and exit 2
    Invalid(String),
}

/// The command line, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub opts: Options,
    /// the arguments after the flags (fswin ignores them)
    pub args: Vec<String>,
    /// the flags given, in order (Go's FlagSet.Visit set)
    pub given: Vec<String>,
}

fn find(name: &str) -> Option<&'static Def> {
    DEFS.iter().find(|d| d.name == name)
}

/// Reads args (without the program name) as Go's flag.Parse does.
pub fn parse<S: AsRef<str>>(args: &[S]) -> Result<Parsed, FlagError> {
    let mut opts = Options::default();
    let mut given = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let s = args[i].as_ref();
        if s.len() < 2 || !s.starts_with('-') {
            break;
        }
        let mut minuses = 1;
        if s.as_bytes()[1] == b'-' {
            minuses = 2;
            if s.len() == 2 {
                i += 1; // "--" ends the flags
                break;
            }
        }
        let mut name = &s[minuses..];
        if name.is_empty() || name.starts_with('-') || name.starts_with('=') {
            return Err(FlagError::Invalid(format!("bad flag syntax: {s}")));
        }
        i += 1;
        let mut value: Option<&str> = None;
        // the '=' cannot be first; bytes, as Go, and '=' is a char boundary
        if let Some(eq) = name.as_bytes()[1..].iter().position(|&c| c == b'=') {
            value = Some(&name[eq + 2..]);
            name = &name[..eq + 1];
        }
        let Some(d) = find(name) else {
            if name == "help" || name == "h" {
                return Err(FlagError::Help);
            }
            return Err(FlagError::Invalid(format!("flag provided but not defined: -{name}")));
        };
        if d.kind == Kind::Bool {
            let v = value.unwrap_or("true");
            if let Err(why) = set(&mut opts, name, v) {
                return Err(FlagError::Invalid(format!(
                    "invalid boolean value {} for -{name}: {why}",
                    golike::quote(v)
                )));
            }
        } else {
            if value.is_none() && i < args.len() {
                value = Some(args[i].as_ref());
                i += 1;
            }
            let Some(v) = value else {
                return Err(FlagError::Invalid(format!("flag needs an argument: -{name}")));
            };
            if let Err(why) = set(&mut opts, name, v) {
                return Err(FlagError::Invalid(format!(
                    "invalid value {} for flag -{name}: {why}",
                    golike::quote(v)
                )));
            }
        }
        if !given.iter().any(|g| g == name) {
            given.push(name.to_string());
        }
    }
    let args = args[i..].iter().map(|a| a.as_ref().to_string()).collect();
    Ok(Parsed { opts, args, given })
}

/// The usage text, as Go's flag.PrintDefaults writes it after
/// "Usage of <program>:".
pub fn usage(program: &str) -> String {
    let mut defs: Vec<&Def> = DEFS.iter().collect();
    defs.sort_by_key(|d| d.name);
    let mut out = format!("Usage of {program}:\n");
    for d in defs {
        let mut line = format!("  -{}", d.name);
        let type_name = match d.kind {
            Kind::Bool => "",
            Kind::Str => "string",
            Kind::Int => "int",
            Kind::Uint => "uint",
        };
        if !type_name.is_empty() {
            line.push(' ');
            line.push_str(type_name);
        }
        if line.len() <= 4 {
            line.push('\t');
        } else {
            line.push_str("\n    \t");
        }
        line.push_str(&d.usage.replace('\n', "\n    \t"));
        let zero = match d.kind {
            Kind::Bool => d.default.is_empty() || d.default == "false",
            Kind::Str => d.default.is_empty(),
            Kind::Int | Kind::Uint => d.default.is_empty() || d.default == "0",
        };
        if !zero {
            if d.kind == Kind::Str {
                line.push_str(&format!(" (default {})", golike::quote(d.default)));
            } else {
                line.push_str(&format!(" (default {})", d.default));
            }
        }
        out.push_str(&line);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Parsed, FlagError> {
        parse(args)
    }

    #[test]
    fn defaults_are_gos() {
        let o = Options::default();
        assert_eq!(o.name, "AuroraVPN");
        assert_eq!(o.doh, "https://cloudflare-dns.com/dns-query");
        assert_eq!(o.doh_ips, "1.1.1.1,1.0.0.1");
        assert!(o.set_dns);
        assert!(!o.full);
        assert_eq!(o.golog, 3);
        assert_eq!(o.dns_type, DNS_DOH);
        assert_eq!(o.dial_strategy, DIAL_NEVER);
        assert_eq!(o.mtu, 0);
        assert_eq!(count(), 56);
    }

    // what ui/main.js engineArgs() passes, with empty values and paths
    #[test]
    fn the_apps_command_line() {
        let args = [
            "-api", "127.0.0.1:47897",
            "-token-file", r"C:\Users\me\AppData\Roaming\AuroraVPN\api-token",
            "-logfile", r"C:\Users\me\AppData\Roaming\AuroraVPN\engine.log",
            "-warp-file", r"C:\Users\me\AppData\Roaming\AuroraVPN\warp.json",
            "-log", "3",
            "-fallback-doh", "https://dns.quad9.net/dns-query",
            "-fallback-ips", "",
            "-mtu", "1400",
            "-dns", "doh", "-doh", "https://cloudflare-dns.com/dns-query", "-doh-ips", "",
            "-dns-cache", "-dnssec", "-full", "-nrpt", "-killswitch", "-allow-lan",
            "-masque", "-usque-dir", r"C:\Users\me\AppData\Roaming\AuroraVPN\usque",
            "-usque-flags", "-s qq.com -m 1300",
            "-rules", r"C:\Users\me\AppData\Roaming\AuroraVPN\rules.json",
            "-dial-strategy", "never", "-dial-timeout", "30", "-tcp-keepalive", "-eim",
            "-pcap", r"C:\x.pcap",
        ];
        let r = p(&args).unwrap();
        let o = r.opts;
        assert_eq!(o.api, "127.0.0.1:47897");
        assert_eq!(o.fallback_ips, "");
        assert_eq!(o.doh_ips, "", "an empty value replaces the default");
        assert_eq!(o.mtu, 1400);
        assert!(o.dns_cache && o.dnssec && o.full && o.nrpt && o.kill && o.allow_lan && o.masque);
        assert!(o.keep_alive && o.eim);
        assert_eq!(o.usque_flags, "-s qq.com -m 1300");
        assert_eq!(o.dial_timeout, 30);
        assert_eq!(o.pcap_file, r"C:\x.pcap");
        assert!(r.args.is_empty());
        assert!(r.given.contains(&"doh-ips".to_string()));
    }

    #[test]
    fn go_flag_syntax() {
        let o = p(&["--full", "-nrpt=false", "--mtu=0x500", "-log=-1", "-name", "My VPN"]).unwrap().opts;
        assert!(o.full);
        assert!(!o.nrpt);
        assert_eq!(o.mtu, 0x500);
        assert_eq!(o.golog, -1);
        assert_eq!(o.name, "My VPN");

        // a bool flag never takes the next argument: parsing stops at "false"
        let r = p(&["-full", "false", "-nrpt"]).unwrap();
        assert!(r.opts.full);
        assert!(!r.opts.nrpt);
        assert_eq!(r.args, vec!["false", "-nrpt"]);

        // "--" ends the flags; so does a lone "-"
        let r = p(&["-full", "--", "-nrpt"]).unwrap();
        assert_eq!(r.args, vec!["-nrpt"]);
        let r = p(&["-", "-full"]).unwrap();
        assert!(!r.opts.full);
        assert_eq!(r.args, vec!["-", "-full"]);

        // a value may start with a dash, and "=" splits at the first one
        let o = p(&["-usque-flags", "-s qq.com", "-doh=https://x/?a=b"]).unwrap().opts;
        assert_eq!(o.usque_flags, "-s qq.com");
        assert_eq!(o.doh, "https://x/?a=b");

        // octal and underscores, as strconv.ParseInt(s, 0, 64)
        assert_eq!(p(&["-mtu", "010"]).unwrap().opts.mtu, 8);
        assert_eq!(p(&["-mtu", "1_400"]).unwrap().opts.mtu, 1400);
        assert_eq!(p(&["-stop-handle", "0x1F4"]).unwrap().opts.stop_handle, 500);
        // -log wraps to int32 as Go's int32(golog)
        assert_eq!(p(&["-log", "4294967299"]).unwrap().opts.golog, 3);
        // the last of a repeated flag wins
        assert_eq!(p(&["-dns", "dot", "-dns", "system"]).unwrap().opts.dns_type, "system");
    }

    #[test]
    fn errors_word_for_word() {
        let bad = |args: &[&str]| match p(args) {
            Err(FlagError::Invalid(m)) => m,
            other => panic!("{args:?}: {other:?}"),
        };
        assert_eq!(bad(&["-nope"]), "flag provided but not defined: -nope");
        assert_eq!(bad(&["--nope=1"]), "flag provided but not defined: -nope");
        assert_eq!(bad(&["---full"]), "bad flag syntax: ---full");
        assert_eq!(bad(&["-=x"]), "bad flag syntax: -=x");
        assert_eq!(bad(&["-mtu"]), "flag needs an argument: -mtu");
        assert_eq!(bad(&["-mtu", "abc"]), "invalid value \"abc\" for flag -mtu: parse error");
        assert_eq!(
            bad(&["-mtu", "99999999999999999999"]),
            "invalid value \"99999999999999999999\" for flag -mtu: value out of range"
        );
        assert_eq!(bad(&["-full=yes"]), "invalid boolean value \"yes\" for -full: parse error");
        assert_eq!(bad(&["-stop-handle", "-1"]), "invalid value \"-1\" for flag -stop-handle: parse error");
        assert_eq!(p(&["-h"]), Err(FlagError::Help));
        assert_eq!(p(&["--help"]), Err(FlagError::Help));
        assert_eq!(p(&["-help=1"]), Err(FlagError::Help));
    }

    #[test]
    fn usage_like_go() {
        let u = usage("fswin.exe");
        assert!(u.starts_with("Usage of fswin.exe:\n  -allow-lan\n    \twith -killswitch"));
        assert!(u.contains("  -dial-strategy string\n    \tanti-censorship: never (connect as-is), auto, split-tcp (split the first TCP segment) or split-tls (fragment the TLS ClientHello) (default \"never\")\n"));
        assert!(u.contains("  -log int\n    \tfirestack log level: 0 very verbose ... 5 errors, 8 none (default 3)\n"));
        assert!(u.contains("  -set-dns\n    \tpoint the adapter's DNS at the tunnel and give it the lowest metric (default true)\n"));
        assert!(u.contains("  -stop-handle uint\n"));
        assert!(u.contains("  -mtu int\n    \tadapter MTU, 1280 to 1500; 0: automatic, from the network and the exit (mtu_windows.go)\n"));
        assert!(u.ends_with("  -wg string\n    \tsend all traffic through the WireGuard server in this wg-quick .conf file (implies -full)\n"));
    }
}
