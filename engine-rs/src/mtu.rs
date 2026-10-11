// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The MTU plan (a port of the pure parts of mtu_windows.go). From the
//! network this PC is on to the AuroraVPN adapter:
//!
//! - link: the IP MTU of the interface the engine's own traffic leaves by
//!   (Ethernet and Wi-Fi 1500, PPPoE 1492, some mobile, satellite and
//!   nested-VPN links less). WireGuard sizes its packets to fit it.
//! - exit: the largest packet the exit carries inside its tunnel.
//! - adapter: the smaller of the two, so programs size their UDP and TCP
//!   segments to fit the exit instead of being dropped inside it.

use std::fmt;

use serde::Serialize;

use crate::exit::{EXIT_CHAIN, EXIT_MASQUE, EXIT_WARP, EXIT_WG};
use crate::golike;

/// WireGuard's overhead over IPv6 (40 IP + 8 UDP + 32 WireGuard); over IPv4
/// it is 60. wg-quick and firestack reserve 80 either way.
pub const WG_OVERHEAD: i64 = 80;
/// IPv6's minimum MTU: no MTU here goes below it.
pub const MIN_MTU: i64 = 1280;
/// Internet paths carry 1500 at most, whatever a LAN's jumbo frames.
pub const MAX_MTU: i64 = 1500;
/// Cloudflare WARP's tunnel MTU, over WireGuard and over MASQUE.
pub const WARP_MTU: i64 = 1280;

/// The MTUs in use; /api/status shows it as Go's `mtuPlan`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MtuPlan {
    pub link: i64,
    pub exit: i64,
    pub adapter: i64,
    /// false: the adapter's was set with -mtu
    pub auto: bool,
    /// what it comes from: "Wi-Fi 1500, WireGuard 1420"
    pub why: String,
    /// the exit's part of `why` (", WireGuard 1420"), kept for when the
    /// link changes
    #[serde(skip)]
    pub exit_why: String,
}

impl fmt::Display for MtuPlan {
    /// The plan for the log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let how = if self.auto { "automatic" } else { "set by hand" };
        write!(f, "adapter {} ({how}), from {}", self.adapter, self.why)
    }
}

impl MtuPlan {
    /// The plan once the network's MTU has changed to `link` (described by
    /// `why`): the exit keeps its MTU, and so does the adapter, whose MTU
    /// is set only when protection starts.
    pub fn with_link(&self, link: i64, why: &str) -> MtuPlan {
        MtuPlan {
            link,
            why: format!("{why}{} (the adapter keeps {} until protection restarts)", self.exit_why, self.adapter),
            ..self.clone()
        }
    }
}

/// Reads an MTU: 16 bits at most, as in an IP header, so it fits whatever
/// it is converted to (the adapter's MTU is a u32). Decimal only, spaces
/// around it allowed, as Go's `strconv.ParseUint(TrimSpace(v), 10, 16)`.
pub fn parse_mtu(v: &str) -> Option<i64> {
    golike::parse_uint(golike::trim_space(v), 10, 16).ok().map(|m| m as i64)
}

/// Keeps an MTU within 1280 and 1500.
pub fn clamp_mtu(m: i64) -> i64 {
    m.clamp(MIN_MTU, MAX_MTU)
}

/// The link MTU and its description from what Windows reports for the
/// default interface (`mtu` 0 when unknown, `name` its alias).
pub fn link_mtu(mtu: u32, name: &str) -> (i64, String) {
    if mtu == 0 {
        return (MAX_MTU, "network MTU unknown, so 1500".to_string());
    }
    (clamp_mtu(mtu as i64), format!("{name} {mtu}"))
}

/// Works out the MTUs for the exit `exit_id` (with its config `cfg`, or
/// usque's extra flags `usque_extra`) over a link of MTU `link`.
/// `adapter` > 0 is the -mtu flag.
pub fn plan_mtu(link: i64, link_why: &str, exit_id: &str, cfg: &str, usque_extra: Option<&[String]>, adapter: i64) -> MtuPlan {
    let mut p = MtuPlan { link, exit: link, auto: adapter <= 0, ..Default::default() };
    let mut why = String::new();
    match exit_id {
        EXIT_WG | EXIT_WARP => {
            // the config's mtu is the packet size on the link, of which
            // WG_OVERHEAD is kept for WireGuard; without one, it fits the link
            let mut inner = link - WG_OVERHEAD;
            let m = uapi_mtu(cfg);
            if m > 0 && m - WG_OVERHEAD < inner {
                inner = m - WG_OVERHEAD;
            }
            p.exit = inner; // what the exit uses, even under MIN_MTU on a tiny link
            why.push_str(&format!(", WireGuard {}", p.exit));
        }
        EXIT_MASQUE => {
            p.exit = flag_int(usque_extra, WARP_MTU, &["-m", "--mtu"]);
            why.push_str(&format!(", WARP (MASQUE) {}", p.exit));
        }
        EXIT_CHAIN => {
            // the chain's packets leave through WARP2: its MTU is the limit
            // (usque fits WARP1 and wg0 under it)
            p.exit = flag_int(usque_extra, WARP_MTU, &["--exit-mtu"]);
            why.push_str(&format!(", WARP chain exit {}", p.exit));
        }
        _ => {}
    }
    p.adapter = if p.auto { clamp_mtu(p.exit.min(link)) } else { clamp_mtu(adapter) };
    p.why = format!("{link_why}{why}");
    p.exit_why = why;
    p
}

/// The mtu line of a WireGuard exit config: 0 when there is none, or it
/// is "auto".
pub fn uapi_mtu(cfg: &str) -> i64 {
    for line in cfg.lines() {
        if let Some(v) = golike::trim_space(line).strip_prefix("mtu=")
            && let Some(m) = parse_mtu(v).filter(|m| *m > 0) {
                return m;
            }
    }
    0
}

/// The value of the first of `names` among usque's extra flags ("-m 1300",
/// "--mtu=1300"), or `dflt`. Flags are tried in order, and for each flag
/// the names in order, as the Go code does.
fn flag_int(extra: Option<&[String]>, dflt: i64, names: &[&str]) -> i64 {
    let Some(f) = extra else {
        return dflt;
    };
    for (i, a) in f.iter().enumerate() {
        for n in names {
            let v = if a == n && i + 1 < f.len() {
                Some(f[i + 1].as_str())
            } else {
                a.strip_prefix(n).and_then(|r| r.strip_prefix('='))
            };
            if let Some(m) = v.and_then(parse_mtu).filter(|m| *m > 0) {
                return m;
            }
        }
    }
    dflt
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::{EXIT_PROXY, wg_quick_to_uapi};

    const ZERO_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn wg_conf(mtu_line: &str) -> String {
        wg_quick_to_uapi(&format!(
            "[Interface]\nPrivateKey = {ZERO_KEY}\nAddress = 10.2.0.2/32\n{mtu_line}\n[Peer]\nPublicKey = {ZERO_KEY}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\n"
        ))
        .unwrap()
    }

    #[test]
    fn wg_quick_mtu_is_the_tunnels_packet_size() {
        // 1420 inside the tunnel is 1500 on the link
        let cfg = wg_conf("MTU = 1420");
        assert!(cfg.contains("mtu=1500\n"), "MTU = 1420 gave\n{cfg}");
        let cfg = wg_conf("");
        assert!(!cfg.contains("mtu="), "no MTU line gave an mtu:\n{cfg}");
    }

    #[test]
    fn plan() {
        let masque = |extra: &[&str]| extra.iter().map(|s| s.to_string()).collect::<Vec<String>>();
        let none: Vec<String> = Vec::new();
        struct Case<'a> {
            name: &'a str,
            link: i64,
            exit: &'a str,
            cfg: String,
            us: Option<Vec<String>>,
            flag: i64,
            want_exit: i64,
            adp: i64,
        }
        let c = |name, link, exit, cfg: String, us: Option<Vec<String>>, flag, want_exit, adp| Case { name, link, exit, cfg, us, flag, want_exit, adp };
        let cases = [
            c("direct", 1500, "", String::new(), None, 0, 1500, 1500),
            c("proxy over PPPoE", 1492, EXIT_PROXY, "socks5://127.0.0.1:1080".into(), None, 0, 1492, 1492),
            c("WireGuard, no MTU line", 1500, EXIT_WG, wg_conf(""), None, 0, 1420, 1420),
            c("WireGuard, no MTU line, PPPoE", 1492, EXIT_WG, wg_conf(""), None, 0, 1412, 1412),
            c("WireGuard MTU 1420 over PPPoE: the link wins", 1492, EXIT_WG, wg_conf("MTU = 1420"), None, 0, 1412, 1412),
            c("WireGuard MTU 1300", 1500, EXIT_WG, wg_conf("MTU = 1300"), None, 0, 1300, 1300),
            c("WireGuard on a tiny link: the adapter stays at 1280", 1300, EXIT_WG, wg_conf(""), None, 0, 1220, 1280),
            c("WARP over WireGuard", 1500, EXIT_WARP, "private_key=00\nmtu=1360\n".into(), None, 0, 1280, 1280),
            c("MASQUE", 1500, EXIT_MASQUE, String::new(), Some(none.clone()), 0, 1280, 1280),
            c("MASQUE -m 1350", 1500, EXIT_MASQUE, String::new(), Some(masque(&["-s", "a.com", "-m", "1350"])), 0, 1350, 1350),
            c("MASQUE --mtu=1400 on a 1380 link", 1380, EXIT_MASQUE, String::new(), Some(masque(&["--mtu=1400"])), 0, 1400, 1380),
            c("chain --exit-mtu 1300", 1500, EXIT_CHAIN, String::new(), Some(masque(&["-m", "1400", "--exit-mtu", "1300"])), 0, 1300, 1300),
            c("set by hand", 1500, EXIT_WG, wg_conf(""), None, 1400, 1420, 1400),
        ];
        for c in cases {
            let p = plan_mtu(c.link, "Wi-Fi", c.exit, &c.cfg, c.us.as_deref(), c.flag);
            assert!(
                p.exit == c.want_exit && p.adapter == c.adp && p.link == c.link && p.auto == (c.flag == 0),
                "{}: {p:?}; want exit {}, adapter {}",
                c.name,
                c.want_exit,
                c.adp
            );
            assert!(!p.why.is_empty(), "{}: no explanation", c.name);
        }
    }

    #[test]
    fn parse() {
        for (s, want) in [("1420", 1420), (" 1280 ", 1280), ("65535", 65535)] {
            assert_eq!(parse_mtu(s), Some(want), "{s:?}");
        }
        for s in ["65536", "-1", "auto", "", "99999999999999999999", "+1400", "0x500", "1_400"] {
            assert_eq!(parse_mtu(s), None, "{s:?}");
        }
        // a hand-set MTU stays within 1280 and 1500 too
        let p = plan_mtu(1500, "Wi-Fi", "", "", None, 9000);
        assert!(p.adapter == 1500 && !p.auto, "-mtu 9000: {p:?}");
    }

    #[test]
    fn clamp() {
        for (m, want) in [(9000, 1500), (1500, 1500), (1492, 1492), (576, 1280)] {
            assert_eq!(clamp_mtu(m), want, "{m}");
        }
    }

    #[test]
    fn texts() {
        let p = plan_mtu(1492, "Ethernet 1492", EXIT_WG, "", None, 0);
        assert_eq!(p.why, "Ethernet 1492, WireGuard 1412");
        assert_eq!(p.to_string(), "adapter 1412 (automatic), from Ethernet 1492, WireGuard 1412");
        let hand = plan_mtu(1500, "Wi-Fi 1500", "", "", None, 1400);
        assert_eq!(hand.to_string(), "adapter 1400 (set by hand), from Wi-Fi 1500");
        // the JSON /api/status shows: no exit_why
        assert_eq!(
            serde_json::to_string(&p).unwrap(),
            r#"{"link":1492,"exit":1412,"adapter":1412,"auto":true,"why":"Ethernet 1492, WireGuard 1412"}"#
        );
        let moved = p.with_link(1400, "Wi-Fi 1400");
        assert_eq!((moved.link, moved.exit, moved.adapter), (1400, 1412, 1412));
        assert_eq!(moved.why, "Wi-Fi 1400, WireGuard 1412 (the adapter keeps 1412 until protection restarts)");
        assert_eq!(link_mtu(0, "Wi-Fi"), (1500, "network MTU unknown, so 1500".to_string()));
        assert_eq!(link_mtu(9000, "Ethernet"), (1500, "Ethernet 9000".to_string()));
        assert_eq!(link_mtu(1492, "PPPoE"), (1492, "PPPoE 1492".to_string()));
        // usque flags: the first name that has a good value wins; a bare flag
        // at the end has no value
        let f = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(flag_int(Some(&f(&["-m"])), 1280, &["-m"]), 1280);
        assert_eq!(flag_int(Some(&f(&["-m", "auto", "--mtu=1300"])), 1280, &["-m", "--mtu"]), 1300);
        assert_eq!(flag_int(Some(&f(&["--mtu1300"])), 1280, &["--mtu"]), 1280);
        assert_eq!(uapi_mtu("x=1\n  mtu=auto\nmtu=0\nmtu=1360\n"), 1360);
    }
}
