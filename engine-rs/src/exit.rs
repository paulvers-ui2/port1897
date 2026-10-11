// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Exits: where -full traffic leaves (a port of the pure parts of
//! exit_windows.go). The ids are firestack's proxy ids, kept so the logs
//! and the API read as with the Go engine; the names are what the app
//! matches in /api/status ("exit") and shows in the Logs ("via").

use crate::gojson::{self, Obj};
use crate::mtu::{WARP_MTU, WG_OVERHEAD, parse_mtu};

pub const EXIT_WG: &str = "wgconf";
pub const EXIT_WARP: &str = "wgwarp";
pub const EXIT_PROXY: &str = "socks";
/// usque socks
pub const EXIT_MASQUE: &str = "masque";
/// usque chain
pub const EXIT_CHAIN: &str = "chain";

/// firestack's id for "leave directly".
pub const BASE: &str = "Base";
/// firestack's id for "drop it".
pub const BLOCK: &str = "Block";

/// The exit's name, as the app knows it.
pub fn exit_name(id: &str) -> String {
    match id {
        EXIT_WG => "WireGuard",
        EXIT_WARP => "Cloudflare WARP",
        EXIT_PROXY => "proxy",
        EXIT_MASQUE => "Cloudflare WARP (MASQUE)",
        EXIT_CHAIN => "WARP chain",
        BASE => "direct",
        BLOCK => "blocked",
        other => other,
    }
    .to_string()
}

/// Converts a wg-quick .conf file to the key=value config firestack's
/// WireGuard proxy reads (WireGuard's UAPI keys plus address, dns and mtu).
/// Keys go from base64 to hex. The Rust WireGuard exit takes the same text,
/// so -wg and -routes files behave as with the Go engine.
pub fn wg_quick_to_uapi(conf: &str) -> Result<String, String> {
    let mut iface = String::new();
    let mut peers = String::new();
    let mut section = String::new();
    let (mut saw_key, mut saw_peer, mut saw_dns) = (false, false, false);
    for raw in conf.split('\n') {
        // Go reads the file with a bufio.Scanner, which stops at a line of
        // 64 KiB or more and keeps what it has read
        if raw.len() >= 64 * 1024 {
            break;
        }
        let mut line = raw.trim();
        if let Some(i) = line.find(['#', ';']) {
            line = line[..i].trim();
        }
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            section = crate::golike::to_lower(line.trim_matches(|c| c == '[' || c == ']' || c == ' '));
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(format!("wg: bad line {}", crate::golike::quote(line)));
        };
        let k = crate::golike::to_lower(k.trim());
        let v = v.trim();
        match section.as_str() {
            "interface" => match k.as_str() {
                "privatekey" => {
                    let h = b64hex(v).map_err(|e| format!("wg: PrivateKey: {e}"))?;
                    iface.push_str(&format!("private_key={h}\n"));
                    saw_key = true;
                }
                "address" => iface.push_str(&format!("address={v}\n")),
                "dns" => {
                    iface.push_str(&format!("dns={v}\n"));
                    saw_dns = true;
                }
                // wg-quick's MTU is the size of a packet inside the tunnel;
                // the exit's is the size on the link, WG_OVERHEAD more
                "mtu" => match parse_mtu(v) {
                    Some(m) if m > 0 => iface.push_str(&format!("mtu={}\n", m + WG_OVERHEAD)),
                    _ => iface.push_str(&format!("mtu={v}\n")),
                },
                "listenport" => iface.push_str(&format!("listen_port={v}\n")),
                _ => {}
            },
            "peer" => match k.as_str() {
                "publickey" => {
                    let h = b64hex(v).map_err(|e| format!("wg: PublicKey: {e}"))?;
                    peers.push_str(&format!("public_key={h}\n"));
                    saw_peer = true;
                }
                "presharedkey" => {
                    let h = b64hex(v).map_err(|e| format!("wg: PresharedKey: {e}"))?;
                    peers.push_str(&format!("preshared_key={h}\n"));
                }
                "endpoint" => peers.push_str(&format!("endpoint={v}\n")),
                "allowedips" => {
                    for ip in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                        peers.push_str(&format!("allowed_ip={ip}\n"));
                    }
                }
                "persistentkeepalive" => peers.push_str(&format!("persistent_keepalive_interval={v}\n")),
                _ => {}
            },
            _ => {}
        }
    }
    if !saw_key || !saw_peer {
        return Err("wg: config needs [Interface] PrivateKey and a [Peer] PublicKey".to_string());
    }
    if !saw_dns {
        iface.push_str("dns=1.1.1.1\n"); // firestack requires one
    }
    Ok(iface + &peers)
}

/// A base64 WireGuard key as hex; it must be 32 bytes.
pub fn b64hex(s: &str) -> Result<String, String> {
    let b = base64_std_decode(s)?;
    if b.len() != 32 {
        return Err(format!("key is {} bytes, want 32", b.len()));
    }
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Go's base64.StdEncoding.DecodeString: padded, '\r' and '\n' skipped,
/// unused low bits ignored. A port of Go's decodeQuantum loop, so a bad key
/// is reported at the same byte as by the Go engine.
pub fn base64_std_decode(s: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bad = |i: usize| format!("illegal base64 data at input byte {i}");
    let skip_newlines = |mut si: usize| {
        while si < s.len() && matches!(s.as_bytes()[si], b'\n' | b'\r') {
            si += 1;
        }
        si
    };
    let src = s.as_bytes();
    let mut out = Vec::with_capacity(src.len() / 4 * 3);
    let mut si = 0;
    while si < src.len() {
        let mut dbuf = [0u8; 4];
        let mut dlen = 4;
        let mut trailing = None;
        let mut j = 0;
        while j < 4 {
            if si == src.len() {
                if j == 0 {
                    return Ok(out);
                }
                return Err(bad(si - j));
            }
            let c = src[si];
            si += 1;
            if let Some(v) = val(c) {
                dbuf[j] = v;
                j += 1;
                continue;
            }
            if c == b'\n' || c == b'\r' {
                continue;
            }
            if c != b'=' {
                return Err(bad(si - 1));
            }
            // padding: the end
            match j {
                0 | 1 => return Err(bad(si - 1)),
                2 => {
                    // "==" is expected, and the first one is read
                    si = skip_newlines(si);
                    if si == src.len() {
                        return Err(bad(src.len()));
                    }
                    if src[si] != b'=' {
                        return Err(bad(si - 1));
                    }
                    si += 1;
                }
                _ => {}
            }
            si = skip_newlines(si);
            if si < src.len() {
                trailing = Some(bad(si));
            }
            dlen = j;
            break;
        }
        let w = (dbuf[0] as u32) << 18 | (dbuf[1] as u32) << 12 | (dbuf[2] as u32) << 6 | dbuf[3] as u32;
        out.extend_from_slice(&[(w >> 16) as u8, (w >> 8) as u8, w as u8][..dlen - 1]);
        if let Some(e) = trailing {
            return Err(e);
        }
    }
    Ok(out)
}

/// Go's base64.StdEncoding.EncodeToString.
pub fn base64_std_encode(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let w = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(A[(w >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// What the engine keeps of a free WARP registration (the -warp-file).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WarpAccount {
    /// base64
    pub private_key: String,
    pub peer_key: String,
    /// base64, 3 bytes
    pub client_id: String,
    pub address4: String,
    /// ip:port
    pub endpoint4: String,
    pub id: String,
    pub token: String,
}

impl WarpAccount {
    /// Reads the account file as Go's json.Unmarshal fills warpAccount.
    pub fn from_json(data: &[u8]) -> Result<WarpAccount, String> {
        let v = gojson::unmarshal(data)?;
        let Some(o) = Obj::of(&v, "warpAccount")? else {
            return Ok(WarpAccount::default());
        };
        Ok(WarpAccount {
            private_key: o.string("private_key")?,
            peer_key: o.string("peer_public_key")?,
            client_id: o.string("client_id")?,
            address4: o.string("address_v4")?,
            endpoint4: o.string("endpoint_v4")?,
            id: o.string("id")?,
            token: o.string("token")?,
        })
    }

    /// The WireGuard config for this WARP account, IPv4 only.
    pub fn uapi(&self) -> Result<String, String> {
        let sk = b64hex(&self.private_key).map_err(|e| format!("warp: private key: {e}"))?;
        let pk = b64hex(&self.peer_key).map_err(|e| format!("warp: peer key: {e}"))?;
        let mut cfg = format!("private_key={sk}\naddress={}/32\ndns=1.1.1.1\n", self.address4);
        // 1280 inside the tunnel, as in Cloudflare's client
        cfg.push_str(&format!("mtu={}\n", WARP_MTU + WG_OVERHEAD));
        // WARP wants its 3-byte client id in the reserved header bytes; as
        // the header words h1..h4 of the four message types
        if let Ok(id) = base64_std_decode(&self.client_id) {
            if id.len() == 3 {
                for (i, typ) in [1u8, 2, 3, 4].iter().enumerate() {
                    let h = u32::from_le_bytes([*typ, id[0], id[1], id[2]]);
                    cfg.push_str(&format!("h{}={h}\n", i + 1));
                }
            }
        }
        cfg.push_str(&format!("public_key={pk}\nendpoint={}\n", self.endpoint4));
        cfg.push_str("allowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n");
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const K1: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const K2: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

    #[test]
    fn wg_quick() {
        let conf = format!(
            "# comment\r\n[Interface]\r\nPrivateKey = {K1}\r\nAddress = 10.0.0.2/32, fd00::2/128\r\nMTU = 1340 ; inside\r\nListenPort=51820\r\n\r\n[Peer]\r\nPublicKey = {K2}\r\nPresharedKey = {K1}\r\nEndpoint = vpn.example:51820\r\nAllowedIPs = 0.0.0.0/0, ::/0\r\nPersistentKeepalive = 25\r\nUnknown = 1\r\n"
        );
        let got = wg_quick_to_uapi(&conf).unwrap();
        let hk1 = "c809f3e5317e9575c9b5ed78b638b7ce530dabe85ddab614220241801ddf0669";
        let hk2 = "c53201039adba14be71f886da1d8dbe9eebded08cb111b75340078999aa9f038";
        assert_eq!(
            got,
            format!(
                "private_key={hk1}\naddress=10.0.0.2/32, fd00::2/128\nmtu=1420\nlisten_port=51820\ndns=1.1.1.1\npublic_key={hk2}\npreshared_key={hk1}\nendpoint=vpn.example:51820\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=25\n"
            )
        );
        assert!(wg_quick_to_uapi("[Interface]\nPrivateKey = x\n").unwrap_err().starts_with("wg: PrivateKey: "));
        assert_eq!(
            wg_quick_to_uapi(&format!("[Interface]\nPrivateKey={K1}\n")).unwrap_err(),
            "wg: config needs [Interface] PrivateKey and a [Peer] PublicKey"
        );
        assert_eq!(wg_quick_to_uapi("[Peer]\nnonsense\n").unwrap_err(), "wg: bad line \"nonsense\"");
        // a line of 64 KiB ends the file, as with Go's bufio.Scanner
        let long = format!("[Interface]\nPrivateKey={K1}\n[Peer]\nPublicKey={K2}\n# {}\nPresharedKey = bad\n", "x".repeat(64 * 1024));
        assert!(wg_quick_to_uapi(&long).is_ok());
        let auto = wg_quick_to_uapi(&format!("[Interface]\nPrivateKey={K1}\nDNS=9.9.9.9\nMTU=auto\n[Peer]\nPublicKey={K2}\n")).unwrap();
        assert!(auto.contains("dns=9.9.9.9\nmtu=auto\n") && !auto.contains("dns=1.1.1.1"), "{auto}");
    }

    #[test]
    fn base64_like_go() {
        assert_eq!(base64_std_decode("").unwrap(), b"");
        assert_eq!(base64_std_decode("Zg==").unwrap(), b"f");
        assert_eq!(base64_std_decode("Zm8=").unwrap(), b"fo");
        assert_eq!(base64_std_decode("Zm9v").unwrap(), b"foo");
        assert_eq!(base64_std_decode("Zm9v\r\nYmFy").unwrap(), b"foobar");
        assert_eq!(base64_std_decode("Zh==").unwrap(), b"f"); // not strict
        assert_eq!(base64_std_decode("Zm9v\nZg=\n=").unwrap(), b"foof");
        assert_eq!(base64_std_decode("Z\ng\n=\n=").unwrap(), b"f");
        // the byte Go's decoder reports
        for (bad, at) in [
            ("Zg", 0),
            ("Zg=", 3),
            ("Z===", 1),
            ("Zg==Zg==", 4),
            ("Zm9v!A==", 4),
            ("Zm=v", 2),
            ("=", 0),
            ("====", 0),
            ("Zm9vY", 4),
            ("Zm9vYmE", 4),
            ("Zg=a", 2),
            ("Zm9v====", 4),
        ] {
            assert_eq!(base64_std_decode(bad).unwrap_err(), format!("illegal base64 data at input byte {at}"), "{bad}");
        }
        for b in [&b""[..], b"f", b"fo", b"foo", b"foob", &[0xff, 0xfe, 0x00, 0x01]] {
            assert_eq!(base64_std_decode(&base64_std_encode(b)).unwrap(), b);
        }
        assert_eq!(b64hex("AAAA").unwrap_err(), "key is 3 bytes, want 32");
    }

    #[test]
    fn warp_uapi() {
        let a = WarpAccount::from_json(
            format!(r#"{{"private_key":"{K1}","peer_public_key":"{K2}","client_id":"AQID","address_v4":"172.16.0.2","endpoint_v4":"162.159.192.1:2408","id":"x","token":"y"}}"#).as_bytes(),
        )
        .unwrap();
        let cfg = a.uapi().unwrap();
        // h1 = LE(1, 1, 2, 3) = 0x03020101
        assert!(cfg.contains(&format!("h1={}\nh2={}\nh3={}\nh4={}\n", 0x03020101u32, 0x03020102u32, 0x03020103u32, 0x03020104u32)), "{cfg}");
        assert!(cfg.starts_with("private_key=c809f3e5") && cfg.contains("address=172.16.0.2/32\ndns=1.1.1.1\nmtu=1360\n"));
        assert!(cfg.ends_with("endpoint=162.159.192.1:2408\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n"));
        let no_id = WarpAccount { client_id: String::new(), ..a.clone() }.uapi().unwrap();
        assert!(!no_id.contains("h1="));
        assert!(WarpAccount { private_key: "bad".into(), ..a }.uapi().unwrap_err().starts_with("warp: private key: "));
    }

    #[test]
    fn names() {
        assert_eq!(exit_name(EXIT_MASQUE), "Cloudflare WARP (MASQUE)");
        assert_eq!(exit_name(BASE), "direct");
        assert_eq!(exit_name("wgapp1"), "wgapp1");
    }
}
