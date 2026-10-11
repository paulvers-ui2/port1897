// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The process that owns a TCP or UDP flow (a port of win/owner): the
//! stand-in for Android's getConnectionOwnerUid, over IP Helper's owner
//! tables. Read only: its tests need no admin rights.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID};
use windows_sys::Win32::Networking::WinSock::AF_INET;
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW};

use super::err_text;
use crate::engine::Owners;

/// MIB_TCPROW_OWNER_PID: state, laddr, lport, raddr, rport, pid.
const TCP_ROW: usize = 24;
/// MIB_UDPROW_OWNER_PID: laddr, lport, pid.
const UDP_ROW: usize = 12;

pub const NOT_FOUND: &str = "owner: no matching socket";
const UNSUPPORTED: &str = "owner: only IPv4 is supported";

/// How old a table copy may be and still answer: programs open
/// connections in bursts, and a burst finds its sockets in one copy. A
/// socket newer than the copy is not in it: that miss asks Windows again.
const SNAP_TTL: Duration = Duration::from_millis(250);
/// How long a pid -> path entry is trusted; pids get reused.
const PATH_TTL: Duration = Duration::from_secs(30);

type Snap = Mutex<Option<(Vec<u8>, Instant)>>;

/// Owner lookups with their caches.
#[derive(Default)]
pub struct WinOwners {
    tcp: Snap,
    udp: Snap,
    paths: Mutex<HashMap<u32, (String, Instant)>>,
}

#[derive(Clone, Copy)]
enum Kind {
    Tcp,
    Udp,
}

impl WinOwners {
    pub fn new() -> WinOwners {
        WinOwners::default()
    }

    /// A copy of the table no older than SNAP_TTL, or a fresh one.
    fn table_copy(&self, kind: Kind, fresh: bool) -> Result<Vec<u8>, String> {
        let snap = match kind {
            Kind::Tcp => &self.tcp,
            Kind::Udp => &self.udp,
        };
        let mut s = snap.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((buf, at)) = s.as_ref() {
            if !fresh && at.elapsed() < SNAP_TTL {
                return Ok(buf.clone());
            }
        }
        let buf = table(kind)?;
        *s = Some((buf.clone(), Instant::now()));
        Ok(buf)
    }
}

impl Owners for WinOwners {
    fn tcp4(&self, local: SocketAddr, remote: SocketAddr) -> Result<u32, String> {
        if !local.is_ipv4() || !remote.is_ipv4() {
            return Err(UNSUPPORTED.into());
        }
        // a recent copy answers only for this very connection
        let buf = self.table_copy(Kind::Tcp, false)?;
        if let (pid, true) = tcp_lookup(&buf, local, remote) {
            if pid != 0 {
                return Ok(pid);
            }
        }
        let buf = self.table_copy(Kind::Tcp, true)?;
        match tcp_lookup(&buf, local, remote) {
            (pid, exact) if exact || pid != 0 => Ok(pid),
            _ => Err(NOT_FOUND.into()),
        }
    }

    fn udp4(&self, local: SocketAddr) -> Result<u32, String> {
        if !local.is_ipv4() {
            return Err(UNSUPPORTED.into());
        }
        // UDP sockets mostly bind the wildcard address, so a recent copy
        // answers for local's port
        for fresh in [false, true] {
            let buf = self.table_copy(Kind::Udp, fresh)?;
            let pid = udp_lookup(&buf, local);
            if pid != 0 {
                return Ok(pid);
            }
        }
        Err(NOT_FOUND.into())
    }

    /// The full path of pid's executable; pid 4 is "System".
    fn exe_path(&self, pid: u32) -> Result<String, String> {
        match pid {
            0 => return Err(NOT_FOUND.into()),
            4 => return Ok("System".into()),
            _ => {}
        }
        if let Some((p, at)) = self.paths.lock().unwrap_or_else(|e| e.into_inner()).get(&pid) {
            if at.elapsed() < PATH_TTL {
                return Ok(p.clone());
            }
        }
        let path = process_path(pid)?;
        let mut m = self.paths.lock().unwrap_or_else(|e| e.into_inner());
        if m.len() > 4096 {
            m.clear();
        }
        m.insert(pid, (path.clone(), Instant::now()));
        Ok(path)
    }
}

fn last_error() -> String {
    err_text(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32)
}

/// QueryFullProcessImageNameW on a limited-information handle.
pub fn process_path(pid: u32) -> Result<String, String> {
    // SAFETY: plain call; the handle is checked and closed below
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return Err(last_error());
    }
    let mut buf = vec![0u16; 32768]; // MAX_LONG_PATH
    let mut n = buf.len() as u32;
    // SAFETY: h is a process handle; buf holds n characters
    let ok = unsafe { QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut n) };
    let err = (ok == 0).then(last_error);
    // SAFETY: h is ours, closed once
    unsafe { CloseHandle(h) };
    if let Some(e) = err {
        return Err(e);
    }
    Ok(String::from_utf16_lossy(&buf[..n as usize]))
}

/// GetExtendedTcpTable or GetExtendedUdpTable for AF_INET, unsorted.
fn table(kind: Kind) -> Result<Vec<u8>, String> {
    let mut size: u32 = 16 << 10;
    for _ in 0..4 {
        let mut buf = vec![0u8; size as usize];
        // SAFETY: buf holds size bytes; size is updated by the call
        let r = unsafe {
            match kind {
                Kind::Tcp => GetExtendedTcpTable(buf.as_mut_ptr().cast(), &mut size, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0),
                Kind::Udp => GetExtendedUdpTable(buf.as_mut_ptr().cast(), &mut size, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0),
            }
        };
        match r {
            NO_ERROR => {
                // a row count, then the rows; trust no size outside the buffer
                if size < 4 || size as usize > buf.len() {
                    return Err(NOT_FOUND.into());
                }
                buf.truncate(size as usize);
                return Ok(buf);
            }
            // the table may grow between calls
            ERROR_INSUFFICIENT_BUFFER => size += 4 << 10,
            e => return Err(err_text(e)),
        }
    }
    Err(err_text(ERROR_INSUFFICIENT_BUFFER))
}

fn u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// The port as MIB rows keep it: the low 16 bits, network order.
fn port(p: &[u8]) -> u16 {
    (p[0] as u16) << 8 | p[1] as u16
}

/// An IPv4 address (network order) and port as MIB rows keep them.
fn addr_port(a: &[u8], p: &[u8]) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3])), port(p))
}

/// local -> remote in a TCP table: its pid and true; else the pid of a
/// socket on local's port and false (0 if none).
fn tcp_lookup(buf: &[u8], local: SocketAddr, remote: SocketAddr) -> (u32, bool) {
    if buf.len() < 4 {
        return (0, false);
    }
    let n = u32_le(buf) as usize;
    let rows = &buf[4..];
    let mut port_only = 0;
    for i in 0..n {
        let Some(r) = rows.get(i * TCP_ROW..(i + 1) * TCP_ROW) else { break };
        if addr_port(&r[4..8], &r[8..12]) != local {
            if port(&r[8..12]) == local.port() && port_only == 0 {
                port_only = u32_le(&r[20..24]);
            }
            continue;
        }
        if addr_port(&r[12..16], &r[16..20]) == remote {
            return (u32_le(&r[20..24]), true);
        }
    }
    (port_only, false)
}

/// The socket bound to local in a UDP table, or else the one bound to the
/// wildcard address on local's port: its pid, or 0.
fn udp_lookup(buf: &[u8], local: SocketAddr) -> u32 {
    if buf.len() < 4 {
        return 0;
    }
    let n = u32_le(buf) as usize;
    let rows = &buf[4..];
    let mut wildcard = 0;
    for i in 0..n {
        let Some(r) = rows.get(i * UDP_ROW..(i + 1) * UDP_ROW) else { break };
        let ap = addr_port(&r[0..4], &r[4..8]);
        if ap.port() != local.port() {
            continue;
        }
        let pid = u32_le(&r[8..12]);
        if ap.ip() == local.ip() {
            return pid;
        }
        if ap.ip().is_unspecified() && wildcard == 0 {
            wildcard = pid;
        }
    }
    wildcard
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream, UdpSocket};

    #[test]
    fn tcp4_finds_new_sockets_despite_the_copy() {
        let o = WinOwners::new();
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut keep = Vec::new();
        // the second connection opens after the first lookup copied the
        // table: that copy must not hide it
        for i in 0..2 {
            let c = TcpStream::connect(ln.local_addr().unwrap()).unwrap();
            keep.push(ln.accept().unwrap().0);
            let pid = o.tcp4(c.local_addr().unwrap(), c.peer_addr().unwrap());
            assert_eq!(pid, Ok(std::process::id()), "connection {i}");
            keep.push(c);
        }
        assert_eq!(o.tcp4("[::1]:1".parse().unwrap(), "1.1.1.1:1".parse().unwrap()).unwrap_err(), UNSUPPORTED);
    }

    #[test]
    fn udp4() {
        let o = WinOwners::new();
        let bound = UdpSocket::bind("127.0.0.1:0").unwrap();
        let wild = UdpSocket::bind("0.0.0.0:0").unwrap();
        for local in [bound.local_addr().unwrap(), SocketAddr::new("127.0.0.1".parse().unwrap(), wild.local_addr().unwrap().port())] {
            assert_eq!(o.udp4(local), Ok(std::process::id()), "{local}");
        }
        assert_eq!(o.udp4("127.0.0.1:1".parse().unwrap()).unwrap_err(), NOT_FOUND);
    }

    #[test]
    fn paths() {
        let o = WinOwners::new();
        let me = o.exe_path(std::process::id()).unwrap();
        assert!(crate::golike::equal_fold(&me, &std::env::current_exe().unwrap().to_string_lossy()), "{me}");
        assert_eq!(o.exe_path(4).unwrap(), "System");
        assert_eq!(o.exe_path(0).unwrap_err(), NOT_FOUND);
        // a pid that is not running
        assert!(o.exe_path(0xFFFF_FFF0).is_err());
    }

    #[test]
    fn lookups_ignore_short_or_torn_tables() {
        let local: SocketAddr = "10.0.0.2:5000".parse().unwrap();
        let remote: SocketAddr = "1.1.1.1:443".parse().unwrap();
        // a row count larger than the rows present
        let mut buf = vec![0u8; 4 + TCP_ROW / 2];
        buf[0] = 200;
        assert_eq!(tcp_lookup(&buf, local, remote), (0, false));
        assert_eq!(udp_lookup(&buf, local), 0);
        assert_eq!(tcp_lookup(&[1, 0], local, remote), (0, false));
        // a row on local's port from another address: the port-only answer
        let mut t = vec![1, 0, 0, 0];
        t.extend([5, 0, 0, 0, 10, 0, 0, 9, 0x13, 0x88, 0, 0, 1, 1, 1, 1, 1, 187, 0, 0, 42, 0, 0, 0]);
        assert_eq!(tcp_lookup(&t, local, remote), (42, false));
        t[11] = 2; // now 10.0.0.2:5000 -> 1.1.1.1:443
        assert_eq!(tcp_lookup(&t, local, remote), (42, true));
    }
}
