# AuroraVPN for Windows: firestack

This repository is a fork of [paulvers-ui/firestack](https://github.com/paulvers-ui/firestack)
(itself a fork of [celzero/firestack](https://github.com/celzero/firestack)), branched at
commit `05a6645`. The goal is a Windows build of the networking engine behind the
Rethink DNS + Firewall / AuroraVPN Android apps.

## Phase 1: Windows build and a first tunnel

Done on branch `phase1-windows`; CI builds it for windows/amd64 and windows/arm64
and checks that linux and android still build.

- Linux/Android-only code is behind build tags, with Windows counterparts:
  | Area | Linux / Android | Windows |
  |---|---|---|
  | Tunnel device (`intra/netstack`) | fd + gVisor `rawfile`/`fdbased` | Wintun via `golang.zx2c4.com/wireguard/tun`; `netstack.RegisterTun` hands out the id passed where Android passes the tun fd |
  | TCP user timeout (`intra/core`) | `TCP_USER_TIMEOUT` | `TCP_MAXRT` (seconds) |
  | Pooled-conn liveness check | `poll(2)` | skipped; age-based eviction |
  | Unprivileged ICMP (`intra/protect`) | `SOCK_DGRAM` ICMP | raw ICMP socket (needs admin) |
  | WireGuard sockets (`intra/ipn/wg`) | `SO_MARK`, UDP GSO/GRO, `SO_*BUFFORCE` | buffers only; no mark, no GSO |
  | Split-and-desync dialer (`intra/dialers`) | memfd/sendfile/`MSG_ERRQUEUE` | plain dial (later phase) |
  | Runtime secure mode (`intra/core`) | linknamed | none |
- `github.com/celzero/gotrie` is vendored in `third_party/gotrie` with a Windows mmap.
- `cmd/fswin`: test tool. Creates a Wintun adapter, runs firestack in DNS-only mode
  with a DoH upstream, and prints every DNS query and connection it sees.

### Trying fswin

1. Download the `fswin-windows-amd64` artifact from the latest "Windows build" run
   (it holds `fswin.exe` and the official `wintun.dll`).
2. In an elevated terminal: `fswin.exe` (flags: `-doh`, `-doh-ips`, `-name`, `-log`).
3. Browse; DNS queries show up as `dns ...` lines. Ctrl+C removes the adapter.
   `fswin.exe -full -nrpt` sends all IPv4 traffic and all DNS through firestack and
   shows the program behind each connection; add `-block chrome.exe` to block one.

fswin is IPv4 only for now. Windows may still send DNS to other adapters in parallel; stopping that (NRPT and
firewall rules) is Phase 2 work.

## Phase 2: firewall core (in progress)

| Step | Status | Where |
|---|---|---|
| Full-tunnel mode; firestack's own sockets pinned to the physical interface (`IP_UNICAST_IF`), the stand-in for `VpnService.protect` | done | `win/ifbind`, `fswin -full` |
| Connection owner: TCP/UDP table -> pid -> exe path, stable numeric uid per exe | done | `win/owner`, `fswin` |
| Block programs by exe name | done (flag) | `fswin -block` |
| DNS leak fix: NRPT catch-all rule to the tunnel | done (opt-in) | `win/dnspolicy`, `fswin -nrpt` / `-cleanup` |
| DNSSEC switch (port of the Android DnsSecGuard: bogus/bogon answers blocked, AD-verified answers marked) and DNS booster (cached transports) | done (flags) | `cmd/fswin/dnssec_windows.go`, `fswin -dnssec` / `-dns-cache` |
| VPN exits: WireGuard config files, free Cloudflare WARP (auto-registered), SOCKS5/HTTP proxies | done (flags) | `fswin -wg` / `-warp` / `-proxy` |
| MASQUE WARP and the WARP chain (WARP2 -> wg0 -> WARP1) via usque as a child process, password-protected loopback SOCKS | done (flags) | `fswin -masque` / `-chain`, `cmd/fswin/usque_windows.go` |
| Kill switch with the Windows Filtering Platform, persistent across crashes | done (flag) | `win/wfp`, `fswin -killswitch` / `-cleanup` |
| App window (Electron) with tray icon, styled after the Android home screen | done | `ui/` |
| Rules engine ported from the Android app: app modes (block, isolate, bypass DNS & firewall, bypass universal, exclude, allow for 15 min), per-app and global IP / domain rules, universal rules, DNS record types, pause; rules apply live through the API and close blocked connections | done | `cmd/fswin/rules_windows.go`, `ui/renderer/firewall.js` |
| DNS types ODoH (with relay) and DNS proxy, DNSCrypt relays, RethinkDNS blocklists on-device (download + md5 check) and on the server (stamp in the URL) | done | `cmd/fswin/dns_windows.go`, `ui/renderer/blocklists.js` |
| Per-app routes (Android's WireGuard advanced mode and proxy app lists): apps go through their own WireGuard config or SOCKS5/HTTP proxy | done | `cmd/fswin/routes_windows.go`, App info → Route through |
| Ping test, welcome slides, weekly update check (GitHub releases), log filters; tagged builds publish a GitHub release | done | `ui/renderer/tools.js`, `.github/workflows/app.yml` |
| Packet capture (`-pcap`); automation (`AuroraVPN.exe --start/--stop/--pause/--resume`) | done | `cmd/fswin`, `ui/main.js` |
| Live tunnel status (state, last handshake, bytes) for the exit and per-app routes | done | `GET /api/proxies`, Proxy screen |
| Anti-censorship dial strategy (split TCP / TLS ClientHello); desync is not implemented on Windows | done (flags) | `fswin -dial-strategy` |
| Windows service + named-pipe API for the UI | later | |

Notes:
- IPv4 only for now; with `-full`, IPv6 traffic still goes out directly.
- Another VPN's catch-all NRPT rule (Proton VPN adds one) competes with `-nrpt`;
  fswin warns about it. Disconnect the other VPN while testing.
- If fswin is killed rather than stopped with Ctrl+C, its NRPT rule stays and DNS
  fails until `fswin -cleanup` (or the next fswin run) removes it.
- Errno checks such as `syscall.EADDRINUSE` in `intra/ipn/wg` do not match Winsock
  errors (`WSAEADDRINUSE`); retries keyed on them do not fire on Windows yet.

## Licenses

- firestack is MPL-2.0 (see `LICENSE`). Modified files stay MPL-2.0.
- `third_party/gotrie` is MPL-2.0 (celzero/gotrie).
- Wintun (`wintun.dll`) is under WireGuard LLC's prebuilt-binaries license from
  <https://www.wintun.net>. It is not committed here; CI downloads the official
  0.14.1 zip (SHA-256 pinned) and ships the dll with its license next to fswin.exe.

## Disclaimer

This is an unofficial, community project. It is not affiliated with or endorsed by
Celzero (Rethink), Cloudflare, or Microsoft. "WARP" and "Cloudflare" are trademarks
of Cloudflare, Inc. Use at your own risk.
