# AuroraVPN for Linux (.deb): plan

The next port after Windows: the same engine and app on Debian and Ubuntu,
shipped as a `.deb`. This file is the plan; nothing here is built yet.

## Targets

| | |
|---|---|
| Built on | Debian 12 (bookworm), amd64 |
| Supported | Debian 12 and 13, Ubuntu 22.04 and 24.04 |
| Best effort | Debian 11 (bullseye): past its LTS; the engine is a static Go binary and runs there, the app (Electron) is tested in CI before it is promised |
| Later | arm64 |

## What already works on Linux

- **firestack** (`intra/`, `tunnel/`) is Linux code first: Android is Linux. It
  takes a TUN file descriptor (`intra.Connect(fd, ...)`,
  `intra/netstack/fdbased.go`), so no driver like Wintun is needed: the kernel's
  `/dev/net/tun` is enough. CI already builds it for linux/amd64.
- **usque** already ships a linux/amd64 build in every release.
- **Most of the engine's logic is not Windows code**, only named so. Of the
  ~9,300 lines in `cmd/fswin`, the journal, open connections, routes, rules,
  geo-IP, ASN, DNS setup, exits and the supervisor barely touch Windows. What
  does: `service_windows.go`, `main_windows.go`, `asuser_windows.go`, parts of
  `usque_windows.go`, `killswitch_windows.go`, `keep_windows.go`.
- **The app** (`ui/`, Electron) is cross-platform; `electron-builder` has a
  `deb` target.

## What has to be written

Each row replaces one Windows piece with its Linux counterpart, behind the
same Go interface so `cmd/fswin` stays one program.

| Windows (today) | Linux | Notes |
|---|---|---|
| Wintun adapter (`intra/netstack/wintun_windows.go`) | TUN device from `/dev/net/tun` | fd goes straight to `intra.Connect` |
| `win/ipconf`: adapter address, routes | netlink (`ip addr`, `ip route`, `ip rule`) | a routing table of its own plus `ip rule`, as WireGuard's `wg-quick` does |
| `win/ifbind`: keep the engine's own sockets out of the tunnel | `SO_MARK` on every engine socket + `ip rule not fwmark X lookup <table>` | simpler than Windows: no per-interface bind, survives network changes |
| `win/owner`: which program owns a connection | netlink `sock_diag` (uid and inode of the socket), then `/proc/<pid>/fd` for the pid and `/proc/<pid>/exe` for the path | exact 4-tuple match, so no port-only fallback; cache pid by inode |
| `win/dnspolicy` (NRPT): no DNS leaks | `resolvectl dns/domain ~.` on the TUN link when systemd-resolved runs; else swap `/etc/resolv.conf` and restore it on stop and on `-cleanup` | NetworkManager without resolved: its D-Bus API, later |
| `win/wfp`: kill switch | nftables table `inet auroravpn`: drop everything not marked, not loopback, not the TUN; survives an engine crash, removed by `-cleanup` | needs `nftables` (Debian 11 has 0.9.8: enough) |
| AuroraVPN Service (`service_windows.go`) | a systemd unit running the engine as root with `CAP_NET_ADMIN`, hardened (`ProtectSystem=strict`, `NoNewPrivileges`, ...) | the app talks to it over a unix socket owned by the `auroravpn` group, instead of a named pipe |
| Run usque as the user (`asuser_windows.go`) | drop to the user's uid/gid before `exec` | |
| Installer (NSIS), portable exe | `.deb` from `electron-builder`; `postinst` installs and enables the unit, `prerm` stops it and runs `-cleanup` | `Depends: nftables, iproute2` |

Not ported: SmartScreen, code signing, the PC-locked rule (later, through
logind), Windows Firewall checks in the debug zip.

## Phases

| Phase | What | Done when |
|---|---|---|
| L0 | Split `cmd/fswin`: files without Windows code lose `_windows` and build everywhere; the Windows pieces sit behind small interfaces (`tun`, `binder`, `owner`, `dnsleak`, `killswitch`) | Windows CI unchanged and green; `go build ./cmd/fswin` passes on Linux (stubs) |
| L1 | Engine on Linux from a terminal: TUN, routes, `SO_MARK`, DNS, owner lookup | `sudo fswin -full` on Debian 12 shows `dns` and `flow` lines with program names; Ctrl+C restores the network |
| L2 | Exits and kill switch: WARP, WireGuard, SOCKS5/HTTP, MASQUE and chain through usque, nftables | each exit passes the same end-to-end test as on Windows, in a network namespace in CI |
| L3 | Service and app: systemd unit, unix-socket API, Electron paths (`~/.config/AuroraVPN`), tray | start and stop from the app without `sudo` |
| L4 | `.deb`: build in CI, install/upgrade/remove tests in `debian:12`, `debian:13`, `debian:11`, `ubuntu:24.04` containers; attach to releases | `apt install ./auroravpn_*.deb` then Start works on a clean VM |

L0 is the only phase that touches Windows code: it goes in alone, with no
behaviour change, before anything Linux is added.

## Risks

- **Owner lookup cost.** `/proc` scans are slow on a busy desktop: cache by
  socket inode, fall back to uid only.
- **DNS on Linux is not one thing** (resolved, NetworkManager, plain
  `resolv.conf`, `resolvconf`). L1 covers resolved and plain; the rest later.
- **Other VPNs and Docker** add their own rules and nftables tables: detect
  and warn, as the Windows build does for other VPNs.
- **Debian 11 and Electron.** If the current Electron no longer starts on
  bullseye, the engine and service still ship there; the app says so.
