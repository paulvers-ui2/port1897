# Keeping AuroraVPN going

AuroraVPN is a free VPN and firewall for people whose internet is filtered or
watched. This file is for whoever keeps it going: how it is built, how a
release goes out, and what is left to do. You do not need the original author
to do any of it.

## The pieces

| Path | What | Language |
|---|---|---|
| `desktop/` | The app: window, tray, settings, history, installer hooks (`desktop/nsis/hooks.nsh`) | Rust (Tauri 2) |
| `ui/renderer/` | The app's screens; `port-tauri.js` connects them to the Rust side | HTML/JS |
| `cmd/fswin/` | The engine `fswin.exe` (runs as admin) and AuroraVPN Service | Go |
| `intra/`, `tunnel/` | firestack, the engine's network core (DNS transports, proxies, WireGuard) | Go |
| `win/` | Windows parts: NRPT DNS rule, WFP kill switch, IP Helper, which program owns a connection | Go |
| `engine-rs/` | The engine being rewritten in Rust; not shipped yet, see `engine-rs/PLAN.md` | Rust |
| `ui/` (rest) | The old Electron app, kept for reference, no longer built | JS |
| `tools/sim/` | End-to-end tests the CI runs on an admin Windows machine | PowerShell |

The app talks to the engine only through `fswin.exe`'s command-line flags and its
local API on `127.0.0.1:47897` (bearer token in `%APPDATA%\AuroraVPN\api-token`).
AuroraVPN Service (named pipe `\\.\pipe\AuroraVPN`) starts the engine for the
installed app without a UAC prompt. User data lives in `%APPDATA%\AuroraVPN`.

MASQUE and the WARP chain use `usque.exe`, built in CI from
[paulvers-ui2/usque](https://github.com/paulvers-ui2/usque) at the commit
pinned in `.github/workflows/app.yml`.

## Building

Everything builds on GitHub Actions; you don't need a local setup to release.
To build locally on Windows:

- Go (version in `go.mod`'s `toolchain` line): `go build -ldflags=-checklinkname=0 ./cmd/fswin`
- Rust 1.99 and Node: `cd desktop && npm ci && npx tauri build`
- The installer expects `ui/engine/` to hold `fswin.exe`, `usque.exe`,
  `wintun.dll` and their licences; `app.yml` shows how CI fills it.

Tests: `go test ./cmd/fswin ./win/...`, `cd desktop && cargo test`,
`cd engine-rs && cargo test`. Admin-only tests run on the CI runner.

## Releasing

Every pull request merged into `main` publishes a new version
(`.github/workflows/app.yml`): the next patch tag, the installer
`AuroraVPN-Setup-<version>.exe`, the portable zip, checksums and build
provenance. Put `[skip release]` in the merge commit message to merge without
releasing. Push a tag like `v0.3.0` to choose the version number yourself.

Before merging, wait until every check is green: Simulate and the AuroraVPN
Service e2e run the real engine with admin rights, and catch most breakage.

## Rules the project keeps

- The app stays in English.
- Releases are published in this repository only.
- Never register a WARP account from CI or tools; the app does it on the
  user's PC.
- Pin every GitHub Action by its full commit SHA.
- Security reports: see [SECURITY.md](SECURITY.md).

## What is left

- **The Rust engine** (`engine-rs/`, binary `fswin-rs.exe`): it now runs
  with `fswin.exe`'s command line: the userspace network stack, the direct
  exit, the DNS layer (DoH, DoT, plain DNS, cache), the start and stop order,
  the API, the kill switch, NRPT, AuroraVPN Service and the `-proxy` exit.
  CI runs the same end-to-end scripts against it as against the Go engine
  (`engine-rs.yml`, job "End to end with fswin-rs as fswin.exe").
  Flags it cannot serve yet are refused at start with a clear error. Left:
  `-wg`, `-warp` (WARP needs a patched boringtun), `-routes`, `-pcap`,
  MASQUE and the chain through usque, DNSCrypt, ODoH, on-device blocklists,
  the anti-censorship dialers, and a throughput comparison with the Go
  engine. Until it matches `fswin.exe`, the Go engine ships. Details and
  estimates are in `engine-rs/PLAN.md`.
- **Code signing:** the installer is not signed, so SmartScreen warns. A free
  option for open-source projects is [SignPath Foundation](https://signpath.org).
- **IPv6** inside the tunnel.
- **Auto-update** in the app.
- **A WARP stall** seen once (2026-10-09): restarting usque didn't fix it,
  a full engine restart did. The cause is unknown.

## Access

Keep at least two people with admin rights on this repository, so releases
can go on if one of them can't. Mirrors (for example on Codeberg) keep the code
reachable if GitHub is blocked in a country.
