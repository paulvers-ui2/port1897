# port1897: firestack for Windows

An open-source effort to bring the engine behind the Android firewall
[Rethink DNS + Firewall](https://github.com/celzero/rethink-app) to Windows:
encrypted DNS, per-app firewall rules, connection logs and WireGuard, in a free
app for everyone.

> **Early test software.** It needs administrator rights and changes network
> settings while it runs. Do not rely on it for privacy or security yet.

This is an unofficial community project. It is not affiliated with or endorsed by
Celzero (Rethink), Cloudflare, WireGuard LLC or Microsoft.

## What works today

The networking engine, [firestack](FIRESTACK.md), now builds and runs on Windows
(x64 and ARM64). A command-line test tool, `fswin`, drives it:

- **Encrypted DNS:** Windows' DNS lookups go through firestack to a DNS-over-HTTPS
  server (Cloudflare by default).
- **Full tunnel** (`-full`): all IPv4 traffic goes through firestack, which logs
  every connection.
- **Which program?** Each connection is shown with the program that made it
  (`chrome.exe`, `discord.exe`, ...).
- **Block programs** (`-block chrome.exe`).
- **No DNS leaks** (`-nrpt`): a Windows DNS policy sends every lookup to the tunnel.
- **VPN exits:** send everything through free Cloudflare WARP (`-warp`), any
  WireGuard server (`-wg my.conf`), or a SOCKS5/HTTP proxy (`-proxy socks5://...`).

Not yet: an app window, a background service, saved rules, a kill switch, IPv6.
See the [roadmap](#roadmap).

## Try it

1. Open the latest successful
   [Windows build](https://github.com/wowjes92jsj2oe0-star/port1897/actions/workflows/windows.yml?query=branch%3Amain+is%3Asuccess)
   and download **fswin-windows-amd64** (or **-arm64** for ARM PCs) under *Artifacts*.
   You need to be signed in to GitHub to download artifacts.
2. Unzip it. It contains `fswin.exe` and `wintun.dll` (the official
   [Wintun](https://www.wintun.net) driver from the WireGuard project).
3. Disconnect any other VPN (Proton VPN, NordVPN, ...). They fight over the same
   network settings.
4. Open **Terminal (Admin)** in that folder and run:

   ```powershell
   .\fswin.exe -full -nrpt
   ```

   or, to also hide your IP address behind free Cloudflare WARP:

   ```powershell
   .\fswin.exe -warp -nrpt
   ```

5. Browse. You will see lines like:

   ```
   dns   example.com (type 1) -> 93.184.215.14 via Preferred 21ms ...
   flow  #12 tcp msedge.exe 10.111.222.1:51234 -> 93.184.215.14:443 [example.com]
   ```

6. Press **Ctrl+C** to stop. Everything is undone: the network adapter, its routes
   and the DNS rule are removed.

If `fswin` was closed some other way (window closed, crash) and websites stop
loading, run `.\fswin.exe -cleanup` from an admin terminal to restore DNS.

Windows SmartScreen or antivirus may warn about `fswin.exe` because it is not
code-signed yet.

Please tell us how it went with a
[test report](https://github.com/wowjes92jsj2oe0-star/port1897/issues/new?template=test_report.yml).

### Options

| Flag | Meaning |
|---|---|
| `-full` | Send all IPv4 traffic through the tunnel (default: DNS only) |
| `-nrpt` | Send every DNS query to the tunnel, whatever other adapters say |
| `-block a.exe,b.exe` | Block these programs (exe names or full paths); needs `-full` |
| `-warp` | Use free Cloudflare WARP as the VPN. The first run registers a free account and saves it in `fswin-warp.json` next to `fswin.exe` (keep that file private) |
| `-wg my.conf` | Use a WireGuard server; `my.conf` is a normal WireGuard config file |
| `-proxy socks5://user:pass@host:port` | Use a SOCKS5 (or `http://`) proxy |
| `-doh URL -doh-ips IPs` | Use another DNS-over-HTTPS server |
| `-cleanup` | Remove a DNS rule left behind by a crashed `fswin`, then exit |
| `-log 0..8` | firestack log detail: 0 very verbose, 3 default, 8 none |
| `-version` | Print the build and exit |

## Roadmap

| Phase | What | Status |
|---|---|---|
| 1 | firestack builds on Windows; Wintun network adapter; `fswin` test tool | done |
| 2 | Firewall core: program lookup, blocking, DNS leak fix, kill switch, rules engine and SQLite storage | in progress |
| 3 | WireGuard and WARP (MASQUE) inside the service | planned |
| 4 | App window and tray icon, installer, code signing, auto-update | planned |

The design and the details of every phase are in [PORT.md](PORT.md).

## How it is put together

| Path | What |
|---|---|
| `intra/`, `tunnel/` | firestack, the engine (from [celzero/firestack](https://github.com/celzero/firestack) via [paulvers-ui/firestack](https://github.com/paulvers-ui/firestack)). Linux-only parts sit in `_linux.go` files with `_windows.go` counterparts. |
| `intra/netstack/wintun_windows.go` | Connects firestack's network stack to a Wintun adapter |
| `win/` | Windows-only pieces: `ifbind` (keep firestack's own traffic out of the tunnel), `owner` (which program owns a connection), `dnspolicy` (DNS leak fix) |
| `cmd/fswin` | The test tool |
| `third_party/gotrie` | A patched copy of a firestack dependency, with Windows support |

Builds run on GitHub Actions: every push builds Windows x64 and ARM64 and checks
that the Android build still works.

## Help wanted

Testing on your PC is the most useful thing right now: different Windows versions,
Wi-Fi and Ethernet, other VPNs and antivirus. Code, docs and ideas are welcome too.
See [CONTRIBUTING.md](CONTRIBUTING.md).

## Licenses

- firestack and the code here: [Mozilla Public License 2.0](LICENSE). Changes to
  existing files stay MPL-2.0 and must be shared.
- Parts derived from gVisor and the Rethink Android app: Apache-2.0; from
  wireguard-go: MIT (noted at the top of those files).
- `third_party/gotrie`: MPL-2.0.
- `wintun.dll` (in the downloads, not in this repository): WireGuard LLC's
  prebuilt-binaries license, shipped next to `wintun-LICENSE.txt`.

## Thanks

[Celzero](https://github.com/celzero) for firestack and Rethink,
[paulvers-ui](https://github.com/paulvers-ui) for the AuroraVPN fork this starts
from, the [WireGuard](https://www.wireguard.com) project for Wintun and
wireguard-go, and Google's [gVisor](https://gvisor.dev) for the network stack.
