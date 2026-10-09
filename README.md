# AuroraVPN for Windows: firestack

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
- **Every DNS type of the Android app:** DoH, DoT, DNSCrypt (with relays), Oblivious
  DoH, DNS proxy, RethinkDNS with 195+ blocklists (on the server, or downloaded and
  applied on this PC).
- **DNSSEC and DNS booster** (`-dnssec`, `-dns-cache`): bogus answers are blocked,
  repeat lookups come from the cache.
- **VPN exits:** send everything through free Cloudflare WARP (`-warp`), WARP over
  MASQUE (`-masque`, looks like HTTPS), the WARP chain WARP -> your WireGuard
  server -> WARP (`-chain my.conf`), any WireGuard server (`-wg my.conf`), or a
  SOCKS5/HTTP proxy (`-proxy socks5://...`). MASQUE and the chain use
  [usque](https://github.com/paulvers-ui/usque).
- **Firewall rules** (`-rules`): per app block, isolate, bypass or exclude; IP and
  domain rules; the universal rules (block UDP, ICMP, port 80, unknown or new apps,
  DNS bypass, PC locked, lockdown); allowed DNS record types; pause.
- **Anti-censorship** (`-dial-strategy`): split TCP or the TLS ClientHello.
- **Split tunnel** (`-routes`): send chosen apps through their own WireGuard config
  or proxy, the rest through the main VPN.
- **Kill switch** (`-killswitch`): Windows Filtering Platform rules block everything
  outside the tunnel, and keep blocking if the engine crashes.
- **App window** (`ui/`): an Electron app styled after the Android home screen, with
  a tray icon. Download the installer or the portable exe from the
  [latest release](https://github.com/paulvers-ui2/port1897/releases/latest);
  every change merged into `main` is published there as a new version.

Not yet: a background service, IPv6, country and network-provider stats.
See the [roadmap](#roadmap).

## Try it

1. Open the latest successful
   [Windows build](https://github.com/paulvers-ui2/port1897/actions/workflows/windows.yml?query=branch%3Amain+is%3Asuccess)
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
[test report](https://github.com/paulvers-ui2/port1897/issues/new?template=test_report.yml).

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
| `-dnssec` | Block DNS answers that point a public name at a private, loopback or test address (a sign of DNS poisoning); answers with DNSSEC proof are marked in the logs |
| `-dns-cache` | DNS booster: answer repeat lookups from the cache |
| `-dns odoh -odoh URL [-odoh-relay URL]` | Oblivious DoH: a relay hides your IP from the DNS server |
| `-dns proxy -dns-proxy ip:port` | Plain DNS to a server or a local forwarder (like Tor's DNSPort) |
| `-dnscrypt-relays sdns://...` | Anonymized DNSCrypt through relays |
| `-blocklists DIR -blocklist-stamp 1-...` | On-device RethinkDNS blocklists (the app downloads them, ~60 MB) |
| `-masque` | Use free Cloudflare WARP over MASQUE (needs `usque.exe` next to `fswin.exe`) |
| `-chain my.conf` | WARP -> the WireGuard server in `my.conf` -> WARP (needs `usque.exe`) |
| `-killswitch` | Block all traffic outside the tunnel, even if `fswin` crashes |
| `-pcap file.pcap` | Packet capture of the tunnel, for Wireshark |
| `-routes routes.json` | Split tunnel: extra WireGuard configs or SOCKS5/HTTP proxies that chosen apps use instead of the main exit |
| `-rules rules.json` | Firewall rules as the app writes them: a mode per app (block, isolate, bypass, exclude), IP and domain rules, universal rules, allowed DNS record types, pause |
| `-dial-strategy never\|auto\|split-tcp\|split-tls` | Anti-censorship: split the first TCP segment or the TLS ClientHello to get past DPI filters (default `never`, as on Android) |
| `-dial-retry never\|split\|plain` | What to do when a connection fails |
| `-dial-timeout 300` | Close idle TCP and UDP sockets after this many seconds |
| `-tcp-keepalive` | Shorter TCP keep alive |
| `-eim` | Endpoint-independent mapping and filtering for UDP (games, calls) |
| `-cleanup` | Remove a DNS rule or kill switch left behind by a crashed `fswin`, then exit |
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
