# fswin-rs: a Rust engine for AuroraVPN on Windows

Goal: a Rust program that can replace `fswin.exe` (Go, `cmd/fswin` + `win/*`
on top of firestack, gVisor and wireguard-go) **without changing the app**.
The app talks to the engine only through:

1. the command line flags (`cmd/fswin/main_windows.go`; what the app passes is
   `engineArgs()` in `ui/main.js`),
2. the loopback HTTP API on `127.0.0.1:47897` with a bearer token
   (`cmd/fswin/api_windows.go`),
3. AuroraVPN Service's named pipe `\\.\pipe\AuroraVPN`
   (`cmd/fswin/service_windows.go`), which runs **the same executable** with
   `-service run` and starts it again as the engine. So the Rust binary has to
   be the service too before it can ship.

The plan builds on proven Rust crates rather than translating firestack line
by line. Go is memory safe too; what the rewrite buys is no garbage collector,
no Go runtime, a smaller binary and one language with the Tauri app. It does
not remove `unsafe`: the Win32 calls that `golang.org/x/sys/windows` makes for
us today (WFP, tokens, pipes, IP Helper) become our own `unsafe` blocks, kept
in a few small modules.

Effort is in engineer-weeks (ew) for one engineer who knows Rust and Windows
networking. Estimates include tests, not review or release. They are honest
guesses with wide error bars; the userspace TCP/IP stack and the DNS layer
are where they are most likely to slip.

## Crates (checked 2026-10-10; versions at least two weeks old)

| Need | Crate | Version | Licence | Notes |
|---|---|---|---|---|
| Async runtime | tokio | 1.53.1 | MIT | |
| HTTP API server | hyper + hyper-util + http-body-util | 1.11.1 / 0.1.21 / 0.1.x | MIT | HTTP/1.1 only, like Go's server; axum is not needed for 10 routes |
| JSON | serde, serde_json | 1.0.229 / 1.0.151 | MIT/Apache | Go's JSON quirks handled in our code (see below) |
| Constant-time compare | subtle | 2.6.1 | BSD-3 | token check |
| Wintun | wintun-bindings | 0.7.40 (2026-08-17) | MIT | in use (`src/win/wintun.rs`), default features off; brings libloading 0.9.0 (ISC), log 0.4 and thiserror 2 (MIT/Apache). Maintained (tun2proxy org); `wintun` 0.5.1 is stale since 2025-01. `tun-rs` 2.8.11 (Apache-2.0) is the fallback. Its netsh helpers find netsh through PATH: not used |
| Userspace TCP/IP | netstack-smoltcp (on smoltcp 0.14, 0BSD) | 0.2.4 | MIT/Apache | alternatives: ipstack 1.0.1 (Apache-2.0, own TCP, used by tun2proxy), own glue on smoltcp. Behind a trait so it can be swapped |
| Packet parsing | etherparse | 0.21.0 | MIT/Apache | owner lookup, pcap, ICMP |
| WireGuard | boringtun | 0.7.1 | BSD-3 | Cloudflare; sans-IO `Tunn`. gotatun 0.9.2 (Mullvad fork, MPL-2.0) is the alternative. Neither does WARP's reserved header bytes (see gaps) |
| X25519 for WARP registration | x25519-dalek | 3.0.0 | BSD-3 | |
| HTTPS client (DoH, WARP API) | hyper + hyper-rustls / reqwest | 0.27.10 / 0.13.5 | Apache/ISC/MIT | rustls 0.23.45 with ring or aws-lc-rs |
| TLS (DoT) | tokio-rustls | 0.26.5 | MIT/Apache | |
| DNS messages | hickory-proto | 0.26.3 | MIT/Apache | parse/build only; firestack is a forwarding proxy, not a stub resolver, so hickory-resolver is not a fit for the main path |
| DNS stamps (sdns://) | dnsstamps | 0.1.11 | ISC | jedisct1 |
| DNSCrypt | own client on `crypto_box`/`chacha20poly1305` (RustCrypto) | | MIT/Apache | `dnscrypt` 0.3.0 exists but is four months old with 170 downloads: not yet |
| Oblivious DoH | odoh-rs | 1.0.5 | BSD-2 | Cloudflare; protocol only, transport is our DoH client |
| SOCKS5 client | tokio-socks | 0.5.3 | MIT | TCP; UDP ASSOCIATE needs own code (fast-socks5 1.0.0 has some) |
| Win32 | windows-sys | 0.61.2 | MIT/Apache | in use (`src/win/`): registry, processes, WFP, IP Helper; already in the lock file through tokio |
| WFP | wfp (Mullvad) | 0.2.0 | MIT/Apache | evaluate; fallback is a port of `win/wfp` (from wireguard-windows, MIT) on `windows-sys` |
| Windows service | windows-service (Mullvad) | 0.8.1 | MIT/Apache | |
| MASQUE | none mature | | | quinn 0.11.12 + h3 0.0.8 (+ h3-datagram) could carry CONNECT-IP (RFC 9484); keep `usque.exe` as a child process |

## Contract notes the Rust code must keep

- **Flags**: Go's `flag` package syntax, not GNU: `-name value`, `-name=value`,
  `--name` works too, bool flags take no separate value (`-full=false` only),
  parsing stops at the first non-flag or `--`, ints are `strconv.ParseInt(s, 0, 64)`
  (so `0x10`, `010` = 8, `1_000`), bools are `ParseBool` (`1 t T TRUE true True`
  ...). Errors print the message and the usage and exit 2; `-h`/`-help` exit 0.
  The app passes empty values (`-doh-ips ""`). Done in phase 1 (`src/flags.rs`).
- **API**: every request is checked before routing: an `Origin` header or a
  `Host` other than the listen address gives `403 forbidden`; a wrong
  `Authorization: Bearer <token>` gives `401 unauthorized` (constant-time).
  Then Go 1.22 `ServeMux` rules: `GET` routes also answer `HEAD`, a known path
  with the wrong method is `405` with `Allow`, unknown paths `404 page not
  found`. Errors are `text/plain; charset=utf-8` with a trailing newline; JSON
  replies are `application/json`, `Cache-Control: no-store`, with a trailing
  newline (Go's `Encoder`). Lists are `[]`, never `null`. Field order and
  `omitempty` as in the Go structs. Bodies: first JSON value only (Go's
  `Decoder`), size caps 4 KiB (block, close, killswitch) and 8 MiB (rules).
  Endpoints: `GET /api/status`, `GET /api/events?after=&max=`, `GET /api/stats`,
  `POST /api/block`, `POST /api/rules`, `GET /api/conns?app=`,
  `GET /api/proxies`, `POST /api/close`, `POST /api/killswitch`,
  `POST /api/stop`. Done in phase 1 (`src/api.rs`) against an in-memory engine.
- **JSON input quirks of Go** kept on purpose: keys match struct fields
  case-insensitively, `null` leaves a field at its zero value, duplicate keys:
  the last wins, invalid UTF-8 becomes U+FFFD. Error *wording* differs from
  Go's (the app only shows it).
- **Pipe**: one JSON request per connection `{"cmd": "ping"|"start"|"stop"|
  "cleanup", "args": [...]}`, reply `{"ok", "error", "pid", "version"}` plus a
  newline; client must be the installed `AuroraVPN.exe`; flags `-service -app
  -stop-handle -user-token -usque` refused; at most 256 args of 8 KiB.
- **IDs and labels** the app shows or matches: exit names ("WireGuard",
  "Cloudflare WARP", "proxy", "Cloudflare WARP (MASQUE)", "WARP chain",
  "direct", "blocked"; the app's `runsExit` compares `status.exit`), DNS
  transport ids in event `via` ("Preferred", "CachePreferred", "System",
  "BlockAll"), rule reasons ("universal: outgoing allowed" is matched by the
  app), proxy states ("connected", "up", "idle", "not responding", "failing",
  "paused", "stopped", "missing", "unknown").
- **Fixed addresses**: adapter 10.111.222.1/24, DNS 10.111.222.3:53; only that
  exact ip:port is answered locally (marked Base), :853 there is refused.
- **Fixed keys** so a crashed run is cleaned up by the next: NRPT rule key
  `{4A0F3C2E-8B71-4D5A-9E26-AF1D7C3B5E90}` (comment/display "AuroraVPN", and
  the old "port1897"), WFP provider/sublayer/filter GUIDs `6b1c2a47-5f2e-...`
  (`win/wfp/killswitch_windows.go`). The Rust engine must use the same ones so
  either engine cleans up after the other.

## Feature map

Legend: **P1..P4** = phase. Effort is for the Rust side only.

### Process, flags, service

| Go | What it does | Rust approach | Phase | Effort |
|---|---|---|---|---|
| `main_windows.go` flags | 56 flags | own Go-compatible parser (`flags.rs`) | P1 | done |
| `-version`, `-cleanup` | print build; remove NRPT + WFP | trivial over the NRPT and WFP modules | P1 | 0.2 ew |
| `run()` order of start | API preflight, exit prep, MTU plan, adapter, NRPT before DNS, IP config, kill switch before own sockets, DNS, routes, usque after routes, API last | port the order exactly; it encodes several fixed bugs (PRs #26, #28, Proton case) | P1 | 1 ew |
| `-logfile`, `-log` | output to a file opened as the user | own small logger (or `tracing` with a writer); `SetStdHandle` | P1 | 0.5 ew |
| `-stop-handle` | inherited event from the service | `WaitForSingleObject` on a blocking thread → shutdown channel | P1 | 0.2 ew |
| Ctrl+C | stop | `tokio::signal::ctrl_c` | P1 | - |
| `service_windows.go` | SCM install/uninstall/run, locked-down folder ACL, pipe with SDDL, client check (path of the pipe client process), impersonation to get the user token, `CreateProcess` with handle list | `windows-service` for SCM; tokio `NamedPipeServer` (`reject_remote_clients`, `first_pipe_instance`, raw security attributes); `windows` crate for `ImpersonateNamedPipeClient`, `DuplicateTokenEx`, `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, `SetNamedSecurityInfo` | P1 | 1.5 ew |
| `asuser_windows.go` | restricted user token (Administrators deny-only, no privileges, medium integrity, default DACL), file I/O impersonated on a locked thread, usque started with it | `windows` crate: `CreateRestrictedToken`, `SetTokenInformation`, `SetThreadToken` on a dedicated OS thread (not a tokio worker), `CreateProcessAsUserW` + `CreateEnvironmentBlock` | P1 | 1.5 ew; security-sensitive, needs review |
| `mtu_windows.go` | MTU plan from link + exit, re-checked every 15 s | pure logic ported in P1 (`mtu.rs`); the watcher needs the stack's MTU setter | P1 | logic done; watcher 0.1 ew |

### Tunnel, stack, routing

| Go | Rust approach | Phase | Effort |
|---|---|---|---|
| Wintun adapter (`tun.CreateTUN`, tunnel type "AuroraVPN", LUID) | `wintun-bindings`: load `wintun.dll` by full path next to the exe, `Adapter::create`, ring session, LUID | P1 | 0.5 ew |
| gVisor netstack via firestack (`intra.Connect`): TCP/UDP/ICMP forwarders, fake DNS trap, `CloseConns`, `Stat`, link MTU change | netstack-smoltcp (smoltcp underneath) behind a `Netstack` trait: accept TCP and UDP "sockets" per flow, ask the engine (`Engine::flow`, done in P1) for a verdict, then splice to a dialer (direct, WireGuard, SOCKS, HTTP). ICMP echo forwarding is own code (raw `IcmpSendEcho2` or answer locally) | P1 | 4 to 6 ew; the biggest risk |
| `win/ipconf` (address, DNS server, metric, two /1 routes, netsh fallback) | `windows` IP Helper: `CreateUnicastIpAddressEntry`, `SetInterfaceDnsSettings`, `SetIpInterfaceEntry`, `CreateIpForwardEntry2`; keep netsh fallback | P1 | 0.5 ew |
| `win/ifbind` (IP_UNICAST_IF on the engine's own sockets, default interface, on-link prefixes, DNS servers of the physical adapter, VPN-adapter heuristics, link MTU) | `windows-sys` `setsockopt(IP_UNICAST_IF / IPV6_UNICAST_IF)` via `socket2` raw socket before connect; `GetIpForwardTable2`, `GetAdaptersAddresses` | P1 | 1 ew |
| `win/owner` (owner pid of a flow, exe path, snapshot cache) | `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)`, `GetExtendedUdpTable(UDP_TABLE_OWNER_PID)`, `QueryFullProcessImageNameW`; port the snapshot/refresh logic and its tests | P1 | 0.5 ew |
| `-pcap` | own pcap writer (24-byte header + records), file opened as the user | P2 | 0.3 ew |
| `-dial-strategy`, `-dial-retry`, `-dial-timeout`, `-tcp-keepalive` (split first TCP segment, fragment TLS ClientHello into records, retry) | own dialer code; `socket2` for keepalive; validation done in P1 | P4 | 1.5 ew |
| `-eim` (endpoint-independent mapping/filtering for UDP) | one bound UDP socket per local endpoint in the UDP forwarder | P4 | 0.5 ew |

### DNS

| Go | Rust approach | Phase | Effort |
|---|---|---|---|
| fake DNS at 10.111.222.3:53 (UDP + TCP), per-query callbacks `OnQuery`/`OnUpstreamAnswer`/`OnResponse`, BlockAll (REFUSED-style answer: 0.0.0.0 / :: for A/AAAA, HINFO otherwise, rcode 0) | own forwarder on hickory-proto messages; the decision code is the P1 port of the bridge (`Engine::on_query`, `on_upstream_answer`, `on_response`) | P1 | 1.5 ew |
| `-dns doh` + `-doh-ips` bootstrap, `-fallback-doh/-ips` default transport, `-dns-fallback` | own DoH client on hyper + hyper-rustls with fixed IPs (no DNS for the DoH host), HTTP/2 reuse, padding (RFC 8467), POST `application/dns-message` | P1 | 1.5 ew |
| `-dns-cache` ("CT" cache transport) | own TTL cache keyed by (qname, qtype, class) | P2 | 0.5 ew |
| `-dnssec` (bogon answers blocked) | pure logic ported in P1 (`dnssec.rs`) | P1 | done |
| `-dns-direct` | pid choice in `on_query`, done in P1 | P1 | done |
| `-dns system`, `-undelegated` (System transport = physical adapter's DNS servers, undelegated TLDs) | DNS53 transport (UDP, TCP on truncation) bound off-tunnel | P2 | 1 ew |
| `-dns dot` | tokio-rustls, length-prefixed, connection reuse, `tls://` normalisation (ported) | P4 | 0.5 ew |
| `-dns proxy` (plain DNS to ip:port) | the DNS53 transport | P2 | 0.2 ew |
| `-dns dnscrypt`, `-dnscrypt-relays` (anonymized DNSCrypt) | own client: `dnsstamps` + certificate fetch/verify (Ed25519) + X25519-XSalsa20Poly1305 / XChaCha20Poly1305 boxes + relay header | P4 | 2 ew |
| `-dns odoh`, `-odoh-relay`, `-odoh-ips` | `odoh-rs` + DoH client (`/.well-known/odohconfigs`, targethost/targetpath) | P4 | 1 ew |
| `-blocklists`, `-blocklist-stamp`, `-filetag` (RethinkDNS on-device trie td.txt/rd.txt, stamps; remote filetag names) | **no Rust equivalent**: port firestack's `dnsx/rethinkdns.go` and the succinct trie reader. The app no longer offers on-device lists but still passes `-filetag` | P4 | 2 to 3 ew |
| NRPT (`win/dnspolicy`): fixed key, `.` rule to 10.111.222.3, written before the adapter gets its DNS server, `ipconfig /registerdns` nudge (async on add, ≤5 s on remove), `DnsFlushResolverCache`, `Others()` conflict detection incl. group policy key | `windows-registry` (or `windows-sys` Reg*) behind a `Registry` trait; `CreateProcessW` with the full System32 path; `GetProcAddress` for the flush | P1 | 0.7 ew (logic + fake-registry tests started in P1) |

### Exits and routes

| Go | Rust approach | Phase | Effort |
|---|---|---|---|
| "direct" exit (Base): sockets bound to the physical interface | dialer with IP_UNICAST_IF | P1 | in the stack estimate |
| `-wg` wg-quick file → config | parser ported in P1 (`exit.rs`, same validation and output keys); boringtun `Tunn` + own UDP loop + a second smoltcp/netstack instance (or IP-packet relay) for the inner side | P2 | 3 ew |
| `-warp` (register at api.cloudflareclient.com, save account JSON as the user, WireGuard with client id in reserved bytes h1..h4, MTU 1280) | reqwest/hyper + x25519-dalek for registration; boringtun **patched** for the header bytes (see gaps) | P2 | 1.5 ew + the patch |
| `-proxy socks5://` / `http://` | tokio-socks (TCP); UDP ASSOCIATE own; HTTP CONNECT own (~100 lines); UDP over an HTTP proxy is impossible (Go behaviour to be checked and copied) | P2 | 1 ew |
| `-routes` per-app WireGuard/proxy routes (ids `wgapp*`, `pxsocks`, `pxhttp`), `/api/proxies` stats | route table in the engine (P1 has the decision side and the stats shape); one exit instance per route | P2 | 1 ew |
| `-masque` (usque socks child), `-chain` (usque chain: WARP2 → wg0 → WARP1), `-usque`, `-usque-dir`, `-usque-flags` | keep **usque.exe as a child**: random port/user/pass, job object kill-on-close, started as the user after the routes, output piped to the log, bypass of its own flows, supervisor (restart backoff 1 s → 60 s, SOCKS probe to 1.1.1.1:80 every 15 s, 30 s start grace, network-change check, "Tunnel connection lost" log trigger). Flag checks and defaults ported in P1 (`usque.rs`) | P3 | 2 ew |
| native MASQUE (WARP over CONNECT-IP, HTTP/3 with HTTP/2 fallback, Cloudflare enrolment + client cert) | quinn + h3 + h3-datagram + own CONNECT-IP capsules; HTTP/2 extended CONNECT via h2 | later | 6 to 10 ew; not planned before parity |

### Firewall, kill switch, API, journal

| Go | Rust approach | Phase | Effort |
|---|---|---|---|
| `rules_windows.go` (modes, IP/domain rules per app and global, universal rules, outgoing only, pause, screen locked, DNS query types, known apps) | faithful port with its tests (`rules.rs`) | P1 | done |
| `bridge_windows.go` decisions (Flow, Inflow, OnSocketClosed, OnQuery, OnUpstreamAnswer, OnResponse, enforce on rule change, close by app/ids, app uid table) | engine core in `engine.rs`, independent of the stack; the netstack glue calls it. Not ported: Bind4/Bind6/Protect (they belong to the dialer, `win/ifbind`) | P1 | done (logic) |
| `events_windows.go` journal (2000-event ring, counters, top apps/domains) | `events.rs` | P1 | done |
| `conns_windows.go` (open connection table, why-cache for blocked DNS) | `conns.rs` | P1 | done |
| `geoip` (embedded db-ip tables) | `include_bytes!` of the same files, same binary search (`geoip.rs`) | P1 | done |
| `api_windows.go` | hyper server (`api.rs`) over the engine; same guard, routes, shapes | P1 | done (in-memory engine) |
| `killswitch_windows.go` + `win/wfp` (persistent provider/sublayer/filters with fixed GUIDs, permit self + usque + loopback + LAN option + tunnel LUID + DHCP + NDP, block all; `Disable` removes leftovers; `-allow-lan`) | state machine ported in P1 behind a `Firewall` trait; WFP backend: evaluate Mullvad's `wfp` crate, else port `rules.go` (1,229 lines of wireguard-windows code) to `windows-sys` | P1 | 2 ew for the WFP backend |
| conflict detection (other catch-all NRPT rules, traffic leaving via another VPN's adapter) | NRPT module + ifbind `Describe` | P1 | 0.3 ew |

## Gaps (no mature Rust equivalent yet)

1. **WARP's reserved header bytes.** firestack's wireguard-go fork takes
   AmneziaWG-style `h1..h4` header words; boringtun and gotatun have no such
   option. The handshake MACs cover the header, so a socket shim that rewrites
   bytes after the fact breaks `mac1` (it could be recomputed with the peer key,
   but `mac2` under a cookie cannot). Plan: a small patch to boringtun (or
   gotatun) making the 4-byte message header configurable, kept as a fork until
   upstream takes it. Without it, `-warp` works only where Cloudflare does not
   insist on the client id.
2. **MASQUE.** No mature Rust CONNECT-IP client exists (`h3-masque` is
   CONNECT-UDP on MsQuic with 110 downloads; `hopf-masque` is LGPL and weeks
   old). `usque.exe` stays a Go child process; the engine is then Rust, the
   WARP-over-MASQUE path is not.
3. **RethinkDNS on-device blocklists** (succinct trie, stamps, filetags): own
   port needed.
4. **DNSCrypt client**: own implementation on audited primitives.
5. **gVisor-grade TCP.** smoltcp/ipstack lack some of gVisor's TCP (SACK
   recovery, RACK, mature congestion control, large receive windows tuned for
   gigabit). Throughput and loss behaviour must be measured early (phase 1
   exit criterion), not assumed.
6. **Anti-censorship dialers** (split TCP / TLS record fragmentation): own code.

## Phases

Each phase ships behind the same CLI and API. Until a phase reaches parity for
a flag, `fswin-rs` refuses that flag with a clear error at start (before it
touches the system) so the app shows the reason, and the Go engine stays the
shipping engine. Rollout: the installer carries `fswin-rs.exe` renamed to
`fswin.exe` on a beta channel only after the phase's simulations pass.

### Phase 1: the most-used path (≈ 14 to 20 ew)

Wintun adapter + userspace stack + DoH DNS (fake DNS trap, BlockAll, fallback
transport) + firewall rules + "direct" exit + owner lookup + interface
binding + IP configuration and the two /1 routes + the API + kill switch +
NRPT + conflict warnings + MTU plan + AuroraVPN Service + user-token file
access + `-cleanup`, `-logfile`, `-stop-handle`.

Started in this branch (no admin needed, all unit-tested):

- done: `flags.rs` Go-compatible flag parsing for all 56 flags
- done: `rules.rs` the firewall rules, with `rules_windows_test.go` ported
- done: `events.rs`, `conns.rs` the journal, connection table, why-cache
- done: `geoip.rs`, `dnssec.rs`
- done: `mtu.rs` the MTU plan, with `mtu_windows_test.go` ported; `exit.rs`
  (wg-quick to the exit's config, WARP account config, exit names; Go's
  base64 decoder and 64 KiB line limit copied so errors match)
- done: `engine.rs` the bridge's decisions and counters (flow, inflow, socket
  closed, DNS query/upstream answer/response, rule updates that close
  connections, close by app or id, owner lookup and proxy stats behind
  `Owners` / `Proxies` traits), with `bridge_windows_test.go` ported
- done: `killswitch.rs` the kill switch state machine (killswitch_windows.go)
  behind a `Firewall` trait with a fake; win/wfp's filter plan as data
  (the 27 + 4 per allowed program (+4 LAN) filters in Go's order, names,
  layers, weights, conditions, the 160-key limit with Go's error wording),
  the fixed provider/sublayer/filter GUIDs shared with the Go engine, and
  the leftover removal. The `windows-sys` backend that executes the plan
  (FwpmEngineOpen0, transactions, app ids) is still to write
- done: `api.rs` the control API over the engine on hyper: the guard
  (Origin, Host incl. absolute-form, constant-time bearer), Go 1.22 ServeMux
  behaviour (HEAD on GET routes, 405 with Allow, 404, 301 to the clean path,
  `OPTIONS *`), http.Error and json.Encoder output (HTML escaping, trailing
  newline, field order, `[]`), body caps with Go's first-value decoding,
  `status_of`, `check_addr`, `token_from`. Tests listen on 127.0.0.1:0.
  Not yet like Go: the idle (60 s) and write (30 s) timeouts; the header
  (5 s) and body (15 s) read timeouts are in. Several servers on several
  tokio runtimes in one test process stalled for 10 s now and then on this
  PC, so the API tests run one server at a time; one server with 64
  parallel clients does not stall. The stall did not come back after a
  clean build (that build had corrupt rlibs); the lock stays as cheap
  insurance
- done: `usque.rs` the `-usque-flags` checks (core flags, pflag shorthand
  bundles, subcommands), `usqueDefaults`, the start and register argument
  lists, the SOCKS URL, exit-code wording, the "tunnel lost" log trigger and
  the supervisor's timings and backoff. The process, job object and
  supervisor loop are phase 3
- done: `service.rs` the pipe protocol (request decoding as Go's Decoder,
  reply encoding), the request dispatch behind an `EngineControl` trait,
  `checkEngineArgs`, `samePath`, `installRoot`, `validAdapterName`, and
  x/sys `ComposeCommandLine` / `EscapeArg` (compared with Go's output). The
  SCM, pipe ACL, impersonation and `CreateProcess` are still to write
- done: `nrpt.rs` win/dnspolicy behind a `Registry` trait with a fake
  registry and a nudge function: add (replace ours, the seven values,
  not-applied vs failed), remove, `Others()` over local and group-policy
  rules, our-rule detection (fixed key in any case, "AuroraVPN" and
  "port1897" tags), with `nrpt_windows_test.go` ported. The HKLM backend,
  ipconfig /registerdns and DnsFlushResolverCache are still to write
- done: the Win32 backends in `src/win/` (Windows only; tests that change
  the system are `#[ignore]`d with the reason, for the admin CI runner):
  - `registry.rs` the `Registry` trait over the real registry (values as
    x/sys/windows/registry reads them), the nudge (ipconfig /registerdns
    from System32, no shell; DnsFlushResolverCache looked up in
    dnsapi.dll); tested under HKCU as the Go tests are
  - `proc.rs` hidden child processes by full path
  - `owner.rs` win/owner over GetExtendedTcpTable/UdpTable, with its tests
    (read only, no admin)
  - `wfp.rs` executes the kill switch plan (dynamic session unless
    persistent, one transaction, service SID matched as in Go); the whole
    plan is installed in an aborted transaction on the CI runner
  - `ipconf.rs` address, DNS (SetInterfaceDnsSettings looked up at run
    time), metric, on-link routes, and the netsh fallback's commands
  - `wintun.rs` adapter create/close over wintun-bindings, wintun.dll by
    full path, tunnel type "AuroraVPN", 8 MiB ring; like wireguard-go it
    does not set the interface MTU (the stack uses the planned one)
- done: `dns/` the DNS layer, all unit-tested and without a tunnel:
  - `msg.rs` the message helpers on hickory-proto after firestack's
    xdns (query name and type, RFC 7830 padding, the BlockAll answer,
    SERVFAIL, the summary's answer data)
  - `doh.rs` the DoH client (bootstrap IPs with no name lookup, HTTP/2
    with an HTTP/1.1 fallback, POST falling back to GET on 405, one
    connection per exit, Go's timeouts), `dot.rs` DoT with its
    connection pool, `tls.rs` rustls on ring with the system's roots
  - `cache.rs` the cached transport behind `-dns-cache` (the `Cache`
    id prefix): the answer kept while its TTL lasts, counted down, the
    key case-insensitive, SERVFAIL and transport failures not kept
  - `fake.rs` the resolver the netstack's DNS trap hands queries to:
    `on_query` for the verdict, `BlockAll` answered here, the cached
    wrapper made on demand, `-dns-fallback` to `Default`, the DNSSEC
    switch's second verdict on the answer, and `on_response` either
    way. SERVFAIL goes back to the asker as firestack does
  - the DNS53/System transport, the undelegated domains and the
    blocklists are phases 2 and 4, as below

Exit criteria: `tools/sim/e2e-windows.ps1` and `tools/sim/service-windows.ps1`
pass with `fswin-rs.exe` copied in as `dist/fswin.exe`; iperf-style throughput
through the direct exit within 20 % of the Go engine on the runner; no leak
with the kill switch on (WFP state equal to the Go engine's, compared with
`netsh wfp show filters`).

### Phase 2: WireGuard, WARP, proxies, per-app routes (≈ 7 to 9 ew)

`-wg`, `-warp` (registration + patched boringtun), `-proxy`, `-routes`,
`/api/proxies` live stats, DNS cache, System DNS / `-undelegated`,
`-dns proxy`, `-pcap`.

### Phase 3: MASQUE and the chain through usque (≈ 2 to 3 ew)

`-masque`, `-chain`, `-usque*`, the supervisor, usque started as the user,
`exitRestarts`/`exitIssue` in the status.

### Phase 4: the rest of DNS and the dialers (≈ 8 to 11 ew)

DoT, DNSCrypt (+ relays), ODoH, blocklists/filetag, dial strategies and retry,
EIM, keep-alive.

### Later

Native MASQUE in Rust (6 to 10 ew) once quinn/h3 CONNECT-IP support matures;
then usque.exe can go.

Total to parity: roughly 31 to 43 engineer-weeks, i.e. 7 to 10 months for one
person. Agent help speeds up the porting; the admin-only integration work on
real networks does not shrink as much.

## Testing

- **Unit tests, no admin** (`cargo test`, any OS for the pure modules; Windows
  for the rest): every Go test that does not need firestack or admin is ported
  with the same cases (rules, bridge decisions, journal, API guard and shapes,
  country lookup, MTU plan, wg-quick, usque flags, service argument checks).
  The API tests listen on `127.0.0.1:0`, never on 47897.
- **Fakes** for system state: `Firewall` (WFP), `Registry` (NRPT), later
  `Netstack` and `Dialer`, so the start/stop order and failure handling are
  tested without admin.
- **Property tests / fuzzing**: the Go fuzz targets (`FuzzRules`,
  `FuzzCountry`) become `cargo fuzz` targets (nightly, CI only) and
  stable-toolchain property tests on random inputs.
- **No real TLS in the tests.** The DoH and DoT tests dial a
  `tokio::io::duplex` pipe through the transports' own `Dialer`
  (`dns/pipe.rs`), never a socket, not even to 127.0.0.1. An antivirus
  that inspects TLS re-signs the server's certificate with a root of its
  own, and every handshake then fails with `UnknownIssuer` however
  correct the test CA is: on a developer machine here Avast's Web/Mail
  Shield did that to a loopback connection, handing the client a
  certificate with our subject and our SANs but issued by "Avast
  Web/Mail Shield Untrusted Root". It cost hours to find, because the
  fixtures and the rustls setup were both right. Pipes also make the
  tests faster and keep them off the firewall's radar.
- **CI now**: `.github/workflows/engine-rs.yml` (windows-latest, Rust
  1.99.0): build, clippy `-D warnings`, unit tests, then the `#[ignore]`d
  system tests one at a time with the pinned Wintun 0.14.1. Not yet: a
  `cargo fmt --check` (the code is not rustfmt-formatted), the e2e scripts
  below (no engine binary yet), `cargo deny`.
- **Integration on GitHub's Windows runners** (admin, like
  `.github/workflows/sim.yml`): a new job builds `fswin-rs.exe`, downloads
  Wintun 0.14.1 with the pinned SHA-256, copies the binary in as
  `dist/fswin.exe`, and runs the existing `tools/sim/e2e-windows.ps1` and
  `tools/sim/service-windows.ps1` unchanged: the same scripts passing against
  both engines is the parity test. Extra Rust-only checks: Wintun adapter
  create/close, WFP enable/disable/leftover cleanup with the fixed GUIDs, NRPT
  add/remove under HKLM, crash-then-cleanup (kill the engine, run `-cleanup`).
- **Cross-engine leftovers**: start Go, kill it, start Rust (and the reverse)
  and check each cleans up the other's NRPT rule and WFP filters.
- **Supply chain**: `cargo deny` (licences, advisories, duplicates), the
  existing osv-scanner job extended to `engine-rs/Cargo.lock`, pinned
  versions in `Cargo.lock`.

## Biggest risks

1. Userspace TCP/IP stack quality and throughput versus gVisor (gap 5).
2. Hidden firestack behaviour the app relies on without saying so (the 3 s
   hold for a new flow until the exit exists, BlockAll answers, CT cache ids,
   DNS summary fields). Mitigation: run the same simulation scripts against
   both engines; read firestack where a behaviour is unclear.
3. Security-sensitive Win32 code (tokens, pipe ACLs, WFP) moving from Go's
   x/sys wrappers to our own `unsafe`: keep it small, reviewed, and tested on
   the runners.
4. WARP header patch maintenance (gap 1) and usque staying in Go (gap 2).
5. Schedule: 7 to 10 months of work to reach full parity.
