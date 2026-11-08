# Vendored code in `intra/dnssecv`

| Path | Upstream | Licence | Pinned at |
|---|---|---|---|
| `resolver/` | github.com/nsmithuk/resolver | MIT (`resolver/LICENSE`) | default branch, cloned 2026-11-07 |
| `anchors/` | github.com/nsmithuk/dnssec-root-anchors-go | MIT (`anchors/LICENSE`) | default branch, cloned 2026-11-07 |

Record the exact upstream commit SHAs here when you merge
(`git ls-remote https://github.com/nsmithuk/resolver HEAD`).

Upstream marks the resolver **alpha**. The wrapper (`validator.go`) therefore
fails closed: any error, timeout or recovered panic is reported as `Unknown`,
never `Secure`.

Mechanical changes: import paths rewritten to
`github.com/celzero/firestack/intra/dnssecv/...`; upstream `_test.go` files
dropped (they need `testify`; run them upstream before each re-vendor).

## Functional patches (grep for `FIRESTACK PATCH`)

- **P1 — injectable dialer** (`config.go`, `nameserver.go`, `ipv6.go`).
  `DialerFactory` supplies the `net.Dialer` for every query. On Android it
  must protect sockets via `VpnService.protect()`, or queries loop back into
  the TUN and firestack's DNS trap answers them from the DoH upstream.
- **P2 — configurable timeouts** (`config.go`, `nameserver.go`). Upstream's
  150 ms UDP / 600 ms TCP constants are tuned for servers; mobile links need
  more. `TimeoutUDP` / `TimeoutTCP` vars (wrapper sets 900 ms / 2 s).
- **P3 — no network I/O at package init** (`config.go`). Upstream started an
  IPv6 probe in `init()`, i.e. at app start, before any dialer was installed,
  sending unprotected packets into the tunnel. Now lazy.
- **P4 — refreshable IPv6 probe** (`ipv6.go`). Upstream's package-level
  `sync.Once` could never re-probe after Wi-Fi ⇄ mobile.
  `ResetIPv6Availability()` added.
- **P5 — dropped `github.com/google/uuid`** (`trace.go`). Only used for log
  trace labels; replaced with 16 bytes from `crypto/rand`. One fewer
  dependency (NIST SSDF PW.4).

- **P6 — canonical name ordering fix** (`dnssec/doe/functions.go`, found
  by CodeQL). Upstream decoded `\DDD` escapes with `string(rune(n))`, which
  emits UTF-8 (`\200` → bytes `C3 88`, not `0xC8`) and accepted values above
  255. It also left `\X` escapes undecoded and didn't lowercase escaped
  letters. Any of these can mis-order NSEC owner names (RFC 4034 §6.1) and so
  break denial-of-existence proofs for names containing escaped octets.
  Covered by `functions_firestack_test.go`. **Worth reporting upstream.**
- **P7 — RRSIG validity clamp** (`dnssec/authenticate_rrset.go`, gosec
  G115). An expired signature made the remaining-validity delta negative,
  which wrapped to a huge `uint32`. Now clamped to `[0, MaxUint32]`.
- **P8 — errors no longer dropped** (`resolver_exchange.go`,
  `zone_factory.go`, gosec G104). Logged via the resolver's Warn/Debug hooks.

- **P9 — nil safety** (`cname.go`, `nameserver.go`, `dnssec/doe/functions.go`,
  `dnssec/authenticate_rrset.go`, `dnssec/verify_dnskey.go`; found by
  nilaway in CI). The important one: `verify_dnskey.go` called
  `k.ToDS(d.DigestType).Digest` with the digest type taken from the parent's
  DS record on the network. `ToDS` returns nil for types miekg/dns doesn't
  implement (e.g. GOST, 3), so **a zone publishing such a DS crashed the
  lookup**. An undigestable DS now just doesn't match (RFC 4035 §5.2).
  Covered by `verify_dnskey_firestack_test.go`. **Worth reporting upstream.**

- **P10 — more nil safety** (nilaway, second pass). Real crash paths fixed:
  `pool_exchange.go` dereferenced a nil response when no nameserver of either
  address family was available; `resolver_exchange.go` indexed
  `knownZones[0]` on an empty zone list; `Exchange`, `nameserver.exchange`
  and `Authenticator.AddResponse` indexed `Question[0]` on question-less
  messages (the last one on responses straight from the network). Plus
  explicit guards in `zones.add`, root-hint parsing, pool building and
  `Response.truncated`.

  Remaining nilaway reports in `resolver/` are reviewed false positives:
  `net.IP(nil).String()` is safe in Go, and `Question` flows through
  `msg.Copy()` are rejected at the new entry guards. CI therefore runs
  nilaway **strict on all firestack code except `resolver/`**, and
  **report-only on `resolver/`** (`.github/workflows/go.yml`, 🔮 Vet).

- **P11 — dead comparison** (`dnssec/doe/doe.go`, staticcheck SA4003 in
  port1897's security lint). `r.Flags < 0` on a `uint8` is always false;
  removed. Behaviour unchanged: NSEC3 records with flags other than 0 or 1
  are still ignored (RFC 5155 §8.2).

## Re-vendoring checklist

1. Diff upstream against the pinned SHA; read every change in `dnssec/`.
2. Re-apply P1–P11; `grep -rn "FIRESTACK PATCH"` must list them all.
3. Run upstream's own tests in a scratch checkout.
4. `go test -race ./intra/dnssecv/...` here, then `DNSSECV_LIVE=1` on a
   network that allows UDP/TCP 53.
5. Check `anchors/embedded.go` still lists the current IANA root KSKs
   (20326 = KSK-2017, 38696 = KSK-2024) against
   https://data.iana.org/root-anchors/root-anchors.xml.
