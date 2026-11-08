# dnssecv — local validating DNSSEC resolver

Resolves iteratively from the root servers and validates each answer up to the
embedded IANA root trust anchors, including NSEC/NSEC3 authenticated denial of
existence. It never trusts an upstream AD bit.

Kotlin entry point (bound through package `intra`, so no second Go runtime):

```kotlin
val v = Intra.newDNSSECValidator(ProbeController(-1L, null)) // protects sockets
val r = v.validate("example.com", 1 /* A */, 6000)          // r.status, r.rcode, r.answers
val rep = v.selfTest(15000)                                   // rep.health, rep.summary
```

Verdicts: `Secure`, `Insecure` (provably unsigned), `Bogus` (forged/broken,
answers withheld), `Unknown` (no verdict; treat as not validated).

Self-test health is `Validating` only when a signed zone validates **and**
`dnssec-failed.org` is rejected. If the broken zone is ever accepted the health
is `Broken`, which the UI must never show as green.

Safety properties: input names/types are allowlisted; at most 8 concurrent
lookups; a 6 s budget per lookup and 100 upstream queries max; cache capped at
10 000 entries and 1 h TTL; panics are recovered and reported as `Unknown`.

Privacy: queries leave the device in plaintext on port 53 from the real IP,
outside DoH/WARP. The app currently only sends the fixed self-test probes.
Read `docs/security/THREAT_MODEL.md` in the app repo before routing user
lookups through this path.

Tests: `go test -race ./intra/dnssecv/...` (offline);
`DNSSECV_LIVE=1 go test -run Live ./intra/dnssecv/` (needs port 53).
