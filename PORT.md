# port1897: firestack for Windows

This repository is a fork of [paulvers-ui/firestack](https://github.com/paulvers-ui/firestack)
(itself a fork of [celzero/firestack](https://github.com/celzero/firestack)), branched at
commit `05a6645`. The goal is a Windows build of the networking engine behind the
Rethink DNS + Firewall / AuroraVPN Android apps.

## Phase 1 (in progress)

- Move Linux/Android-only code (`x/sys/unix`, gVisor `rawfile`/`fdbased`, `SO_MARK`,
  UDP GSO/GRO, `TCP_USER_TIMEOUT`, the split-and-desync dialer) into `_linux.go` /
  `_unix.go` files, with `_windows.go` counterparts, so `GOOS=windows go build` works.
- Add a Wintun-backed `SeamlessEndpoint`.
- Add a small command-line tool that runs DNS-only mode and logs every connection.

The Android build is meant to keep working; changes use build tags rather than edits
to shared code, so they can be offered back upstream.

## Licenses

- firestack is MPL-2.0 (see `LICENSE`). Modified files stay MPL-2.0.
- Wintun (`wintun.dll`) is distributed under its own prebuilt-binaries license from
  <https://www.wintun.net>; it is not committed to this repository.

## Disclaimer

This is an unofficial, community project. It is not affiliated with or endorsed by
Celzero (Rethink), Cloudflare, or Microsoft. "WARP" and "Cloudflare" are trademarks
of Cloudflare, Inc. Use at your own risk.
