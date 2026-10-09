# Contributing

Thanks for helping bring firestack to Windows. Every kind of help counts.

## Test it

The most useful thing right now. Follow [Try it](README.md#try-it), then open a
[test report](https://github.com/paulvers-ui2/port1897/issues/new?template=test_report.yml),
whether it worked or not. Reports from different setups matter most: Windows 10 and
11, x64 and ARM, Wi-Fi and Ethernet, other VPNs or antivirus installed.

Found something broken? Open a
[bug report](https://github.com/paulvers-ui2/port1897/issues/new?template=bug_report.yml)
with the `fswin -version` output and the log.

## Write code

### Build

You need [Go](https://go.dev/dl/) (the version in `go.mod`). From the repository
root:

```powershell
$env:GOOS = "windows"
go build -ldflags=-checklinkname=0 -o fswin.exe ./cmd/fswin
go vet ./intra/... ./tunnel/... ./cmd/... ./win/...
```

`-checklinkname=0` is required: `intra/core/overreach.go` links to Go runtime
internals, as the upstream Makefile does. Put `wintun.dll` (from
[wintun.net](https://www.wintun.net), `bin/amd64` or `bin/arm64`) next to
`fswin.exe` and run it from an admin terminal.

No Go installed? Push to a branch of your fork: the
[Windows build](.github/workflows/windows.yml) workflow builds and vets everything
and uploads `fswin` as an artifact.

### Ground rules

- **Keep Android building.** This is still firestack. Put Windows-only code in
  `_windows.go` files (or under `win/`) and move Linux-only code to `_linux.go`
  files, rather than editing shared code. CI checks the Linux and Android builds on
  every push. Small, tagged changes can also be offered back to
  [paulvers-ui/firestack](https://github.com/paulvers-ui/firestack) and
  [celzero/firestack](https://github.com/celzero/firestack).
- **Match the code around you**: naming, comment style, log format.
- **New files** start with the MPL-2.0 header used in the rest of the repository.
- **Changing dependencies:** run the manual
  [Update deps](.github/workflows/deps.yml) workflow (or `go get` + `go mod tidy`
  locally) and commit the resulting `go.mod` and `go.sum`.
- One topic per pull request, with a short description of what you tested.

### Licenses of code you bring in

The project is MPL-2.0. You may copy code under MIT, BSD or Apache-2.0 (for
example [wireguard-windows](https://git.zx2c4.com/wireguard-windows) or
[tailscale](https://github.com/tailscale/tailscale)); keep its copyright notice at
the top of the file. **Do not copy GPL code** (sing-tun, Portmaster, simplewall,
...): reading it for ideas is fine, copying it would force the whole project
under the GPL.

### What to work on

See the roadmap in [README.md](README.md#roadmap) and the Phase 2 table in
[PORT.md](PORT.md). Open an issue before starting something large so work is not
duplicated.

### Releases

Every pull request merged into `main` publishes the next patch version (v0.2.1,
v0.2.2, ...) as the latest GitHub release: the installer, the portable exe and
SHA256SUMS.txt, with notes listing the merged pull requests, and a few minutes
later firestack's Android library (AAR) with its own checksums. Put
`[skip release]` in the merge commit message to merge without one. For a minor
or major version, push a tag such as `v0.3.0`; later merges continue from it.
Releases are published here only: nothing is pushed to other repositories or
to Maven. The workflows are `.github/workflows/app.yml` and
`.github/workflows/release-aar.yml`.

## Security issues

Do not open a public issue. Use GitHub's private
[security advisory](https://github.com/paulvers-ui2/port1897/security/advisories/new)
form for problems in this repository. Problems in firestack itself that also affect
the Android app belong with [celzero/firestack](https://github.com/celzero/firestack/security).

## Not this project

Issues with the Android app go to
[celzero/rethink-app](https://github.com/celzero/rethink-app/issues).
