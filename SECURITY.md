# Security

## Reporting

Do not open a public issue. Report privately with GitHub's
[security advisory form](https://github.com/paulvers-ui2/port1897/security/advisories/new)
([how it works](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability#privately-reporting-a-security-vulnerability)).
Problems in firestack itself that also affect the Android app belong with
[celzero/firestack](https://github.com/celzero/firestack/security).

This project follows a 90 day disclosure timeline. We will respond within 30
days. If the issue is confirmed as a vulnerability, we will open a Security
Advisory and acknowledge your contributions.

## Checking a download

Every release is built by GitHub Actions from the commit it names, and
nowhere else:

- `SHA256SUMS.txt` on the release lists the hash of each file.
- Each `.exe` has a signed build provenance attestation (Sigstore). With the
  [GitHub CLI](https://cli.github.com):

  ```sh
  gh attestation verify AuroraVPN-Setup-<version>.exe -R paulvers-ui2/port1897
  ```

  It fails for a file that was not built by this repository's workflow.

The Windows files are not code-signed yet, so Windows SmartScreen warns about
them.

## How the app is protected

AuroraVPN for Windows has two parts: the app window (Electron), which runs
with the user's rights, and the engine (`fswin.exe`, firestack), which needs
admin rights to create the tunnel adapter, routes, DNS rules and the kill
switch, and is started through a UAC prompt.

**The engine**
- **Control API:** loopback only. Every request needs the per-install
  token. Requests from web pages (an `Origin` header) and other host names
  (DNS rebinding) are refused. Bodies and headers are size-limited, and
  stalled clients time out.
- **Your files:** the engine opens the app's files in the user's folder
  (`%APPDATA%\AuroraVPN`) with the user's rights, never its own: the log,
  token, rules, routes, WireGuard and WARP files, blocklists and packet
  captures. It uses a restricted copy of its token (Administrators deny-only,
  no privileges, medium integrity), so a link planted there cannot make it
  write, delete or read a system file (CWE-59).
- **usque** (WARP over MASQUE) runs unelevated with that same token. A flaw
  in its network code does not give admin rights, and it may not run hook
  programs (`--on-connect`, `--on-disconnect`).
- **Kill switch:** Windows Filtering Platform rules let only the tunnel, the
  engine, usque, loopback, DHCP and (optionally) the LAN through. They stay
  in place after a crash until protection starts again or is released.

**The app window**
- **Electron settings:** sandboxed renderer with context isolation and no
  Node. No navigation, new windows, webviews or permission requests. DevTools
  are off in releases. A strict CSP allows no inline script and nothing
  remote except the optional DuckDuckGo website icons.
- **IPC:** every call must come from the app's own page, in its top frame.
  Settings from the window are checked against the known settings and their
  types. DNS-over-HTTPS addresses must be `https://`. Names from the network
  (apps, domains) cannot pollute object prototypes.
- **Packaging:** Electron fuses turn off running the app as plain Node,
  `NODE_OPTIONS` and inspector flags, and load app code only from the
  packaged archive. CI starts every packaged build once (`--self-test`).
- **Dependencies:** npm (`ui/package-lock.json`, installed with `npm ci`), Go
  (`go.sum`) and usque (a pinned commit) are pinned with hashes.

**Known limits**
- **Install location:** the installer installs for the current user, into a
  folder that user can write. Malware already running as the user could
  replace the engine there before the next UAC prompt. A per-machine engine
  installed as a Windows service, with a locked-down named pipe instead of
  the loopback API, would close this. It is the planned next step.
- **Code signing:** the files are not code-signed.

**Continuous checks**
CodeQL, golangci-lint (gosec, staticcheck), govulncheck, Semgrep, zizmor
(workflows), gitleaks (secrets), OSV-Scanner (dependencies),
Electronegativity (Electron) and PSScriptAnalyzer run on every pull request
and on main (`.github/workflows/security.yml`).
