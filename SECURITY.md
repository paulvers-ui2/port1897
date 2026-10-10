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

AuroraVPN for Windows has three parts:
- the app window (Electron), which runs with the user's rights;
- the engine (`fswin.exe`, firestack), which needs admin rights to create the
  tunnel adapter, routes, DNS rules and the kill switch;
- AuroraVPN Service (`fswin.exe -service run`, LocalSystem), installed with
  the app, which starts the engine without a UAC prompt each time.

**AuroraVPN Service**
- **Install:** the installer is per-machine (Program Files) and sets the
  service up once, from a folder only SYSTEM and administrators may change.
  The service locks that folder down itself, in case it was installed
  elsewhere.
- **Who it answers:** its named pipe (`\\.\pipe\AuroraVPN`) refuses
  remote clients and anyone but SYSTEM, administrators and interactive users.
  It answers only the installed `AuroraVPN.exe`, checked by the client
  process's image path, and only for administrators. Standard users are
  refused, as UAC would refuse them.
- **What it starts:** the engine from its own folder, with the user's own
  elevated token (the one a UAC prompt hands out), in the user's session and
  with the user's environment. That is the engine of a UAC prompt, so
  everything below still holds. Flags that would pick a program to run are
  refused. The engine configures the adapter and the NRPT rule through
  Windows APIs and the registry; its `netsh` fallback (for a Windows without
  those APIs) comes from System32, never through `PATH`. Every request is
  answered on its own thread.
- **Without it** (the portable app, or a standard user), the engine starts
  through a UAC prompt, as before.

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
- **Control by the user's programs:** with the service, programs running as
  an administrator account, even unelevated, can turn protection on or off
  and change its settings without a prompt. That is how other VPN services
  work. They still cannot run their own code with admin rights through it.
- **The portable app** runs from a folder the user can write, and starts
  the engine through a UAC prompt from there.
- **Before sign-in:** the engine runs in the user's session, so protection
  starts when the user signs in, not at boot.
- **Code signing:** the files are not code-signed.

**Continuous checks**
CodeQL, golangci-lint (gosec, staticcheck), govulncheck, Semgrep, zizmor
(workflows), gitleaks (secrets), OSV-Scanner (dependencies),
Electronegativity (Electron) and PSScriptAnalyzer run on every pull request
and on main (`.github/workflows/security.yml`).
