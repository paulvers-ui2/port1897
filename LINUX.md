# AuroraVPN on Linux (.deb)

The same engine (fswin) and app (Electron) as on Windows, as a `.deb` for
Debian 12 and 13 and Ubuntu 22.04 and 24.04, amd64. Debian 11 is best effort:
CI installs it there and warns if that breaks.

## Install

    sudo apt install ./AuroraVPN-<version>-amd64.deb

The package installs the app in `/opt/AuroraVPN`, the command `auroravpn`, and
**AuroraVPN Service** (`auroravpn.service`), enabled and started. The app runs
as you; the service starts the engine as root when you turn protection on, as
on Windows. `sudo apt remove auroravpn` stops it and undoes its network
changes first.

## How each Windows piece maps

| Windows | Linux |
|---|---|
| Wintun | kernel TUN (`/dev/net/tun`), adapter `AuroraVPN` |
| `win/ifbind` (interface bind) | firewall mark `0x1897` on the engine's sockets + `ip rule not fwmark 0x1897 lookup 51897` |
| `win/owner` (IP Helper tables) | `/proc/net/{tcp,udp}` and socket inodes in `/proc/<pid>/fd` |
| NRPT | systemd-resolved on the TUN link, else `/etc/resolv.conf` (restored on stop and by `fswin -cleanup`) |
| WFP kill switch | nftables table `inet auroravpn` |
| AuroraVPN Service, pipe `\\.\pipe\AuroraVPN` | `fswin -service run` under systemd, socket `/run/auroravpn/auroravpn.sock`; same protocol (`service_proto.go`); answers only `/opt/AuroraVPN/auroravpn`, the caller known from `SO_PEERCRED` |
| engine as SYSTEM with the user's token | engine as root with `-user-token <uid>`: the user's files and usque run as that user |

## From a terminal

    sudo fswin -full            # all IPv4 through the tunnel
    sudo fswin -cleanup         # undo what a killed fswin left behind

## Not yet

- keep/watch (the Windows service restarts a dead engine): the app restarts it
- NetworkManager without systemd-resolved: plain `/etc/resolv.conf` only
- arm64
