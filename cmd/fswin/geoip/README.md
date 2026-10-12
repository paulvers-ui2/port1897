# Country database

`dbip.v4` and `dbip.v6` map IP addresses to countries. They are the files the
Rethink DNS Android app ships as `assets/dbip.v4` and `assets/dbip.v6`, taken
from AuroraVPN v1.11.1 (rethink-app-masque).

Geo-IP data: [db-ip.com](https://db-ip.com) "IP to Country Lite", licensed
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The Android app
also credits [IPinfo Lite](https://ipinfo.io/lite).

## Format

Sorted, fixed-size records with no header:

| file      | record   | fields                                          |
|-----------|----------|-------------------------------------------------|
| `dbip.v4` | 6 bytes  | first IPv4 address of a range, 2-letter country |
| `dbip.v6` | 18 bytes | first IPv6 address of a range, 2-letter country |

An address belongs to the last record that starts at or below it. `ZZ` marks
private and unassigned ranges. fswin embeds both files (`geoip_windows.go`)
and looks them up as the Android app's `CountryMap` does, by binary search.

| file      | sha256                                                             |
|-----------|--------------------------------------------------------------------|
| `dbip.v4` | `3655fdd81a38c735d0f86dd6d097e2c25152cc43ff536eba8470ec62682b96bd` |
| `dbip.v6` | `b66a5be32c1c0cf092dc29d22893e8e21100a2ca860f05473f3dab8d0db66aa2` |

# Network (ASN) database

`asn.v4` and `asn.v6` map IP addresses to the autonomous system (network)
that announces them, for blocking a whole network. fswin embeds them
(`asn_windows.go`) and looks them up by binary search, exactly as the country
database above.

Data: [iptoasn.com](https://iptoasn.com), public domain.

The files committed to the repo are **empty placeholders**. A release build
fills them in CI (`.github/workflows/app.yml`), downloading the current
iptoasn tables and converting them with `genasn` (`geoip/genasn`). A plain
source checkout therefore has no ASN data, and `asn()` returns 0 for every
address until a release build is made.

## Format

Sorted, fixed-size records with no header:

| file     | record   | fields                                                   |
|----------|----------|----------------------------------------------------------|
| `asn.v4` | 8 bytes  | first IPv4 address of a range, 4-byte big-endian ASN     |
| `asn.v6` | 20 bytes | first IPv6 address of a range, 4-byte big-endian ASN     |

An address belongs to the last record that starts at or below it. ASN `0`
marks unrouted ranges and the space after the last range.
