# Third-party material in the app window

- **Icons and home-screen layout** (`renderer/icons.js`, the card layout and
  colors in `renderer/styles.css`) come from the
  [Rethink DNS + Firewall](https://github.com/celzero/rethink-app) Android app,
  via the [AuroraVPN fork](https://github.com/paulvers-ui/rethink-app-masque) at
  commit `5ab34320`, under the Apache License 2.0. Some of those icons are
  Google's Material icons, also Apache-2.0. Android vector drawables were
  converted to SVG with the "True Black Plus" theme colors.
- **DNS lists, ODoH servers, DNS proxies and DNSCrypt relays** (`renderer/data.js`)
  come from the Android app's prefilled database (Apache-2.0).
- **Countries of addresses** (the flags in Logs) come from the engine, which
  embeds the Android app's geo-IP database: db-ip.com "IP to Country Lite"
  (the Android app also credits IPinfo Lite), under
  [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). See
  `cmd/fswin/geoip/README.md`.
- **Electron** is MIT licensed.
- **Wintun** (`engine/wintun.dll`, added at build time) is © WireGuard LLC under
  its prebuilt-binaries license, shipped next to the engine as
  `wintun-LICENSE.txt`.
