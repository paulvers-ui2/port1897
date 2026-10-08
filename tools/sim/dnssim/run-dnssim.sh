#!/usr/bin/env bash
# Runs the DoH failure simulation, one scenario per process.
# Usage, from the repo root (the tests are package intra, behind the
# dnssim build tag so ordinary builds skip them):
#   cp tools/sim/dnssim/dnssim_*test.go intra/
#   GOFLAGS='-tags=dnssim -ldflags=-checklinkname=0' tools/sim/dnssim/run-dnssim.sh [scenario ...]
# Env: SIM_LOG (default 3), SIM_ONLINE=1, SIM_BLACKHOLE_IPS, SIM_NO443=1
set -u

local_scenarios="control-local refused refused-2ips tls-unknown-ca tls-hang no-headers http503 rcode-servfail rcode-refused rcode-nxdomain blackhole-local blackhole-testnet fallback"
online_scenarios="wrong-host-tls real"

run() {
  echo "################ $1"
  go test ./intra -run "^TestDNSSim\$/^$1\$" -count=1 -v -timeout 15m 2>&1 |
    grep -v -e '^=== RUN' -e '^PASS$' -e '^ok '
}

if [ $# -gt 0 ]; then
  for s in "$@"; do run "$s"; done
  exit 0
fi

for s in $local_scenarios; do run "$s"; done

if [ "${SIM_ONLINE:-0}" = 1 ]; then
  for s in $online_scenarios; do run "$s"; done
  # the closest to the incident: the real IPs, dropped (needs root + iptables)
  if [ "$(id -u)" = 0 ] && command -v iptables >/dev/null; then
    for ip in 1.1.1.1 1.0.0.1; do iptables -I OUTPUT -p tcp -d "$ip" --dport 443 -j DROP; done
    SIM_LABEL="real Cloudflare IPs, tcp/443 DROPped by iptables" run real
    for ip in 1.1.1.1 1.0.0.1; do iptables -D OUTPUT -p tcp -d "$ip" --dport 443 -j DROP; done
  fi
fi
