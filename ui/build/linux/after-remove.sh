#!/bin/sh
# AuroraVPN .deb: after remove (an upgrade installs the unit again)
set -e
case "$1" in
  remove|purge)
    if [ -d /run/systemd/system ]; then systemctl disable auroravpn.service 2>/dev/null || true; fi
    rm -f /usr/lib/systemd/system/auroravpn.service /usr/bin/auroravpn
    if [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi
    ;;
esac
exit 0
