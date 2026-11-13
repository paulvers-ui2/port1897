#!/bin/sh
# AuroraVPN .deb: before remove or upgrade. The service stops the engine,
# which undoes its routes, DNS and kill switch, while its files still exist.
set -e
if [ -d /run/systemd/system ]; then
  systemctl stop auroravpn.service 2>/dev/null || true
fi
if [ -x /opt/AuroraVPN/resources/engine/fswin ]; then
  /opt/AuroraVPN/resources/engine/fswin -cleanup >/dev/null 2>&1 || true
fi
exit 0
