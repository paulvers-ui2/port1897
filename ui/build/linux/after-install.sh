#!/bin/sh
# AuroraVPN .deb: after install or upgrade
set -e
APP=/opt/AuroraVPN

# what electron-builder's own script does: the command and Chromium's sandbox
ln -sf "$APP/auroravpn" /usr/bin/auroravpn
chmod 4755 "$APP/chrome-sandbox" 2>/dev/null || true
if command -v update-mime-database >/dev/null 2>&1; then update-mime-database /usr/share/mime || true; fi
if command -v update-desktop-database >/dev/null 2>&1; then update-desktop-database /usr/share/applications || true; fi

# the engine and usque: root's to change, everyone's to run
chown -R root:root "$APP/resources/engine"
chmod 0755 "$APP/resources/engine/fswin" "$APP/resources/engine/usque"

# AuroraVPN Service
install -D -m 0644 "$APP/resources/linux/auroravpn.service" /usr/lib/systemd/system/auroravpn.service
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
  systemctl enable auroravpn.service || true
  systemctl restart auroravpn.service || true
fi
exit 0
