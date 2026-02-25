#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root."
  exit 1
fi

install -m 755 "${SCRIPT_DIR}/c2f-firstboot.sh" /usr/local/sbin/c2f-firstboot.sh
install -m 644 "${SCRIPT_DIR}/c2f-firstboot.service" /etc/systemd/system/c2f-firstboot.service

systemctl daemon-reload
systemctl enable c2f-firstboot.service

echo "Installed c2f-firstboot.service"
echo "It will run once on next boot if /var/lib/click2fix/firstboot.done is absent."
