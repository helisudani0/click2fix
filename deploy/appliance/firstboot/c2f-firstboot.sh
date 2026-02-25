#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="/opt/click2fix/deploy/appliance"
STATE_DIR="/var/lib/click2fix"
DONE_FILE="${STATE_DIR}/firstboot.done"
LOG_FILE="/var/log/c2f-firstboot.log"

mkdir -p "${STATE_DIR}"
touch "${LOG_FILE}"
chmod 600 "${LOG_FILE}" || true

if [[ -f "${DONE_FILE}" ]]; then
  exit 0
fi

if [[ ! -d "${BASE_DIR}" ]]; then
  echo "ERROR: appliance directory not found: ${BASE_DIR}" | tee -a "${LOG_FILE}"
  exit 1
fi

if [[ ! -x "${BASE_DIR}/install.sh" ]]; then
  chmod +x "${BASE_DIR}/install.sh" || true
fi

echo "=== Click2Fix first-boot setup started: $(date -Iseconds) ===" | tee -a "${LOG_FILE}"
echo "Launching interactive installer..." | tee -a "${LOG_FILE}"

if "${BASE_DIR}/install.sh" </dev/tty >/dev/tty 2>>"${LOG_FILE}"; then
  touch "${DONE_FILE}"
  echo "=== Click2Fix first-boot setup completed: $(date -Iseconds) ===" | tee -a "${LOG_FILE}"
  exit 0
fi

echo "=== Click2Fix first-boot setup failed: $(date -Iseconds) ===" | tee -a "${LOG_FILE}"
exit 1
