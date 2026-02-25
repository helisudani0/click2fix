#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -f "${SCRIPT_DIR}/.env.appliance" ]]; then
  exec bash "${SCRIPT_DIR}/install.sh"
fi

exec bash "${SCRIPT_DIR}/manage.sh"
