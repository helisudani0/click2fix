#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.appliance.yml"
ENV_FILE="${SCRIPT_DIR}/.env.appliance"

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command not found: ${cmd}" >&2
    exit 1
  fi
}

require_cmd docker

if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: docker compose plugin is required." >&2
  exit 1
fi

while true; do
  cat <<EOF

== Click2Fix Appliance Control Center ==
1) First-time install / reconfigure
2) Start services
3) Stop services
4) Restart services
5) Show status
6) Tail backend logs
7) Upgrade images and restart
8) Exit
EOF
  read -r -p "Select option: " choice
  case "${choice}" in
    1) bash "${SCRIPT_DIR}/install.sh" ;;
    2) docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" up -d ;;
    3) docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" stop ;;
    4) docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" restart ;;
    5) docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" ps ;;
    6) docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" logs -f backend ;;
    7) bash "${SCRIPT_DIR}/upgrade.sh" ;;
    8) break ;;
    *) echo "Invalid choice." ;;
  esac
done
