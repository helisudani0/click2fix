#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.appliance.yml"
ENV_FILE="${SCRIPT_DIR}/.env.appliance"

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker is required." >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: docker compose plugin is required." >&2
  exit 1
fi
if [[ ! -f "${ENV_FILE}" ]]; then
  echo "ERROR: missing ${ENV_FILE}. Run install.sh first." >&2
  exit 1
fi

env_get() {
  local key="$1"
  local file="$2"
  local line
  line="$(grep -E "^${key}=" "${file}" | head -n 1 || true)"
  echo "${line#*=}"
}

set_env() {
  local key="$1"
  local value="$2"
  local file="$3"
  local tmp
  tmp="$(mktemp)"
  awk -F= -v k="$key" -v v="$value" '
    BEGIN { done=0 }
    $1==k { print k "=" v; done=1; next }
    { print }
    END { if (!done) print k "=" v }
  ' "$file" > "$tmp"
  mv "$tmp" "$file"
}

port_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -ltn "sport = :${port}" 2>/dev/null | awk 'NR>1 {found=1} END {exit(found?0:1)}'
    return $?
  fi
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1
    return $?
  fi
  if command -v netstat >/dev/null 2>&1; then
    netstat -lnt 2>/dev/null | awk '{print $4}' | grep -Eq "(^|[:.])${port}$"
    return $?
  fi
  return 1
}

port_owned_by_container() {
  local port="$1"
  local container="$2"
  local ports
  ports="$(docker ps --filter "name=^${container}$" --format '{{.Ports}}' 2>/dev/null | head -n 1 || true)"
  [[ -n "${ports}" ]] && grep -Eq "[:.]${port}->" <<< "${ports}"
}

find_free_port() {
  local start_port="$1"
  local max_tries="${2:-200}"
  local candidate="$start_port"
  local i
  for ((i=0; i<max_tries; i++)); do
    if ! port_in_use "${candidate}"; then
      echo "${candidate}"
      return 0
    fi
    candidate=$((candidate + 1))
  done
  return 1
}

normalize_port() {
  local raw="$1"
  local fallback="$2"
  if [[ "${raw}" =~ ^[0-9]+$ ]] && (( raw > 0 && raw < 65536 )); then
    echo "${raw}"
  else
    echo "${fallback}"
  fi
}

resolve_port_conflicts() {
  local public_host frontend_port backend_port db_port old_frontend_port
  public_host="$(env_get C2F_PUBLIC_HOST "${ENV_FILE}")"
  frontend_port="$(env_get C2F_FRONTEND_PORT "${ENV_FILE}")"
  backend_port="$(env_get C2F_BACKEND_PORT "${ENV_FILE}")"
  db_port="$(env_get C2F_DB_PORT "${ENV_FILE}")"

  [[ -n "${public_host}" ]] || public_host="localhost"
  frontend_port="$(normalize_port "${frontend_port:-}" "5173")"
  backend_port="$(normalize_port "${backend_port:-}" "8000")"
  db_port="$(normalize_port "${db_port:-}" "5432")"
  old_frontend_port="${frontend_port}"

  if port_in_use "${backend_port}" && ! port_owned_by_container "${backend_port}" "c2f-backend"; then
    backend_port="$(find_free_port $((backend_port + 1)))" || {
      echo "ERROR: backend port conflict and no free fallback found." >&2
      exit 1
    }
    echo "Port conflict detected. Reassigned backend to ${backend_port}."
    set_env C2F_BACKEND_PORT "${backend_port}" "${ENV_FILE}"
  fi

  if port_in_use "${frontend_port}" && ! port_owned_by_container "${frontend_port}" "c2f-frontend"; then
    frontend_port="$(find_free_port $((frontend_port + 1)))" || {
      echo "ERROR: frontend port conflict and no free fallback found." >&2
      exit 1
    }
    echo "Port conflict detected. Reassigned frontend to ${frontend_port}."
    set_env C2F_FRONTEND_PORT "${frontend_port}" "${ENV_FILE}"
  fi

  if port_in_use "${db_port}" && ! port_owned_by_container "${db_port}" "c2f-db"; then
    db_port="$(find_free_port $((db_port + 1)))" || {
      echo "ERROR: db port conflict and no free fallback found." >&2
      exit 1
    }
    echo "Port conflict detected. Reassigned db host port to ${db_port}."
    set_env C2F_DB_PORT "${db_port}" "${ENV_FILE}"
  fi

  if [[ "${frontend_port}" != "${old_frontend_port}" ]]; then
    set_env C2F_CORS_ORIGINS "http://${public_host}:${frontend_port}" "${ENV_FILE}"
  fi
}

resolve_port_conflicts

echo "Pulling latest configured image tags..."
docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" pull

echo "Applying upgrade..."
docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" up -d

echo "Upgrade complete."
echo "Check service status with:"
echo "  docker compose --env-file ${ENV_FILE} -f ${COMPOSE_FILE} ps"
