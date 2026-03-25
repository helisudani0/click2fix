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

to_bool() {
  local raw="${1:-}"
  local default="${2:-false}"
  local normalized
  normalized="$(printf '%s' "${raw}" | tr '[:upper:]' '[:lower:]' | xargs || true)"
  case "${normalized}" in
    1|true|yes|on) echo "true" ;;
    0|false|no|off) echo "false" ;;
    "") echo "${default}" ;;
    *) echo "${default}" ;;
  esac
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

current_advertise_host() {
  local fallback="${1:-localhost}"
  local candidate=""
  if command -v ip >/dev/null 2>&1; then
    candidate="$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="src") { print $(i+1); exit }}')"
  fi
  if [[ -z "${candidate}" ]] && command -v hostname >/dev/null 2>&1; then
    candidate="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -Ev '^(127\.|169\.254\.|$)' | head -n 1 || true)"
  fi
  if [[ -n "${candidate}" ]]; then
    echo "${candidate}"
  elif [[ -n "${fallback}" ]]; then
    echo "${fallback}"
  else
    echo "localhost"
  fi
}

is_ipv4_literal() {
  local value="${1:-}"
  [[ "${value}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local IFS='.'
  local octet
  for octet in ${value}; do
    [[ "${octet}" =~ ^[0-9]+$ ]] || return 1
    ((octet >= 0 && octet <= 255)) || return 1
  done
  return 0
}

resolve_runtime_public_host() {
  local configured="${1:-}"
  if [[ -z "${configured}" ]]; then
    current_advertise_host "localhost"
    return
  fi
  local lower
  lower="$(printf '%s' "${configured}" | tr '[:upper:]' '[:lower:]')"
  if [[ "${lower}" == "localhost" ]] || is_ipv4_literal "${configured}"; then
    current_advertise_host "${configured}"
    return
  fi
  echo "${configured}"
}

join_unique_csv() {
  awk '
    {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
      if ($0 == "") next
      key=tolower($0)
      if (!seen[key]++) {
        out = out (out ? "," : "") $0
      }
    }
    END { print out }
  '
}

build_cors_origins() {
  local public_host="$1"
  local frontend_port="$2"
  local existing="$3"
  local primary="http://${public_host}:${frontend_port}"
  {
    echo "${primary}"
    tr ',' '\n' <<< "${existing}"
  } | join_unique_csv
}

build_trusted_hosts() {
  local public_host="$1"
  local existing="$2"
  {
    echo "localhost"
    echo "127.0.0.1"
    echo "*.localhost"
    echo "backend"
    echo "frontend"
    echo "c2f-backend"
    echo "c2f-frontend"
    if [[ -n "${public_host}" ]]; then
      echo "${public_host}"
    fi
    tr ',' '\n' <<< "${existing}"
  } | join_unique_csv
}

resolve_port_conflicts() {
  local public_host configured_host frontend_port backend_port db_port
  public_host="$(env_get C2F_PUBLIC_HOST "${ENV_FILE}")"
  configured_host="${public_host}"
  frontend_port="$(env_get C2F_FRONTEND_PORT "${ENV_FILE}")"
  backend_port="$(env_get C2F_BACKEND_PORT "${ENV_FILE}")"
  db_port="$(env_get C2F_DB_PORT "${ENV_FILE}")"

  public_host="$(resolve_runtime_public_host "${configured_host}")"
  [[ -n "${public_host}" ]] || public_host="localhost"
  frontend_port="$(normalize_port "${frontend_port:-}" "5173")"
  backend_port="$(normalize_port "${backend_port:-}" "8000")"
  db_port="$(normalize_port "${db_port:-}" "5432")"

  if [[ "${public_host}" != "${configured_host}" ]]; then
    set_env C2F_PUBLIC_HOST "${public_host}" "${ENV_FILE}"
  fi

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

  local existing_cors desired_cors existing_trusted desired_trusted
  existing_cors="$(env_get C2F_CORS_ORIGINS "${ENV_FILE}")"
  desired_cors="$(build_cors_origins "${public_host}" "${frontend_port}" "${existing_cors}")"
  if [[ "${desired_cors}" != "${existing_cors}" ]]; then
    set_env C2F_CORS_ORIGINS "${desired_cors}" "${ENV_FILE}"
  fi

  existing_trusted="$(env_get C2F_TRUSTED_HOSTS "${ENV_FILE}")"
  desired_trusted="$(build_trusted_hosts "${public_host}" "${existing_trusted}")"
  if [[ "${desired_trusted}" != "${existing_trusted}" ]]; then
    set_env C2F_TRUSTED_HOSTS "${desired_trusted}" "${ENV_FILE}"
  fi
}

resolve_port_conflicts

BACKEND_IMAGE="$(env_get C2F_BACKEND_IMAGE "${ENV_FILE}")"
FRONTEND_IMAGE="$(env_get C2F_FRONTEND_IMAGE "${ENV_FILE}")"
AGENT_MANAGER_IMAGE="$(env_get C2F_AGENT_MANAGER_IMAGE "${ENV_FILE}")"
EVENT_INDEXER_IMAGE="$(env_get C2F_EVENT_INDEXER_IMAGE "${ENV_FILE}")"
IMAGE_TAG="$(env_get C2F_IMAGE_TAG "${ENV_FILE}")"
SKIP_PULL="$(to_bool "$(env_get C2F_SKIP_PULL "${ENV_FILE}")" false)"

if [[ "${SKIP_PULL}" == "true" ]]; then
  echo "C2F_SKIP_PULL=true, using local images only."
  docker image inspect "${BACKEND_IMAGE}:${IMAGE_TAG}" >/dev/null 2>&1
  docker image inspect "${FRONTEND_IMAGE}:${IMAGE_TAG}" >/dev/null 2>&1
  docker image inspect "${AGENT_MANAGER_IMAGE}:${IMAGE_TAG}" >/dev/null 2>&1
  docker image inspect "${EVENT_INDEXER_IMAGE}:${IMAGE_TAG}" >/dev/null 2>&1
else
  echo "Pulling latest configured image tags..."
  docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" pull
fi

echo "Applying upgrade..."
if [[ "${SKIP_PULL}" == "true" ]]; then
  docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" up -d --force-recreate agent-manager event-indexer backend frontend
else
  docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" up -d
fi

echo "Upgrade complete."
echo "Check service status with:"
echo "  docker compose --env-file ${ENV_FILE} -f ${COMPOSE_FILE} ps"
