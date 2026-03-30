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
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker engine is not running. Start Docker Desktop/daemon and retry." >&2
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

to_int() {
  local raw="${1:-}"
  local default="${2:-0}"
  if [[ "${raw}" =~ ^[0-9]+$ ]]; then
    echo "${raw}"
  else
    echo "${default}"
  fi
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

image_repo_from_ref() {
  local ref="${1:-}"
  ref="${ref%%@*}"
  if [[ "${ref}" == *:* ]]; then
    echo "${ref%:*}"
    return
  fi
  echo "${ref}"
}

cleanup_repo_images() {
  local image_ref="${1:-}"
  local keep_count="${2:-2}"
  local repo
  repo="$(image_repo_from_ref "${image_ref}")"
  [[ -n "${repo}" ]] || return 0

  local -a ids=()
  mapfile -t ids < <(
    docker image ls "${repo}" --format '{{.ID}}|{{.Repository}}:{{.Tag}}' 2>/dev/null |
      awk -F'|' '$2 !~ /<none>:<none>/ && $1 != "" && !seen[$1]++ { print $1 }'
  )

  local total="${#ids[@]}"
  if (( total <= keep_count )); then
    echo "Image retention: ${repo} has ${total} image(s); keep=${keep_count}, nothing to prune."
    return 0
  fi

  local removed=0
  local idx id
  for idx in "${!ids[@]}"; do
    if (( idx < keep_count )); then
      continue
    fi
    id="${ids[$idx]}"
    [[ -n "${id}" ]] || continue
    docker image rm "${id}" >/dev/null 2>&1 || true
    removed=$((removed + 1))
  done

  echo "Image retention: pruned ${removed} old image(s) for ${repo}; kept newest ${keep_count}."
}

cleanup_appliance_images() {
  local keep_count_raw keep_count
  keep_count_raw="$(env_get C2F_IMAGE_RETENTION_COUNT "${ENV_FILE}")"
  keep_count="$(to_int "${keep_count_raw}" "2")"
  if (( keep_count < 1 )); then
    echo "Image retention disabled (C2F_IMAGE_RETENTION_COUNT=${keep_count_raw:-0})."
    return 0
  fi

  cleanup_repo_images "${BACKEND_IMAGE}:${IMAGE_TAG}" "${keep_count}"
  cleanup_repo_images "${FRONTEND_IMAGE}:${IMAGE_TAG}" "${keep_count}"
  docker image prune -f >/dev/null 2>&1 || true
}

compose_project_default_name() {
  local leaf
  leaf="$(basename "${SCRIPT_DIR}" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')"
  leaf="$(printf '%s' "${leaf}" | sed 's/^[^a-z0-9]*//')"
  if [[ -z "${leaf}" ]]; then
    leaf="click2fix"
  fi
  printf '%s' "${leaf}"
}

ensure_compose_project_name() {
  local existing
  existing="$(env_get COMPOSE_PROJECT_NAME "${ENV_FILE}")"
  if [[ -z "${existing}" ]]; then
    existing="$(compose_project_default_name)"
    set_env COMPOSE_PROJECT_NAME "${existing}" "${ENV_FILE}"
  fi
  printf '%s' "${existing}"
}

compose_cmd() {
  docker compose -p "${COMPOSE_PROJECT_NAME}" --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" "$@"
}

service_ports() {
  local service
  for service in "$@"; do
    [[ -n "${service}" ]] || continue
    local ports
    ports="$(docker ps \
      --filter "label=com.docker.compose.project=${COMPOSE_PROJECT_NAME}" \
      --filter "label=com.docker.compose.service=${service}" \
      --format '{{.Ports}}' 2>/dev/null | head -n 1 || true)"
    if [[ -n "${ports}" ]]; then
      printf '%s' "${ports}"
      return 0
    fi
  done
  return 1
}

project_container_ids() {
  local args=(ps --filter "label=com.docker.compose.project=${COMPOSE_PROJECT_NAME}" --format '{{.ID}}')
  if [[ "${1:-}" == "--all" ]]; then
    args=(ps -a --filter "label=com.docker.compose.project=${COMPOSE_PROJECT_NAME}" --format '{{.ID}}')
  fi
  docker "${args[@]}" 2>/dev/null | sed '/^[[:space:]]*$/d' || true
}

dead_project_containers() {
  docker ps -a \
    --filter "label=com.docker.compose.project=${COMPOSE_PROJECT_NAME}" \
    --format '{{.ID}}|{{.Names}}|{{.Status}}|{{.Labels}}' 2>/dev/null |
    awk -F'|' '
      function label_value(labels, key,    n, i, item, pos, name, value) {
        n = split(labels, parts, ",")
        for (i = 1; i <= n; i++) {
          item = parts[i]
          sub(/^[[:space:]]+/, "", item)
          sub(/[[:space:]]+$/, "", item)
          pos = index(item, "=")
          if (pos < 1) continue
          name = substr(item, 1, pos - 1)
          value = substr(item, pos + 1)
          if (name == key) return value
        }
        return ""
      }
      $3 ~ /^Dead/ {
        printf "%s|%s|%s|%s|%s\n", $1, $2, $3, label_value($4, "com.docker.compose.service"), label_value($4, "com.docker.compose.replace")
      }'
}

assert_no_dead_project_containers() {
  local dead
  dead="$(dead_project_containers || true)"
  if [[ -z "${dead}" ]]; then
    return 0
  fi
  local affected
  affected="$(printf '%s\n' "${dead}" |
    awk -F'|' '{ if ($4 != "") print $4; else if ($5 != "") print $5; else print $1 }' |
    awk '!seen[$0]++' |
    paste -sd ', ' -)"
  echo "ERROR: Docker has stale Click2Fix containers in the Dead state for project '${COMPOSE_PROJECT_NAME}' (${affected:-unknown services}). Restart Docker Desktop/daemon to clear the orphaned container metadata, then rerun the upgrade. Named volumes such as the Click2Fix database volume are preserved by a Docker restart." >&2
  return 1
}

remove_project_containers() {
  local ids
  ids="$(project_container_ids --all)"
  if [[ -n "${ids}" ]]; then
    while IFS= read -r id; do
      [[ -n "${id}" ]] || continue
      docker rm -f "${id}" >/dev/null 2>&1 || true
    done <<< "${ids}"
  fi
  docker network rm "${COMPOSE_PROJECT_NAME}_default" >/dev/null 2>&1 || true
}

prepare_compose_project_for_up() {
  local all_ids running_ids
  all_ids="$(project_container_ids --all)"
  [[ -n "${all_ids}" ]] || return 0
  running_ids="$(project_container_ids)"
  if [[ -n "${running_ids}" ]]; then
    return 0
  fi
  echo "No Click2Fix services are currently running. Recreating project containers to avoid stale Docker restart state."
  remove_project_containers
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

port_owned_by_service() {
  local port="$1"
  shift
  local ports
  ports="$(service_ports "$@" || true)"
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
    echo "c2f-lb"
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

  if port_in_use "${backend_port}" && ! port_owned_by_service "${backend_port}" c2f-lb backend; then
    backend_port="$(find_free_port $((backend_port + 1)))" || {
      echo "ERROR: backend port conflict and no free fallback found." >&2
      exit 1
    }
    echo "Port conflict detected. Reassigned backend to ${backend_port}."
    set_env C2F_BACKEND_PORT "${backend_port}" "${ENV_FILE}"
  fi

  if port_in_use "${frontend_port}" && ! port_owned_by_service "${frontend_port}" frontend; then
    frontend_port="$(find_free_port $((frontend_port + 1)))" || {
      echo "ERROR: frontend port conflict and no free fallback found." >&2
      exit 1
    }
    echo "Port conflict detected. Reassigned frontend to ${frontend_port}."
    set_env C2F_FRONTEND_PORT "${frontend_port}" "${ENV_FILE}"
  fi

  if port_in_use "${db_port}" && ! port_owned_by_service "${db_port}" db; then
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

COMPOSE_PROJECT_NAME="$(ensure_compose_project_name)"

resolve_port_conflicts

BACKEND_IMAGE="$(env_get C2F_BACKEND_IMAGE "${ENV_FILE}")"
FRONTEND_IMAGE="$(env_get C2F_FRONTEND_IMAGE "${ENV_FILE}")"
POSTGRES_IMAGE_TAG="$(env_get POSTGRES_IMAGE_TAG "${ENV_FILE}")"
IMAGE_TAG="$(env_get C2F_IMAGE_TAG "${ENV_FILE}")"
SKIP_PULL="$(to_bool "$(env_get C2F_SKIP_PULL "${ENV_FILE}")" false)"
POSTGRES_IMAGE_TAG="${POSTGRES_IMAGE_TAG:-16}"

if [[ "${SKIP_PULL}" == "true" ]]; then
  echo "C2F_SKIP_PULL=true, using local images only."
  docker image inspect "postgres:${POSTGRES_IMAGE_TAG}" >/dev/null 2>&1
  docker image inspect "${BACKEND_IMAGE}:${IMAGE_TAG}" >/dev/null 2>&1
  docker image inspect "${FRONTEND_IMAGE}:${IMAGE_TAG}" >/dev/null 2>&1
else
  echo "Pulling latest configured image tags..."
  assert_no_dead_project_containers
  compose_cmd pull
fi

echo "Applying upgrade..."
assert_no_dead_project_containers
prepare_compose_project_for_up
if [[ "${SKIP_PULL}" == "true" ]]; then
  compose_cmd up -d --remove-orphans --force-recreate backend frontend
else
  compose_cmd up -d --remove-orphans
fi

cleanup_appliance_images

echo "Upgrade complete."
echo "Check service status with:"
echo "  docker compose -p ${COMPOSE_PROJECT_NAME} --env-file ${ENV_FILE} -f ${COMPOSE_FILE} ps"
