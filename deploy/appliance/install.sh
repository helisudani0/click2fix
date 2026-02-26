#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.appliance.yml"
ENV_TEMPLATE="${SCRIPT_DIR}/.env.appliance.template"
ENV_FILE="${SCRIPT_DIR}/.env.appliance"

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command not found: ${cmd}" >&2
    exit 1
  fi
}

bool_env() {
  local value="${1:-}"
  case "${value,,}" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

get_env() {
  local key="$1"
  local file="$2"
  awk -F= -v k="$key" '$1==k {sub($1"=",""); print; exit}' "$file"
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

show_diagnostics() {
  echo
  echo "---- docker compose ps ----" >&2
  docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" ps >&2 || true
  echo >&2
  echo "---- backend logs (tail 160) ----" >&2
  docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" logs --tail 160 backend >&2 || true
  echo >&2
  echo "---- db logs (tail 80) ----" >&2
  docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" logs --tail 80 db >&2 || true
}

detect_public_host() {
  local detected=""
  if command -v ip >/dev/null 2>&1; then
    detected="$(ip route get 1.1.1.1 2>/dev/null | awk '
      /src/ {
        for (i=1; i<=NF; i++) {
          if ($i == "src") { print $(i+1); exit }
        }
      }')"
  fi
  if [[ -z "${detected}" ]]; then
    detected="$(hostname -I 2>/dev/null | awk '
      {
        for (i=1; i<=NF; i++) {
          if ($i !~ /^127\./ && $i !~ /^172\.17\./) { print $i; exit }
        }
      }')"
  fi
  printf '%s' "${detected}"
}

generate_secret() {
  head -c 48 /dev/urandom | base64 | tr -d '\n'
}

prompt_value() {
  local label="$1"
  local default_value="$2"
  local out_var="$3"
  local answer
  read -r -p "${label} [${default_value}]: " answer
  answer="${answer:-$default_value}"
  printf -v "$out_var" "%s" "$answer"
}

prompt_secret() {
  local label="$1"
  local default_value="$2"
  local out_var="$3"
  local answer
  read -r -s -p "${label} [hidden, press Enter to keep current]: " answer
  echo
  if [[ -z "${answer}" ]]; then
    answer="${default_value}"
  fi
  printf -v "$out_var" "%s" "$answer"
}

configure_static_network() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: static network configuration requires root (run with sudo)." >&2
    exit 1
  fi
  local iface="$1"
  local ip="$2"
  local prefix="$3"
  local gateway="$4"
  local dns_csv="$5"

  cat > /etc/netplan/99-click2fix.yaml <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${iface}:
      dhcp4: no
      addresses:
        - ${ip}/${prefix}
      routes:
        - to: default
          via: ${gateway}
      nameservers:
        addresses: [${dns_csv}]
EOF
  netplan generate
  netplan apply
}

require_cmd docker

if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: docker compose plugin is required." >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker engine is not running. Start Docker Desktop/daemon and retry." >&2
  exit 1
fi

if [[ ! -f "${ENV_FILE}" ]]; then
  cp "${ENV_TEMPLATE}" "${ENV_FILE}"
  chmod 600 "${ENV_FILE}"
fi

echo "== Click2Fix Appliance First-Boot Setup =="
echo "Environment file: ${ENV_FILE}"
echo

current_brand="$(get_env APP_BRAND "${ENV_FILE}")"
current_public_host="$(get_env C2F_PUBLIC_HOST "${ENV_FILE}")"
current_frontend_port="$(get_env C2F_FRONTEND_PORT "${ENV_FILE}")"
current_backend_port="$(get_env C2F_BACKEND_PORT "${ENV_FILE}")"
current_wazuh_url="$(get_env WAZUH_URL "${ENV_FILE}")"
current_wazuh_user="$(get_env WAZUH_USER "${ENV_FILE}")"
current_wazuh_password="$(get_env WAZUH_PASSWORD "${ENV_FILE}")"
current_indexer_url="$(get_env INDEXER_URL "${ENV_FILE}")"
current_indexer_user="$(get_env INDEXER_USER "${ENV_FILE}")"
current_indexer_password="$(get_env INDEXER_PASSWORD "${ENV_FILE}")"
current_winrm_user="$(get_env C2F_WINRM_USERNAME "${ENV_FILE}")"
current_winrm_password="$(get_env C2F_WINRM_PASSWORD "${ENV_FILE}")"
current_admin_user="$(get_env C2F_BOOTSTRAP_ADMIN_USERNAME "${ENV_FILE}")"
current_admin_password="$(get_env C2F_BOOTSTRAP_ADMIN_PASSWORD "${ENV_FILE}")"
current_backend_image="$(get_env C2F_BACKEND_IMAGE "${ENV_FILE}")"
current_frontend_image="$(get_env C2F_FRONTEND_IMAGE "${ENV_FILE}")"
current_image_tag="$(get_env C2F_IMAGE_TAG "${ENV_FILE}")"
current_skip_pull="$(get_env C2F_SKIP_PULL "${ENV_FILE}")"
current_jwt_secret="$(get_env JWT_SECRET "${ENV_FILE}")"

prompt_value "Public host or static IP for UI access" "${current_public_host:-$(detect_public_host)}" public_host
prompt_value "Frontend port" "${current_frontend_port:-5173}" frontend_port
prompt_value "Backend port" "${current_backend_port:-8000}" backend_port

prompt_value "Wazuh manager URL (include https:// and port)" "${current_wazuh_url:-https://WAZUH_MANAGER_IP:55000}" wazuh_url
prompt_value "Wazuh API user" "${current_wazuh_user:-c2f_api}" wazuh_user
prompt_secret "Wazuh API password" "${current_wazuh_password:-}" wazuh_password

prompt_value "Wazuh indexer URL (include https:// and port)" "${current_indexer_url:-https://WAZUH_INDEXER_IP:9200}" indexer_url
prompt_value "Wazuh indexer user" "${current_indexer_user:-admin}" indexer_user
prompt_secret "Wazuh indexer password" "${current_indexer_password:-}" indexer_password

prompt_value "Global WinRM username (blank if per-agent strategy later)" "${current_winrm_user:-}" winrm_user
prompt_secret "Global WinRM password" "${current_winrm_password:-}" winrm_password

prompt_value "Initial Click2Fix admin username" "${current_admin_user:-admin}" admin_user
prompt_secret "Initial Click2Fix admin password" "${current_admin_password:-}" admin_password

app_brand="${current_brand:-Click2Fix}"
backend_image="${current_backend_image:-click2fix-backend}"
frontend_image="${current_frontend_image:-click2fix-frontend}"
image_tag="${current_image_tag:-local}"
skip_pull="${current_skip_pull:-false}"
jwt_secret="${current_jwt_secret:-}"
if [[ -z "${jwt_secret}" || "${jwt_secret}" == CHANGE_ME* || ${#jwt_secret} -lt 32 ]]; then
  jwt_secret="$(generate_secret)"
  echo "Generated secure JWT secret for this appliance."
fi

echo
read -r -p "Configure static network now? [y/N]: " configure_network
if [[ "${configure_network,,}" == "y" || "${configure_network,,}" == "yes" ]]; then
  prompt_value "Network interface" "eth0" net_iface
  prompt_value "Static IP address" "${public_host}" net_ip
  prompt_value "CIDR prefix (e.g., 24)" "24" net_prefix
  prompt_value "Gateway IP" "" net_gateway
  prompt_value "DNS servers (comma-separated)" "8.8.8.8,1.1.1.1" net_dns
  configure_static_network "${net_iface}" "${net_ip}" "${net_prefix}" "${net_gateway}" "${net_dns}"
  public_host="${net_ip}"
fi

if [[ -z "${public_host}" ]]; then
  echo "ERROR: public host/IP is required." >&2
  exit 1
fi
if [[ -z "${wazuh_password}" || -z "${indexer_password}" || -z "${admin_password}" ]]; then
  echo "ERROR: passwords cannot be empty." >&2
  exit 1
fi
if [[ ${#admin_user} -lt 3 ]]; then
  echo "ERROR: initial admin username must be at least 3 characters." >&2
  exit 1
fi
if [[ ${#admin_password} -lt 8 ]]; then
  echo "ERROR: initial admin password must be at least 8 characters." >&2
  exit 1
fi

trusted_hosts="localhost,127.0.0.1,*.localhost,backend,frontend,c2f-backend,c2f-frontend,${public_host}"
cors_origins="http://${public_host}:${frontend_port}"

set_env APP_BRAND "${app_brand}" "${ENV_FILE}"
set_env C2F_PUBLIC_HOST "${public_host}" "${ENV_FILE}"
set_env C2F_FRONTEND_PORT "${frontend_port}" "${ENV_FILE}"
set_env C2F_BACKEND_PORT "${backend_port}" "${ENV_FILE}"
set_env C2F_TRUSTED_HOSTS "${trusted_hosts}" "${ENV_FILE}"
set_env C2F_CORS_ORIGINS "${cors_origins}" "${ENV_FILE}"
set_env WAZUH_URL "${wazuh_url}" "${ENV_FILE}"
set_env WAZUH_USER "${wazuh_user}" "${ENV_FILE}"
set_env WAZUH_PASSWORD "${wazuh_password}" "${ENV_FILE}"
set_env INDEXER_URL "${indexer_url}" "${ENV_FILE}"
set_env INDEXER_USER "${indexer_user}" "${ENV_FILE}"
set_env INDEXER_PASSWORD "${indexer_password}" "${ENV_FILE}"
set_env JWT_SECRET "${jwt_secret}" "${ENV_FILE}"
set_env C2F_WINRM_USERNAME "${winrm_user}" "${ENV_FILE}"
set_env C2F_WINRM_PASSWORD "${winrm_password}" "${ENV_FILE}"
set_env C2F_BOOTSTRAP_ADMIN_USERNAME "${admin_user}" "${ENV_FILE}"
set_env C2F_BOOTSTRAP_ADMIN_PASSWORD "${admin_password}" "${ENV_FILE}"

echo
echo "Pulling and starting appliance services..."
if bool_env "${skip_pull}"; then
  echo "Skipping docker pull (C2F_SKIP_PULL=${skip_pull}). Expecting local images:"
  echo "  ${backend_image}:${image_tag}"
  echo "  ${frontend_image}:${image_tag}"
  if ! docker image inspect "${backend_image}:${image_tag}" >/dev/null 2>&1; then
    echo "ERROR: backend image not found locally: ${backend_image}:${image_tag}" >&2
    exit 1
  fi
  if ! docker image inspect "${frontend_image}:${image_tag}" >/dev/null 2>&1; then
    echo "ERROR: frontend image not found locally: ${frontend_image}:${image_tag}" >&2
    exit 1
  fi
else
  if ! docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" pull; then
    echo "ERROR: image pull failed." >&2
    echo "Common causes:" >&2
    echo "  1) Docker engine unavailable" >&2
    echo "  2) Private registry auth required (run: docker login ghcr.io with read:packages token)" >&2
    exit 1
  fi
fi
if ! docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" up -d db backend; then
  echo "ERROR: failed to start backend stack." >&2
  show_diagnostics
  exit 1
fi

echo "Waiting for backend health..."
for _ in $(seq 1 60); do
  status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' c2f-backend 2>/dev/null || true)"
  if [[ "${status}" == "healthy" ]]; then
    break
  fi
  sleep 2
done

status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' c2f-backend 2>/dev/null || true)"
if [[ "${status}" != "healthy" ]]; then
  echo "ERROR: backend is not healthy. Check logs:" >&2
  echo "  docker compose --env-file ${ENV_FILE} -f ${COMPOSE_FILE} logs backend" >&2
  show_diagnostics
  exit 1
fi

if ! docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" up -d frontend; then
  echo "ERROR: failed to start frontend." >&2
  show_diagnostics
  exit 1
fi

echo "Bootstrapping admin user..."
bootstrap_force="$(get_env C2F_BOOTSTRAP_ADMIN_FORCE_RESET "${ENV_FILE}")"
bootstrap_args=()
if [[ "${bootstrap_force,,}" == "true" || "${bootstrap_force}" == "1" ]]; then
  bootstrap_args+=(--force-reset)
fi
if ! docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" exec -T -w /app backend \
  python -m tools.bootstrap_admin \
  --username "${admin_user}" \
  --password "${admin_password}" \
  --role admin \
  "${bootstrap_args[@]}"; then
  echo "ERROR: failed to bootstrap admin user." >&2
  show_diagnostics
  exit 1
fi

echo
echo "Appliance is ready."
echo "UI URL: http://${public_host}:${frontend_port}"
echo "Backend API/docs: http://${public_host}:${backend_port}/docs"
echo "Backend Ops: http://${public_host}:${backend_port}/ops"
echo "Login user: ${admin_user}"
echo
echo "Next checks:"
echo "  1) Verify connector status in UI"
echo "  2) Run endpoint-healthcheck on one pilot agent"
echo "  3) Run one low-risk Global Shell command"
