#!/usr/bin/env bash
set -euo pipefail

OWNER="${OWNER:-helisudani0}"
REPO="${REPO:-click2fix}"
VERSION="${VERSION:-v1.1.4}"
INSTALL_DIR="${INSTALL_DIR:-${PWD}/click2fix-appliance}"
PULL_IMAGES="${PULL_IMAGES:-false}"
LAUNCH_SETUP="${LAUNCH_SETUP:-false}"

if [[ "${VERSION}" != v* ]]; then
  VERSION="v${VERSION}"
fi

require_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "ERROR: required command not found: ${cmd}" >&2
    exit 1
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

update_image_defaults() {
  local file="$1"
  local tag="${VERSION#v}"
  set_env C2F_BACKEND_IMAGE "ghcr.io/${OWNER}/click2fix-backend" "$file"
  set_env C2F_FRONTEND_IMAGE "ghcr.io/${OWNER}/click2fix-frontend" "$file"
  set_env C2F_IMAGE_TAG "${tag}" "$file"
  set_env C2F_SKIP_PULL "false" "$file"
}

require_cmd curl
mkdir -p "${INSTALL_DIR}"

FILES=(
  ".env.appliance.template"
  "docker-compose.appliance.yml"
  "preflight.ps1"
  "install.ps1"
  "manage.ps1"
  "upgrade.ps1"
  "setup.cmd"
  "setup.sh"
  "install.sh"
  "manage.sh"
  "upgrade.sh"
  "README.md"
)

BASE_URL="https://raw.githubusercontent.com/${OWNER}/${REPO}/${VERSION}/deploy/appliance"

for file in "${FILES[@]}"; do
  echo "Downloading ${file} ..."
  curl -fsSL "${BASE_URL}/${file}" -o "${INSTALL_DIR}/${file}"
done

update_image_defaults "${INSTALL_DIR}/.env.appliance.template"
if [[ -f "${INSTALL_DIR}/.env.appliance" ]]; then
  update_image_defaults "${INSTALL_DIR}/.env.appliance"
fi

chmod +x \
  "${INSTALL_DIR}/setup.sh" \
  "${INSTALL_DIR}/install.sh" \
  "${INSTALL_DIR}/manage.sh" \
  "${INSTALL_DIR}/upgrade.sh"

if [[ "${PULL_IMAGES,,}" == "true" ]]; then
  if command -v docker >/dev/null 2>&1; then
    tag="${VERSION#v}"
    echo "Pulling appliance images ..."
    docker pull postgres:16
    docker pull "ghcr.io/${OWNER}/click2fix-backend:${tag}"
    docker pull "ghcr.io/${OWNER}/click2fix-frontend:${tag}"
    set_env C2F_SKIP_PULL "true" "${INSTALL_DIR}/.env.appliance.template"
    if [[ -f "${INSTALL_DIR}/.env.appliance" ]]; then
      set_env C2F_SKIP_PULL "true" "${INSTALL_DIR}/.env.appliance"
    fi
  else
    echo "Docker is not installed. Skipping image pulls." >&2
  fi
fi

echo
echo "Bootstrap complete."
echo "Install directory: ${INSTALL_DIR}"
echo "Next step: run ${INSTALL_DIR}/setup.sh"

if [[ "${LAUNCH_SETUP,,}" == "true" ]]; then
  exec "${INSTALL_DIR}/setup.sh"
fi
