#!/usr/bin/env bash
set -euo pipefail

OWNER="${OWNER:-helisudani0}"
REPO="${REPO:-click2fix}"
VERSION="${VERSION:-min-v1.1.4}"
INSTALL_DIR="${INSTALL_DIR:-${PWD}/click2fix-patch-workbench}"
PULL_IMAGES="${PULL_IMAGES:-false}"
LAUNCH_SETUP="${LAUNCH_SETUP:-false}"

normalize_version() {
  local raw="$1"
  if [[ "${raw}" == min-v* ]]; then
    echo "${raw}"
    return
  fi
  if [[ "${raw}" == v* ]]; then
    echo "min-${raw}"
    return
  fi
  echo "min-v${raw}"
}

clean_tag() {
  local raw="$1"
  if [[ "${raw}" == min-v* ]]; then
    echo "${raw#min-v}"
    return
  fi
  if [[ "${raw}" == v* ]]; then
    echo "${raw#v}"
    return
  fi
  echo "${raw}"
}

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
  local tag="$2"
  set_env C2F_BACKEND_IMAGE "ghcr.io/${OWNER}/click2fix-backend-min" "$file"
  set_env C2F_FRONTEND_IMAGE "ghcr.io/${OWNER}/click2fix-frontend-min" "$file"
  set_env C2F_IMAGE_TAG "${tag}" "$file"
  set_env C2F_SKIP_PULL "false" "$file"
}

VERSION="$(normalize_version "${VERSION}")"
IMAGE_TAG="$(clean_tag "${VERSION}")"

require_cmd curl
mkdir -p "${INSTALL_DIR}"

FILES=(
  ".env.patch-workbench.template"
  "docker-compose.patch-workbench.yml"
  "nginx.conf"
  "preflight.ps1"
  "install-patch-workbench.ps1"
  "manage-patch-workbench.ps1"
  "upgrade-patch-workbench.ps1"
  "install-patch-workbench.sh"
  "manage-patch-workbench.sh"
  "upgrade-patch-workbench.sh"
  "README.md"
)

BASE_URL="https://raw.githubusercontent.com/${OWNER}/${REPO}/${VERSION}/deploy/appliance"

for file in "${FILES[@]}"; do
  echo "Downloading ${file} ..."
  curl -fsSL "${BASE_URL}/${file}" -o "${INSTALL_DIR}/${file}"
done

TEMPLATE_FILE="${INSTALL_DIR}/.env.patch-workbench.template"
update_image_defaults "${TEMPLATE_FILE}" "${IMAGE_TAG}"
if [[ -f "${INSTALL_DIR}/.env.patch-workbench" ]]; then
  update_image_defaults "${INSTALL_DIR}/.env.patch-workbench" "${IMAGE_TAG}"
fi

chmod +x \
  "${INSTALL_DIR}/install-patch-workbench.sh" \
  "${INSTALL_DIR}/manage-patch-workbench.sh" \
  "${INSTALL_DIR}/upgrade-patch-workbench.sh"

if [[ "${PULL_IMAGES,,}" == "true" ]]; then
  if command -v docker >/dev/null 2>&1; then
    echo "Pulling patch-workbench appliance images ..."
    docker pull postgres:16
    docker pull "ghcr.io/${OWNER}/click2fix-backend-min:${IMAGE_TAG}"
    docker pull "ghcr.io/${OWNER}/click2fix-frontend-min:${IMAGE_TAG}"
    set_env C2F_SKIP_PULL "true" "${TEMPLATE_FILE}"
    if [[ -f "${INSTALL_DIR}/.env.patch-workbench" ]]; then
      set_env C2F_SKIP_PULL "true" "${INSTALL_DIR}/.env.patch-workbench"
    fi
  else
    echo "Docker is not installed. Skipping image pulls." >&2
  fi
fi

echo
echo "Patch Workbench bootstrap complete."
echo "Install directory: ${INSTALL_DIR}"
echo "Next step: run ${INSTALL_DIR}/install-patch-workbench.sh"

if [[ "${LAUNCH_SETUP,,}" == "true" ]]; then
  exec "${INSTALL_DIR}/install-patch-workbench.sh"
fi
