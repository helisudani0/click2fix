#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
APPLIANCE_DIR="${ROOT_DIR}/deploy/appliance"

test_git_source_available() {
  command -v git >/dev/null 2>&1 || return 1
  git -C "${ROOT_DIR}" rev-parse --is-inside-work-tree >/dev/null 2>&1
}

source_file_exists() {
  local fs_path="$1"
  local repo_path="$2"
  if [[ "${USE_GIT_SOURCE}" == "true" ]]; then
    if git -C "${ROOT_DIR}" cat-file -e "HEAD:${repo_path}" >/dev/null 2>&1; then
      return 0
    fi
  fi
  [[ -f "${fs_path}" ]]
}

read_source_text() {
  local fs_path="$1"
  local repo_path="$2"
  if [[ "${USE_GIT_SOURCE}" == "true" ]] && git -C "${ROOT_DIR}" cat-file -e "HEAD:${repo_path}" >/dev/null 2>&1; then
    git -C "${ROOT_DIR}" show "HEAD:${repo_path}"
    return
  fi
  cat "${fs_path}"
}

export_source_file() {
  local fs_path="$1"
  local repo_path="$2"
  local dest_path="$3"
  mkdir -p "$(dirname "${dest_path}")"
  if [[ "${USE_GIT_SOURCE}" == "true" ]] && git -C "${ROOT_DIR}" cat-file -e "HEAD:${repo_path}" >/dev/null 2>&1; then
    read_source_text "${fs_path}" "${repo_path}" > "${dest_path}"
    return
  fi
  cp "${fs_path}" "${dest_path}"
}

assert_current_appliance_layout() {
  local compose_path="${APPLIANCE_DIR}/docker-compose.patch-workbench.yml"
  local env_template_path="${APPLIANCE_DIR}/.env.patch-workbench.template"
  source_file_exists "${compose_path}" "deploy/appliance/docker-compose.patch-workbench.yml" || {
    echo "ERROR: missing required appliance file: docker-compose.patch-workbench.yml" >&2
    exit 1
  }
  source_file_exists "${env_template_path}" "deploy/appliance/.env.patch-workbench.template" || {
    echo "ERROR: missing required appliance file: .env.patch-workbench.template" >&2
    exit 1
  }

  read_source_text "${compose_path}" "deploy/appliance/docker-compose.patch-workbench.yml" | grep -Eq '^[[:space:]]*(agent-manager|event-indexer|alert-service|case-service|ingest-gateway|soar-service|detection-service)[[:space:]]*:' && {
    echo "ERROR: deploy/appliance/docker-compose.patch-workbench.yml currently includes v2-only services. Clean it before building the current release bundle." >&2
    exit 1
  }

  read_source_text "${compose_path}" "deploy/appliance/docker-compose.patch-workbench.yml" | grep -Eq '^[[:space:]]*db[[:space:]]*:' || {
    echo "ERROR: patch-workbench compose file is missing db service." >&2
    exit 1
  }
  read_source_text "${compose_path}" "deploy/appliance/docker-compose.patch-workbench.yml" | grep -Eq '^[[:space:]]*backend[[:space:]]*:' || {
    echo "ERROR: patch-workbench compose file is missing backend service." >&2
    exit 1
  }
  read_source_text "${compose_path}" "deploy/appliance/docker-compose.patch-workbench.yml" | grep -Eq '^[[:space:]]*frontend[[:space:]]*:' || {
    echo "ERROR: patch-workbench compose file is missing frontend service." >&2
    exit 1
  }

  read_source_text "${env_template_path}" "deploy/appliance/.env.patch-workbench.template" | grep -Eq '^[[:space:]]*(AGENT_MANAGER_IMAGE|EVENT_INDEXER_IMAGE|ALERT_SERVICE_IMAGE|CASE_SERVICE_IMAGE|INGEST_GATEWAY_IMAGE|SOAR_SERVICE_IMAGE|DETECTION_SERVICE_IMAGE)=' && {
    echo "ERROR: deploy/appliance/.env.patch-workbench.template currently includes v2-only image settings. Clean it before building the current release bundle." >&2
    exit 1
  }
}

VERSION="${1:-v0.0.0-local}"
OWNER="${2:-your-org}"
BACKEND_IMAGE="${3:-ghcr.io/${OWNER}/click2fix-backend-min}"
FRONTEND_IMAGE="${4:-ghcr.io/${OWNER}/click2fix-frontend-min}"
if [[ "${VERSION}" == min-v* ]]; then
  IMAGE_TAG_DEFAULT="${VERSION#min-v}"
else
  IMAGE_TAG_DEFAULT="${VERSION#v}"
fi
IMAGE_TAG="${5:-${IMAGE_TAG_DEFAULT}}"
USE_GIT_SOURCE="false"
if test_git_source_available; then
  USE_GIT_SOURCE="true"
fi

assert_current_appliance_layout

OUT_DIR="${ROOT_DIR}/deploy/releases/${VERSION}"
BUNDLE_DIR="${OUT_DIR}/click2fix-appliance-${VERSION}"
ZIP_FILE="${OUT_DIR}/click2fix-patch-workbench-installer-${VERSION}.zip"
SHA_FILE="${OUT_DIR}/click2fix-patch-workbench-installer-${VERSION}.sha256"
APPLIANCE_FILES=(
  ".env.patch-workbench.template"
  "bootstrap-patch-workbench.ps1"
  "bootstrap-patch-workbench.sh"
  "docker-compose.patch-workbench.yml"
  "nginx.conf"
  "install-patch-workbench.ps1"
  "install-patch-workbench.sh"
  "manage-patch-workbench.ps1"
  "manage-patch-workbench.sh"
  "PATCH_WORKBENCH_MIN_INSTALL_AND_CONFIGURATION.md"
  "preflight.ps1"
  "README.md"
  "upgrade-patch-workbench.ps1"
  "upgrade-patch-workbench.sh"
)

mkdir -p "${OUT_DIR}"
rm -rf "${BUNDLE_DIR}" "${ZIP_FILE}" "${SHA_FILE}"
mkdir -p "${BUNDLE_DIR}"

for file in "${APPLIANCE_FILES[@]}"; do
  export_source_file "${APPLIANCE_DIR}/${file}" "deploy/appliance/${file}" "${BUNDLE_DIR}/${file}"
done

ENV_FILE="${BUNDLE_DIR}/.env.patch-workbench.template"
sed -i "s|^C2F_BACKEND_IMAGE=.*|C2F_BACKEND_IMAGE=${BACKEND_IMAGE}|" "${ENV_FILE}"
sed -i "s|^C2F_FRONTEND_IMAGE=.*|C2F_FRONTEND_IMAGE=${FRONTEND_IMAGE}|" "${ENV_FILE}"
sed -i "s|^C2F_IMAGE_TAG=.*|C2F_IMAGE_TAG=${IMAGE_TAG}|" "${ENV_FILE}"
sed -i "s|^C2F_SKIP_PULL=.*|C2F_SKIP_PULL=false|" "${ENV_FILE}"

(
  cd "${BUNDLE_DIR}"
  zip -r "${ZIP_FILE}" . >/dev/null
)

(
  cd "${OUT_DIR}"
  sha256sum "$(basename "${ZIP_FILE}")" > "$(basename "${SHA_FILE}")"
)

echo "Built installer bundle:"
echo "  ${ZIP_FILE}"
echo "  ${SHA_FILE}"
