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
    git -C "${ROOT_DIR}" cat-file -e "HEAD:${repo_path}" >/dev/null 2>&1
    return $?
  fi
  [[ -f "${fs_path}" ]]
}

read_source_text() {
  local fs_path="$1"
  local repo_path="$2"
  if [[ "${USE_GIT_SOURCE}" == "true" ]]; then
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
  if [[ "${USE_GIT_SOURCE}" == "true" ]]; then
    read_source_text "${fs_path}" "${repo_path}" > "${dest_path}"
    return
  fi
  cp "${fs_path}" "${dest_path}"
}

assert_current_appliance_layout() {
  local compose_path="${APPLIANCE_DIR}/docker-compose.appliance.yml"
  local env_template_path="${APPLIANCE_DIR}/.env.appliance.template"
  source_file_exists "${compose_path}" "deploy/appliance/docker-compose.appliance.yml" || {
    echo "ERROR: missing required appliance file: docker-compose.appliance.yml" >&2
    exit 1
  }
  source_file_exists "${env_template_path}" "deploy/appliance/.env.appliance.template" || {
    echo "ERROR: missing required appliance file: .env.appliance.template" >&2
    exit 1
  }

  read_source_text "${compose_path}" "deploy/appliance/docker-compose.appliance.yml" | grep -Eq '^[[:space:]]*(agent-manager|event-indexer|alert-service|case-service|ingest-gateway|soar-service|detection-service)[[:space:]]*:' && {
    echo "ERROR: deploy/appliance/docker-compose.appliance.yml currently includes v2-only services. Clean it before building the current release bundle." >&2
    exit 1
  }

  read_source_text "${compose_path}" "deploy/appliance/docker-compose.appliance.yml" | grep -Eq '^[[:space:]]*db[[:space:]]*:' || {
    echo "ERROR: appliance compose file is missing db service." >&2
    exit 1
  }
  read_source_text "${compose_path}" "deploy/appliance/docker-compose.appliance.yml" | grep -Eq '^[[:space:]]*backend[[:space:]]*:' || {
    echo "ERROR: appliance compose file is missing backend service." >&2
    exit 1
  }
  read_source_text "${compose_path}" "deploy/appliance/docker-compose.appliance.yml" | grep -Eq '^[[:space:]]*frontend[[:space:]]*:' || {
    echo "ERROR: appliance compose file is missing frontend service." >&2
    exit 1
  }

  read_source_text "${env_template_path}" "deploy/appliance/.env.appliance.template" | grep -Eq '^[[:space:]]*(AGENT_MANAGER_IMAGE|EVENT_INDEXER_IMAGE|ALERT_SERVICE_IMAGE|CASE_SERVICE_IMAGE|INGEST_GATEWAY_IMAGE|SOAR_SERVICE_IMAGE|DETECTION_SERVICE_IMAGE)=' && {
    echo "ERROR: deploy/appliance/.env.appliance.template currently includes v2-only image settings. Clean it before building the current release bundle." >&2
    exit 1
  }
}

VERSION="${1:-v0.0.0-local}"
OWNER="${2:-your-org}"
BACKEND_IMAGE="${3:-ghcr.io/${OWNER}/click2fix-backend}"
FRONTEND_IMAGE="${4:-ghcr.io/${OWNER}/click2fix-frontend}"
IMAGE_TAG="${5:-${VERSION#v}}"
USE_GIT_SOURCE="false"
if test_git_source_available; then
  USE_GIT_SOURCE="true"
fi

assert_current_appliance_layout

OUT_DIR="${ROOT_DIR}/deploy/releases/${VERSION}"
BUNDLE_DIR="${OUT_DIR}/click2fix-appliance-${VERSION}"
ZIP_FILE="${OUT_DIR}/click2fix-appliance-installer-${VERSION}.zip"
SHA_FILE="${OUT_DIR}/click2fix-appliance-installer-${VERSION}.sha256"
APPLIANCE_FILES=(
  ".env.appliance.template"
  "bootstrap-from-github.ps1"
  "bootstrap-from-github.sh"
  "build-local-images.ps1"
  "build-local-images.sh"
  "docker-compose.appliance.yml"
  "nginx.conf"
  "export-images.ps1"
  "export-images.sh"
  "import-images.ps1"
  "import-images.sh"
  "install.ps1"
  "install.sh"
  "manage.cmd"
  "manage.ps1"
  "manage.sh"
  "preflight.ps1"
  "README.md"
  "setup.cmd"
  "setup.sh"
  "upgrade.ps1"
  "upgrade.sh"
  "firstboot/c2f-firstboot.service"
  "firstboot/c2f-firstboot.sh"
  "firstboot/install-firstboot-service.sh"
)

mkdir -p "${OUT_DIR}"
rm -rf "${BUNDLE_DIR}" "${ZIP_FILE}" "${SHA_FILE}"
mkdir -p "${BUNDLE_DIR}"

for file in "${APPLIANCE_FILES[@]}"; do
  export_source_file "${APPLIANCE_DIR}/${file}" "deploy/appliance/${file}" "${BUNDLE_DIR}/${file}"
done

ENV_FILE="${BUNDLE_DIR}/.env.appliance.template"
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
