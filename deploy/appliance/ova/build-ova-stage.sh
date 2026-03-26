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

VERSION="${1:-v0.0.0-local}"
OWNER="${2:-your-org}"
BACKEND_IMAGE="${3:-ghcr.io/${OWNER}/click2fix-backend}"
FRONTEND_IMAGE="${4:-ghcr.io/${OWNER}/click2fix-frontend}"
IMAGE_TAG="${5:-${VERSION#v}}"
USE_GIT_SOURCE="false"
if test_git_source_available; then
  USE_GIT_SOURCE="true"
fi

assert_current_appliance_layout() {
  local required=(
    ".env.appliance.template"
    "docker-compose.appliance.yml"
    "install.sh"
    "setup.sh"
    "manage.sh"
    "upgrade.sh"
    "firstboot/c2f-firstboot.sh"
    "firstboot/c2f-firstboot.service"
    "firstboot/install-firstboot-service.sh"
  )

  local path
  for path in "${required[@]}"; do
    source_file_exists "${APPLIANCE_DIR}/${path}" "deploy/appliance/${path}" || {
      echo "ERROR: missing required appliance file: ${path}" >&2
      exit 1
    }
  done

  read_source_text "${APPLIANCE_DIR}/docker-compose.appliance.yml" "deploy/appliance/docker-compose.appliance.yml" | grep -Eq '^[[:space:]]*(agent-manager|event-indexer|alert-service|case-service|ingest-gateway|soar-service|detection-service)[[:space:]]*:' && {
    echo "ERROR: deploy/appliance/docker-compose.appliance.yml currently includes v2-only services. Clean it before building current-version OVA assets." >&2
    exit 1
  }

  read_source_text "${APPLIANCE_DIR}/docker-compose.appliance.yml" "deploy/appliance/docker-compose.appliance.yml" | grep -Eq '^[[:space:]]*db[[:space:]]*:' || {
    echo "ERROR: appliance compose file is missing db service." >&2
    exit 1
  }
  read_source_text "${APPLIANCE_DIR}/docker-compose.appliance.yml" "deploy/appliance/docker-compose.appliance.yml" | grep -Eq '^[[:space:]]*backend[[:space:]]*:' || {
    echo "ERROR: appliance compose file is missing backend service." >&2
    exit 1
  }
  read_source_text "${APPLIANCE_DIR}/docker-compose.appliance.yml" "deploy/appliance/docker-compose.appliance.yml" | grep -Eq '^[[:space:]]*frontend[[:space:]]*:' || {
    echo "ERROR: appliance compose file is missing frontend service." >&2
    exit 1
  }

  read_source_text "${APPLIANCE_DIR}/.env.appliance.template" "deploy/appliance/.env.appliance.template" | grep -Eq '^[[:space:]]*(AGENT_MANAGER_IMAGE|EVENT_INDEXER_IMAGE|ALERT_SERVICE_IMAGE|CASE_SERVICE_IMAGE|INGEST_GATEWAY_IMAGE|SOAR_SERVICE_IMAGE|DETECTION_SERVICE_IMAGE)=' && {
    echo "ERROR: deploy/appliance/.env.appliance.template currently includes v2-only image settings. Clean it before building current-version OVA assets." >&2
    exit 1
  }
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

assert_current_appliance_layout

OUT_DIR="${ROOT_DIR}/deploy/releases/${VERSION}"
STAGE_DIR="${OUT_DIR}/click2fix-appliance-ova-stage-${VERSION}"
STAGE_ROOT="${STAGE_DIR}/opt/click2fix/deploy/appliance"
STAGE_README="${STAGE_DIR}/OVA_STAGE_README.txt"

APPLIANCE_FILES=(
  ".env.appliance.template"
  "bootstrap-from-github.ps1"
  "bootstrap-from-github.sh"
  "build-local-images.ps1"
  "build-local-images.sh"
  "docker-compose.appliance.yml"
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

rm -rf "${STAGE_DIR}"

for file in "${APPLIANCE_FILES[@]}"; do
  export_source_file "${APPLIANCE_DIR}/${file}" "deploy/appliance/${file}" "${STAGE_ROOT}/${file}"
done

ENV_FILE="${STAGE_ROOT}/.env.appliance.template"
set_env C2F_BACKEND_IMAGE "${BACKEND_IMAGE}" "${ENV_FILE}"
set_env C2F_FRONTEND_IMAGE "${FRONTEND_IMAGE}" "${ENV_FILE}"
set_env C2F_IMAGE_TAG "${IMAGE_TAG}" "${ENV_FILE}"
set_env C2F_SKIP_PULL "false" "${ENV_FILE}"

cat > "${STAGE_README}" <<EOF
Click2Fix OVA Stage Bundle
==========================

Version: ${VERSION}
Backend image: ${BACKEND_IMAGE}:${IMAGE_TAG}
Frontend image: ${FRONTEND_IMAGE}:${IMAGE_TAG}
Database image: postgres:16

This staged directory is intended to be copied into a Linux VM image at:

  /opt/click2fix/deploy/appliance

Recommended VM build flow:

1. Start from Ubuntu Server LTS.
2. Install Docker Engine and the Docker Compose plugin inside the VM.
3. Copy the staged opt/ tree from this bundle into the VM root filesystem.
4. Inside the VM, run:

     cd /opt/click2fix/deploy/appliance/firstboot
     sudo ./install-firstboot-service.sh

5. Power off the VM and export it as an OVA from your hypervisor.

When the customer boots the VM, the first-boot unit launches the existing
Click2Fix installer and keeps the runtime on the supported v1.1.4 image set.
EOF

echo "Built OVA stage bundle:"
echo "  ${STAGE_DIR}"
echo
echo "Next step:"
echo "  Copy the staged opt/ tree into a Linux VM image and install the first-boot service."
