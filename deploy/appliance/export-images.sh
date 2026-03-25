#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env.appliance"
OUTPUT_FILE="${1:-${SCRIPT_DIR}/click2fix-images.tar}"

get_env() {
  local key="$1"
  local default="$2"
  if [[ -f "${ENV_FILE}" ]]; then
    local value
    value="$(awk -F= -v k="$key" '$1==k {sub($1"=",""); print; exit}' "${ENV_FILE}")"
    if [[ -n "${value}" ]]; then
      echo "${value}"
      return
    fi
  fi
  echo "${default}"
}

BACKEND_IMAGE="$(get_env C2F_BACKEND_IMAGE click2fix-backend)"
FRONTEND_IMAGE="$(get_env C2F_FRONTEND_IMAGE click2fix-frontend)"
POSTGRES_IMAGE_TAG="$(get_env POSTGRES_IMAGE_TAG 16)"
IMAGE_TAG="$(get_env C2F_IMAGE_TAG local)"
POSTGRES_IMAGE="postgres:${POSTGRES_IMAGE_TAG}"

if ! docker image inspect "${POSTGRES_IMAGE}" >/dev/null 2>&1; then
  echo "Pulling ${POSTGRES_IMAGE} ..."
  docker pull "${POSTGRES_IMAGE}" >/dev/null
fi
docker image inspect "${BACKEND_IMAGE}:${IMAGE_TAG}" >/dev/null 2>&1
docker image inspect "${FRONTEND_IMAGE}:${IMAGE_TAG}" >/dev/null 2>&1

echo "Exporting images to ${OUTPUT_FILE} ..."
docker save -o "${OUTPUT_FILE}" "${POSTGRES_IMAGE}" "${BACKEND_IMAGE}:${IMAGE_TAG}" "${FRONTEND_IMAGE}:${IMAGE_TAG}"
echo "Export complete."
