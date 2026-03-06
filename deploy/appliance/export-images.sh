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
AGENT_MANAGER_IMAGE="$(get_env C2F_AGENT_MANAGER_IMAGE click2fix-agent-manager)"
EVENT_INDEXER_IMAGE="$(get_env C2F_EVENT_INDEXER_IMAGE click2fix-event-indexer)"
IMAGE_TAG="$(get_env C2F_IMAGE_TAG local)"

docker image inspect "${BACKEND_IMAGE}:${IMAGE_TAG}" >/dev/null 2>&1
docker image inspect "${FRONTEND_IMAGE}:${IMAGE_TAG}" >/dev/null 2>&1
docker image inspect "${AGENT_MANAGER_IMAGE}:${IMAGE_TAG}" >/dev/null 2>&1
docker image inspect "${EVENT_INDEXER_IMAGE}:${IMAGE_TAG}" >/dev/null 2>&1

echo "Exporting images to ${OUTPUT_FILE} ..."
docker save -o "${OUTPUT_FILE}" "${BACKEND_IMAGE}:${IMAGE_TAG}" "${FRONTEND_IMAGE}:${IMAGE_TAG}" "${AGENT_MANAGER_IMAGE}:${IMAGE_TAG}" "${EVENT_INDEXER_IMAGE}:${IMAGE_TAG}"
echo "Export complete."
