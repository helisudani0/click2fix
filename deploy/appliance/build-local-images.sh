#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env.appliance"

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

echo "Building local appliance images..."
echo "  Backend:  ${BACKEND_IMAGE}:${IMAGE_TAG}"
echo "  Frontend: ${FRONTEND_IMAGE}:${IMAGE_TAG}"
echo "  Agent Manager: ${AGENT_MANAGER_IMAGE}:${IMAGE_TAG}"
echo "  Event Indexer: ${EVENT_INDEXER_IMAGE}:${IMAGE_TAG}"

docker build -f "${ROOT_DIR}/docker/backend.Dockerfile" -t "${BACKEND_IMAGE}:${IMAGE_TAG}" "${ROOT_DIR}"
docker build -f "${ROOT_DIR}/docker/frontend.Dockerfile" -t "${FRONTEND_IMAGE}:${IMAGE_TAG}" "${ROOT_DIR}"
docker build -f "${ROOT_DIR}/docker/agent-manager.Dockerfile" -t "${AGENT_MANAGER_IMAGE}:${IMAGE_TAG}" "${ROOT_DIR}"
docker build -f "${ROOT_DIR}/docker/event-indexer.Dockerfile" -t "${EVENT_INDEXER_IMAGE}:${IMAGE_TAG}" "${ROOT_DIR}"

echo "Build complete."
