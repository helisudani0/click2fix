#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INPUT_FILE="${1:-${SCRIPT_DIR}/click2fix-images.tar}"

if [[ ! -f "${INPUT_FILE}" ]]; then
  echo "ERROR: image bundle not found: ${INPUT_FILE}" >&2
  exit 1
fi

echo "Importing images from ${INPUT_FILE} ..."
docker load -i "${INPUT_FILE}"
echo "Import complete."
