#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
APPLIANCE_DIR="${ROOT_DIR}/deploy/appliance"

VERSION="${1:-v0.0.0-local}"
OWNER="${2:-your-org}"
BACKEND_IMAGE="${3:-ghcr.io/${OWNER}/click2fix-backend}"
FRONTEND_IMAGE="${4:-ghcr.io/${OWNER}/click2fix-frontend}"
IMAGE_TAG="${5:-${VERSION#v}}"

OUT_DIR="${ROOT_DIR}/deploy/releases/${VERSION}"
BUNDLE_DIR="${OUT_DIR}/click2fix-appliance-${VERSION}"
ZIP_FILE="${OUT_DIR}/click2fix-appliance-installer-${VERSION}.zip"
SHA_FILE="${OUT_DIR}/click2fix-appliance-installer-${VERSION}.sha256"

mkdir -p "${OUT_DIR}"
rm -rf "${BUNDLE_DIR}" "${ZIP_FILE}" "${SHA_FILE}"
mkdir -p "${BUNDLE_DIR}"

cp -r "${APPLIANCE_DIR}/." "${BUNDLE_DIR}/"

ENV_FILE="${BUNDLE_DIR}/.env.appliance.template"
sed -i "s|^C2F_BACKEND_IMAGE=.*|C2F_BACKEND_IMAGE=${BACKEND_IMAGE}|" "${ENV_FILE}"
sed -i "s|^C2F_FRONTEND_IMAGE=.*|C2F_FRONTEND_IMAGE=${FRONTEND_IMAGE}|" "${ENV_FILE}"
sed -i "s|^C2F_IMAGE_TAG=.*|C2F_IMAGE_TAG=${IMAGE_TAG}|" "${ENV_FILE}"
sed -i "s|^C2F_SKIP_PULL=.*|C2F_SKIP_PULL=false|" "${ENV_FILE}"

(
  cd "${OUT_DIR}"
  zip -r "$(basename "${ZIP_FILE}")" "$(basename "${BUNDLE_DIR}")" >/dev/null
)

(
  cd "${OUT_DIR}"
  sha256sum "$(basename "${ZIP_FILE}")" > "$(basename "${SHA_FILE}")"
)

echo "Built installer bundle:"
echo "  ${ZIP_FILE}"
echo "  ${SHA_FILE}"
