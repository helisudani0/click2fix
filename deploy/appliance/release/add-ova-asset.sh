#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

VERSION="${1:-}"
SOURCE_OVA="${2:-}"
ASSET_NAME="${3:-}"

if [[ -z "${VERSION}" || -z "${SOURCE_OVA}" ]]; then
  echo "Usage: $0 <version-tag> <source-ova-path> [asset-name]"
  echo "Example: $0 v1.1.4 /tmp/click2fix-appliance-v1.1.4.ova"
  exit 1
fi

if [[ ! -f "${SOURCE_OVA}" ]]; then
  echo "ERROR: source OVA file not found: ${SOURCE_OVA}" >&2
  exit 1
fi

if [[ -z "${ASSET_NAME}" ]]; then
  ASSET_NAME="click2fix-appliance-${VERSION}.ova"
fi

OUT_DIR="${ROOT_DIR}/deploy/releases/${VERSION}"
mkdir -p "${OUT_DIR}"

TARGET_OVA="${OUT_DIR}/${ASSET_NAME}"
cp "${SOURCE_OVA}" "${TARGET_OVA}"

HASH="$(sha256sum "${TARGET_OVA}" | awk '{print $1}')"
SHA_FILE="${TARGET_OVA}.sha256"
printf "%s  %s\n" "${HASH}" "$(basename "${TARGET_OVA}")" > "${SHA_FILE}"

echo "Prepared OVA release assets:"
echo "  ${TARGET_OVA}"
echo "  ${SHA_FILE}"
echo
echo "Upload both files to the GitHub release for ${VERSION}."
