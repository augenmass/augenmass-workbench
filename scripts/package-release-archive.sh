#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: $0 <target-triple> <binary-path> <tar.gz|zip> <out-dir>" >&2
  exit 2
fi

TARGET="$1"
BINARY="$2"
PACKAGE_EXT="$3"
OUT_DIR="$4"

if [ ! -f "${BINARY}" ]; then
  echo "binary does not exist: ${BINARY}" >&2
  exit 1
fi

VERSION="$(
  awk -F '=' '
    $1 ~ /^[[:space:]]*version[[:space:]]*$/ {
      gsub(/[[:space:]"]/, "", $2);
      print $2;
      exit;
    }
  ' Cargo.toml
)"
if [ -z "${VERSION}" ]; then
  echo "could not read package version from Cargo.toml" >&2
  exit 1
fi

NAME="augenmass-v${VERSION}-${TARGET}"
PACKAGE_DIR="${OUT_DIR}/${NAME}"
ARCHIVE="${OUT_DIR}/${NAME}.${PACKAGE_EXT}"

rm -rf "${PACKAGE_DIR}" "${ARCHIVE}"
mkdir -p "${PACKAGE_DIR}"

cp "${BINARY}" "${PACKAGE_DIR}/"
cp README.md LICENSE NOTICE "${PACKAGE_DIR}/"
cp -R docs examples fixtures "${PACKAGE_DIR}/"

case "${PACKAGE_EXT}" in
  tar.gz)
    tar -C "${OUT_DIR}" -czf "${ARCHIVE}" "${NAME}"
    ;;
  zip)
    if command -v 7z >/dev/null 2>&1; then
      (cd "${OUT_DIR}" && 7z a "${NAME}.zip" "${NAME}" >/dev/null)
    elif command -v zip >/dev/null 2>&1; then
      (cd "${OUT_DIR}" && zip -qr "${NAME}.zip" "${NAME}")
    else
      echo "missing required command for zip packaging: 7z or zip" >&2
      exit 1
    fi
    ;;
  *)
    echo "unsupported package extension: ${PACKAGE_EXT}" >&2
    exit 2
    ;;
esac

echo "${ARCHIVE}"
