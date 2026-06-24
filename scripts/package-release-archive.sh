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

hash_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    echo "missing required command for hashing: shasum or sha256sum" >&2
    exit 1
  fi
}

json_escape() {
  awk -v s="$1" 'BEGIN {
    gsub(/\\/, "\\\\", s);
    gsub(/"/, "\\\"", s);
    gsub(/\t/, "\\t", s);
    gsub(/\r/, "\\r", s);
    gsub(/\n/, "\\n", s);
    printf "%s", s;
  }'
}

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

ARCHIVE_BASE="$(basename "${ARCHIVE}")"
BINARY_BASE="$(basename "${BINARY}")"
ARCHIVE_SHA256="$(hash_file "${ARCHIVE}")"
BINARY_SHA256="$(hash_file "${BINARY}")"
RUSTC_VERSION="$(rustc -V)"
RUSTC_HOST="$(rustc -vV | sed -n 's/^host: //p')"
BINARY_ACTUAL_HOST="${AUGENMASS_RELEASE_BINARY_ACTUAL_HOST:-${RUSTC_HOST}}"
GIT_COMMIT="$(git rev-parse HEAD 2>/dev/null || printf unknown)"
if git diff --quiet --ignore-submodules -- 2>/dev/null && git diff --cached --quiet --ignore-submodules -- 2>/dev/null; then
  GIT_DIRTY=false
else
  GIT_DIRTY=true
fi
if [ "${AUGENMASS_RELEASE_LAYOUT_ONLY:-0}" = "1" ]; then
  LAYOUT_ONLY=true
  NATIVE_EXECUTION=false
else
  LAYOUT_ONLY=false
  NATIVE_EXECUTION=true
fi
GITHUB_REF_VALUE="${GITHUB_REF_NAME:-${GITHUB_REF:-}}"
GITHUB_RUN_ID_VALUE="${GITHUB_RUN_ID:-}"

printf '%s  %s\n' "${ARCHIVE_SHA256}" "${ARCHIVE_BASE}" >"${ARCHIVE}.sha256"

cat >"${ARCHIVE}.manifest.json" <<EOF
{
  "schema": "augenmass-release-manifest-v1",
  "version": "${VERSION}",
  "target": "${TARGET}",
  "packageName": "${NAME}",
  "packageExt": "${PACKAGE_EXT}",
  "archive": "${ARCHIVE_BASE}",
  "archiveSha256": "${ARCHIVE_SHA256}",
  "binary": "${BINARY_BASE}",
  "binarySha256": "${BINARY_SHA256}",
  "binaryActualHost": "$(json_escape "${BINARY_ACTUAL_HOST}")",
  "layoutOnly": ${LAYOUT_ONLY},
  "nativeExecution": ${NATIVE_EXECUTION},
  "gitCommit": "$(json_escape "${GIT_COMMIT}")",
  "gitDirty": ${GIT_DIRTY},
  "rustcVersion": "$(json_escape "${RUSTC_VERSION}")",
  "rustcHost": "$(json_escape "${RUSTC_HOST}")",
  "githubRef": "$(json_escape "${GITHUB_REF_VALUE}")",
  "githubRunId": "$(json_escape "${GITHUB_RUN_ID_VALUE}")"
}
EOF

echo "${ARCHIVE}"
