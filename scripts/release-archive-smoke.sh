#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <release-archive.tar.gz|release-archive.zip>" >&2
  exit 2
fi

ARCHIVE="$1"
ROOT="$(mktemp -d "${TMPDIR:-/tmp}/augenmass-release-archive-smoke.XXXXXX")"

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

manifest_has() {
  local key="$1"
  local value="$2"
  grep -Fq "\"${key}\": \"${value}\"" "${MANIFEST}"
}

manifest_value() {
  local key="$1"
  awk -v key="\"${key}\"" '
    index($0, key) {
      sub(/^.*: *"/, "", $0);
      sub(/".*$/, "", $0);
      print;
      exit;
    }
  ' "${MANIFEST}"
}

manifest_bool() {
  local key="$1"
  awk -v key="\"${key}\"" '
    index($0, key) {
      sub(/^.*: */, "", $0);
      sub(/[,[:space:]].*$/, "", $0);
      print;
      exit;
    }
  ' "${MANIFEST}"
}

cleanup() {
  rm -rf "${ROOT}"
}
trap cleanup EXIT

ARCHIVE_SHA256="$(hash_file "${ARCHIVE}")"
SHA_FILE="${ARCHIVE}.sha256"
MANIFEST="${ARCHIVE}.manifest.json"

if [ ! -f "${SHA_FILE}" ] || [ ! -f "${MANIFEST}" ]; then
  if [ "${AUGENMASS_ALLOW_MISSING_RELEASE_SIDECARS:-0}" != "1" ]; then
    echo "release archive is missing required sidecars: ${SHA_FILE} and ${MANIFEST}" >&2
    echo "set AUGENMASS_ALLOW_MISSING_RELEASE_SIDECARS=1 only for legacy archives" >&2
    exit 1
  fi
fi

if [ -f "${SHA_FILE}" ]; then
  read -r expected_sha expected_name <"${SHA_FILE}"
  if [ "${expected_sha}" != "${ARCHIVE_SHA256}" ]; then
    echo "archive checksum sidecar does not match ${ARCHIVE}" >&2
    exit 1
  fi
  if [ "${expected_name}" != "$(basename "${ARCHIVE}")" ]; then
    echo "archive checksum sidecar names ${expected_name}, expected $(basename "${ARCHIVE}")" >&2
    exit 1
  fi
fi

if [ -f "${MANIFEST}" ]; then
  manifest_has schema "augenmass-release-manifest-v1" || {
    echo "release manifest has an unknown schema" >&2
    exit 1
  }
  manifest_has archive "$(basename "${ARCHIVE}")" || {
    echo "release manifest names the wrong archive" >&2
    exit 1
  }
  manifest_has archiveSha256 "${ARCHIVE_SHA256}" || {
    echo "release manifest archiveSha256 does not match ${ARCHIVE}" >&2
    exit 1
  }
fi

case "${ARCHIVE}" in
  *.tar.gz | *.tgz)
    tar -xzf "${ARCHIVE}" -C "${ROOT}"
    ;;
  *.zip)
    if command -v unzip >/dev/null 2>&1; then
      unzip -q "${ARCHIVE}" -d "${ROOT}"
    elif command -v 7z >/dev/null 2>&1; then
      7z x "-o${ROOT}" "${ARCHIVE}" >/dev/null
    else
      echo "missing required command for zip extraction: unzip or 7z" >&2
      exit 1
    fi
    ;;
  *)
    echo "unsupported archive type: ${ARCHIVE}" >&2
    exit 2
    ;;
esac

shopt -s nullglob
entries=("${ROOT}"/*)
if [ "${#entries[@]}" -ne 1 ] || [ ! -d "${entries[0]}" ]; then
  echo "archive must contain exactly one top-level package directory" >&2
  exit 1
fi
PACKAGE="${entries[0]}"
PACKAGE_NAME="$(basename "${PACKAGE}")"

if [ -f "${MANIFEST}" ] && ! manifest_has packageName "${PACKAGE_NAME}"; then
  echo "release manifest packageName does not match ${PACKAGE_NAME}" >&2
  exit 1
fi

BIN="${PACKAGE}/augenmass"
if [ ! -f "${BIN}" ]; then
  BIN="${PACKAGE}/augenmass.exe"
fi
if [ ! -f "${BIN}" ]; then
  echo "archive does not contain an augenmass binary" >&2
  exit 1
fi
if [[ "${BIN}" != *.exe && ! -x "${BIN}" ]]; then
  echo "archive binary is not executable: ${BIN}" >&2
  exit 1
fi
BINARY_SHA256="$(hash_file "${BIN}")"

if [ -f "${MANIFEST}" ]; then
  manifest_has binary "$(basename "${BIN}")" || {
    echo "release manifest names the wrong binary" >&2
    exit 1
  }
  manifest_has binarySha256 "${BINARY_SHA256}" || {
    echo "release manifest binarySha256 does not match ${BIN}" >&2
    exit 1
  }
  layout_only="$(manifest_bool layoutOnly)"
  native_execution="$(manifest_bool nativeExecution)"
  target="$(manifest_value target)"
  actual_host="$(manifest_value binaryActualHost)"
  if [ "${layout_only}" != "true" ] && [ "${layout_only}" != "false" ]; then
    echo "release manifest layoutOnly must be a boolean" >&2
    exit 1
  fi
  if [ "${native_execution}" != "true" ] && [ "${native_execution}" != "false" ]; then
    echo "release manifest nativeExecution must be a boolean" >&2
    exit 1
  fi
  if [ "${layout_only}" = "true" ] && [ "${native_execution}" != "false" ]; then
    echo "release manifest layoutOnly=true must set nativeExecution=false" >&2
    exit 1
  fi
  if [ "${layout_only}" = "false" ] && [ "${native_execution}" != "true" ]; then
    echo "release manifest layoutOnly=false must set nativeExecution=true" >&2
    exit 1
  fi
  if [ "${target}" != "${actual_host}" ] && [ "$(basename "${BIN}")" = "augenmass.exe" ]; then
    if [ "${layout_only}" != "true" ] || [ "${native_execution}" != "false" ]; then
      echo "non-native Windows-style zip smoke must be marked layoutOnly=true and nativeExecution=false" >&2
      exit 1
    fi
  fi
fi

(
  cd "${PACKAGE}"
  test -f README.md
  test -f LICENSE
  test -f NOTICE
  test -f docs/INSTALL.md
  test -f docs/RELEASE.md
  test -f docs/COMMANDS.md
  test -f examples/min.json
  test -f examples/over.json
  test -f fixtures/requests/eudiplo-request.jwt
  test -f fixtures/mdoc/issuer-signed.hex
  test -f fixtures/dcql/eudiplo-haip-pid-de.dcql.json
  test -f fixtures/presentations/erica-vp-VALID.sdjwt
  test -f fixtures/certs/erica-trust-anchor.pem

  "${BIN}" --version
  "${BIN}" --help >/dev/null
  "${BIN}" inspect fixtures/requests/eudiplo-request.jwt >/dev/null
  "${BIN}" check examples/min.json >/dev/null
  if "${BIN}" check examples/over.json >/dev/null 2>&1; then
    echo "expected examples/over.json to fail" >&2
    exit 1
  fi
  "${BIN}" decode mdoc fixtures/mdoc/issuer-signed.hex >/dev/null
  "${BIN}" validate dcql fixtures/dcql/eudiplo-haip-pid-de.dcql.json >/dev/null
  "${BIN}" verify presentation fixtures/presentations/erica-vp-VALID.sdjwt \
    --nonce b4ba2623-76a2-486b-a1f6-f1656025d07b \
    --aud https://self-issued.me/v2 \
    --now 1780435200 >/dev/null
  "${BIN}" verify trust fixtures/presentations/erica-vp-VALID.sdjwt \
    --anchor fixtures/certs/erica-trust-anchor.pem \
    --now 1780435200 >/dev/null
)

echo "release archive smoke passed: ${ARCHIVE}"
