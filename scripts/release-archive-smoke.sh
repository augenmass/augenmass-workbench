#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <release-archive.tar.gz|release-archive.zip>" >&2
  exit 2
fi

ARCHIVE="$1"
ROOT="$(mktemp -d "${TMPDIR:-/tmp}/augenmass-release-archive-smoke.XXXXXX")"

cleanup() {
  rm -rf "${ROOT}"
}
trap cleanup EXIT

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
