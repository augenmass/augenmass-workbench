#!/usr/bin/env bash
set -euo pipefail

TARGET="${AUGENMASS_ZIP_LAYOUT_TARGET:-x86_64-pc-windows-msvc}"
OUT="${AUGENMASS_ZIP_LAYOUT_OUT:-dist/local-release-zip-layout-smoke}"
ROOT="$(mktemp -d "${TMPDIR:-/tmp}/augenmass-release-zip-layout.XXXXXX")"

cleanup() {
  rm -rf "${ROOT}"
}
trap cleanup EXIT

host="$(rustc -vV | sed -n 's/^host: //p')"
binary="target/release/augenmass"
if [ ! -f "${binary}" ] && [ -f "${binary}.exe" ]; then
  binary="${binary}.exe"
fi
if [ ! -f "${binary}" ]; then
  echo "release binary does not exist: run cargo build --release --locked first" >&2
  exit 1
fi

mkdir -p "${ROOT}" "${OUT}"
cp "${binary}" "${ROOT}/augenmass.exe"
chmod +x "${ROOT}/augenmass.exe" 2>/dev/null || true

archive="$(
  AUGENMASS_RELEASE_LAYOUT_ONLY=1 \
  AUGENMASS_RELEASE_BINARY_ACTUAL_HOST="${host}" \
    ./scripts/package-release-archive.sh "${TARGET}" "${ROOT}/augenmass.exe" zip "${OUT}"
)"
./scripts/release-archive-smoke.sh "${archive}"

if [ "${host}" = "${TARGET}" ]; then
  echo "zip release layout smoke passed for native ${TARGET}: ${archive}"
else
  echo "zip release layout smoke passed for ${TARGET}: ${archive}"
  echo "note: this proves the zip package layout on ${host}, not native Windows execution"
fi
