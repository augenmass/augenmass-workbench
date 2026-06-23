#!/usr/bin/env bash
set -euo pipefail

ROOT="$(mktemp -d "${TMPDIR:-/tmp}/augenmass-install-smoke.XXXXXX")"

cleanup() {
  rm -rf "${ROOT}"
}
trap cleanup EXIT

if ! command -v cargo >/dev/null 2>&1; then
  echo "missing required command: cargo" >&2
  exit 1
fi

cargo install --locked --path . --bin augenmass --root "${ROOT}" --force

BIN="${ROOT}/bin/augenmass"
if [ ! -f "${BIN}" ] && [ -f "${BIN}.exe" ]; then
  BIN="${BIN}.exe"
fi
if [ ! -x "${BIN}" ]; then
  echo "installed binary is missing or not executable: ${BIN}" >&2
  exit 1
fi

"${BIN}" --version
"${BIN}" --help >/dev/null
"${BIN}" inspect fixtures/requests/eudiplo-request.jwt >/dev/null
"${BIN}" generate regbody --json | "${BIN}" check - >/dev/null

echo "install smoke passed: ${BIN}"
