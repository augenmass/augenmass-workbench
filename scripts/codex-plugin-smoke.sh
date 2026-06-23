#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd -P)"
TMP_CODEX_HOME="$(mktemp -d "${TMPDIR:-/tmp}/augenmass-codex-plugin-smoke.XXXXXX")"
OUT="$(mktemp "${TMPDIR:-/tmp}/augenmass-codex-plugin-smoke-out.XXXXXX")"
CARGO_VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "${ROOT}/Cargo.toml" | head -n 1)"

cleanup() {
  rm -rf "${TMP_CODEX_HOME}"
  rm -f "${OUT}"
}
trap cleanup EXIT

if ! command -v codex >/dev/null 2>&1; then
  echo "missing required command: codex" >&2
  exit 1
fi

if [ -z "${CARGO_VERSION}" ]; then
  echo "could not read package version from Cargo.toml" >&2
  exit 1
fi

CODEX_HOME="${TMP_CODEX_HOME}" codex plugin marketplace add "${ROOT}" --json >"${OUT}"
grep -q '"marketplaceName": "augenmass"' "${OUT}"
grep -q '"alreadyAdded": false' "${OUT}"

CODEX_HOME="${TMP_CODEX_HOME}" codex plugin list --available --json >"${OUT}"
grep -q '"pluginId": "augenmass-workbench@augenmass"' "${OUT}"
grep -q '"installed": false' "${OUT}"

CODEX_HOME="${TMP_CODEX_HOME}" codex plugin add augenmass-workbench@augenmass --json >"${OUT}"
grep -q '"pluginId": "augenmass-workbench@augenmass"' "${OUT}"
grep -q "\"version\": \"${CARGO_VERSION}\"" "${OUT}"
grep -q '"authPolicy": "ON_INSTALL"' "${OUT}"

CODEX_HOME="${TMP_CODEX_HOME}" codex plugin list --json >"${OUT}"
grep -q '"pluginId": "augenmass-workbench@augenmass"' "${OUT}"
grep -q '"installed": true' "${OUT}"
grep -q '"enabled": true' "${OUT}"

echo "codex plugin smoke passed"
