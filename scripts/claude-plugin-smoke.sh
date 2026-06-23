#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd -P)"
TMP_HOME="$(mktemp -d "${TMPDIR:-/tmp}/augenmass-claude-plugin-smoke.XXXXXX")"
OUT="$(mktemp "${TMPDIR:-/tmp}/augenmass-claude-plugin-smoke-out.XXXXXX")"
PLUGIN_ROOT="${ROOT}/plugins/augenmass-workbench"
MARKETPLACE="${ROOT}/.claude-plugin/marketplace.json"
CARGO_VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "${ROOT}/Cargo.toml" | head -n 1)"

cleanup() {
  rm -rf "${TMP_HOME}"
  rm -f "${OUT}"
}
trap cleanup EXIT

if ! command -v claude >/dev/null 2>&1; then
  echo "missing required command: claude" >&2
  exit 1
fi

if [ -z "${CARGO_VERSION}" ]; then
  echo "could not read package version from Cargo.toml" >&2
  exit 1
fi

HOME="${TMP_HOME}" claude plugin validate --strict "${PLUGIN_ROOT}" >"${OUT}"
HOME="${TMP_HOME}" claude plugin validate --strict "${MARKETPLACE}" >"${OUT}"

HOME="${TMP_HOME}" claude plugin marketplace add "${MARKETPLACE}" >"${OUT}"
grep -q "Successfully added marketplace: augenmass" "${OUT}"

HOME="${TMP_HOME}" claude plugin list --available --json >"${OUT}"
grep -q '"pluginId": "augenmass-workbench@augenmass"' "${OUT}"
grep -q '"marketplaceName": "augenmass"' "${OUT}"
grep -q '"source": "./plugins/augenmass-workbench"' "${OUT}"

HOME="${TMP_HOME}" claude plugin install augenmass-workbench@augenmass --scope user >"${OUT}"
grep -q "Successfully installed plugin: augenmass-workbench@augenmass" "${OUT}"

HOME="${TMP_HOME}" claude plugin list --json >"${OUT}"
grep -q '"id": "augenmass-workbench@augenmass"' "${OUT}"
grep -q "\"version\": \"${CARGO_VERSION}\"" "${OUT}"
grep -q '"scope": "user"' "${OUT}"
grep -q '"enabled": true' "${OUT}"

echo "claude plugin smoke passed"
