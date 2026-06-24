#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd -P)"
SOURCE="${AUGENMASS_PLUGIN_ONLY_SOURCE:-${ROOT}/plugins/augenmass-workbench}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/augenmass-plugin-only-smoke.XXXXXX")"
OUT="$(mktemp "${TMPDIR:-/tmp}/augenmass-plugin-only-smoke-out.XXXXXX")"

cleanup() {
  rm -rf "${TMP}"
  rm -f "${OUT}"
}
trap cleanup EXIT

must_fail() {
  if "$@" >"${OUT}" 2>&1; then
    echo "command unexpectedly succeeded: $*" >&2
    exit 1
  fi
}

if [ ! -d "${SOURCE}" ]; then
  echo "missing plugin source: ${SOURCE}" >&2
  exit 1
fi

cp -R "${SOURCE}" "${TMP}/augenmass-workbench"
PLUGIN_ROOT="${TMP}/augenmass-workbench"
BIN="${PLUGIN_ROOT}/bin/augenmass"
SKILL="${PLUGIN_ROOT}/skills/augenmass/SKILL.md"
OPENAI_AGENT="${PLUGIN_ROOT}/skills/augenmass/agents/openai.yaml"
ASK_REF="${PLUGIN_ROOT}/skills/augenmass/reference/ask-it-like-this.md"
EXPLAINER_REF="${PLUGIN_ROOT}/skills/augenmass/reference/explainer.md"
RUN_DIR="${TMP}/no-checkout"
mkdir -p "${RUN_DIR}"

for path in "${BIN}" "${SKILL}" "${OPENAI_AGENT}" "${ASK_REF}" "${EXPLAINER_REF}" "${PLUGIN_ROOT}/.claude-plugin/plugin.json" "${PLUGIN_ROOT}/.codex-plugin/plugin.json"; do
  if [ ! -e "${path}" ]; then
    echo "plugin-only copy is missing: ${path}" >&2
    exit 1
  fi
done

if [ ! -x "${BIN}" ]; then
  echo "plugin-only binary is not executable: ${BIN}" >&2
  exit 1
fi

cd "${RUN_DIR}"

if [ -e fixtures ] || [ -e examples ]; then
  echo "plugin-only smoke must run without checkout fixtures/examples" >&2
  exit 1
fi

"${BIN}" --version >"${OUT}"
grep -q '^augenmass ' "${OUT}"

"${BIN}" baselines >"${OUT}"
grep -q 'age_gate_18' "${OUT}"

"${BIN}" generate regbody --json | "${BIN}" check - >"${OUT}"
grep -q 'OK: no over-ask' "${OUT}"

if "${BIN}" generate regbody --over-broad | "${BIN}" check - >"${OUT}" 2>&1; then
  echo "over-broad generated body unexpectedly passed check" >&2
  exit 1
fi
grep -q 'OVER-ASK' "${OUT}"

must_fail "${BIN}" audit --request overask --purpose age_gate_18
grep -q 'OVER-ASK' "${OUT}"

"${BIN}" generate dcql --claim age_equal_or_over.18 | "${BIN}" validate dcql - >"${OUT}"
grep -q 'DCQL VALID' "${OUT}"

"${BIN}" cache serve --help >"${OUT}"
grep -q -- '--max-entries' "${OUT}"
grep -q -- '--allowed-rp' "${OUT}"

"${BIN}" cache status --help >"${OUT}"
grep -q -- '--api-base' "${OUT}"
grep -q -- '--admin-token' "${OUT}"

"${BIN}" serve --help >"${OUT}"
grep -q -- '--unsafe-debug-artifacts' "${OUT}"

grep -q 'Do not assume those files exist' "${SKILL}"
grep -q 'Use \$augenmass to show the purpose baselines' "${OPENAI_AGENT}"
grep -q 'Non-Technical Answer Example' "${ASK_REF}"
grep -q 'Plain-Language Rule' "${EXPLAINER_REF}"

echo "plugin-only smoke passed"
