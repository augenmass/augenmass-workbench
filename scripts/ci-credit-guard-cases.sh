#!/usr/bin/env bash
set -euo pipefail

# Regression cases for scripts/ci-credit-guard.sh. Each workflow under
# tests/ci-credit-guard/pass must pass the guard on its own, and each one under
# tests/ci-credit-guard/fail must make it exit 1. Every case runs in its own
# directory under WORK_DIR (first argument, or a fresh mktemp directory).

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="${ROOT}/scripts/ci-credit-guard.sh"
CASES="${ROOT}/tests/ci-credit-guard"
WORK_DIR="${1:-$(mktemp -d "${TMPDIR:-/tmp}/ci-credit-guard-cases.XXXXXX")}"

shopt -s nullglob
FAILED=0
COUNT=0

run_case() {
  local expected="$1" case_file="$2" name dir status
  name="$(basename "${case_file}" .yml)"
  dir="${WORK_DIR}/${expected}-${name}"
  mkdir -p "${dir}/.github/workflows"
  cp "${case_file}" "${dir}/.github/workflows/${name}.yml"
  set +e
  (cd "${dir}" && bash "${GUARD}") > "${dir}/guard.log" 2>&1
  status=$?
  set -e
  COUNT=$((COUNT + 1))
  if [ "${expected}" = "pass" ] && [ "${status}" -ne 0 ]; then
    echo "FAIL ${expected}/${name}: guard exited ${status}, expected 0" >&2
    sed 's/^/  /' "${dir}/guard.log" >&2
    FAILED=1
  elif [ "${expected}" = "fail" ] && [ "${status}" -ne 1 ]; then
    echo "FAIL ${expected}/${name}: guard exited ${status}, expected 1" >&2
    FAILED=1
  else
    echo "ok   ${expected}/${name} (exit ${status})"
  fi
}

for case_file in "${CASES}"/pass/*.yml; do
  run_case pass "${case_file}"
done
for case_file in "${CASES}"/fail/*.yml; do
  run_case fail "${case_file}"
done

if [ "${COUNT}" -eq 0 ]; then
  echo "no ci credit guard cases found under ${CASES}" >&2
  exit 1
fi
if [ "${FAILED}" -ne 0 ]; then
  exit 1
fi
echo "ci credit guard cases passed: ${COUNT} cases"
