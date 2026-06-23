#!/usr/bin/env bash
set -euo pipefail

BIN="${AUGENMASS_SMOKE_BIN:-./plugins/augenmass-workbench/bin/augenmass}"
RP="${AUGENMASS_SMOKE_RP:-2af138a8-59ea-4a84-aea3-666cafdb1369}"
WRITE="${AUGENMASS_LIVE_SANDBOX_WRITE:-0}"
BODY="$(mktemp "${TMPDIR:-/tmp}/augenmass-live-sandbox-smoke.XXXXXX")"

cleanup() {
  rm -f "${BODY}"
}
trap cleanup EXIT

missing=()
for name in AUGENMASS_OIDC_TOKEN_URL AUGENMASS_USERNAME AUGENMASS_PASSWORD; do
  if [ -z "${!name:-}" ]; then
    missing+=("${name}")
  fi
done

if [ "${#missing[@]}" -gt 0 ]; then
  printf 'live sandbox smoke skipped: missing %s\n' "${missing[*]}"
  exit 0
fi

if [ ! -x "${BIN}" ]; then
  echo "smoke binary is not executable: ${BIN}" >&2
  exit 1
fi

"${BIN}" check examples/min.json >"${BODY}"
grep -q "OK: no over-ask" "${BODY}"
echo "local guardrail check: ok"

"${BIN}" register examples/min.json --target sandbox >"${BODY}"
grep -q "DRY RUN: nothing written" "${BODY}"
echo "sandbox dry-run write: ok"

"${BIN}" list --target sandbox --rp "${RP}" >"${BODY}"
grep -q "registration(s) for RP ${RP} on sandbox" "${BODY}"
echo "sandbox list: $(sed -n '1p' "${BODY}")"

if [ "${WRITE}" = "1" ]; then
  "${BIN}" register examples/min.json --target sandbox --yes >"${BODY}"
  echo "sandbox confirmed write: $(sed -n '1p' "${BODY}")"
else
  echo "sandbox confirmed write: skipped (set AUGENMASS_LIVE_SANDBOX_WRITE=1 to enable)"
fi

echo "live sandbox smoke passed"
