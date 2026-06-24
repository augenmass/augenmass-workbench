#!/usr/bin/env bash
set -euo pipefail

resolve_bin() {
  if [ -n "${AUGENMASS_SMOKE_BIN:-}" ]; then
    printf '%s\n' "${AUGENMASS_SMOKE_BIN}"
  elif [ -n "${AUGENMASS_BIN:-}" ]; then
    printf '%s\n' "${AUGENMASS_BIN}"
  else
    printf '%s\n' "./plugins/augenmass-workbench/bin/augenmass"
  fi
}

BIN="$(resolve_bin)"
RP="${AUGENMASS_SMOKE_RP:-2af138a8-59ea-4a84-aea3-666cafdb1369}"
WRITE="${AUGENMASS_LIVE_SANDBOX_WRITE:-0}"
REQUIRED="${AUGENMASS_LIVE_SANDBOX_REQUIRED:-0}"
BODY_JSON="$(mktemp "${TMPDIR:-/tmp}/augenmass-live-sandbox-body.XXXXXX.json")"
OUT="$(mktemp "${TMPDIR:-/tmp}/augenmass-live-sandbox-smoke.XXXXXX")"

cleanup() {
  rm -f "${BODY_JSON}" "${OUT}"
}
trap cleanup EXIT

missing=()
for name in AUGENMASS_OIDC_TOKEN_URL AUGENMASS_USERNAME AUGENMASS_PASSWORD; do
  if [ -z "${!name:-}" ]; then
    missing+=("${name}")
  fi
done

if [ "${#missing[@]}" -gt 0 ]; then
  if [ "${REQUIRED}" = "1" ]; then
    printf 'live sandbox smoke required mode missing %s\n' "${missing[*]}" >&2
    exit 1
  fi
  printf 'live sandbox smoke skipped: missing %s\n' "${missing[*]}"
  exit 0
fi

if [ ! -x "${BIN}" ]; then
  echo "smoke binary is not executable: ${BIN}" >&2
  exit 1
fi

"${BIN}" generate regbody --rp "${RP}" --json >"${BODY_JSON}"

"${BIN}" check "${BODY_JSON}" >"${OUT}"
grep -q "OK: no over-ask" "${OUT}"
echo "local guardrail check: ok"

"${BIN}" register "${BODY_JSON}" --target sandbox >"${OUT}"
grep -q "DRY RUN: nothing written" "${OUT}"
echo "sandbox dry-run write: ok"

"${BIN}" list --target sandbox --rp "${RP}" >"${OUT}"
grep -q "registration(s) for RP ${RP} on sandbox" "${OUT}"
echo "sandbox list: $(sed -n '1p' "${OUT}")"

if [ "${WRITE}" = "1" ]; then
  "${BIN}" register "${BODY_JSON}" --target sandbox --yes >"${OUT}"
  echo "sandbox confirmed write: $(sed -n '1p' "${OUT}")"
else
  echo "sandbox confirmed write: skipped (set AUGENMASS_LIVE_SANDBOX_WRITE=1 to enable)"
fi

echo "live sandbox smoke passed"
