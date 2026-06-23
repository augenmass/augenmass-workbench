#!/usr/bin/env bash
set -euo pipefail

resolve_bin() {
  if [ -n "${AUGENMASS_DEPLOYED_CACHE_BIN:-}" ]; then
    printf '%s\n' "${AUGENMASS_DEPLOYED_CACHE_BIN}"
  elif [ -n "${AUGENMASS_BIN:-}" ]; then
    printf '%s\n' "${AUGENMASS_BIN}"
  else
    printf '%s\n' "./plugins/augenmass-workbench/bin/augenmass"
  fi
}

BIN="$(resolve_bin)"
BASE="${1:-${AUGENMASS_DEPLOYED_CACHE_API_BASE:-}}"
ADMIN="${AUGENMASS_DEPLOYED_CACHE_ADMIN_TOKEN:-}"
RP="${AUGENMASS_DEPLOYED_CACHE_RP:-2af138a8-59ea-4a84-aea3-666cafdb1369}"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/augenmass-deployed-cache-smoke.XXXXXX")"
HEADERS="${WORKDIR}/headers"
BODY="${WORKDIR}/body"
LIST_OUT="${WORKDIR}/list"

cleanup() {
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

cache_header() {
  awk -F': ' 'tolower($1)=="x-augenmass-cache" {gsub(/\r/,"",$2); print $2}' "${HEADERS}"
}

expect_cache_header() {
  case "$1" in
    HIT|MISS|REFRESHED|STALE) return 0 ;;
    *)
      echo "unexpected x-augenmass-cache header: $1" >&2
      cat "${HEADERS}" >&2
      return 1
      ;;
  esac
}

require curl
require awk
require grep

if [ -z "${BASE}" ]; then
  echo "skipping deployed cache smoke: set AUGENMASS_DEPLOYED_CACHE_API_BASE or pass the API base URL" >&2
  exit 0
fi

BASE="${BASE%/}"

if [ ! -x "${BIN}" ]; then
  echo "smoke binary is not executable: ${BIN}" >&2
  exit 1
fi

curl --max-time 10 -fsS "${BASE}/health" >"${BODY}"
grep -q '"service":"augenmass cache"' "${BODY}"
echo "health: $(cat "${BODY}")"

curl --max-time 30 -fsS -D "${HEADERS}" -o "${BODY}" "${BASE}/schema-metadata" >/dev/null
schema_cache="$(cache_header)"
expect_cache_header "${schema_cache}"
schema_bytes="$(wc -c <"${BODY}" | tr -d ' ')"
test "${schema_bytes}" -gt 1000
echo "schema fetch: ${schema_cache}, ${schema_bytes} bytes"

AUGENMASS_CACHE_API_BASE="${BASE}" "${BIN}" list --target cached-sandbox --rp "${RP}" >"${LIST_OUT}"
grep -q "registration(s) for RP ${RP} on cached-sandbox" "${LIST_OUT}"
echo "cached-sandbox list: $(sed -n '1p' "${LIST_OUT}")"

if [ -z "${ADMIN}" ]; then
  echo "admin checks skipped: set AUGENMASS_DEPLOYED_CACHE_ADMIN_TOKEN to verify protected refresh/status"
  echo "deployed cache smoke passed"
  exit 0
fi

code="$(curl --max-time 10 -s -o "${BODY}" -w '%{http_code}' "${BASE}/cache/status")"
test "${code}" = "401"
echo "admin status without token: ${code}"

code="$(curl --max-time 10 -s -o "${BODY}" -w '%{http_code}' -H "Authorization: Bearer ${ADMIN}" "${BASE}/cache/status")"
test "${code}" = "200"
grep -q '"kind":"augenmass-cache-status"' "${BODY}"
echo "admin status with token: ${code}"

"${BIN}" cache warm --api-base "${BASE}" --admin-token "${ADMIN}" --rp "${RP}" >"${BODY}"
grep -q "Cache warm complete" "${BODY}"
grep -q "schema-metadata/vocabularies" "${BODY}"
grep -q "registration-certificates?rp=${RP}" "${BODY}"
echo "cache warm: $(sed -n '1p' "${BODY}")"

curl --max-time 10 -fsS -H "Authorization: Bearer ${ADMIN}" "${BASE}/cache/status" >"${BODY}"
grep -q "schema-metadata" "${BODY}"
grep -q "registration-certificates" "${BODY}"

echo "deployed cache smoke passed"
