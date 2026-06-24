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
BLOCKED_RP="${AUGENMASS_DEPLOYED_CACHE_BLOCKED_RP:-blocked-rp-smoke}"
REQUIRED="${AUGENMASS_DEPLOYED_CACHE_REQUIRED:-0}"
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

validate_required_hosted_base() {
  if [ "${REQUIRED}" != "1" ]; then
    return 0
  fi

  case "${BASE}" in
    https://*) ;;
    *)
      echo "deployed cache required mode requires an https API base" >&2
      exit 1
      ;;
  esac

  host_port="${BASE#https://}"
  host_port="${host_port%%/*}"
  host="${host_port%%:*}"

  case "${host_port}" in
    \[*\])
      host="${host_port#[}"
      host="${host%]}"
      ;;
    \[*\]:*)
      host="${host_port#[}"
      host="${host%%]*}"
      ;;
  esac

  lower_host="$(printf '%s' "${host}" | tr '[:upper:]' '[:lower:]')"
  case "${lower_host}" in
    ""|localhost|localhost.*|*.localhost|127.*|0.*|10.*|192.168.*|169.254.*|::1|0:0:0:0:0:0:0:1|::ffff:127.*|fc*:*|fd*:*|fe80:*)
      echo "deployed cache required mode requires a non-local hosted API base, got ${BASE}" >&2
      exit 1
      ;;
    172.*)
      second_octet="${lower_host#172.}"
      second_octet="${second_octet%%.*}"
      if [ "${second_octet}" -ge 16 ] 2>/dev/null && [ "${second_octet}" -le 31 ] 2>/dev/null; then
        echo "deployed cache required mode requires a non-local hosted API base, got ${BASE}" >&2
        exit 1
      fi
      ;;
  esac
}

require curl
require awk
require grep
require jq

if [ -z "${BASE}" ]; then
  if [ "${REQUIRED}" = "1" ]; then
    echo "deployed cache smoke requires AUGENMASS_DEPLOYED_CACHE_API_BASE or an API base argument" >&2
    exit 1
  fi
  echo "skipping deployed cache smoke: set AUGENMASS_DEPLOYED_CACHE_API_BASE or pass the API base URL" >&2
  exit 0
fi

BASE="${BASE%/}"
validate_required_hosted_base

if [ "${REQUIRED}" = "1" ] && [ -z "${ADMIN}" ]; then
  echo "deployed cache smoke required mode requires AUGENMASS_DEPLOYED_CACHE_ADMIN_TOKEN to prove protected status and refresh" >&2
  exit 1
fi

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
jq -e . "${BODY}" >/dev/null
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

"${BIN}" --json cache status --api-base "${BASE}" --admin-token "${ADMIN}" >"${BODY}"
jq -e '.kind == "augenmass-cache-status"' "${BODY}" >/dev/null
jq -e --arg rp "${RP}" '(.allowedRps // []) | index($rp) != null' "${BODY}" >/dev/null
echo "admin status with token: CLI"

if [ "${BLOCKED_RP}" = "${RP}" ]; then
  echo "AUGENMASS_DEPLOYED_CACHE_BLOCKED_RP must differ from AUGENMASS_DEPLOYED_CACHE_RP" >&2
  exit 1
fi
code="$(curl --max-time 10 -s -o "${BODY}" -w '%{http_code}' "${BASE}/registration-certificates?rp=${BLOCKED_RP}")"
test "${code}" = "403"
echo "blocked RP read-through: ${code}"

"${BIN}" cache warm --api-base "${BASE}" --admin-token "${ADMIN}" --rp "${RP}" >"${BODY}"
grep -q "Cache warm complete" "${BODY}"
grep -q "schema-metadata/vocabularies" "${BODY}"
grep -q "registration-certificates?rp=${RP}" "${BODY}"
echo "cache warm: $(sed -n '1p' "${BODY}")"

"${BIN}" --json cache status --api-base "${BASE}" --admin-token "${ADMIN}" >"${BODY}"
jq -e '.entries | map(.key) | index("schema-metadata") != null' "${BODY}" >/dev/null
jq -e --arg key "registration-certificates?rp=${RP}" \
  '.entries | map(.key) | index($key) != null' "${BODY}" >/dev/null

echo "deployed cache smoke passed"
