#!/usr/bin/env bash
set -euo pipefail

BIN="${AUGENMASS_SMOKE_BIN:-./plugins/augenmass-workbench/bin/augenmass}"
RP="${AUGENMASS_SMOKE_RP:-2af138a8-59ea-4a84-aea3-666cafdb1369}"
PORT="${AUGENMASS_SMOKE_PORT:-18983}"
ADMIN="${AUGENMASS_SMOKE_ADMIN_TOKEN:-local-smoke-token}"
BASE="http://127.0.0.1:${PORT}/api"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/augenmass-live-cache-smoke.XXXXXX")"
DB="${WORKDIR}/cache.sqlite"
LOG="${WORKDIR}/cache.log"
HEADERS="${WORKDIR}/headers"
BODY="${WORKDIR}/body"
PID=""

cleanup() {
  if [ -n "${PID}" ]; then
    kill "${PID}" 2>/dev/null || true
    wait "${PID}" 2>/dev/null || true
  fi
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

wait_for_health() {
  for _ in $(seq 1 40); do
    if curl --max-time 2 -fsS "${BASE}/health" >"${BODY}" 2>/dev/null; then
      return 0
    fi
    sleep 0.25
  done
  echo "cache server did not become healthy" >&2
  cat "${LOG}" >&2 || true
  return 1
}

cache_header() {
  awk -F': ' 'tolower($1)=="x-augenmass-cache" {gsub(/\r/,"",$2); print $2}' "${HEADERS}"
}

require curl
require awk
require grep

if [ ! -x "${BIN}" ]; then
  echo "smoke binary is not executable: ${BIN}" >&2
  exit 1
fi

"${BIN}" cache serve --db "${DB}" --port "${PORT}" --admin-token "${ADMIN}" >"${LOG}" 2>&1 &
PID="$!"
wait_for_health

echo "health: $(cat "${BODY}")"

code="$(curl --max-time 5 -s -o "${BODY}" -w '%{http_code}' "${BASE}/cache/status")"
test "${code}" = "401"
echo "admin status without token: ${code}"

code="$(curl --max-time 5 -s -o "${BODY}" -w '%{http_code}' -H "Authorization: Bearer ${ADMIN}" "${BASE}/cache/status")"
test "${code}" = "200"
echo "admin status with token: ${code}"

curl --max-time 30 -fsS -D "${HEADERS}" -o "${BODY}" "${BASE}/schema-metadata" >/dev/null
first="$(cache_header)"
bytes="$(wc -c <"${BODY}" | tr -d ' ')"
test "${first}" = "MISS"
test "${bytes}" -gt 1000
echo "schema first fetch: ${first}, ${bytes} bytes"

curl --max-time 30 -fsS -D "${HEADERS}" -o "${BODY}" "${BASE}/schema-metadata" >/dev/null
second="$(cache_header)"
test "${second}" = "HIT"
echo "schema second fetch: ${second}"

AUGENMASS_CACHE_API_BASE="${BASE}" "${BIN}" list --target cached-sandbox --rp "${RP}" >"${BODY}"
grep -q "registration(s) for RP ${RP} on cached-sandbox" "${BODY}"
echo "cached-sandbox list: $(sed -n '1p' "${BODY}")"

curl --max-time 5 -fsS -H "Authorization: Bearer ${ADMIN}" "${BASE}/cache/status" >"${BODY}"
grep -q "schema-metadata" "${BODY}"
grep -q "registration-certificates" "${BODY}"

kill "${PID}" 2>/dev/null || true
wait "${PID}" 2>/dev/null || true
PID=""

"${BIN}" cache serve \
  --db "${DB}" \
  --port "${PORT}" \
  --admin-token "${ADMIN}" \
  --ttl-secs 0 \
  --timeout-secs 1 \
  --upstream "http://127.0.0.1:9/api" >"${LOG}" 2>&1 &
PID="$!"
wait_for_health

curl --max-time 10 -fsS -D "${HEADERS}" -o "${BODY}" "${BASE}/registration-certificates?rp=${RP}" >/dev/null
stale="$(cache_header)"
bytes="$(wc -c <"${BODY}" | tr -d ' ')"
test "${stale}" = "STALE"
test "${bytes}" -gt 1000
echo "registration stale fallback: ${stale}, ${bytes} bytes"

echo "live cache smoke passed"
