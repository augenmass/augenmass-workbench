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

pick_free_port() {
  # Pick a loopback TCP port nothing is currently listening on. A stray
  # `cache serve` left behind on a fixed port co-binds (SO_REUSEPORT) and splits
  # our requests, which flakes the MISS/HIT/STALE assertions. Callers can still
  # pin a port via AUGENMASS_SMOKE_PORT.
  local candidate
  for _ in $(seq 1 50); do
    candidate=$(( (RANDOM % 20000) + 20000 ))
    if ! (exec 3<>"/dev/tcp/127.0.0.1/${candidate}") 2>/dev/null; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  echo "could not find a free loopback port for the cache smoke" >&2
  return 1
}

BIN="$(resolve_bin)"
RP="${AUGENMASS_SMOKE_RP:-2af138a8-59ea-4a84-aea3-666cafdb1369}"
BLOCKED_RP="${AUGENMASS_SMOKE_BLOCKED_RP:-blocked-rp-smoke}"
PORT="${AUGENMASS_SMOKE_PORT:-$(pick_free_port)}"
ADMIN="${AUGENMASS_SMOKE_ADMIN_TOKEN:-local-smoke-token}"
BASE="http://127.0.0.1:${PORT}/api"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/augenmass-live-cache-smoke.XXXXXX")"
DB="${WORKDIR}/cache.sqlite"
LOG="${WORKDIR}/cache.log"
HEADERS="${WORKDIR}/headers"
BODY="${WORKDIR}/body"
PID=""

stop_server() {
  # The bundled `augenmass` launcher runs the real binary as a child (it inspects
  # the exit status afterwards instead of exec-ing it), so signalling ${PID} alone
  # reaps only the launcher and orphans the server, leaking the listen port into
  # the next step or run. Signal the launcher's child first, then the launcher.
  if [ -n "${PID}" ]; then
    pkill -P "${PID}" 2>/dev/null || true
    kill "${PID}" 2>/dev/null || true
    wait "${PID}" 2>/dev/null || true
    PID=""
  fi
}

cleanup() {
  stop_server
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
require pkill

if [ ! -x "${BIN}" ]; then
  echo "smoke binary is not executable: ${BIN}" >&2
  exit 1
fi

"${BIN}" cache serve --db "${DB}" --port "${PORT}" --admin-token "${ADMIN}" --allowed-rp "${RP}" >"${LOG}" 2>&1 &
PID="$!"
wait_for_health

kill -0 "${PID}" 2>/dev/null
grep -q '"service":"augenmass cache"' "${BODY}"
grep -q '"allowedRpCount":1' "${BODY}"
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

code="$(curl --max-time 5 -s -o "${BODY}" -w '%{http_code}' "${BASE}/registration-certificates?rp=${BLOCKED_RP}")"
test "${code}" = "403"
echo "blocked RP read-through: ${code}"

"${BIN}" cache status --api-base "${BASE}" --admin-token "${ADMIN}" >"${BODY}"
grep -q "Cache status for" "${BODY}"
grep -q "schema-metadata" "${BODY}"
grep -q "registration-certificates" "${BODY}"
echo "cache status: $(grep -m1 '^  entries:' "${BODY}" | sed 's/^ *//')"

"${BIN}" cache warm --api-base "${BASE}" --admin-token "${ADMIN}" --rp "${RP}" >"${BODY}"
grep -q "Cache warm complete" "${BODY}"
grep -q "schema-metadata/vocabularies" "${BODY}"
grep -q "registration-certificates?rp=${RP}" "${BODY}"
echo "cache warm: $(sed -n '1p' "${BODY}")"

stop_server

"${BIN}" cache serve \
  --db "${DB}" \
  --port "${PORT}" \
  --admin-token "${ADMIN}" \
  --allowed-rp "${RP}" \
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
