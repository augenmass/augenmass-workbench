#!/usr/bin/env bash
set -euo pipefail

resolve_bin() {
  if [ -n "${AUGENMASS_RELAY_SMOKE_BIN:-}" ]; then
    printf '%s\n' "${AUGENMASS_RELAY_SMOKE_BIN}"
  elif [ -n "${AUGENMASS_BIN:-}" ]; then
    printf '%s\n' "${AUGENMASS_BIN}"
  else
    printf '%s\n' "./target/debug/augenmass"
  fi
}

resolve_relay_bin() {
  if [ -n "${AUGENMASS_RELAY_SMOKE_RELAY_BIN:-}" ]; then
    printf '%s\n' "${AUGENMASS_RELAY_SMOKE_RELAY_BIN}"
  else
    printf '%s\n' "./target/debug/augenmass-relay"
  fi
}

BIN="$(resolve_bin)"
RELAY_BIN="$(resolve_relay_bin)"
RELAY_PORT="${AUGENMASS_RELAY_SMOKE_RELAY_PORT:-18994}"
SERVE_PORT="${AUGENMASS_RELAY_SMOKE_SERVE_PORT:-18995}"
RELAY_BASE="http://127.0.0.1:${RELAY_PORT}"
LOCAL_BASE="http://127.0.0.1:${SERVE_PORT}"
TOKEN="relay-smoke-token"
BODY_SENTINEL="relay-body-sentinel"
HEADER_SENTINEL="relay-header-sentinel"
QUERY_SENTINEL="relay-query-sentinel"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/augenmass-relay-smoke.XXXXXX")"
RELAY_LOG="${WORKDIR}/relay.log"
SERVE_LOG="${WORKDIR}/serve.log"
BODY="${WORKDIR}/body"
HEADERS="${WORKDIR}/headers"
TRACE="${WORKDIR}/trace.json"
SESSIONS="${WORKDIR}/sessions.json"
LOCAL_JAR="${WORKDIR}/local.jar"
RELAY_JAR="${WORKDIR}/relay.jar"
RELAY_PID=""
SERVE_PID=""

cleanup() {
  if [ -n "${SERVE_PID}" ]; then
    kill "${SERVE_PID}" 2>/dev/null || true
    wait "${SERVE_PID}" 2>/dev/null || true
  fi
  if [ -n "${RELAY_PID}" ]; then
    kill "${RELAY_PID}" 2>/dev/null || true
    wait "${RELAY_PID}" 2>/dev/null || true
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

header_value() {
  awk -F': ' -v name="$1" 'tolower($1)==tolower(name) {gsub(/\r/,"",$2); print $2; exit}' "${HEADERS}"
}

wait_for_url() {
  local url="$1"
  local name="$2"
  for _ in $(seq 1 60); do
    if curl --max-time 2 -fsS "${url}" >"${BODY}" 2>/dev/null; then
      return 0
    fi
    sleep 0.25
  done
  echo "${name} did not become healthy" >&2
  cat "${RELAY_LOG}" >&2 || true
  cat "${SERVE_LOG}" >&2 || true
  return 1
}

require awk
require cmp
require curl
require cut
require grep
require sed

if [ ! -x "${BIN}" ]; then
  echo "relay smoke binary is not executable: ${BIN}" >&2
  exit 1
fi
if [ ! -x "${RELAY_BIN}" ]; then
  echo "relay smoke relay binary is not executable: ${RELAY_BIN}" >&2
  exit 1
fi

env -u AUGENMASS_RELAY_PUBLIC_BASE \
  RUST_LOG=augenmass_relay=info \
  AUGENMASS_RELAY_HOST=127.0.0.1 \
  AUGENMASS_RELAY_PORT="${RELAY_PORT}" \
  AUGENMASS_RELAY_AUTH_TOKEN="${TOKEN}" \
  "${RELAY_BIN}" >"${RELAY_LOG}" 2>&1 &
RELAY_PID="$!"
wait_for_url "${RELAY_BASE}/healthz" "relay"
grep -q '"service":"augenmass-relay"' "${BODY}"
echo "relay health: $(cat "${BODY}")"

env -u AUGENMASS_RELAY_URL \
  AUGENMASS_RELAY_TOKEN="${TOKEN}" \
  "${BIN}" serve \
  --host 127.0.0.1 \
  --port "${SERVE_PORT}" \
  --relay "ws://127.0.0.1:${RELAY_PORT}/_relay/tunnel" \
  --quiet >"${SERVE_LOG}" 2>&1 &
SERVE_PID="$!"
wait_for_url "${LOCAL_BASE}/health" "serve"
grep -q '"service":"augenmass serve"' "${BODY}"
echo "serve health: $(cat "${BODY}")"

PUBLIC="$(sed -n 's/^  public       : //p' "${SERVE_LOG}" | tail -n 1)"
if ! printf '%s\n' "${PUBLIC}" | grep -Eq "^${RELAY_BASE}/r/[^/]+/$"; then
  echo "could not parse relay public URL from serve log" >&2
  cat "${SERVE_LOG}" >&2
  exit 1
fi
RUN_ID="$(printf '%s\n' "${PUBLIC}" | sed -E 's#.*/r/([^/]+)/$#\1#')"
RUN_SHORT="$(printf '%s' "${RUN_ID}" | cut -c1-8)"
echo "relay run: ${RUN_SHORT}"

curl --max-time 10 -fsS "${LOCAL_BASE}/" >"${BODY}"
grep -q "Present your German PID" "${BODY}"
grep -q "${PUBLIC}request/" "${BODY}"
echo "local landing minted a relay-backed session"

curl --max-time 10 -fsS "${LOCAL_BASE}/api/sessions" >"${SESSIONS}"
SID="$(grep -Eo '"session"[[:space:]]*:[[:space:]]*"[0-9a-fA-F-]{36}"' "${SESSIONS}" | tail -n 1 | sed -E 's/.*"([0-9a-fA-F-]{36})"$/\1/')"
if ! printf '%s\n' "${SID}" | grep -Eq '^[0-9a-fA-F-]{36}$'; then
  echo "could not parse session id from /api/sessions" >&2
  cat "${SESSIONS}" >&2
  exit 1
fi
echo "session: ${SID}"

curl --max-time 10 -fsS -D "${HEADERS}" -o "${LOCAL_JAR}" "${LOCAL_BASE}/request/${SID}" >/dev/null
test "$(header_value content-type)" = "application/oauth-authz-req+jwt"
curl --max-time 10 -fsS -D "${HEADERS}" -o "${RELAY_JAR}" "${PUBLIC}request/${SID}" >/dev/null
test "$(header_value content-type)" = "application/oauth-authz-req+jwt"
cmp "${LOCAL_JAR}" "${RELAY_JAR}"
echo "request object forwarded byte-for-byte"

trace_code="$(curl --max-time 10 -sS -o "${BODY}" -w '%{http_code}' "${PUBLIC}trace/${SID}")"
test "${trace_code}" = "404"
inspect_code="$(curl --max-time 10 -sS -o "${BODY}" -w '%{http_code}' "${PUBLIC}inspect/${SID}")"
test "${inspect_code}" = "404"
echo "relay does not expose trace or inspect"

code="$(
  curl --max-time 10 -sS \
    -H 'content-type: application/x-www-form-urlencoded' \
    -H "x-forwarded-for: ${HEADER_SENTINEL}" \
    -H "cookie: relay-cookie=${HEADER_SENTINEL}" \
    -o "${BODY}" \
    -w '%{http_code}' \
    --data-urlencode "vp_token={\"pid\":[\"${BODY_SENTINEL}\"]}" \
    --data 'state=abc' \
    "${PUBLIC}response/${SID}?probe=${QUERY_SENTINEL}"
)"
test "${code}" = "422"
grep -q '"status":"rejected"' "${BODY}"
grep -q "plaintext direct_post response rejected" "${BODY}"
echo "plaintext direct_post rejected through relay: ${code}"

curl --max-time 10 -fsS "${LOCAL_BASE}/api/trace/${SID}" >"${TRACE}"
grep -q '"code":"RESPONSE_RECEIVED"' "${TRACE}"
grep -q '"code":"REJECTED"' "${TRACE}"
if grep -Fq -- "${BODY_SENTINEL}" "${TRACE}"; then
  echo "trace leaked plaintext wallet sentinel" >&2
  exit 1
fi
echo "local trace stayed redacted"

grep -q 'relay forward' "${RELAY_LOG}"
grep -q 'route="request"' "${RELAY_LOG}"
grep -q 'route="response"' "${RELAY_LOG}"
grep -q 'status=200' "${RELAY_LOG}"
grep -q 'status=422' "${RELAY_LOG}"
grep -q "run=${RUN_SHORT}" "${RELAY_LOG}"

for forbidden in \
  "${RUN_ID}" \
  "${SID}" \
  "${TOKEN}" \
  "${BODY_SENTINEL}" \
  "${HEADER_SENTINEL}" \
  "${QUERY_SENTINEL}" \
  "Authorization" \
  "Cookie" \
  "X-Forwarded" \
  "/r/${RUN_ID}/"; do
  if grep -Fq -- "${forbidden}" "${RELAY_LOG}"; then
    echo "relay log leaked forbidden value: ${forbidden}" >&2
    cat "${RELAY_LOG}" >&2
    exit 1
  fi
done
echo "relay logs are redacted"

echo "relay smoke passed"
