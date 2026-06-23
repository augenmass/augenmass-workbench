#!/usr/bin/env bash
set -euo pipefail

BIN="${AUGENMASS_SERVE_SMOKE_BIN:-./plugins/augenmass-workbench/bin/augenmass}"
PORT="${AUGENMASS_SERVE_SMOKE_PORT:-18989}"
BASE="http://127.0.0.1:${PORT}"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/augenmass-serve-smoke.XXXXXX")"
LOG="${WORKDIR}/serve.log"
BODY="${WORKDIR}/body"
HEADERS="${WORKDIR}/headers"
TRACE="${WORKDIR}/trace.json"
SESSIONS="${WORKDIR}/sessions.json"
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

header_value() {
  awk -F': ' -v name="$1" 'tolower($1)==tolower(name) {gsub(/\r/,"",$2); print $2; exit}' "${HEADERS}"
}

wait_for_health() {
  for _ in $(seq 1 40); do
    if curl --max-time 2 -fsS "${BASE}/health" >"${BODY}" 2>/dev/null; then
      return 0
    fi
    sleep 0.25
  done
  echo "serve did not become healthy" >&2
  cat "${LOG}" >&2 || true
  return 1
}

require awk
require curl
require grep
require sed
require wc

if [ ! -x "${BIN}" ]; then
  echo "serve smoke binary is not executable: ${BIN}" >&2
  exit 1
fi

"${BIN}" serve \
  --host 127.0.0.1 \
  --port "${PORT}" \
  --public-url "${BASE}/" \
  --quiet >"${LOG}" 2>&1 &
PID="$!"
wait_for_health

grep -q '"service":"augenmass serve"' "${BODY}"
echo "health: $(cat "${BODY}")"

curl --max-time 10 -fsS "${BASE}/" >"${BODY}"
grep -q "Present your German PID" "${BODY}"
grep -q "client_id" "${BODY}"
echo "landing page minted a session"

curl --max-time 10 -fsS "${BASE}/api/sessions" >"${SESSIONS}"
SID="$(grep -Eo '"session"[[:space:]]*:[[:space:]]*"[0-9a-fA-F-]{36}"' "${SESSIONS}" | tail -n 1 | sed -E 's/.*"([0-9a-fA-F-]{36})"$/\1/')"
if ! printf '%s\n' "${SID}" | grep -Eq '^[0-9a-fA-F-]{36}$'; then
  echo "could not parse session id from /api/sessions" >&2
  cat "${SESSIONS}" >&2
  exit 1
fi
echo "session: ${SID}"

curl --max-time 10 -fsS -D "${HEADERS}" -o "${BODY}" "${BASE}/request/${SID}" >/dev/null
content_type="$(header_value content-type)"
test "${content_type}" = "application/oauth-authz-req+jwt"
jar_parts="$(awk -F'.' '{print NF}' "${BODY}")"
test "${jar_parts}" = "3"
echo "request object: ${content_type}, compact JWS"

curl --max-time 10 -fsS "${BASE}/api/trace/${SID}" >"${TRACE}"
grep -q '"code":"SESSION_CREATED"' "${TRACE}"
grep -q '"code":"REQUEST_BUILT"' "${TRACE}"
grep -q '"code":"REQUEST_OBJECT_FETCHED"' "${TRACE}"
grep -q '"jwt"' "${TRACE}"
curl --max-time 10 -fsS "${BASE}/api/sessions" >"${SESSIONS}"
grep -q '"lastCode":"REQUEST_OBJECT_FETCHED"' "${SESSIONS}"
echo "request trace recorded"

code="$(
  curl --max-time 10 -sS \
    -H 'content-type: application/x-www-form-urlencoded' \
    -o "${BODY}" \
    -w '%{http_code}' \
    --data-urlencode 'vp_token={"pid":["secret-claim"]}' \
    --data 'state=abc' \
    "${BASE}/response/${SID}"
)"
test "${code}" = "422"
grep -q '"status":"rejected"' "${BODY}"
grep -q "plaintext direct_post response rejected" "${BODY}"
echo "plaintext direct_post rejected: ${code}"

curl --max-time 10 -fsS "${BASE}/api/trace/${SID}" >"${TRACE}"
grep -q '"code":"RESPONSE_RECEIVED"' "${TRACE}"
grep -q '"code":"REJECTED"' "${TRACE}"
grep -q '"bodySha256"' "${TRACE}"
grep -q '"bodyLen"' "${TRACE}"
curl --max-time 10 -fsS "${BASE}/api/sessions" >"${SESSIONS}"
grep -q '"lastCode":"REJECTED"' "${SESSIONS}"
grep -q '"lastLevel":"bad"' "${SESSIONS}"
if grep -q 'secret-claim' "${TRACE}"; then
  echo "trace leaked plaintext wallet claim" >&2
  exit 1
fi
if grep -q 'rawBody' "${TRACE}"; then
  echo "trace leaked raw POST body field" >&2
  exit 1
fi
if grep -q 'direct-post.body' "${TRACE}"; then
  echo "trace leaked unsafe debug artifact filename without opt-in" >&2
  exit 1
fi
if grep -q 'session-enc-key' "${TRACE}"; then
  echo "trace leaked session encryption key artifact without opt-in" >&2
  exit 1
fi
echo "response trace redacted"

curl --max-time 10 -fsS "${BASE}/trace/${SID}" >"${BODY}"
grep -q "Wallet-interaction trace" "${BODY}"
grep -q "PID-bearing wallet response material is redacted" "${BODY}"
echo "trace page rendered"

curl --max-time 10 -fsS "${BASE}/inspect/${SID}" >"${BODY}"
grep -q "plaintext direct_post response rejected" "${BODY}"
echo "inspect rejection rendered"

echo "serve smoke passed"
