#!/usr/bin/env bash
set -euo pipefail

resolve_bin() {
  if [ -n "${AUGENMASS_DEPLOYED_RELAY_BIN:-}" ]; then
    printf '%s\n' "${AUGENMASS_DEPLOYED_RELAY_BIN}"
  elif [ -n "${AUGENMASS_BIN:-}" ]; then
    printf '%s\n' "${AUGENMASS_BIN}"
  else
    printf '%s\n' "./target/debug/augenmass"
  fi
}

derive_control_url() {
  local input="$1"
  case "${input}" in
    wss://*|ws://*) printf '%s\n' "${input}" ;;
    https://*) printf 'wss://%s/_relay/tunnel\n' "${input#https://}" ;;
    http://*) printf 'ws://%s/_relay/tunnel\n' "${input#http://}" ;;
    *) printf '%s\n' "${input}" ;;
  esac
}

derive_health_base() {
  local control="$1"
  case "${control}" in
    wss://*) printf 'https://%s\n' "${control#wss://}" | sed 's#/_relay/tunnel$##' ;;
    ws://*) printf 'http://%s\n' "${control#ws://}" | sed 's#/_relay/tunnel$##' ;;
    *) printf '%s\n' "${control}" | sed 's#/_relay/tunnel$##' ;;
  esac
}

validate_required_hosted_control() {
  local control="$1"
  if [ "${REQUIRED}" != "1" ]; then
    return 0
  fi

  case "${control}" in
    wss://*) ;;
    *)
      echo "deployed relay required mode requires a wss control URL or https base" >&2
      exit 1
      ;;
  esac

  host_port="${control#wss://}"
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
      echo "deployed relay required mode requires a non-local hosted control URL, got ${control}" >&2
      exit 1
      ;;
    172.*)
      second_octet="${lower_host#172.}"
      second_octet="${second_octet%%.*}"
      if [ "${second_octet}" -ge 16 ] 2>/dev/null && [ "${second_octet}" -le 31 ] 2>/dev/null; then
        echo "deployed relay required mode requires a non-local hosted control URL, got ${control}" >&2
        exit 1
      fi
      ;;
  esac
}

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
  for _ in $(seq 1 80); do
    if curl --max-time 2 -fsS "${url}" >"${BODY}" 2>/dev/null; then
      return 0
    fi
    sleep 0.25
  done
  echo "${name} did not become healthy" >&2
  cat "${SERVE_LOG}" >&2 || true
  return 1
}

BIN="$(resolve_bin)"
INPUT="${1:-${AUGENMASS_DEPLOYED_RELAY_BASE:-${AUGENMASS_DEPLOYED_RELAY_URL:-}}}"
TOKEN="${AUGENMASS_DEPLOYED_RELAY_TOKEN:-}"
REQUIRED="${AUGENMASS_DEPLOYED_RELAY_REQUIRED:-0}"
SERVE_PORT="${AUGENMASS_DEPLOYED_RELAY_SERVE_PORT:-18996}"
LOCAL_BASE="http://127.0.0.1:${SERVE_PORT}"
BODY_SENTINEL="deployed-relay-body-sentinel"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/augenmass-deployed-relay-smoke.XXXXXX")"
SERVE_LOG="${WORKDIR}/serve.log"
BODY="${WORKDIR}/body"
HEADERS="${WORKDIR}/headers"
TRACE="${WORKDIR}/trace.json"
SESSIONS="${WORKDIR}/sessions.json"
LOCAL_JAR="${WORKDIR}/local.jar"
RELAY_JAR="${WORKDIR}/relay.jar"
SERVE_PID=""

cleanup() {
  if [ -n "${SERVE_PID}" ]; then
    kill "${SERVE_PID}" 2>/dev/null || true
    wait "${SERVE_PID}" 2>/dev/null || true
  fi
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

require awk
require cmp
require curl
require grep
require sed

if [ -z "${INPUT}" ]; then
  if [ "${REQUIRED}" = "1" ]; then
    echo "deployed relay smoke requires AUGENMASS_DEPLOYED_RELAY_BASE, AUGENMASS_DEPLOYED_RELAY_URL, or a URL argument" >&2
    exit 1
  fi
  echo "skipping deployed relay smoke: set AUGENMASS_DEPLOYED_RELAY_BASE or pass the relay URL" >&2
  exit 0
fi

CONTROL="$(derive_control_url "${INPUT%/}")"
HEALTH_BASE="$(derive_health_base "${CONTROL}")"
validate_required_hosted_control "${CONTROL}"

if [ "${REQUIRED}" = "1" ] && [ -z "${TOKEN}" ]; then
  echo "deployed relay required mode requires AUGENMASS_DEPLOYED_RELAY_TOKEN" >&2
  exit 1
fi
if [ ! -x "${BIN}" ]; then
  echo "deployed relay smoke binary is not executable: ${BIN}" >&2
  exit 1
fi

curl --max-time 10 -fsS "${HEALTH_BASE}/healthz" >"${BODY}"
grep -q '"service":"augenmass-relay"' "${BODY}"
echo "relay health: $(cat "${BODY}")"

env AUGENMASS_RELAY_TOKEN="${TOKEN}" \
  "${BIN}" serve \
  --host 127.0.0.1 \
  --port "${SERVE_PORT}" \
  --relay "${CONTROL}" \
  --quiet >"${SERVE_LOG}" 2>&1 &
SERVE_PID="$!"
wait_for_url "${LOCAL_BASE}/health" "serve"

PUBLIC="$(sed -n 's/^  public       : //p' "${SERVE_LOG}" | tail -n 1)"
case "${PUBLIC}" in
  http://*|https://*) ;;
  *)
    echo "could not parse public relay URL from serve log" >&2
    cat "${SERVE_LOG}" >&2
    exit 1
    ;;
esac
echo "relay public: ${PUBLIC}"

curl --max-time 10 -fsS "${LOCAL_BASE}/" >"${BODY}"
grep -q "${PUBLIC}request/" "${BODY}"

curl --max-time 10 -fsS "${LOCAL_BASE}/api/sessions" >"${SESSIONS}"
SID="$(grep -Eo '"session"[[:space:]]*:[[:space:]]*"[0-9a-fA-F-]{36}"' "${SESSIONS}" | tail -n 1 | sed -E 's/.*"([0-9a-fA-F-]{36})"$/\1/')"
if ! printf '%s\n' "${SID}" | grep -Eq '^[0-9a-fA-F-]{36}$'; then
  echo "could not parse session id from /api/sessions" >&2
  cat "${SESSIONS}" >&2
  exit 1
fi

curl --max-time 20 -fsS -D "${HEADERS}" -o "${LOCAL_JAR}" "${LOCAL_BASE}/request/${SID}" >/dev/null
test "$(header_value content-type)" = "application/oauth-authz-req+jwt"
curl --max-time 20 -fsS -D "${HEADERS}" -o "${RELAY_JAR}" "${PUBLIC}request/${SID}" >/dev/null
test "$(header_value content-type)" = "application/oauth-authz-req+jwt"
cmp "${LOCAL_JAR}" "${RELAY_JAR}"
echo "request object forwarded byte-for-byte"

trace_code="$(curl --max-time 10 -sS -o "${BODY}" -w '%{http_code}' "${PUBLIC}trace/${SID}")"
test "${trace_code}" = "404"
inspect_code="$(curl --max-time 10 -sS -o "${BODY}" -w '%{http_code}' "${PUBLIC}inspect/${SID}")"
test "${inspect_code}" = "404"
echo "relay does not expose trace or inspect"

code="$(
  curl --max-time 20 -sS \
    -H 'content-type: application/x-www-form-urlencoded' \
    -o "${BODY}" \
    -w '%{http_code}' \
    --data-urlencode "vp_token={\"pid\":[\"${BODY_SENTINEL}\"]}" \
    --data 'state=abc' \
    "${PUBLIC}response/${SID}"
)"
test "${code}" = "422"
grep -q '"status":"rejected"' "${BODY}"
echo "plaintext direct_post rejected through relay: ${code}"

curl --max-time 10 -fsS "${LOCAL_BASE}/api/trace/${SID}" >"${TRACE}"
grep -q '"code":"RESPONSE_RECEIVED"' "${TRACE}"
grep -q '"code":"REJECTED"' "${TRACE}"
if grep -q "${BODY_SENTINEL}" "${TRACE}"; then
  echo "trace leaked plaintext wallet sentinel" >&2
  exit 1
fi
echo "local trace stayed redacted"

echo "deployed relay smoke passed"
