#!/usr/bin/env bash
set -euo pipefail

IMAGE="${AUGENMASS_DOCKER_IMAGE:-augenmass-cache-smoke}"
PORT="${AUGENMASS_DOCKER_SMOKE_PORT:-18984}"
NAME="${AUGENMASS_DOCKER_SMOKE_NAME:-augenmass-cache-smoke-$$}"
VOLUME="${AUGENMASS_DOCKER_SMOKE_VOLUME:-${NAME}-data}"
ADMIN="${AUGENMASS_DOCKER_SMOKE_ADMIN_TOKEN:-local-smoke-token}"
RP="${AUGENMASS_DOCKER_SMOKE_RP:-2af138a8-59ea-4a84-aea3-666cafdb1369}"
BLOCKED_RP="${AUGENMASS_DOCKER_SMOKE_BLOCKED_RP:-blocked-rp-smoke}"
PLATFORM="${AUGENMASS_DOCKER_PLATFORM:-}"
NO_CACHE="${AUGENMASS_DOCKER_NO_CACHE:-0}"
BASE="http://127.0.0.1:${PORT}/api"
BODY="$(mktemp "${TMPDIR:-/tmp}/augenmass-docker-smoke.XXXXXX")"
HEADERS="$(mktemp "${TMPDIR:-/tmp}/augenmass-docker-smoke-headers.XXXXXX")"

cleanup() {
  docker rm -f "${NAME}" >/dev/null 2>&1 || true
  docker volume rm "${VOLUME}" >/dev/null 2>&1 || true
  rm -f "${BODY}" "${HEADERS}"
}
trap cleanup EXIT

if ! command -v docker >/dev/null 2>&1; then
  echo "missing required command: docker" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "missing required command: curl" >&2
  exit 1
fi
if ! command -v awk >/dev/null 2>&1; then
  echo "missing required command: awk" >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "missing required command: jq" >&2
  exit 1
fi

header_value() {
  awk -F': ' -v name="$1" 'tolower($1)==tolower(name) {gsub(/\r/,"",$2); print $2; exit}' "$2"
}

body_bytes() {
  wc -c <"$1" | tr -d '[:space:]'
}

docker info >/dev/null
BUILD_ARGS=()
RUN_ARGS=()
if [ -n "${PLATFORM}" ]; then
  BUILD_ARGS+=(--platform "${PLATFORM}")
  RUN_ARGS+=(--platform "${PLATFORM}")
  echo "docker platform: ${PLATFORM}"
else
  echo "docker platform: daemon default"
fi
if [ "${NO_CACHE}" = "1" ]; then
  BUILD_ARGS+=(--no-cache)
  echo "docker build cache: disabled"
fi

docker build "${BUILD_ARGS[@]}" -t "${IMAGE}" .

run_container() {
  docker run "${RUN_ARGS[@]}" --rm -d \
    --name "${NAME}" \
    -p "127.0.0.1:${PORT}:${PORT}" \
    -e "PORT=${PORT}" \
    -e "AUGENMASS_CACHE_ADMIN_TOKEN=${ADMIN}" \
    -e "AUGENMASS_CACHE_ALLOWED_RPS=${RP}" \
    -v "${VOLUME}:/data" \
    "${IMAGE}" >/dev/null
}

wait_healthy() {
  for _ in $(seq 1 40); do
    if curl --max-time 2 -fsS "${BASE}/health" >"${BODY}" 2>/dev/null; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

docker rm -f "${NAME}" >/dev/null 2>&1 || true
docker volume rm "${VOLUME}" >/dev/null 2>&1 || true
run_container

if ! wait_healthy; then
  echo "container did not become healthy" >&2
  docker logs "${NAME}" >&2 || true
  exit 1
fi

echo "container health: $(cat "${BODY}")"
jq -e '.allowedRpCount == 1' "${BODY}" >/dev/null

uid="$(docker exec "${NAME}" sh -c "awk '/^Uid:/ {print \$2}' /proc/1/status")"
test "${uid}" = "10001"
echo "container process uid: ${uid}"

docker exec -u 10001:10001 "${NAME}" sh -c 'test -w /data && touch /data/write-smoke'
echo "container data path: writable"

code="$(curl --max-time 5 -s -o "${BODY}" -w '%{http_code}' "${BASE}/cache/status")"
test "${code}" = "401"
echo "admin status without token: ${code}"

code="$(curl --max-time 5 -s -o "${BODY}" -w '%{http_code}' -H "Authorization: Bearer ${ADMIN}" "${BASE}/cache/status")"
test "${code}" = "200"
echo "admin status with token: ${code}"

code="$(curl --max-time 15 -s -D "${HEADERS}" -o "${BODY}" -w '%{http_code}' "${BASE}/schema-metadata")"
test "${code}" = "200"
test "$(header_value x-augenmass-cache "${HEADERS}")" = "MISS"
schema_bytes="$(body_bytes "${BODY}")"
test "${schema_bytes}" -gt 1000
jq -e . "${BODY}" >/dev/null
echo "container schema first fetch: MISS, ${schema_bytes} bytes"

code="$(curl --max-time 15 -s -D "${HEADERS}" -o "${BODY}" -w '%{http_code}' "${BASE}/schema-metadata")"
test "${code}" = "200"
test "$(header_value x-augenmass-cache "${HEADERS}")" = "HIT"
jq -e . "${BODY}" >/dev/null
echo "container schema second fetch: HIT"

code="$(curl --max-time 5 -s -o "${BODY}" -w '%{http_code}' "${BASE}/registration-certificates?rp=${BLOCKED_RP}")"
test "${code}" = "403"
echo "container blocked RP read-through: ${code}"

docker stop "${NAME}" >/dev/null
docker rm -f "${NAME}" >/dev/null 2>&1 || true
run_container
if ! wait_healthy; then
  echo "container did not become healthy after restart" >&2
  docker logs "${NAME}" >&2 || true
  exit 1
fi

code="$(curl --max-time 15 -s -D "${HEADERS}" -o "${BODY}" -w '%{http_code}' "${BASE}/schema-metadata")"
test "${code}" = "200"
test "$(header_value x-augenmass-cache "${HEADERS}")" = "HIT"
jq -e . "${BODY}" >/dev/null
echo "container schema after restart: HIT"

echo "docker smoke passed"
