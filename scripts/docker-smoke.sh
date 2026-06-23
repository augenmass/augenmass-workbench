#!/usr/bin/env bash
set -euo pipefail

IMAGE="${AUGENMASS_DOCKER_IMAGE:-augenmass-cache-smoke}"
PORT="${AUGENMASS_DOCKER_SMOKE_PORT:-18984}"
NAME="${AUGENMASS_DOCKER_SMOKE_NAME:-augenmass-cache-smoke-$$}"
VOLUME="${AUGENMASS_DOCKER_SMOKE_VOLUME:-${NAME}-data}"
ADMIN="${AUGENMASS_DOCKER_SMOKE_ADMIN_TOKEN:-local-smoke-token}"
PLATFORM="${AUGENMASS_DOCKER_PLATFORM:-}"
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

docker build "${BUILD_ARGS[@]}" -t "${IMAGE}" .

docker rm -f "${NAME}" >/dev/null 2>&1 || true
docker volume rm "${VOLUME}" >/dev/null 2>&1 || true
docker run "${RUN_ARGS[@]}" --rm -d \
  --name "${NAME}" \
  -p "127.0.0.1:${PORT}:${PORT}" \
  -e "PORT=${PORT}" \
  -e "AUGENMASS_CACHE_ADMIN_TOKEN=${ADMIN}" \
  -v "${VOLUME}:/data" \
  "${IMAGE}" >/dev/null

for _ in $(seq 1 40); do
  if curl --max-time 2 -fsS "${BASE}/health" >"${BODY}" 2>/dev/null; then
    break
  fi
  sleep 0.25
done

if ! curl --max-time 2 -fsS "${BASE}/health" >"${BODY}" 2>/dev/null; then
  echo "container did not become healthy" >&2
  docker logs "${NAME}" >&2 || true
  exit 1
fi

echo "container health: $(cat "${BODY}")"

uid="$(docker exec "${NAME}" id -u)"
test "${uid}" = "10001"
echo "container uid: ${uid}"

docker exec "${NAME}" sh -c 'test -w /data && touch /data/write-smoke'
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
echo "container schema first fetch: MISS, ${schema_bytes} bytes"

code="$(curl --max-time 15 -s -D "${HEADERS}" -o "${BODY}" -w '%{http_code}' "${BASE}/schema-metadata")"
test "${code}" = "200"
test "$(header_value x-augenmass-cache "${HEADERS}")" = "HIT"
echo "container schema second fetch: HIT"

echo "docker smoke passed"
