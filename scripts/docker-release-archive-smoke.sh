#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <linux/arm64|linux/amd64>" >&2
  exit 2
fi

PLATFORM="$1"
case "${PLATFORM}" in
  linux/arm64 | linux/amd64) ;;
  *)
    echo "unsupported platform: ${PLATFORM}" >&2
    exit 2
    ;;
esac

SAFE_PLATFORM="${PLATFORM//\//-}"
OUT="${AUGENMASS_DOCKER_RELEASE_ARCHIVE_OUT:-dist/docker-release-archive-smoke/${SAFE_PLATFORM}}"

if ! command -v docker >/dev/null 2>&1; then
  echo "missing required command: docker" >&2
  exit 1
fi

docker info >/dev/null
docker buildx version >/dev/null

BUILD_ARGS=(
  --platform "${PLATFORM}"
  --target release-archive-export
  --output "type=local,dest=${OUT}"
)

if [ "${AUGENMASS_DOCKER_NO_CACHE:-0}" = "1" ]; then
  BUILD_ARGS+=(--no-cache)
fi

rm -rf "${OUT}"
mkdir -p "${OUT}"

docker buildx build "${BUILD_ARGS[@]}" .

shopt -s nullglob
archives=("${OUT}"/augenmass-v*-*.tar.gz)
if [ "${#archives[@]}" -ne 1 ]; then
  echo "expected exactly one exported archive in ${OUT}" >&2
  exit 1
fi

echo "docker release archive smoke passed for ${PLATFORM}: ${archives[0]}"
