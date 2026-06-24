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
OUT_TMP="${OUT}.tmp.$$"
GIT_COMMIT="$(git rev-parse HEAD 2>/dev/null || printf unknown)"
if git diff --quiet --ignore-submodules -- 2>/dev/null && git diff --cached --quiet --ignore-submodules -- 2>/dev/null; then
  GIT_DIRTY=false
else
  GIT_DIRTY=true
fi

hash_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    echo "missing required command for hashing: shasum or sha256sum" >&2
    exit 1
  fi
}

cleanup() {
  rm -rf "${OUT_TMP}"
}
trap cleanup EXIT

if ! command -v docker >/dev/null 2>&1; then
  echo "missing required command: docker" >&2
  exit 1
fi

docker info >/dev/null
docker buildx version >/dev/null

BUILD_ARGS=(
  --platform "${PLATFORM}"
  --target release-archive-export
  --output "type=local,dest=${OUT_TMP}"
  --build-arg "AUGENMASS_RELEASE_GIT_COMMIT=${GIT_COMMIT}"
  --build-arg "AUGENMASS_RELEASE_GIT_DIRTY=${GIT_DIRTY}"
)

if [ "${AUGENMASS_DOCKER_NO_CACHE:-0}" = "1" ]; then
  BUILD_ARGS+=(--no-cache)
fi

rm -rf "${OUT_TMP}"
mkdir -p "${OUT_TMP}" "$(dirname "${OUT}")"

docker buildx build "${BUILD_ARGS[@]}" .

shopt -s nullglob
archives=("${OUT_TMP}"/augenmass-v*-*.tar.gz)
if [ "${#archives[@]}" -ne 1 ]; then
  echo "expected exactly one exported archive in ${OUT_TMP}" >&2
  exit 1
fi
sidecars=("${archives[0]}.sha256" "${archives[0]}.manifest.json")
for sidecar in "${sidecars[@]}"; do
  if [ ! -f "${sidecar}" ]; then
    echo "exported archive is missing sidecar: ${sidecar}" >&2
    exit 1
  fi
done

archive_sha="$(hash_file "${archives[0]}")"
read -r expected_sha expected_name <"${archives[0]}.sha256"
if [ "${expected_sha}" != "${archive_sha}" ]; then
  echo "exported archive checksum sidecar does not match ${archives[0]}" >&2
  exit 1
fi
if [ "${expected_name}" != "$(basename "${archives[0]}")" ]; then
  echo "exported archive checksum sidecar names ${expected_name}, expected $(basename "${archives[0]}")" >&2
  exit 1
fi
grep -Fq '"schema": "augenmass-release-manifest-v1"' "${archives[0]}.manifest.json"
grep -Fq "\"archive\": \"$(basename "${archives[0]}")\"" "${archives[0]}.manifest.json"
grep -Fq "\"archiveSha256\": \"${archive_sha}\"" "${archives[0]}.manifest.json"
grep -Fq "\"gitCommit\": \"${GIT_COMMIT}\"" "${archives[0]}.manifest.json"
grep -Fq "\"gitDirty\": ${GIT_DIRTY}" "${archives[0]}.manifest.json"

rm -rf "${OUT}"
mv "${OUT_TMP}" "${OUT}"
archives=("${OUT}"/augenmass-v*-*.tar.gz)
if [ "${#archives[@]}" -ne 1 ]; then
  echo "expected exactly one exported archive after publish in ${OUT}" >&2
  exit 1
fi

echo "docker release archive smoke passed for ${PLATFORM}: ${archives[0]}"
echo "proof: Dockerfile release-archive-export copies only from the in-container release-archive-smoke stage"
