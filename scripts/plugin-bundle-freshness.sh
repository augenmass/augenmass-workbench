#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd -P)"
cd "${ROOT}"

PLUGIN_BIN="${ROOT}/plugins/augenmass-workbench/bin/augenmass"
BUILD_BIN="${ROOT}/target/release/augenmass"

hash_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    echo "missing shasum or sha256sum" >&2
    exit 1
  fi
}

host="$(rustc -vV | sed -n 's/^host: //p')"
if [ "${host}" != "aarch64-apple-darwin" ]; then
  echo "plugin bundle freshness requires aarch64-apple-darwin (got ${host})" >&2
  echo "use 'just local-cli-release-proof' for plugin-free source and archive proof on this platform" >&2
  exit 1
fi

if [ ! -x "${PLUGIN_BIN}" ]; then
  echo "plugin binary is missing or not executable: ${PLUGIN_BIN}" >&2
  exit 1
fi

cargo build --release --locked

if [ ! -x "${BUILD_BIN}" ]; then
  echo "release binary is missing or not executable after build: ${BUILD_BIN}" >&2
  exit 1
fi

cargo_version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)"
expected_version="augenmass ${cargo_version}"
plugin_version="$("${PLUGIN_BIN}" --version)"
build_version="$("${BUILD_BIN}" --version)"

if [ "${plugin_version}" != "${expected_version}" ]; then
  echo "plugin binary version mismatch: expected '${expected_version}', got '${plugin_version}'" >&2
  exit 1
fi

if [ "${build_version}" != "${expected_version}" ]; then
  echo "release binary version mismatch: expected '${expected_version}', got '${build_version}'" >&2
  exit 1
fi

plugin_sha="$(hash_file "${PLUGIN_BIN}")"
build_sha="$(hash_file "${BUILD_BIN}")"

if [ "${plugin_sha}" != "${build_sha}" ]; then
  echo "plugin binary is stale relative to target/release/augenmass" >&2
  echo "plugin sha: ${plugin_sha}" >&2
  echo "build sha:  ${build_sha}" >&2
  echo "run 'just bundle', review the binary diff, then rerun this check" >&2
  exit 1
fi

echo "plugin bundle freshness passed: ${plugin_sha}"
