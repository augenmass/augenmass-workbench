#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd -P)"
cd "${ROOT}"

PLUGIN_LAUNCHER="${ROOT}/plugins/augenmass-workbench/bin/augenmass"
PLUGIN_MANIFEST="${ROOT}/plugins/augenmass-workbench/bin/manifest.json"
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

if [ ! -x "${PLUGIN_LAUNCHER}" ]; then
  echo "plugin launcher is missing or not executable: ${PLUGIN_LAUNCHER}" >&2
  exit 1
fi
if [ ! -f "${PLUGIN_MANIFEST}" ]; then
  echo "plugin bundle manifest is missing: ${PLUGIN_MANIFEST}" >&2
  exit 1
fi

cargo_version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)"
expected_version="augenmass ${cargo_version}"
expected_binary_marker="augenmass/${cargo_version}"

jq -e \
  --arg version "${cargo_version}" \
  '.schema == "augenmass-plugin-bundle-v1"
    and .version == $version
    and .unsignedPreview == true
    and (.targets | length) == 4' \
  "${PLUGIN_MANIFEST}" >/dev/null

for target in aarch64-apple-darwin x86_64-apple-darwin x86_64-unknown-linux-gnu x86_64-pc-windows-msvc; do
  binary_path="$(jq -r --arg target "${target}" '.targets[] | select(.target == $target) | .binary' "${PLUGIN_MANIFEST}")"
  if [ -z "${binary_path}" ] || [ "${binary_path}" = "null" ]; then
    echo "plugin bundle manifest is missing target ${target}" >&2
    exit 1
  fi
  if [ ! -f "${ROOT}/plugins/augenmass-workbench/bin/${binary_path}" ]; then
    echo "plugin target binary is missing: ${binary_path}" >&2
    exit 1
  fi
  binary_sha="$(hash_file "${ROOT}/plugins/augenmass-workbench/bin/${binary_path}")"
  manifest_sha="$(jq -r --arg target "${target}" '.targets[] | select(.target == $target) | .binarySha256' "${PLUGIN_MANIFEST}")"
  if [ "${binary_sha}" != "${manifest_sha}" ]; then
    echo "plugin target binary hash mismatch for ${target}" >&2
    echo "manifest sha: ${manifest_sha}" >&2
    echo "binary sha:   ${binary_sha}" >&2
    exit 1
  fi
  if ! grep -aFq "${expected_binary_marker}" "${ROOT}/plugins/augenmass-workbench/bin/${binary_path}"; then
    echo "plugin target binary version marker mismatch for ${target}: expected '${expected_binary_marker}'" >&2
    exit 1
  fi
done

plugin_version="$("${PLUGIN_LAUNCHER}" --version)"

if [ "${plugin_version}" != "${expected_version}" ]; then
  echo "plugin launcher version mismatch: expected '${expected_version}', got '${plugin_version}'" >&2
  exit 1
fi

host_binary_path="$(jq -r --arg target "${host}" '.targets[] | select(.target == $target) | .binary' "${PLUGIN_MANIFEST}")"
if [ -n "${host_binary_path}" ] && [ "${host_binary_path}" != "null" ]; then
  PLUGIN_HOST_BIN="${ROOT}/plugins/augenmass-workbench/bin/${host_binary_path}"
  "${PLUGIN_HOST_BIN}" --version >/dev/null 2>&1 || true
fi

if [ "${AUGENMASS_STRICT_LOCAL_PLUGIN_BUILD:-0}" = "1" ]; then
  case "${host}" in
    aarch64-apple-darwin | x86_64-apple-darwin | x86_64-unknown-linux-gnu)
      ;;
    *)
      echo "strict local plugin build comparison is unsupported on ${host}" >&2
      exit 1
      ;;
  esac

  if [ -z "${host_binary_path}" ] || [ "${host_binary_path}" = "null" ]; then
    echo "plugin bundle manifest has no current-host target ${host}" >&2
    exit 1
  fi

  cargo build --release --locked
  if [ ! -x "${BUILD_BIN}" ]; then
    echo "release binary is missing or not executable after build: ${BUILD_BIN}" >&2
    exit 1
  fi
  build_version="$("${BUILD_BIN}" --version)"
  if [ "${build_version}" != "${expected_version}" ]; then
    echo "release binary version mismatch: expected '${expected_version}', got '${build_version}'" >&2
    exit 1
  fi

  plugin_sha="$(hash_file "${PLUGIN_HOST_BIN}")"
  build_sha="$(hash_file "${BUILD_BIN}")"
  if [ "${plugin_sha}" != "${build_sha}" ]; then
    echo "strict local compare failed for ${host}; release-built binaries are not byte-identical to this local build" >&2
    echo "plugin sha: ${plugin_sha}" >&2
    echo "build sha:  ${build_sha}" >&2
    exit 1
  fi
fi

echo "plugin bundle freshness passed for release manifest ${cargo_version}"
