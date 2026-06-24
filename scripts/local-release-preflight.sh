#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-all}"
PLUGIN_LAUNCHER="./plugins/augenmass-workbench/bin/augenmass"
PLUGIN_MANIFEST="./plugins/augenmass-workbench/bin/manifest.json"

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command for ${MODE} proof: $1" >&2
    exit 1
  fi
}

require bash
require cargo
require rustc
require rustup
require curl
require jq

case "${MODE}" in
  cli|all|presenter) ;;
  *)
    echo "usage: $0 [cli|presenter|all]" >&2
    exit 2
    ;;
esac

if [ "${MODE}" = "cli" ] || [ "${MODE}" = "all" ]; then
  require docker
  docker info >/dev/null
  docker buildx version >/dev/null
fi

if [ "${MODE}" = "presenter" ] || [ "${MODE}" = "all" ]; then
  require claude
  require codex

  require jq

  host="$(rustc -vV | awk '/^host:/ {print $2}')"
  if [ ! -x "${PLUGIN_LAUNCHER}" ]; then
    echo "presenter plugin launcher is missing or not executable: ${PLUGIN_LAUNCHER}" >&2
    exit 1
  fi
  if [ ! -f "${PLUGIN_MANIFEST}" ]; then
    echo "presenter plugin manifest is missing: ${PLUGIN_MANIFEST}" >&2
    exit 1
  fi
  host_binary_path="$(jq -r --arg target "${host}" '.targets[] | select(.target == $target) | .binary' "${PLUGIN_MANIFEST}")"
  if [ -z "${host_binary_path}" ] || [ "${host_binary_path}" = "null" ]; then
    echo "presenter plugin proof has no bundled target binary for host ${host}" >&2
    echo "use 'just local-cli-release-proof' for plugin-free native CLI proof on this platform" >&2
    exit 1
  fi
  if [ ! -f "./plugins/augenmass-workbench/bin/${host_binary_path}" ]; then
    echo "presenter plugin host binary is missing: ${host_binary_path}" >&2
    exit 1
  fi
  "${PLUGIN_LAUNCHER}" --version >/dev/null
fi

echo "${MODE} release preflight passed"
