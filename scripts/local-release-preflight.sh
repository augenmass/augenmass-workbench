#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-all}"
PLUGIN_BIN="./plugins/augenmass-workbench/bin/augenmass"

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

  host="$(rustc -vV | awk '/^host:/ {print $2}')"
  if [ "${host}" != "aarch64-apple-darwin" ]; then
    echo "presenter plugin proof requires the committed macOS Apple Silicon bundle (host is ${host})" >&2
    echo "use 'just local-cli-release-proof' for plugin-free native CLI proof on this platform" >&2
    exit 1
  fi

  if [ ! -x "${PLUGIN_BIN}" ]; then
    echo "presenter plugin binary is missing or not executable: ${PLUGIN_BIN}" >&2
    exit 1
  fi
  "${PLUGIN_BIN}" --version >/dev/null
fi

echo "${MODE} release preflight passed"
