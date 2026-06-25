#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd -P)"
cd "${ROOT}"

OUT="$(mktemp "${TMPDIR:-/tmp}/augenmass-deployed-relay-guard-smoke.XXXXXX")"
cleanup() {
  rm -f "${OUT}"
}
trap cleanup EXIT

must_fail() {
  if AUGENMASS_DEPLOYED_RELAY_REQUIRED=1 \
    AUGENMASS_DEPLOYED_RELAY_TOKEN=guard-token \
    ./scripts/deployed-relay-smoke.sh "$1" >"${OUT}" 2>&1; then
    echo "deployed relay required mode unexpectedly accepted: $1" >&2
    cat "${OUT}" >&2
    exit 1
  fi
}

must_fail "http://wallet.example"
must_fail "ws://wallet.example/_relay/tunnel"
must_fail "https://127.0.0.1"
must_fail "https://localhost"
must_fail "https://[::1]"
must_fail "https://10.0.0.1"
must_fail "https://172.16.0.1"
must_fail "https://192.168.0.1"
must_fail "https://169.254.169.254"

echo "deployed relay guard smoke passed"
