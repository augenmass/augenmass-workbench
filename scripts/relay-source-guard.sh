#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd -P)"
cd "${ROOT}"

fail_if_rg() {
  local pattern="$1"
  local message="$2"
  shift 2
  if rg -n "${pattern}" "$@"; then
    echo "${message}" >&2
    exit 1
  fi
}

fail_if_rg \
  'from_utf8_lossy|TraceLayer' \
  "relay source guard: do not add lossy body decoding or request URI TraceLayer logging to the relay" \
  crates/augenmass-relay src/serve/relay_client.rs

fail_if_rg \
  'tracing::(trace|debug|info|warn|error)!\([^;]*(body_b64|headers|query|path|Authorization|Cookie|run_id|session)' \
  "relay source guard: relay logs must not include raw paths, queries, headers, full run ids, sessions, or forwarded bodies" \
  crates/augenmass-relay

fail_if_rg \
  'trace|inspect|api/trace|unsafe' \
  "relay source guard: public relay routes must stay wallet-only and must not expose trace/inspect/debug artifacts" \
  crates/augenmass-relay/src/routes.rs

echo "relay source guard passed"
