#!/usr/bin/env bash
set -euo pipefail

resolve_release_bin() {
  if [ -n "${AUGENMASS_BIN:-}" ]; then
    printf '%s\n' "${AUGENMASS_BIN}"
    return
  fi

  for candidate in ./target/release/augenmass ./target/release/augenmass.exe; do
    if [ -x "${candidate}" ]; then
      printf '%s\n' "${candidate}"
      return
    fi
  done

  echo "no executable release binary found at ./target/release/augenmass or ./target/release/augenmass.exe" >&2
  echo "run: just release" >&2
  exit 1
}

BIN="$(resolve_release_bin)"
echo "local CLI release binary: ${BIN}"

AUGENMASS_DEMO_BIN="${BIN}" AUGENMASS_BIN="${BIN}" ./scripts/demo-run.sh
AUGENMASS_BIN="${BIN}" ./scripts/serve-smoke.sh
AUGENMASS_BIN="${BIN}" ./scripts/live-cache-smoke.sh
