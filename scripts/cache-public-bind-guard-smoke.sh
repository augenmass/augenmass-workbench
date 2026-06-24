#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd -P)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/augenmass-cache-public-bind-guard.XXXXXX")"
BASE_PORT="${AUGENMASS_CACHE_PUBLIC_BIND_GUARD_PORT:-19181}"

cleanup() {
  rm -rf "${TMP}"
}
trap cleanup EXIT

resolve_bin() {
  if [ -n "${AUGENMASS_SMOKE_BIN:-}" ]; then
    printf '%s\n' "${AUGENMASS_SMOKE_BIN}"
  elif [ -n "${AUGENMASS_BIN:-}" ]; then
    printf '%s\n' "${AUGENMASS_BIN}"
  else
    printf '%s\n' "${ROOT}/plugins/augenmass-workbench/bin/augenmass"
  fi
}

BIN="$(resolve_bin)"
if [ ! -x "${BIN}" ]; then
  echo "smoke binary is not executable: ${BIN}" >&2
  exit 1
fi

BASE_ENV=(
  env
  -u AUGENMASS_CACHE_ADMIN_TOKEN
  -u AUGENMASS_CACHE_ALLOWED_RPS
  -u AUGENMASS_CACHE_ALLOW_ANY_RP
  -u AUGENMASS_CACHE_UNSAFE_UPSTREAM
  -u AUGENMASS_CACHE_UPSTREAM
  -u AUGENMASS_CACHE_PORT
  -u PORT
)

expect_refuse() {
  local label="$1"
  local expected="$2"
  shift 2

  local safe_label out rc_file pid rc
  safe_label="$(printf '%s' "${label}" | tr -c '[:alnum:]_-' '_')"
  out="${TMP}/${safe_label}.log"
  rc_file="${TMP}/${safe_label}.rc"

  (
    set +e
    "${BASE_ENV[@]}" "$@" >"${out}" 2>&1
    printf '%s' "$?" >"${rc_file}"
  ) &
  pid="$!"

  for _ in $(seq 1 40); do
    if [ -s "${rc_file}" ]; then
      wait "${pid}" >/dev/null 2>&1 || true
      rc="$(cat "${rc_file}")"
      if [ "${rc}" -eq 0 ]; then
        echo "${label}: command unexpectedly succeeded" >&2
        cat "${out}" >&2
        exit 1
      fi
      if ! grep -q "${expected}" "${out}"; then
        echo "${label}: expected refusal containing: ${expected}" >&2
        cat "${out}" >&2
        exit 1
      fi
      echo "${label}: refused"
      return
    fi
    sleep 0.1
  done

  kill "${pid}" >/dev/null 2>&1 || true
  wait "${pid}" >/dev/null 2>&1 || true
  echo "${label}: command kept running; expected a startup refusal" >&2
  cat "${out}" >&2 || true
  exit 1
}

cd "${ROOT}"

expect_refuse \
  "public bind without admin token" \
  "AUGENMASS_CACHE_ADMIN_TOKEN is required" \
  "${BIN}" cache serve \
    --host 0.0.0.0 \
    --port "${BASE_PORT}" \
    --db "${TMP}/no-admin.sqlite"

expect_refuse \
  "public bind without allowed RP" \
  "AUGENMASS_CACHE_ALLOWED_RPS must include at least one RP" \
  env AUGENMASS_CACHE_ADMIN_TOKEN=local-smoke AUGENMASS_CACHE_ALLOWED_RPS= \
  "${BIN}" cache serve \
    --host 0.0.0.0 \
    --port "$((BASE_PORT + 1))" \
    --db "${TMP}/no-rp.sqlite"

expect_refuse \
  "public bind with plain-http upstream" \
  "AUGENMASS_CACHE_UPSTREAM must use https" \
  env AUGENMASS_CACHE_ADMIN_TOKEN=local-smoke \
  "${BIN}" cache serve \
    --host 0.0.0.0 \
    --port "$((BASE_PORT + 2))" \
    --db "${TMP}/http-upstream.sqlite" \
    --upstream "http://127.0.0.1:9/api"

expect_refuse \
  "public bind with private upstream" \
  "AUGENMASS_CACHE_UPSTREAM must not point at" \
  env AUGENMASS_CACHE_ADMIN_TOKEN=local-smoke \
  "${BIN}" cache serve \
    --host 0.0.0.0 \
    --port "$((BASE_PORT + 3))" \
    --db "${TMP}/private-upstream.sqlite" \
    --upstream "https://127.0.0.1/api"

expect_refuse \
  "zero cache entries" \
  "cache max entries must be at least 1" \
  env AUGENMASS_CACHE_ADMIN_TOKEN=local-smoke \
  "${BIN}" cache serve \
    --host 0.0.0.0 \
    --port "$((BASE_PORT + 4))" \
    --db "${TMP}/zero-entries.sqlite" \
    --max-entries 0

echo "cache public-bind guard smoke passed"
