#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  cat >&2 <<'EOF'
usage: scripts/bundesdruckerei-wallet-trust-status-proof.sh <evidence-bundle.json>

Fetches the current Bundesdruckerei preprod PID root/signing material, then runs:
  evidence assert-live
  evidence prove-trust-status --fetch-status-token
EOF
  exit 2
fi

BUNDLE="$1"
PROVIDER_BASE="${AUGENMASS_BUNDESDRUCKEREI_PREPROD_BASE:-https://preprod.pid-provider.bundesdruckerei.de}"
ROOT_CA_URL="${AUGENMASS_BUNDESDRUCKEREI_PREPROD_ROOT_CA_URL:-}"
SIGNER_URL="${AUGENMASS_BUNDESDRUCKEREI_PREPROD_SIGNER_URL:-}"
TIMEOUT="${AUGENMASS_BUNDESDRUCKEREI_PREPROD_TIMEOUT_SECS:-30}"
MAX_BYTES="${AUGENMASS_BUNDESDRUCKEREI_PREPROD_MAX_BYTES:-1048576}"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/augenmass-bdr-wallet-proof.XXXXXX")"
ROOT_CA="${WORKDIR}/root-ca.crt"
SIGNER="${WORKDIR}/signer.crt"

cleanup() {
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

trim_base() {
  printf '%s' "$1" | sed 's:/*$::'
}

resolve_bin() {
  if [ -n "${AUGENMASS_BUNDESDRUCKEREI_PREPROD_BIN:-}" ]; then
    printf '%s\n' "${AUGENMASS_BUNDESDRUCKEREI_PREPROD_BIN}"
  elif [ -n "${AUGENMASS_SMOKE_BIN:-}" ]; then
    printf '%s\n' "${AUGENMASS_SMOKE_BIN}"
  elif [ -n "${AUGENMASS_BIN:-}" ]; then
    printf '%s\n' "${AUGENMASS_BIN}"
  else
    printf '%s\n' "./plugins/augenmass-workbench/bin/augenmass"
  fi
}

validate_fetch_url() {
  local label="$1"
  local url="$2"
  case "${url}" in
    https://*) ;;
    *)
      echo "${label} must be an https URL: ${url}" >&2
      exit 1
      ;;
  esac
  case "${url#https://}" in
    *@* | *\?* | *\#*)
      echo "${label} must not contain userinfo, query, or fragment: ${url}" >&2
      exit 1
      ;;
  esac
}

fetch() {
  local url="$1"
  local body="$2"
  if ! curl --max-time "${TIMEOUT}" --max-filesize "${MAX_BYTES}" -fsS -o "${body}" "${url}" >/dev/null; then
    echo "fetch failed or exceeded AUGENMASS_BUNDESDRUCKEREI_PREPROD_MAX_BYTES=${MAX_BYTES}: ${url}" >&2
    exit 1
  fi
}

require curl
require grep
require sed

if [ ! -f "${BUNDLE}" ]; then
  echo "evidence bundle does not exist: ${BUNDLE}" >&2
  exit 1
fi

BIN="$(resolve_bin)"
if [ ! -x "${BIN}" ]; then
  echo "Bundesdruckerei wallet proof binary is not executable: ${BIN}" >&2
  exit 1
fi

PROVIDER_BASE="$(trim_base "${PROVIDER_BASE}")"
if [ -z "${ROOT_CA_URL}" ]; then
  ROOT_CA_URL="${PROVIDER_BASE}/certificates/root-ca.crt"
fi
if [ -z "${SIGNER_URL}" ]; then
  SIGNER_URL="${PROVIDER_BASE}/certificates/signer.crt"
fi

validate_fetch_url "AUGENMASS_BUNDESDRUCKEREI_PREPROD_BASE" "${PROVIDER_BASE}/"
validate_fetch_url "AUGENMASS_BUNDESDRUCKEREI_PREPROD_ROOT_CA_URL" "${ROOT_CA_URL}"
validate_fetch_url "AUGENMASS_BUNDESDRUCKEREI_PREPROD_SIGNER_URL" "${SIGNER_URL}"

fetch "${ROOT_CA_URL}" "${ROOT_CA}"
fetch "${SIGNER_URL}" "${SIGNER}"
grep -q 'BEGIN CERTIFICATE' "${ROOT_CA}"
grep -q 'BEGIN CERTIFICATE' "${SIGNER}"

"${BIN}" evidence assert-live "${BUNDLE}"
"${BIN}" evidence prove-trust-status "${BUNDLE}" \
  --trust-anchor "${ROOT_CA}" \
  --fetch-status-token \
  --status-key "${SIGNER}"

echo "Bundesdruckerei wallet trust/status proof passed"
