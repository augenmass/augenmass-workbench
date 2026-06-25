#!/usr/bin/env bash
set -euo pipefail

PROVIDER_BASE="${AUGENMASS_BUNDESDRUCKEREI_PREPROD_BASE:-https://preprod.pid-provider.bundesdruckerei.de}"
ROOT_CA_URL="${AUGENMASS_BUNDESDRUCKEREI_PREPROD_ROOT_CA_URL:-}"
SIGNER_URL="${AUGENMASS_BUNDESDRUCKEREI_PREPROD_SIGNER_URL:-}"
TRUSTLIST_URL="${AUGENMASS_BUNDESDRUCKEREI_PREPROD_TRUSTLIST_URL:-https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/pid-provider.jwt}"
TIMEOUT="${AUGENMASS_BUNDESDRUCKEREI_PREPROD_TIMEOUT_SECS:-30}"
MAX_BYTES="${AUGENMASS_BUNDESDRUCKEREI_PREPROD_MAX_BYTES:-1048576}"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/augenmass-bundesdruckerei-preprod-material-smoke.XXXXXX")"
ROOT_PAGE="${WORKDIR}/provider.html"
ROOT_CA="${WORKDIR}/root-ca.crt"
SIGNER="${WORKDIR}/signer.crt"
TRUSTLIST="${WORKDIR}/trustlist.jwt"
TRUSTLIST_JSON="${WORKDIR}/trustlist.json"
ROOT_INFO="${WORKDIR}/root-ca.info"
SIGNER_INFO="${WORKDIR}/signer.info"

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

body_bytes() {
  wc -c <"$1" | tr -d '[:space:]'
}

fetch() {
  local url="$1"
  local body="$2"
  if ! curl --max-time "${TIMEOUT}" --max-filesize "${MAX_BYTES}" -fsS -o "${body}" "${url}" >/dev/null; then
    echo "fetch failed or exceeded AUGENMASS_BUNDESDRUCKEREI_PREPROD_MAX_BYTES=${MAX_BYTES}: ${url}" >&2
    exit 1
  fi
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

run_augenmass() {
  "${BIN}" "$@"
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

require curl
require grep
require jq
require sed
require wc
BIN="$(resolve_bin)"
if [ ! -x "${BIN}" ]; then
  echo "Bundesdruckerei preprod material smoke binary is not executable: ${BIN}" >&2
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
validate_fetch_url "AUGENMASS_BUNDESDRUCKEREI_PREPROD_TRUSTLIST_URL" "${TRUSTLIST_URL}"

fetch "${PROVIDER_BASE}/" "${ROOT_PAGE}"
grep -q 'certificates/root-ca.crt' "${ROOT_PAGE}"
grep -q 'certificates/signer.crt' "${ROOT_PAGE}"

fetch "${ROOT_CA_URL}" "${ROOT_CA}"
fetch "${SIGNER_URL}" "${SIGNER}"
fetch "${TRUSTLIST_URL}" "${TRUSTLIST}"

grep -q 'BEGIN CERTIFICATE' "${ROOT_CA}"
grep -q 'BEGIN CERTIFICATE' "${SIGNER}"

run_augenmass x509-hash "${ROOT_CA}" >"${ROOT_INFO}"
run_augenmass x509-hash "${SIGNER}" >"${SIGNER_INFO}"
grep -q 'subject:.*PIDP Preprod CA' "${ROOT_INFO}"
grep -q 'issuer:.*PIDP Preprod CA' "${ROOT_INFO}"
grep -q 'subject:.*PIDP Preprod' "${SIGNER_INFO}"
grep -q 'issuer:.*PIDP Preprod CA' "${SIGNER_INFO}"

run_augenmass decode jwt --json "${TRUSTLIST}" >"${TRUSTLIST_JSON}"
jq -e '.header.typ == "trustlist+jwt"' "${TRUSTLIST_JSON}" >/dev/null
jq -e '.payload.LoTE.TrustedEntitiesList | type == "array" and length > 0' "${TRUSTLIST_JSON}" >/dev/null
jq -e '
  any(.payload.LoTE.TrustedEntitiesList[]?.TrustedEntityInformation.TEName[]?.value; test("Bundesdruckerei"; "i"))
' "${TRUSTLIST_JSON}" >/dev/null
jq -e '
  [.payload.LoTE.TrustedEntitiesList[]?.TrustedEntityServices[]?.ServiceInformation.ServiceTypeIdentifier]
  | index("http://uri.etsi.org/19602/SvcType/PID/Issuance")
  and index("http://uri.etsi.org/19602/SvcType/PID/Revocation")
' "${TRUSTLIST_JSON}" >/dev/null

root_hash="$(sed -n 's/^x509_hash:[[:space:]]*//p' "${ROOT_INFO}" | head -n1)"
signer_hash="$(sed -n 's/^x509_hash:[[:space:]]*//p' "${SIGNER_INFO}" | head -n1)"
entity_count="$(jq '.payload.LoTE.TrustedEntitiesList | length' "${TRUSTLIST_JSON}")"
service_count="$(jq '[.payload.LoTE.TrustedEntitiesList[]?.TrustedEntityServices[]?] | length' "${TRUSTLIST_JSON}")"

echo "provider root page: ok"
echo "root CA: ${root_hash} ($(body_bytes "${ROOT_CA}") bytes)"
echo "status signer: ${signer_hash} ($(body_bytes "${SIGNER}") bytes)"
echo "trustlist: ${entity_count} trusted entity item(s), ${service_count} service item(s)"
echo "Bundesdruckerei preprod material smoke passed"
