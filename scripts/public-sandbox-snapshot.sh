#!/usr/bin/env bash
set -euo pipefail

API_BASE="${AUGENMASS_PUBLIC_SANDBOX_API_BASE:-https://sandbox.eudi-wallet.org/api}"
RP="${AUGENMASS_PUBLIC_SANDBOX_RP:-2af138a8-59ea-4a84-aea3-666cafdb1369}"
TIMEOUT="${AUGENMASS_PUBLIC_SANDBOX_TIMEOUT_SECS:-30}"
MAX_BYTES="${AUGENMASS_PUBLIC_SANDBOX_MAX_BYTES:-5242880}"
REQUIRE_RP="${AUGENMASS_PUBLIC_SANDBOX_REQUIRE_RP:-1}"
OUT_JSON="${AUGENMASS_PUBLIC_SANDBOX_SNAPSHOT_JSON:-}"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/augenmass-public-sandbox-snapshot.XXXXXX")"
SCHEMA_HEADERS="${WORKDIR}/schema.headers"
SCHEMA_BODY="${WORKDIR}/schema.json"
VOCAB_HEADERS="${WORKDIR}/vocabularies.headers"
VOCAB_BODY="${WORKDIR}/vocabularies.json"
REG_HEADERS="${WORKDIR}/registrations.headers"
REG_BODY="${WORKDIR}/registrations.json"
RP_HEADERS="${WORKDIR}/rp-registrations.headers"
RP_BODY="${WORKDIR}/rp-registrations.json"
SUMMARY="${WORKDIR}/summary.json"

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

header_value() {
  awk -F': ' -v name="$1" 'tolower($1)==tolower(name) {gsub(/\r/,"",$2); print $2; exit}' "$2"
}

fetch() {
  local url="$1"
  local headers="$2"
  local body="$3"
  curl --max-time "${TIMEOUT}" -fsS -D "${headers}" -o "${body}" "${url}" >/dev/null
}

body_bytes() {
  wc -c <"$1" | tr -d '[:space:]'
}

assert_under_cap() {
  local label="$1"
  local body="$2"
  local bytes
  bytes="$(body_bytes "${body}")"
  if [ "${bytes}" -gt "${MAX_BYTES}" ]; then
    echo "${label} exceeded AUGENMASS_PUBLIC_SANDBOX_MAX_BYTES=${MAX_BYTES}: ${bytes} bytes" >&2
    exit 1
  fi
}

require awk
require curl
require jq
require sed
require wc

API_BASE="$(trim_base "${API_BASE}")"

fetch "${API_BASE}/schema-metadata" "${SCHEMA_HEADERS}" "${SCHEMA_BODY}"
fetch "${API_BASE}/schema-metadata/vocabularies" "${VOCAB_HEADERS}" "${VOCAB_BODY}"
fetch "${API_BASE}/registration-certificates" "${REG_HEADERS}" "${REG_BODY}"
fetch "${API_BASE}/registration-certificates?rp=${RP}" "${RP_HEADERS}" "${RP_BODY}"

assert_under_cap "schema-metadata" "${SCHEMA_BODY}"
assert_under_cap "schema-metadata/vocabularies" "${VOCAB_BODY}"
assert_under_cap "registration-certificates" "${REG_BODY}"
assert_under_cap "registration-certificates?rp=${RP}" "${RP_BODY}"

jq -e 'type == "array"' "${REG_BODY}" >/dev/null
jq -e 'type == "array"' "${RP_BODY}" >/dev/null
jq -e '.' "${SCHEMA_BODY}" >/dev/null
jq -e 'type == "object"' "${VOCAB_BODY}" >/dev/null

schema_bytes="$(body_bytes "${SCHEMA_BODY}")"
vocab_bytes="$(body_bytes "${VOCAB_BODY}")"
registration_bytes="$(body_bytes "${REG_BODY}")"
rp_bytes="$(body_bytes "${RP_BODY}")"
rp_count="$(jq 'length' "${RP_BODY}")"

if [ "${REQUIRE_RP}" = "1" ] && [ "${rp_count}" -eq 0 ]; then
  echo "configured RP ${RP} has zero public sandbox registrations; set AUGENMASS_PUBLIC_SANDBOX_REQUIRE_RP=0 to allow this" >&2
  exit 1
fi

jq -n \
  --arg apiBase "${API_BASE}" \
  --arg relyingPartyId "${RP}" \
  --arg requireRp "${REQUIRE_RP}" \
  --arg maxBytes "${MAX_BYTES}" \
  --arg capturedAt "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  --arg schemaEtag "$(header_value etag "${SCHEMA_HEADERS}")" \
  --arg schemaLength "$(header_value content-length "${SCHEMA_HEADERS}")" \
  --arg schemaRateLimitRemaining "$(header_value x-ratelimit-remaining "${SCHEMA_HEADERS}")" \
  --arg vocabEtag "$(header_value etag "${VOCAB_HEADERS}")" \
  --arg vocabLength "$(header_value content-length "${VOCAB_HEADERS}")" \
  --arg vocabRateLimitRemaining "$(header_value x-ratelimit-remaining "${VOCAB_HEADERS}")" \
  --arg registrationsEtag "$(header_value etag "${REG_HEADERS}")" \
  --arg registrationsLength "$(header_value content-length "${REG_HEADERS}")" \
  --arg registrationsRateLimitRemaining "$(header_value x-ratelimit-remaining "${REG_HEADERS}")" \
  --arg rpEtag "$(header_value etag "${RP_HEADERS}")" \
  --arg rpLength "$(header_value content-length "${RP_HEADERS}")" \
  --arg rpRateLimitRemaining "$(header_value x-ratelimit-remaining "${RP_HEADERS}")" \
  --argjson schemaBytes "${schema_bytes}" \
  --argjson vocabBytes "${vocab_bytes}" \
  --argjson registrationBytes "${registration_bytes}" \
  --argjson rpBytes "${rp_bytes}" \
  --slurpfile rpRegistrations "${RP_BODY}" \
  --slurpfile registrations "${REG_BODY}" '
  ($registrations[0]) as $regs |
  ($rpRegistrations[0]) as $rpRegs |
  {
    kind: "augenmass-public-sandbox-snapshot",
    apiBase: $apiBase,
    configuredRelyingPartyId: $relyingPartyId,
    capturedAt: $capturedAt,
    maxBytes: ($maxBytes | tonumber),
    requireConfiguredRp: ($requireRp == "1"),
    schemaMetadata: {
      bytes: $schemaBytes,
      contentLength: (if $schemaLength == "" then null else ($schemaLength | tonumber) end),
      etag: $schemaEtag,
      rateLimitRemaining: (if $schemaRateLimitRemaining == "" then null else ($schemaRateLimitRemaining | tonumber) end)
    },
    schemaVocabularies: {
      bytes: $vocabBytes,
      contentLength: (if $vocabLength == "" then null else ($vocabLength | tonumber) end),
      etag: $vocabEtag,
      rateLimitRemaining: (if $vocabRateLimitRemaining == "" then null else ($vocabRateLimitRemaining | tonumber) end)
    },
    registrationCertificates: {
      count: ($regs | length),
      bytes: $registrationBytes,
      contentLength: (if $registrationsLength == "" then null else ($registrationsLength | tonumber) end),
      etag: $registrationsEtag,
      rateLimitRemaining: (if $registrationsRateLimitRemaining == "" then null else ($registrationsRateLimitRemaining | tonumber) end),
      distinctRelyingParties: ([$regs[].relyingPartyId] | map(select(. != null)) | unique | length),
      createdAtMin: ([$regs[].createdAt] | map(select(. != null)) | min),
      createdAtMax: ([$regs[].createdAt] | map(select(. != null)) | max),
      latest: (
        $regs
        | sort_by(.createdAt // "")
        | reverse
        | .[0:5]
        | map({
            createdAt,
            id,
            relyingPartyId,
            purpose: ((.intendedUse.purpose[0].name // "") | tostring)
          })
      ),
      topRelyingParties: (
        $regs
        | group_by(.relyingPartyId)
        | map({
            relyingPartyId: (.[0].relyingPartyId // ""),
            count: length,
            newestCreatedAt: ([.[].createdAt] | map(select(. != null)) | max)
          })
        | sort_by(.count, .newestCreatedAt)
        | reverse
        | .[0:10]
      )
    },
    configuredRelyingPartyRegistrations: {
      relyingPartyId: $relyingPartyId,
      count: ($rpRegs | length),
      bytes: $rpBytes,
      contentLength: (if $rpLength == "" then null else ($rpLength | tonumber) end),
      etag: $rpEtag,
      rateLimitRemaining: (if $rpRateLimitRemaining == "" then null else ($rpRateLimitRemaining | tonumber) end),
      createdAtMin: ([$rpRegs[].createdAt] | map(select(. != null)) | min),
      createdAtMax: ([$rpRegs[].createdAt] | map(select(. != null)) | max),
      latest: (
        $rpRegs
        | sort_by(.createdAt // "")
        | reverse
        | .[0:5]
        | map({
            createdAt,
            id,
            purpose: ((.intendedUse.purpose[0].name // "") | tostring)
          })
      )
    }
  }' >"${SUMMARY}"

if [ -n "${OUT_JSON}" ]; then
  mkdir -p "$(dirname "${OUT_JSON}")"
  cp "${SUMMARY}" "${OUT_JSON}"
fi

jq -r '
  "public sandbox snapshot:",
  "  apiBase: \(.apiBase)",
  "  capturedAt: \(.capturedAt)",
  "  maxBytes: \(.maxBytes)",
  "  schema: bytes=\(.schemaMetadata.bytes) etag=\(.schemaMetadata.etag) rateLimitRemaining=\(.schemaMetadata.rateLimitRemaining // "unknown")",
  "  vocabularies: bytes=\(.schemaVocabularies.bytes) etag=\(.schemaVocabularies.etag) rateLimitRemaining=\(.schemaVocabularies.rateLimitRemaining // "unknown")",
  "  registrations: count=\(.registrationCertificates.count) distinctRelyingParties=\(.registrationCertificates.distinctRelyingParties) bytes=\(.registrationCertificates.bytes) etag=\(.registrationCertificates.etag) rateLimitRemaining=\(.registrationCertificates.rateLimitRemaining // "unknown")",
  "  createdAt: min=\(.registrationCertificates.createdAtMin) max=\(.registrationCertificates.createdAtMax)",
  "  configured RP: \(.configuredRelyingPartyRegistrations.relyingPartyId) count=\(.configuredRelyingPartyRegistrations.count) bytes=\(.configuredRelyingPartyRegistrations.bytes) etag=\(.configuredRelyingPartyRegistrations.etag) newest=\(.configuredRelyingPartyRegistrations.createdAtMax // "none")",
  "  latest registrations:",
  (.registrationCertificates.latest[] | "    \(.createdAt) \(.relyingPartyId) \(.id) \(.purpose)"),
  "  top relying parties:",
  (.registrationCertificates.topRelyingParties[] | "    count=\(.count) newest=\(.newestCreatedAt) rp=\(.relyingPartyId)")
' "${SUMMARY}"

if [ -n "${OUT_JSON}" ]; then
  echo "snapshot summary written: ${OUT_JSON}"
fi
