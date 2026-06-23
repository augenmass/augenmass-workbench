#!/usr/bin/env bash
set -euo pipefail

PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-./plugins/augenmass-workbench}"
BIN="${PLUGIN_ROOT}/bin/augenmass"
SKILL="${PLUGIN_ROOT}/skills/augenmass/SKILL.md"
HOOKS="${PLUGIN_ROOT}/hooks/hooks.json"
PLUGIN_JSON="${PLUGIN_ROOT}/.claude-plugin/plugin.json"
OUT="$(mktemp "${TMPDIR:-/tmp}/augenmass-plugin-smoke.XXXXXX")"
EVIDENCE_SOURCE=""
EVIDENCE_BUNDLE=""

cleanup() {
  rm -f "${OUT}"
  if [ -n "${EVIDENCE_SOURCE}" ]; then
    rm -rf "${EVIDENCE_SOURCE}"
  fi
  if [ -n "${EVIDENCE_BUNDLE}" ]; then
    rm -f "${EVIDENCE_BUNDLE}"
  fi
}
trap cleanup EXIT

help_has() {
  "${BIN}" "$@" --help >"${OUT}"
}

must_fail() {
  if "$@" >"${OUT}" 2>&1; then
    echo "command unexpectedly succeeded: $*" >&2
    exit 1
  fi
}

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

len_file() {
  wc -c <"$1" | tr -d '[:space:]'
}

for path in "${BIN}" "${SKILL}" "${HOOKS}" "${PLUGIN_JSON}"; do
  if [ ! -e "${path}" ]; then
    echo "missing plugin file: ${path}" >&2
    exit 1
  fi
done

if [ ! -x "${BIN}" ]; then
  echo "plugin binary is not executable: ${BIN}" >&2
  exit 1
fi

grep -q '"name": "augenmass-workbench"' "${PLUGIN_JSON}"
grep -q 'chmod +x' "${HOOKS}"
grep -q '\${CLAUDE_PLUGIN_ROOT}/bin/augenmass' "${SKILL}"
grep -q 'cache serve' "${SKILL}"
grep -q 'Prewarm the cached-sandbox mirror before a demo' "${SKILL}"
grep -q 'Debug a live wallet interaction' "${SKILL}"
grep -q 'evidence replay' "${SKILL}"

CARGO_VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)"
PLUGIN_VERSION="$(sed -n 's/.*"version": "\([^"]*\)".*/\1/p' "${PLUGIN_JSON}" | head -n 1)"
if [ "${CARGO_VERSION}" != "${PLUGIN_VERSION}" ]; then
  echo "Cargo.toml version (${CARGO_VERSION}) does not match plugin.json (${PLUGIN_VERSION})" >&2
  exit 1
fi

"${BIN}" --version >"${OUT}"
grep -q "^augenmass ${CARGO_VERSION}$" "${OUT}"
echo "plugin binary: $(cat "${OUT}")"

help_has inspect
grep -q '<INPUT>' "${OUT}"

for decoder in jwt sd-jwt regcert request offer status-list mdoc; do
  help_has decode "${decoder}"
  grep -q '<INPUT>' "${OUT}"
done

help_has check
grep -q '<BODY>' "${OUT}"

help_has audit
grep -q -- '--purpose' "${OUT}"

help_has baselines

for verifier in presentation trust status status-list; do
  help_has verify "${verifier}"
done

help_has x509-hash
grep -q -- '--client-id' "${OUT}"

help_has generate regbody
grep -q -- '--over-broad' "${OUT}"

help_has generate dcql
grep -q -- '--claim' "${OUT}"

help_has doctor
help_has validate dcql

help_has register
grep -q -- '--yes' "${OUT}"
grep -q -- '--force' "${OUT}"

help_has list
help_has clone serve

help_has cache serve
grep -q -- '--admin-token' "${OUT}"
grep -q -- '--timeout-secs' "${OUT}"

help_has cache warm
grep -q -- '--api-base' "${OUT}"
grep -q -- '--admin-token' "${OUT}"
grep -q -- '--rp' "${OUT}"
grep -q -- '--timeout-secs' "${OUT}"

help_has serve
grep -q -- '--unsafe-debug-artifacts' "${OUT}"
grep -q -- '--live-status' "${OUT}"

for evidence in export verify replay; do
  help_has evidence "${evidence}"
done

"${BIN}" inspect fixtures/requests/eudiplo-request.jwt >"${OUT}"
grep -q 'OpenID4VP authorization request / JAR' "${OUT}"

must_fail "${BIN}" doctor examples/bad-request.json
grep -q 'DOCTOR-X5C-STRING' "${OUT}"
grep -q 'DOCTOR-CLIENT-ID-X509HASH' "${OUT}"

"${BIN}" generate regbody --json | "${BIN}" check - >"${OUT}"
grep -q 'OK: no over-ask' "${OUT}"

if "${BIN}" generate regbody --over-broad | "${BIN}" check - >"${OUT}" 2>&1; then
  echo "over-broad generated body unexpectedly passed check" >&2
  exit 1
fi
grep -q 'OVER-ASK' "${OUT}"

"${BIN}" generate dcql --claim given_name --claim age_equal_or_over.18 | "${BIN}" validate dcql - >"${OUT}"
grep -q 'DCQL VALID' "${OUT}"

must_fail "${BIN}" validate dcql '{"credentials":[]}'
grep -q 'DCQL-CREDENTIALS-EMPTY' "${OUT}"

"${BIN}" decode mdoc fixtures/mdoc/issuer-signed.hex >"${OUT}"
grep -q 'mdoc' "${OUT}"

"${BIN}" baselines age_gate_18 >"${OUT}"
grep -q 'Age gate' "${OUT}"

"${BIN}" x509-hash fixtures/certs/access-leaf.pem --client-id x509_hash:VE3qp3vLVkU8JyVmXkjL7CSDVxVoTFdTv5fAEwmjKOI >"${OUT}"
grep -q 'MATCH' "${OUT}"

must_fail "${BIN}" x509-hash fixtures/certs/access-leaf.pem --client-id x509_hash:not-the-right-binding
grep -q 'MISMATCH' "${OUT}"

"${BIN}" verify trust fixtures/presentations/erica-vp-VALID.sdjwt --anchor fixtures/certs/erica-trust-anchor.pem --now 1780435200 >"${OUT}"
grep -q 'TRUSTED' "${OUT}"

"${BIN}" verify status-list --token fixtures/status/status-list-CLEAR.jwt --key fixtures/status/status-list-verify-key.pub.pem --index 42 >"${OUT}"
grep -q 'VALID' "${OUT}"

must_fail "${BIN}" verify status-list --token fixtures/status/status-list-REVOKED.jwt --key fixtures/status/status-list-verify-key.pub.pem --index 42
grep -q 'REVOKED' "${OUT}"

"${BIN}" register examples/min.json --target cached-sandbox >"${OUT}"
grep -q 'DRY RUN' "${OUT}"

must_fail "${BIN}" register examples/min.json --target cached-sandbox --yes
grep -q 'cached-sandbox is read-only' "${OUT}"

EVIDENCE_SOURCE="$(mktemp -d "${TMPDIR:-/tmp}/augenmass-evidence-source.XXXXXX")"
EVIDENCE_BUNDLE="$(mktemp "${TMPDIR:-/tmp}/augenmass-evidence-bundle.XXXXXX.json")"

REQ="${EVIDENCE_SOURCE}/request.payload.json"
BODY="${EVIDENCE_SOURCE}/direct-post.body"
CTX="${EVIDENCE_SOURCE}/verification-context.json"

printf '%s' '{"client_id":"https://self-issued.me/v2","nonce":"n","client_metadata":{"jwks":{"keys":[{"kid":"enc-1"}]}},"dcql_query":{"credentials":[{"id":"pid"}]}}' >"${REQ}"
printf '%s' 'vp_token=secret-claim&state=abc' >"${BODY}"
printf '%s' '{"nonce":"n","aud":"https://self-issued.me/v2","nowUnix":1780435200,"maxAgeSecs":300,"vct":"urn:eudi:pid:de:1"}' >"${CTX}"

cat >"${EVIDENCE_SOURCE}/debug-manifest.json" <<EOF
{
  "schemaVersion": 1,
  "kind": "serve-unsafe-debug-artifacts",
  "session": "11111111-1111-4111-8111-111111111111",
  "sensitive": true,
  "entries": [
    {
      "label": "decoded authorization request payload",
      "filename": "request.payload.json",
      "len": $(len_file "${REQ}"),
      "sha256": "$(hash_file "${REQ}")"
    },
    {
      "label": "raw direct_post form body",
      "filename": "direct-post.body",
      "len": $(len_file "${BODY}"),
      "sha256": "$(hash_file "${BODY}")"
    },
    {
      "label": "verification replay context",
      "filename": "verification-context.json",
      "len": $(len_file "${CTX}"),
      "sha256": "$(hash_file "${CTX}")"
    }
  ]
}
EOF

"${BIN}" evidence export "${EVIDENCE_SOURCE}" --out "${EVIDENCE_BUNDLE}" >"${OUT}"
grep -q 'EVIDENCE BUNDLE EXPORTED' "${OUT}"

"${BIN}" evidence verify "${EVIDENCE_BUNDLE}" >"${OUT}"
grep -q 'EVIDENCE BUNDLE VALID' "${OUT}"

"${BIN}" evidence replay "${EVIDENCE_BUNDLE}" >"${OUT}"
grep -q 'EVIDENCE REPLAY' "${OUT}"
grep -q 'plaintext direct_post response rejected' "${OUT}"
if grep -q 'secret-claim' "${OUT}"; then
  echo "evidence replay leaked raw wallet material" >&2
  exit 1
fi

echo "plugin smoke passed"
