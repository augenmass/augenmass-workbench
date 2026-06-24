#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
cd "${ROOT}"

TARGET="${1:-$(rustc -vV | sed -n 's/^host: //p')}"
PROOF="dist/macos-notarization/${TARGET}/notarization-proof.json"
ARCHIVE="dist/macos-notarization/${TARGET}/augenmass-v$(awk -F '=' '$1 ~ /^[[:space:]]*version[[:space:]]*$/ { gsub(/[[:space:]"]/, "", $2); print $2; exit }' Cargo.toml)-${TARGET}.zip"

if [ ! -f "${PROOF}" ]; then
  echo "missing notarization proof: ${PROOF}" >&2
  echo "run: just macos-notarize-target ${TARGET}" >&2
  exit 1
fi

jq -e '
  .schema == "augenmass-macos-notarization-proof-v1"
  and .target == "'"${TARGET}"'"
  and .notaryStatus == "Accepted"
  and .stapled == false
' "${PROOF}" >/dev/null

if [ ! -f "${ARCHIVE}" ]; then
  echo "missing notarized archive: ${ARCHIVE}" >&2
  exit 1
fi

./scripts/release-archive-smoke.sh "${ARCHIVE}" >/dev/null

echo "macOS notarization proof accepted for ${TARGET}"
echo "archive: ${ARCHIVE}"
echo "submission: $(jq -r '.notarySubmissionId' "${PROOF}")"
echo "spctlAccepted: $(jq -r '.spctlAccepted' "${PROOF}")"
echo "stapled: $(jq -r '.stapled' "${PROOF}")"
echo "note: $(jq -r '.staplingNote' "${PROOF}")"
