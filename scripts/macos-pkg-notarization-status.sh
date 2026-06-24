#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
cd "${ROOT}"

TARGET="${1:-$(rustc -vV | sed -n 's/^host: //p')}"
VERSION="$(
  awk -F '=' '
    $1 ~ /^[[:space:]]*version[[:space:]]*$/ {
      gsub(/[[:space:]"]/, "", $2);
      print $2;
      exit;
    }
  ' Cargo.toml
)"
PKG="dist/macos-pkg/${TARGET}/augenmass-v${VERSION}-${TARGET}.pkg"
PROOF="dist/macos-pkg/${TARGET}/pkg-notarization-proof.json"

if [ ! -f "${PROOF}" ]; then
  echo "missing pkg notarization proof: ${PROOF}" >&2
  echo "run: just macos-pkg-notarize-target ${TARGET}" >&2
  exit 1
fi
if [ ! -f "${PKG}" ]; then
  echo "missing pkg: ${PKG}" >&2
  exit 1
fi

jq -e '
  .schema == "augenmass-macos-pkg-notarization-proof-v1"
  and .target == "'"${TARGET}"'"
  and .notaryStatus == "Accepted"
  and .stapled == true
  and .spctlAccepted == true
' "${PROOF}" >/dev/null

pkgutil --check-signature "${PKG}" >/dev/null
xcrun stapler validate "${PKG}" >/dev/null
spctl --assess --type install --verbose=4 "${PKG}" >/dev/null 2>&1

echo "macOS pkg notarization proof accepted for ${TARGET}"
echo "pkg: ${PKG}"
echo "submission: $(jq -r '.notarySubmissionId' "${PROOF}")"
echo "stapled: $(jq -r '.stapled' "${PROOF}")"
echo "spctlAccepted: $(jq -r '.spctlAccepted' "${PROOF}")"
