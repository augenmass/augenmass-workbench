#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
cd "${ROOT}"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "macOS package signing/notarization must run on macOS" >&2
  exit 1
fi

TARGET="${1:-$(rustc -vV | sed -n 's/^host: //p')}"
case "${TARGET}" in
  aarch64-apple-darwin | x86_64-apple-darwin)
    ;;
  *)
    echo "unsupported macOS package target: ${TARGET}" >&2
    echo "expected aarch64-apple-darwin or x86_64-apple-darwin" >&2
    exit 2
    ;;
esac

for tool in jq pkgbuild xcrun spctl pkgutil; do
  command -v "${tool}" >/dev/null 2>&1 || {
    echo "missing required command: ${tool}" >&2
    exit 1
  }
done

hash_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    echo "missing required command for hashing: shasum or sha256sum" >&2
    exit 1
  fi
}

detect_identity() {
  local explicit="$1"
  local prefix="$2"
  if [ -n "${explicit}" ]; then
    printf '%s\n' "${explicit}"
    return
  fi

  local identities count
  identities="$(
    security find-identity -v 2>/dev/null \
      | sed -n "s/.*\"\\(${prefix}: [^\"]*\\)\".*/\\1/p" \
      | sed '/^$/d'
  )"
  count="$(printf '%s\n' "${identities}" | sed '/^$/d' | wc -l | tr -d ' ')"
  case "${count}" in
    0)
      echo "no ${prefix} signing identity found" >&2
      if [ "${prefix}" = "Developer ID Installer" ]; then
        cat >&2 <<EOF

Create and install a Developer ID Installer certificate from Apple Developer.
A Developer ID Application certificate is not enough for signed flat .pkg
installers. Verify the result with:

  security find-identity -v | grep "Developer ID Installer"
EOF
      fi
      exit 1
      ;;
    1)
      printf '%s\n' "${identities}" | sed -n '1p'
      ;;
    *)
      echo "multiple ${prefix} identities found:" >&2
      printf '%s\n' "${identities}" >&2
      echo "set the exact identity via the documented environment variable" >&2
      exit 1
      ;;
  esac
}

run_with_timeout() {
  local seconds="$1"
  shift
  perl -e '
    my $timeout = shift @ARGV;
    my $pid = fork();
    die "fork failed: $!\n" unless defined $pid;
    if ($pid == 0) {
      exec @ARGV;
      die "exec failed: $!\n";
    }
    my $timed_out = 0;
    $SIG{ALRM} = sub {
      $timed_out = 1;
      kill "TERM", $pid;
      select undef, undef, undef, 0.2;
      kill "KILL", $pid;
    };
    alarm $timeout;
    waitpid($pid, 0);
    my $status = $?;
    alarm 0;
    exit 124 if $timed_out;
    exit 128 + ($status & 127) if $status & 127;
    exit $status >> 8;
  ' "${seconds}" "$@"
}

verify_notary_profile() {
  if [ "${AUGENMASS_SKIP_NOTARY_PROFILE_PREFLIGHT:-0}" = "1" ]; then
    return
  fi

  local err
  err="$(mktemp "${TMPDIR:-/tmp}/augenmass-notary-profile.XXXXXX")"
  set +e
  xcrun notarytool history \
    --keychain-profile "${NOTARY_PROFILE}" \
    --output-format json >/dev/null 2>"${err}"
  local status=$?
  set -e
  if [ "${status}" -ne 0 ]; then
    echo "notarytool profile '${NOTARY_PROFILE}' is not usable" >&2
    sed -n '1,80p' "${err}" >&2
    rm -f "${err}"
    exit "${status}"
  fi
  rm -f "${err}"
}

VERSION="$(
  awk -F '=' '
    $1 ~ /^[[:space:]]*version[[:space:]]*$/ {
      gsub(/[[:space:]"]/, "", $2);
      print $2;
      exit;
    }
  ' Cargo.toml
)"
if [ -z "${VERSION}" ]; then
  echo "could not read package version from Cargo.toml" >&2
  exit 1
fi

NOTARY_PROFILE="${AUGENMASS_NOTARY_PROFILE:-augenmass-notary}"
CODESIGN_TIMEOUT="${AUGENMASS_CODESIGN_TIMEOUT:-60}"
APP_IDENTITY="$(detect_identity "${AUGENMASS_MACOS_CODESIGN_IDENTITY:-}" "Developer ID Application")"
INSTALLER_IDENTITY="$(detect_identity "${AUGENMASS_MACOS_INSTALLER_IDENTITY:-}" "Developer ID Installer")"
PACKAGE_ID="${AUGENMASS_MACOS_PKG_ID:-tech.augenmass.workbench.cli}"
OUT_DIR="${AUGENMASS_MACOS_PKG_OUT:-dist/macos-pkg/${TARGET}}"
PAYLOAD_ROOT="${OUT_DIR}/pkgroot"
SIGNED_BIN="${OUT_DIR}/signed-bin/augenmass"
PKG="${OUT_DIR}/augenmass-v${VERSION}-${TARGET}.pkg"
SUBMIT_JSON="${OUT_DIR}/notary-submit.json"
NOTARY_LOG="${OUT_DIR}/notary-log.json"
STAPLER_LOG="${OUT_DIR}/stapler.txt"
SPCTL_LOG="${OUT_DIR}/spctl.txt"
PKGUTIL_LOG="${OUT_DIR}/pkgutil.txt"
PROOF_JSON="${OUT_DIR}/pkg-notarization-proof.json"

verify_notary_profile

rm -rf "${PAYLOAD_ROOT}" "${OUT_DIR}/signed-bin"
mkdir -p "${PAYLOAD_ROOT}/usr/local/bin" "${OUT_DIR}/signed-bin"

echo "building ${TARGET}"
rustup target add "${TARGET}" >/dev/null
cargo build --release --locked --target "${TARGET}"

BUILD_BIN="target/${TARGET}/release/augenmass"
cp "${BUILD_BIN}" "${SIGNED_BIN}"
chmod +x "${SIGNED_BIN}"

echo "signing CLI with ${APP_IDENTITY}"
set +e
run_with_timeout "${CODESIGN_TIMEOUT}" \
  codesign --force --timestamp --options runtime --sign "${APP_IDENTITY}" "${SIGNED_BIN}"
codesign_status=$?
set -e
if [ "${codesign_status}" -ne 0 ]; then
  echo "codesign failed with exit status ${codesign_status}" >&2
  exit "${codesign_status}"
fi
codesign --verify --strict --verbose=2 "${SIGNED_BIN}"

cp "${SIGNED_BIN}" "${PAYLOAD_ROOT}/usr/local/bin/augenmass"

echo "building signed pkg with ${INSTALLER_IDENTITY}"
rm -f "${PKG}"
pkgbuild \
  --root "${PAYLOAD_ROOT}" \
  --identifier "${PACKAGE_ID}" \
  --version "${VERSION}" \
  --install-location / \
  --ownership recommended \
  --sign "${INSTALLER_IDENTITY}" \
  "${PKG}"

pkgutil --check-signature "${PKG}" >"${PKGUTIL_LOG}" 2>&1

echo "submitting pkg to Apple notarization profile ${NOTARY_PROFILE}"
xcrun notarytool submit "${PKG}" \
  --keychain-profile "${NOTARY_PROFILE}" \
  --wait \
  --timeout "${AUGENMASS_NOTARY_TIMEOUT:-30m}" \
  --output-format json >"${SUBMIT_JSON}"

submission_id="$(jq -r '.id // empty' "${SUBMIT_JSON}")"
status="$(jq -r '.status // empty' "${SUBMIT_JSON}")"
if [ -n "${submission_id}" ]; then
  xcrun notarytool log "${submission_id}" "${NOTARY_LOG}" \
    --keychain-profile "${NOTARY_PROFILE}" >/dev/null
fi

if [ "${status}" != "Accepted" ]; then
  echo "pkg notarization was not accepted; status=${status:-unknown}" >&2
  [ -f "${NOTARY_LOG}" ] && echo "see ${NOTARY_LOG}" >&2
  exit 1
fi

xcrun stapler staple "${PKG}" >"${STAPLER_LOG}" 2>&1
xcrun stapler validate "${PKG}" >>"${STAPLER_LOG}" 2>&1
spctl --assess --type install --verbose=4 "${PKG}" >"${SPCTL_LOG}" 2>&1

printf '%s  %s\n' "$(hash_file "${PKG}")" "$(basename "${PKG}")" >"${PKG}.sha256"

jq -n \
  --arg schema "augenmass-macos-pkg-notarization-proof-v1" \
  --arg target "${TARGET}" \
  --arg version "${VERSION}" \
  --arg packageId "${PACKAGE_ID}" \
  --arg appIdentity "${APP_IDENTITY}" \
  --arg installerIdentity "${INSTALLER_IDENTITY}" \
  --arg keychainProfile "${NOTARY_PROFILE}" \
  --arg pkg "$(basename "${PKG}")" \
  --arg pkgSha256 "$(hash_file "${PKG}")" \
  --arg binarySha256 "$(hash_file "${SIGNED_BIN}")" \
  --arg submissionId "${submission_id}" \
  --arg status "${status}" \
  '{
    schema: $schema,
    target: $target,
    version: $version,
    packageId: $packageId,
    appIdentity: $appIdentity,
    installerIdentity: $installerIdentity,
    keychainProfile: $keychainProfile,
    pkg: $pkg,
    pkgSha256: $pkgSha256,
    binary: "usr/local/bin/augenmass",
    binarySha256: $binarySha256,
    notarySubmissionId: $submissionId,
    notaryStatus: $status,
    stapled: true,
    spctlAccepted: true
  }' >"${PROOF_JSON}"

echo "macOS pkg notarization accepted and stapled: ${PKG}"
echo "proof: ${PROOF_JSON}"
