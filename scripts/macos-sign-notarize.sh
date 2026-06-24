#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
cd "${ROOT}"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "macOS signing/notarization must run on macOS" >&2
  exit 1
fi

TARGET="${1:-$(rustc -vV | sed -n 's/^host: //p')}"
case "${TARGET}" in
  aarch64-apple-darwin | x86_64-apple-darwin)
    ;;
  *)
    echo "unsupported macOS notarization target: ${TARGET}" >&2
    echo "expected aarch64-apple-darwin or x86_64-apple-darwin" >&2
    exit 2
    ;;
esac

if ! command -v jq >/dev/null 2>&1; then
  echo "missing required command: jq" >&2
  exit 1
fi

if ! command -v xcrun >/dev/null 2>&1; then
  echo "missing required command: xcrun" >&2
  exit 1
fi

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

resolve_identity() {
  if [ -n "${AUGENMASS_MACOS_CODESIGN_IDENTITY:-}" ]; then
    printf '%s\n' "${AUGENMASS_MACOS_CODESIGN_IDENTITY}"
    return
  fi

  identities="$(
    security find-identity -v -p codesigning 2>/dev/null \
      | sed -n 's/.*"\(Developer ID Application: [^"]*\)".*/\1/p' \
      | sed '/^$/d'
  )"
  count="$(printf '%s\n' "${identities}" | sed '/^$/d' | wc -l | tr -d ' ')"
  case "${count}" in
    0)
      echo "no Developer ID Application signing identity found" >&2
      echo "install one in Keychain or set AUGENMASS_MACOS_CODESIGN_IDENTITY" >&2
      exit 1
      ;;
    1)
      printf '%s\n' "${identities}" | sed -n '1p'
      ;;
    *)
      echo "multiple Developer ID Application identities found:" >&2
      printf '%s\n' "${identities}" >&2
      echo "set AUGENMASS_MACOS_CODESIGN_IDENTITY to the exact identity" >&2
      exit 1
      ;;
  esac
}

NOTARY_PROFILE="${AUGENMASS_NOTARY_PROFILE:-augenmass-notary}"
TIMEOUT="${AUGENMASS_NOTARY_TIMEOUT:-30m}"
CODESIGN_TIMEOUT="${AUGENMASS_CODESIGN_TIMEOUT:-60}"
IDENTITY="$(resolve_identity)"
OUT_DIR="${AUGENMASS_MACOS_NOTARY_OUT:-dist/macos-notarization/${TARGET}}"
SIGNED_INPUT="${OUT_DIR}/signed-input"
SIGNED_BIN="${SIGNED_INPUT}/augenmass"
SUBMIT_JSON="${OUT_DIR}/notary-submit.json"
NOTARY_LOG="${OUT_DIR}/notary-log.json"
SPCTL_LOG="${OUT_DIR}/spctl.txt"
CODESIGN_LOG="${OUT_DIR}/codesign.txt"
PROOF_JSON="${OUT_DIR}/notarization-proof.json"

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

print_codesign_help() {
  cat >&2 <<EOF
codesign could not complete.

If macOS is waiting for Keychain approval, approve codesign access to the
Developer ID private key. For headless runs, unlock the key once with:

  security set-key-partition-list -S apple-tool:,apple: -s \\
    ~/Library/Keychains/login.keychain-db

To narrow that grant, find the private-key label first:

  security find-key -s -t private ~/Library/Keychains/login.keychain-db

Then add -l "<private-key-label>" to the set-key-partition-list command. The
private-key label can differ from the certificate identity; on this machine it
may be a shorter name such as "Reza Shokri".

That command prompts for the Mac login/keychain password. Do not paste it into
chat, shell history shared with others, or CI logs.

If Keychain access is already granted, check network access to Apple's timestamp
service because this script signs with --timestamp.
EOF
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
    cat >&2 <<EOF

Create or refresh the profile with:

  xcrun notarytool store-credentials "${NOTARY_PROFILE}" \\
    --apple-id "<apple-id-email>" \\
    --team-id "<team-id>"

It will prompt for an app-specific password or Apple credentials. Do not paste
that password into chat, CI logs, or repo files.
EOF
    exit "${status}"
  fi
  rm -f "${err}"
}

rm -rf "${SIGNED_INPUT}"
mkdir -p "${SIGNED_INPUT}" "${OUT_DIR}"

verify_notary_profile

echo "building ${TARGET}"
rustup target add "${TARGET}" >/dev/null
cargo build --release --locked --target "${TARGET}"

BUILD_BIN="target/${TARGET}/release/augenmass"
if [ ! -f "${BUILD_BIN}" ]; then
  echo "release binary not found after build: ${BUILD_BIN}" >&2
  exit 1
fi

cp "${BUILD_BIN}" "${SIGNED_BIN}"
chmod +x "${SIGNED_BIN}"

echo "signing ${SIGNED_BIN}"
set +e
run_with_timeout "${CODESIGN_TIMEOUT}" \
  codesign --force --timestamp --options runtime --sign "${IDENTITY}" "${SIGNED_BIN}"
codesign_status=$?
set -e
if [ "${codesign_status}" -ne 0 ]; then
  if [ "${codesign_status}" -eq 124 ]; then
    echo "codesign timed out after ${CODESIGN_TIMEOUT}s" >&2
  else
    echo "codesign failed with exit status ${codesign_status}" >&2
  fi
  print_codesign_help
  exit "${codesign_status}"
fi
codesign --verify --strict --verbose=2 "${SIGNED_BIN}"
codesign -dv --verbose=4 "${SIGNED_BIN}" >"${CODESIGN_LOG}" 2>&1

echo "packaging signed macOS zip"
archive="$(
  ./scripts/package-release-archive.sh \
    "${TARGET}" \
    "${SIGNED_BIN}" \
    zip \
    "${OUT_DIR}"
)"
./scripts/release-archive-smoke.sh "${archive}"

echo "submitting to Apple notarization profile ${NOTARY_PROFILE}"
xcrun notarytool submit "${archive}" \
  --keychain-profile "${NOTARY_PROFILE}" \
  --wait \
  --timeout "${TIMEOUT}" \
  --output-format json >"${SUBMIT_JSON}"

submission_id="$(jq -r '.id // empty' "${SUBMIT_JSON}")"
status="$(jq -r '.status // empty' "${SUBMIT_JSON}")"
if [ -n "${submission_id}" ]; then
  xcrun notarytool log "${submission_id}" "${NOTARY_LOG}" \
    --keychain-profile "${NOTARY_PROFILE}" >/dev/null
fi

if [ "${status}" != "Accepted" ]; then
  echo "notarization was not accepted; status=${status:-unknown}" >&2
  if [ -f "${NOTARY_LOG}" ]; then
    echo "see ${NOTARY_LOG}" >&2
  fi
  exit 1
fi

spctl_accepted=false
if spctl --assess --type execute --verbose=4 "${SIGNED_BIN}" >"${SPCTL_LOG}" 2>&1; then
  spctl_accepted=true
else
  {
    echo "spctl did not accept the staged standalone CLI binary."
    echo "The notary submission was accepted; standalone CLI zips are not stapled."
    echo "Gatekeeper can still validate notarization online for the submitted code hash."
  } >>"${SPCTL_LOG}"
  if [ "${AUGENMASS_REQUIRE_SPCTL:-0}" = "1" ]; then
    cat "${SPCTL_LOG}" >&2
    exit 1
  fi
fi

archive_sha256="$(hash_file "${archive}")"
binary_sha256="$(hash_file "${SIGNED_BIN}")"
jq -n \
  --arg schema "augenmass-macos-notarization-proof-v1" \
  --arg target "${TARGET}" \
  --arg identity "${IDENTITY}" \
  --arg profile "${NOTARY_PROFILE}" \
  --arg archive "$(basename "${archive}")" \
  --arg archiveSha256 "${archive_sha256}" \
  --arg binarySha256 "${binary_sha256}" \
  --arg submissionId "${submission_id}" \
  --arg status "${status}" \
  --argjson spctlAccepted "${spctl_accepted}" \
  '{
    schema: $schema,
    target: $target,
    identity: $identity,
    keychainProfile: $profile,
    archive: $archive,
    archiveSha256: $archiveSha256,
    binary: "augenmass",
    binarySha256: $binarySha256,
    notarySubmissionId: $submissionId,
    notaryStatus: $status,
    stapled: false,
    staplingNote: "ZIP submissions are notarized, but this standalone CLI archive is not stapled. Use a signed PKG or DMG later if offline stapling is required.",
    spctlAccepted: $spctlAccepted
  }' >"${PROOF_JSON}"

echo "macOS notarization accepted: ${archive}"
echo "proof: ${PROOF_JSON}"
