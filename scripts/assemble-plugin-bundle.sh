#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd -P)"
cd "${ROOT}"

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

TAG="${AUGENMASS_PLUGIN_BUNDLE_TAG:-v${VERSION}}"
REPO="${AUGENMASS_PLUGIN_BUNDLE_REPO:-augenmass/augenmass-workbench}"
ARCHIVE_DIR="${AUGENMASS_PLUGIN_BUNDLE_ARCHIVE_DIR:-dist/plugin-bundle-inputs/${TAG}}"
PLUGIN_BIN="${ROOT}/plugins/augenmass-workbench/bin"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/augenmass-plugin-bundle.XXXXXX")"
MANIFEST_TMP="${TMP}/manifest.json"

cleanup() {
  rm -rf "${TMP}"
}
trap cleanup EXIT

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
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

json_escape() {
  awk -v s="$1" 'BEGIN {
    gsub(/\\/, "\\\\", s);
    gsub(/"/, "\\\"", s);
    gsub(/\t/, "\\t", s);
    gsub(/\r/, "\\r", s);
    gsub(/\n/, "\\n", s);
    printf "%s", s;
  }'
}

ensure_asset() {
  local archive="$1"
  local archive_name
  archive_name="$(basename "${archive}")"
  if [ -f "${archive}" ] && [ -f "${archive}.sha256" ] && [ -f "${archive}.manifest.json" ]; then
    return
  fi

  require gh
  mkdir -p "${ARCHIVE_DIR}"
  echo "downloading ${archive_name} and sidecars from ${REPO} ${TAG}" >&2
  download_asset "${archive_name}"
  download_asset "${archive_name}.sha256"
  download_asset "${archive_name}.manifest.json"
}

download_asset() {
  local name="$1"
  local dest="${ARCHIVE_DIR}/${name}"
  local api_url token
  api_url="$(
    gh release view "${TAG}" \
      --repo "${REPO}" \
      --json assets \
      --jq ".assets[] | select(.name == \"${name}\") | .apiUrl"
  )"
  if [ -z "${api_url}" ]; then
    echo "release asset not found: ${name}" >&2
    exit 1
  fi
  token="$(gh auth token)"

  if command -v aria2c >/dev/null 2>&1; then
    aria2c \
      --file-allocation=none \
      --auto-file-renaming=false \
      --allow-overwrite=true \
      --continue=true \
      --max-connection-per-server=4 \
      --split=4 \
      --min-split-size=1M \
      --summary-interval=10 \
      --header="Authorization: Bearer ${token}" \
      --header="Accept: application/octet-stream" \
      --dir="${ARCHIVE_DIR}" \
      --out="${name}" \
      "${api_url}" >&2
  else
    curl -fL \
      --retry 3 \
      --connect-timeout 20 \
      -H "Authorization: Bearer ${token}" \
      -H "Accept: application/octet-stream" \
      -o "${dest}" \
      "${api_url}"
  fi
}

extract_archive() {
  local archive="$1"
  local out="$2"
  case "${archive}" in
    *.tar.gz | *.tgz)
      tar -xzf "${archive}" -C "${out}"
      ;;
    *.zip)
      if command -v unzip >/dev/null 2>&1; then
        unzip -q "${archive}" -d "${out}"
      elif command -v 7z >/dev/null 2>&1; then
        7z x "-o${out}" "${archive}" >/dev/null
      else
        echo "missing unzip or 7z for ${archive}" >&2
        exit 1
      fi
      ;;
    *)
      echo "unsupported archive type: ${archive}" >&2
      exit 2
      ;;
  esac
}

copy_target() {
  local target="$1"
  local ext="$2"
  local binary="$3"
  local archive_name="augenmass-v${VERSION}-${target}.${ext}"
  local archive="${ARCHIVE_DIR}/${archive_name}"
  local sidecar="${archive}.sha256"
  local release_manifest="${archive}.manifest.json"
  local out="${TMP}/${target}"
  local package="${out}/augenmass-v${VERSION}-${target}"
  local source_bin="${package}/${binary}"
  local dest_dir="${PLUGIN_BIN}/${target}"
  local dest_bin="${dest_dir}/${binary}"

  ensure_asset "${archive}"

  if [ ! -f "${archive}" ] || [ ! -f "${sidecar}" ] || [ ! -f "${release_manifest}" ]; then
    echo "missing release archive or sidecars for ${target} in ${ARCHIVE_DIR}" >&2
    exit 1
  fi

  local actual_archive_sha expected_archive_sha expected_archive_name
  actual_archive_sha="$(hash_file "${archive}")"
  read -r expected_archive_sha expected_archive_name <"${sidecar}"
  if [ "${actual_archive_sha}" != "${expected_archive_sha}" ]; then
    echo "archive checksum mismatch for ${archive_name}" >&2
    exit 1
  fi
  if [ "${expected_archive_name}" != "${archive_name}" ]; then
    echo "checksum sidecar names ${expected_archive_name}, expected ${archive_name}" >&2
    exit 1
  fi

  jq -e \
    --arg target "${target}" \
    --arg archive "${archive_name}" \
    --arg archive_sha "${actual_archive_sha}" \
    --arg binary "${binary}" \
    '.schema == "augenmass-release-manifest-v1"
      and .target == $target
      and .archive == $archive
      and .archiveSha256 == $archive_sha
      and .binary == $binary
      and .layoutOnly == false
      and .nativeExecution == true' \
    "${release_manifest}" >/dev/null

  rm -rf "${out}"
  mkdir -p "${out}"
  extract_archive "${archive}" "${out}"
  if [ ! -f "${source_bin}" ]; then
    echo "archive ${archive_name} does not contain ${binary}" >&2
    exit 1
  fi

  local binary_sha manifest_binary_sha
  binary_sha="$(hash_file "${source_bin}")"
  manifest_binary_sha="$(jq -r '.binarySha256' "${release_manifest}")"
  if [ "${binary_sha}" != "${manifest_binary_sha}" ]; then
    echo "binary checksum mismatch for ${target}" >&2
    exit 1
  fi

  rm -rf "${dest_dir}"
  mkdir -p "${dest_dir}"
  cp "${source_bin}" "${dest_bin}"
  case "${binary}" in
    *.exe) ;;
    *) chmod 0755 "${dest_bin}" ;;
  esac

  printf '    {\n' >>"${MANIFEST_TMP}"
  printf '      "target": "%s",\n' "$(json_escape "${target}")" >>"${MANIFEST_TMP}"
  printf '      "binary": "%s",\n' "$(json_escape "${target}/${binary}")" >>"${MANIFEST_TMP}"
  printf '      "binarySha256": "%s",\n' "$(json_escape "${binary_sha}")" >>"${MANIFEST_TMP}"
  printf '      "archive": "%s",\n' "$(json_escape "${archive_name}")" >>"${MANIFEST_TMP}"
  printf '      "archiveSha256": "%s",\n' "$(json_escape "${actual_archive_sha}")" >>"${MANIFEST_TMP}"
  printf '      "sourceManifest": "%s"\n' "$(json_escape "${archive_name}.manifest.json")" >>"${MANIFEST_TMP}"
  printf '    }' >>"${MANIFEST_TMP}"
}

require jq
mkdir -p "${ARCHIVE_DIR}" "${PLUGIN_BIN}"

cat >"${MANIFEST_TMP}" <<EOF
{
  "schema": "augenmass-plugin-bundle-v1",
  "version": "${VERSION}",
  "source": {
    "kind": "github-release",
    "repository": "$(json_escape "${REPO}")",
    "tag": "$(json_escape "${TAG}")"
  },
  "launchers": [
    "augenmass",
    "augenmass.cmd",
    "augenmass.ps1"
  ],
  "targets": [
EOF

first=1
append_target() {
  if [ "${first}" -eq 0 ]; then
    printf ',\n' >>"${MANIFEST_TMP}"
  fi
  first=0
  copy_target "$@"
}

append_target aarch64-apple-darwin tar.gz augenmass
append_target x86_64-apple-darwin tar.gz augenmass
append_target x86_64-unknown-linux-gnu tar.gz augenmass
append_target x86_64-pc-windows-msvc zip augenmass.exe

cat >>"${MANIFEST_TMP}" <<EOF

  ],
  "unsignedPreview": true,
  "generatedBy": "scripts/assemble-plugin-bundle.sh"
}
EOF

jq -e '.schema == "augenmass-plugin-bundle-v1" and (.targets | length) == 4' "${MANIFEST_TMP}" >/dev/null
cp "${MANIFEST_TMP}" "${PLUGIN_BIN}/manifest.json"

echo "plugin bundle assembled from ${TAG} into ${PLUGIN_BIN}"
