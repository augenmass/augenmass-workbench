#!/usr/bin/env bash
set -euo pipefail

HOST="$(rustc -vV | awk '/^host:/ {print $2}')"
STRICT="${AUGENMASS_STRICT_PLATFORM_SMOKE:-0}"
FAILURES=0

target_installed() {
  rustup target list --installed | grep -qx "$1"
}

note_skip() {
  local target="$1"
  local reason="$2"
  if [ "${STRICT}" = "1" ]; then
    echo "FAIL ${target}: ${reason}" >&2
    FAILURES=1
  else
    echo "SKIP ${target}: ${reason}"
  fi
}

required_tool_for() {
  local target="$1"
  case "${target}" in
    x86_64-unknown-linux-gnu)
      echo "x86_64-linux-gnu-gcc"
      ;;
    aarch64-unknown-linux-gnu)
      echo "aarch64-linux-gnu-gcc"
      ;;
    *-pc-windows-msvc)
      if [ "${target}" != "${HOST}" ]; then
        echo "lib.exe"
      fi
      ;;
  esac
}

run_target() {
  local target="$1"
  if ! target_installed "${target}"; then
    note_skip "${target}" "rust target is not installed"
    return
  fi

  local required_tool
  required_tool="$(required_tool_for "${target}")"
  if [ -n "${required_tool}" ] && ! command -v "${required_tool}" >/dev/null 2>&1; then
    note_skip "${target}" "missing cross C/MSVC tool ${required_tool}"
    return
  fi

  echo "CHECK ${target}"
  cargo check --locked --target "${target}" --all-targets
  echo "PASS ${target}"
}

if [ -n "${AUGENMASS_PLATFORM_TARGETS:-}" ]; then
  # shellcheck disable=SC2206
  TARGETS=(${AUGENMASS_PLATFORM_TARGETS})
else
  TARGETS=("${HOST}" "x86_64-unknown-linux-gnu" "x86_64-pc-windows-msvc")
  if [ "${HOST}" = "aarch64-apple-darwin" ]; then
    TARGETS+=("x86_64-apple-darwin")
  fi
fi

SEEN=""
for target in "${TARGETS[@]}"; do
  case " ${SEEN} " in
    *" ${target} "*)
      continue
      ;;
  esac
  SEEN="${SEEN} ${target}"
  run_target "${target}"
done

if [ "${FAILURES}" -ne 0 ]; then
  echo "platform smoke failed in strict mode" >&2
  exit 1
fi

echo "platform smoke passed for available targets"
