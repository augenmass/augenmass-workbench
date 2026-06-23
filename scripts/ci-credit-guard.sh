#!/usr/bin/env bash
set -euo pipefail

shopt -s nullglob
WORKFLOWS=(.github/workflows/*.yml .github/workflows/*.yaml)

if [ "${#WORKFLOWS[@]}" -eq 0 ]; then
  echo "ci credit guard passed: no GitHub Actions workflows found"
  exit 0
fi

FAILED=0

for workflow in "${WORKFLOWS[@]}"; do
  if ! awk -v file="${workflow}" '
    function indentation(value, prefix) {
      prefix = value
      sub(/[^ ].*$/, "", prefix)
      return length(prefix)
    }

    function fail(line, message) {
      printf "%s:%d: %s\n", file, line, message > "/dev/stderr"
      bad = 1
    }

    function finish_push_block() {
      if (!in_push) {
        return
      }
      if (!push_has_tags) {
        fail(push_line, "push triggers must be tag-only. Normal branch pushes must not spend runner credits.")
      }
      if (push_has_branches) {
        fail(push_line, "push triggers must not include branches or branches-ignore.")
      }
      in_push = 0
      push_has_tags = 0
      push_has_branches = 0
    }

    {
      line = $0
      sub(/[[:space:]]+#.*/, "", line)
      sub(/[[:space:]]+$/, "", line)

      if (line ~ /^[[:space:]]*$/) {
        next
      }

      indent = indentation(line)

      if (in_push && indent <= push_indent && line ~ /^[[:space:]]*[A-Za-z_][A-Za-z0-9_-]*:[[:space:]]*(.*)$/) {
        finish_push_block()
      }

      if (line ~ /^[[:space:]]*workflow_dispatch:[[:space:]]*$/) {
        has_workflow_dispatch = 1
      }

      if (line ~ /^[[:space:]]*pull_request(_target)?:[[:space:]]*$/) {
        fail(NR, "pull_request triggers spend runner credits on PR activity. Use workflow_dispatch for private-repo checks.")
      }

      if (line ~ /^[[:space:]]*on:[[:space:]]*\[.*push.*\]/) {
        fail(NR, "inline push events can run on normal branch pushes. Use workflow_dispatch or a push.tags block.")
      }

      if (line ~ /^[[:space:]]*on:[[:space:]]*\[.*pull_request.*\]/) {
        fail(NR, "inline pull_request events spend runner credits on PR activity. Use workflow_dispatch.")
      }

      if (line ~ /^[[:space:]]*-[[:space:]]*push[[:space:]]*$/) {
        fail(NR, "event-list push entries can run on normal branch pushes. Use workflow_dispatch or a push.tags block.")
      }

      if (line ~ /^[[:space:]]*-[[:space:]]*pull_request(_target)?[[:space:]]*$/) {
        fail(NR, "event-list pull_request entries spend runner credits on PR activity. Use workflow_dispatch.")
      }

      if (line ~ /^[[:space:]]*push:[[:space:]]*$/) {
        in_push = 1
        push_indent = indent
        push_line = NR
        push_has_tags = 0
        push_has_branches = 0
        next
      }

      if (in_push) {
        if (line ~ /^[[:space:]]*tags:[[:space:]]*$/) {
          push_has_tags = 1
        }
        if (line ~ /^[[:space:]]*branches(-ignore)?:[[:space:]]*$/) {
          push_has_branches = 1
        }
      }
    }

    END {
      finish_push_block()
      if (!has_workflow_dispatch) {
        fail(1, "workflow_dispatch is required so checks can be run explicitly without adding branch triggers.")
      }
      exit bad ? 1 : 0
    }
  ' "${workflow}"; then
    FAILED=1
  fi
done

if [ "${FAILED}" -ne 0 ]; then
  exit 1
fi

echo "ci credit guard passed: normal branch pushes cannot start GitHub Actions"
