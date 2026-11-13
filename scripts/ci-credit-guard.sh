#!/usr/bin/env bash
set -euo pipefail

# Two kinds of workflow are allowed:
#
# 1. Manual or tag-only workflows (ci.yml, blacksmith-smoke.yml, release.yml):
#    workflow_dispatch plus, at most, a tag-only push trigger. Any runner.
# 2. Automatic workflows: a workflow with push.branches or pull_request must
#    meet a strict profile, because it runs on ordinary pushes and on pull
#    requests from forks.
#
# The guard matches lines; it does not parse YAML. Every rule is written so
# that a file it cannot classify is rejected (fail closed).
#
# Rules for every workflow, checked before classification:
#   - Every byte is printable ASCII, a tab, or the LF line break. A carriage
#     return, NEL, or Unicode line or paragraph separator is a line break to
#     YAML but not to a line matcher, so it could hide a line from the guard.
#   - The first non-comment line is at column 0 (the root mapping is not
#     indented). Under an indented root a column-0 line can be text inside a
#     multi-line scalar, so the guard could not tell structure from text.
#   - Every non-comment line at column 0 is a plain top-level key
#     (`key:` or `key: value`) from TOP_LEVEL_KEYS, and `on:` occurs exactly
#     once, as a block (`on:` with nothing after it).
#   - Inside on:, every line has one of these exact forms: an event key
#     `push:`, `pull_request:` or `workflow_dispatch:`, each at most once;
#     under push a `branches:` or `tags:` block, under pull_request a
#     `branches:` block; under those, list items `- name` (plain or quoted,
#     no backslash); under workflow_dispatch, plain `key:` or `key: value`
#     lines and `- value` items. Anything else (quoted, escaped, explicit or
#     spaced keys, flow collections, anchors, aliases, inline event lists,
#     other events, branches-ignore) is rejected.
#   - No tab in the indentation.
#   - workflow_dispatch is present.
#   - A push trigger has a branches: or tags: block.
#
# A workflow is automatic when it has pull_request or push.branches. An
# automatic workflow must also meet these rules, all checked line by line:
#   - Raw lines (comments and block scalar contents included): an expression
#     start marker `${{` only on a line equal, character for character, to an
#     entry of EXPRESSION_ALLOW_LIST; no backslash; no `secrets` or
#     `github_token` in any letter case.
#   - Structural lines (outside block scalar contents): after the indentation
#     and any `- ` prefixes, either `key:`, `key: value`, `- value`, or `-`,
#     where key is plain ([A-Za-z_][A-Za-z0-9_-]*) with no space before the
#     colon, and value is a plain scalar, a quoted scalar closed on the same
#     line, or a block scalar header (| |- |+ > >- >+); a plain value holds
#     no colon followed by a space or the line end. No quoted, explicit
#     (?) or merge keys, flow collections, anchors, aliases, or tags. No `if:`
#     key (an implicit expression). No key starting with GITHUB_, RUNNER_,
#     ACTIONS_, or INPUT_ (environment overrides of runner and action inputs).
#   - Permissions: one top-level block of read or none scopes, nowhere else.
#   - Every job: runs-on: ubuntu-latest (literal), timeout-minutes, no
#     reusable workflow.
#   - The only action is actions/checkout pinned to a full commit SHA. Each
#     checkout step has `persist-credentials: false` in its own with: block,
#     and that with: block has no input other than persist-credentials and
#     fetch-depth (no repository, ref, token, ssh-key, or github-server-url).
#
# The guard checks workflow files only. It makes no claim about what the
# commands a run step executes do at run time (scripts, build scripts,
# writes to GITHUB_ENV or GITHUB_PATH); for those the bound is the read-only
# token and the absence of secrets.

shopt -s nullglob
WORKFLOWS=(.github/workflows/*.yml .github/workflows/*.yaml)

if [ "${#WORKFLOWS[@]}" -eq 0 ]; then
  echo "ci credit guard passed: no GitHub Actions workflows found"
  exit 0
fi

# Lines that may carry an expression in an automatic workflow, compared
# character for character with the raw line. Add an entry only on purpose.
EXPRESSION_ALLOW_LIST='  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}'

TOP_LEVEL_KEYS='name run-name on permissions env defaults concurrency jobs'

FAILED=0

for workflow in "${WORKFLOWS[@]}"; do
  # LC_ALL=C makes awk match bytes, not characters, in every awk variant.
  if ! LC_ALL=C EXPRESSION_ALLOW_LIST="${EXPRESSION_ALLOW_LIST}" TOP_LEVEL_KEYS="${TOP_LEVEL_KEYS}" awk -v file="${workflow}" '
    BEGIN {
      n = split(ENVIRON["EXPRESSION_ALLOW_LIST"], entries, "\n")
      for (i = 1; i <= n; i++) {
        allowed_expression_line[entries[i]] = 1
      }
      n = split(ENVIRON["TOP_LEVEL_KEYS"], entries, " ")
      for (i = 1; i <= n; i++) {
        top_level_key[entries[i]] = 1
      }
    }

    function indentation(value, prefix) {
      prefix = value
      sub(/[^ ].*$/, "", prefix)
      return length(prefix)
    }

    function fail(line, message) {
      printf "%s:%d: %s\n", file, line, message > "/dev/stderr"
      bad = 1
    }

    # Violations of the automatic-workflow profile, reported only when the
    # workflow turns out to be automatic.
    function strict(line, message) {
      strict_count++
      strict_line[strict_count] = line
      strict_message[strict_count] = message
    }

    function value_of(text, v) {
      v = text
      sub(/^[^:]*:[[:space:]]*/, "", v)
      return v
    }

    # The on: block grammar (every workflow).
    function on_line(line, indent, body) {
      body = substr(line, indent + 1)
      if (!on_event_indent) {
        on_event_indent = indent
      }
      if (indent < on_event_indent) {
        fail(NR, "inconsistent indentation inside on:.")
        return
      }
      if (indent == on_event_indent) {
        on_event = ""
        on_filter = ""
        on_filter_indent = 0
        if (body !~ /^(push|pull_request|workflow_dispatch):$/) {
          fail(NR, "inside on: only the plain block keys push:, pull_request:, and workflow_dispatch: are allowed, found: " body)
          return
        }
        on_event = substr(body, 1, length(body) - 1)
        if (seen_event[on_event]++) {
          fail(NR, "event " on_event " is declared twice.")
        }
        if (on_event == "push") {
          push_line = NR
        }
        if (on_event == "pull_request") {
          automatic = 1
          automatic_line = automatic_line ? automatic_line : NR
        }
        return
      }
      if (on_event == "workflow_dispatch") {
        if (body !~ /^[A-Za-z_][A-Za-z0-9_-]*:( [^[:space:]].*)?$/ && body !~ /^- [^[:space:]].*$/) {
          fail(NR, "workflow_dispatch may only hold plain key: value lines and - value items.")
          return
        }
        dispatch_value = body
        if (body ~ /^- /) {
          dispatch_value = substr(body, 3)
        } else if (body ~ /: /) {
          dispatch_value = value_of(body)
        } else {
          dispatch_value = ""
        }
        if (dispatch_value ~ /^[[{&*!|>?%@`]/ || dispatch_value ~ /\\/ || (dispatch_value ~ /^"/ && dispatch_value !~ /^"[^"]*"$/) || (dispatch_value ~ /^'"'"'/ && dispatch_value !~ /^'"'"'[^'"'"']*'"'"'$/)) {
          fail(NR, "workflow_dispatch values must be plain or quoted on one line, with no flow collection, anchor, alias, tag, block scalar, or backslash.")
        }
        return
      }
      # push or pull_request filters.
      if (!on_filter_indent) {
        on_filter_indent = indent
      }
      if (indent < on_filter_indent) {
        fail(NR, "inconsistent indentation inside on:.")
        return
      }
      if (indent == on_filter_indent) {
        on_filter = ""
        if (on_event == "push" && body ~ /^(branches|tags):$/) {
          on_filter = substr(body, 1, length(body) - 1)
        } else if (on_event == "pull_request" && body == "branches:") {
          on_filter = "branches"
        } else {
          fail(NR, "push may only hold a branches: or tags: block and pull_request a branches: block, found: " body)
          return
        }
        if (on_event == "push") {
          push_filter[on_filter] = 1
          if (on_filter == "branches") {
            automatic = 1
            automatic_line = automatic_line ? automatic_line : NR
          }
        }
        return
      }
      if (!on_filter || body !~ /^- ([A-Za-z0-9_.*\/+-]+|"[^"\\]*"|'"'"'[^'"'"'\\]*'"'"')$/) {
        fail(NR, "branch and tag filters may only hold - name items (plain or quoted, no backslash), found: " body)
      }
    }

    # The structural grammar of an automatic workflow, for lines outside on:.
    # Returns the key of the line, or "" when it has none.
    function structural(line, indent, body, key, value, col) {
      body = substr(line, indent + 1)
      col = indent
      dashed = 0
      while (body ~ /^- /) {
        body = substr(body, 3)
        col += 2
        dashed = 1
      }
      if (body == "-") {
        return ""
      }
      key = ""
      value = ""
      if (body ~ /^[A-Za-z_][A-Za-z0-9_-]*:$/) {
        key = substr(body, 1, length(body) - 1)
      } else if (body ~ /^[A-Za-z_][A-Za-z0-9_-]*: +[^ ]/) {
        key = body
        sub(/:.*$/, "", key)
        value = value_of(body)
      } else if (dashed) {
        value = body
      } else {
        strict(NR, "a line must be a plain key:, key: value, or - value (no quoted, explicit, merge, or spaced keys, no continuation lines), found: " body)
        return ""
      }
      if (key == "if") {
        strict(NR, "if: conditions are implicit expressions and are not allowed.")
      }
      if (tolower(key) ~ /^(github|runner|actions|input)_/) {
        strict(NR, "environment keys starting with GITHUB_, RUNNER_, ACTIONS_, or INPUT_ are not allowed.")
      }
      if (value ~ /^[|>][-+]?$/) {
        in_scalar = 1
        scalar_col = col
        scalar_content = 0
      } else if (value ~ /^[|>]/) {
        strict(NR, "block scalar indentation indicators are not supported.")
      } else if (value ~ /^"/) {
        if (value !~ /^"[^"]*"$/) {
          strict(NR, "a double-quoted scalar must close on the same line and hold no further quote.")
        }
      } else if (value ~ /^'"'"'/) {
        if (value !~ /^'"'"'([^'"'"']|'"'"''"'"')*'"'"'$/) {
          strict(NR, "a single-quoted scalar must close on the same line.")
        }
      } else if (value ~ /^[[{&*!%@`?]/) {
        strict(NR, "flow collections, anchors, aliases, tags, and reserved indicators are not supported.")
      } else if (value ~ /:( |$)/) {
        # YAML would read a plain `uses : x` or `a: b: c` as a mapping.
        strict(NR, "a plain value must not contain a colon followed by a space or the line end (a spaced or nested key).")
      }
      return key
    }

    function finish_step() {
      if (step_active) {
        if (step_is_checkout && !step_persist) {
          strict(step_line, "every actions/checkout step needs persist-credentials: false in its own with: block.")
        }
        if (step_has_with && !step_is_checkout) {
          strict(step_line, "with: is only allowed on an actions/checkout step.")
        }
      }
      step_active = 0
    }

    function finish_steps() {
      finish_step()
      in_steps = 0
    }

    function finish_job() {
      finish_steps()
      if (!job_name) {
        return
      }
      if (!job_has_runs_on) {
        strict(job_line, "job " job_name " has no runs-on (reusable workflows are not allowed).")
      }
      if (!job_has_timeout) {
        strict(job_line, "job " job_name " needs timeout-minutes.")
      }
      job_name = ""
    }

    {
      raw = $0

      # Raw-line rules of the automatic profile, before comments or block
      # scalar contents are set aside.
      if (index(raw, "${{") && !(raw in allowed_expression_line)) {
        strict(NR, "an expression (${{) is only allowed on a line of the guard expression allow-list.")
      }
      if (index(raw, "\\")) {
        strict(NR, "backslashes are not allowed (YAML escapes could hide an expression or a key).")
      }
      if (tolower(raw) ~ /secrets/ || tolower(raw) ~ /github_token/) {
        strict(NR, "secret and token references are not allowed.")
      }
      if (raw ~ /^ *\t/) {
        fail(NR, "tabs are not allowed in indentation.")
      }
      if (raw ~ /[^\t -~]/) {
        fail(NR, "only printable ASCII, tabs, and LF line breaks are allowed (no carriage return, other control character, or non-ASCII byte).")
      }

      line = raw
      sub(/^[[:space:]]*#.*/, "", line)
      sub(/[[:space:]]+#.*/, "", line)
      sub(/[[:space:]]+$/, "", line)
      if (line ~ /^[[:space:]]*$/) {
        next
      }
      indent = indentation(line)

      # The root mapping starts at column 0. Under an indented root, a
      # column-0 line can be text inside a multi-line scalar.
      if (indent == 0) {
        root_seen = 1
      } else if (!root_seen) {
        if (!root_reported++) {
          fail(NR, "the first non-comment line must be at column 0 (an indented root mapping is not supported).")
        }
        next
      }

      # Block scalar contents are text, not structure.
      if (in_scalar) {
        if (indent > scalar_col) {
          if (!scalar_content) {
            scalar_content = indent
          } else if (indent < scalar_content) {
            strict(NR, "a block scalar line is less indented than its first line.")
          }
          next
        }
        in_scalar = 0
      }

      # Top level: plain keys from the allow-list, on: exactly once.
      if (indent == 0) {
        if (in_jobs) {
          finish_job()
        }
        in_on = 0
        in_jobs = 0
        in_permissions = 0
        jobs_child_indent = 0
        if (line !~ /^[a-z][a-z-]*:( [^[:space:]].*)?$/) {
          fail(NR, "a top-level line must be a plain key: or key: value, found: " line)
          next
        }
        section = line
        sub(/:.*$/, "", section)
        if (!(section in top_level_key)) {
          fail(NR, "top-level key " section " is not allowed.")
          next
        }
        if (section == "on") {
          on_count++
          if (line != "on:") {
            fail(NR, "on: must be a block (on: alone on its line, events below it).")
          }
          in_on = 1
          on_event_indent = 0
          next
        }
        in_jobs = (section == "jobs")
      }

      if (in_on) {
        on_line(line, indent)
        next
      }

      key = structural(line, indent)

      # Permissions: exactly one block at the top level, read or none only.
      if (key == "permissions") {
        permissions_count++
        if (indent != 0) {
          strict(NR, "job-level permissions are not allowed; declare read-only permissions once at the top level.")
        } else if (line != "permissions:") {
          strict(NR, "permissions must be a block of read or none scopes, not an inline value.")
        } else {
          in_permissions = 1
          next
        }
      }
      if (in_permissions && indent > 0) {
        if (line !~ /^[[:space:]]+[a-z][a-z-]*:[[:space:]]*(read|none)$/) {
          strict(NR, "permissions may only grant read or none.")
        }
        permissions_scopes++
      }

      # Jobs: runner, timeout, and no reusable workflow per job.
      if (in_jobs && indent > 0) {
        if (!jobs_child_indent) {
          jobs_child_indent = indent
        }
        if (indent == jobs_child_indent) {
          finish_job()
          job_name = line
          sub(/^[[:space:]]*/, "", job_name)
          sub(/:.*$/, "", job_name)
          job_line = NR
          job_child_indent = 0
          job_has_runs_on = 0
          job_has_timeout = 0
        } else if (job_name) {
          if (!job_child_indent) {
            job_child_indent = indent
          }
          if (indent == job_child_indent && line ~ /^[[:space:]]*runs-on:/) {
            job_has_runs_on = 1
          }
          if (indent == job_child_indent && line ~ /^[[:space:]]*timeout-minutes:[[:space:]]*[0-9]+$/) {
            job_has_timeout = 1
          }
        }
      }

      # Steps: each checkout step must set persist-credentials: false as a
      # direct child of its own with: block, and no other input but
      # fetch-depth.
      step_key_line = ""
      if (in_steps && step_dash < 0) {
        if (line ~ /^[[:space:]]*-([[:space:]]|$)/ && indent >= steps_col) {
          step_dash = indent
        } else {
          in_steps = 0
        }
      }
      if (in_steps) {
        if (indent < step_dash || (indent == step_dash && line !~ /^[[:space:]]*-([[:space:]]|$)/)) {
          finish_steps()
        } else if (indent == step_dash) {
          finish_step()
          step_active = 1
          step_line = NR
          step_is_checkout = 0
          step_persist = 0
          step_has_with = 0
          step_in_with = 0
          step_key_col = -1
          if (match(line, /^[[:space:]]*-[[:space:]]+/)) {
            step_key_col = RLENGTH
            step_key_line = substr(line, RLENGTH + 1)
          }
        } else if (step_active) {
          if (step_key_col < 0) {
            step_key_col = indent
          }
          if (indent == step_key_col) {
            step_key_line = substr(line, indent + 1)
          } else if (indent > step_key_col && step_in_with) {
            if (step_with_child_col < 0) {
              step_with_child_col = indent
            }
            if (indent == step_with_child_col && line ~ /^[[:space:]]*persist-credentials:[[:space:]]*false$/) {
              step_persist = 1
            } else if (!(indent == step_with_child_col && line ~ /^[[:space:]]*fetch-depth:[[:space:]]*[0-9]+$/)) {
              strict(NR, "actions/checkout inputs other than persist-credentials: false and fetch-depth are not allowed.")
            }
          }
        }
        if (step_key_line != "") {
          step_in_with = (step_key_line ~ /^with:$/)
          if (step_in_with) {
            step_has_with = 1
          }
          step_with_child_col = -1
          if (step_key_line ~ /^uses:[[:space:]]*actions\/checkout@/) {
            step_is_checkout = 1
          }
        }
      }
      if (job_name && indent == job_child_indent && line ~ /^[[:space:]]*steps:[[:space:]]*$/) {
        in_steps = 1
        steps_col = indent
        step_dash = -1
        step_active = 0
      }

      if (key == "runs-on") {
        runner = value_of(line)
        if (runner != "ubuntu-latest") {
          strict(NR, "runs-on must be the literal ubuntu-latest, found: " runner)
        }
      }

      if (key == "uses") {
        action = value_of(line)
        sha = action
        if (!(sub(/^actions\/checkout@/, "", sha) && length(sha) == 40 && sha !~ /[^0-9a-f]/)) {
          strict(NR, "only actions/checkout pinned to a full commit SHA is allowed, found: " action)
        }
        if (step_key_line !~ /^uses:/) {
          strict(NR, "uses: is only allowed as a key of a step in a job steps: list.")
        }
      }
    }

    END {
      if (in_jobs) {
        finish_job()
      }
      if (on_count != 1) {
        fail(1, "exactly one top-level on: block is required, found " on_count ".")
      }
      if (!seen_event["workflow_dispatch"]) {
        fail(1, "workflow_dispatch is required so checks can be run explicitly without adding branch triggers.")
      }
      if (seen_event["push"] && !push_filter["branches"] && !push_filter["tags"]) {
        fail(push_line, "push triggers must be tag-only, or branch-filtered in an automatic workflow that meets the strict profile.")
      }
      if (automatic) {
        if (permissions_count == 0 || permissions_scopes == 0) {
          strict(automatic_line, "a top-level permissions block with read-only scopes is required.")
        }
        for (i = 1; i <= strict_count; i++) {
          fail(strict_line[i], "automatic workflow (push.branches or pull_request): " strict_message[i])
        }
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

echo "ci credit guard passed: only the strict ubuntu-latest check workflow runs on branch pushes and pull requests"
