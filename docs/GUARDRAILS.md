# Guardrails: catch over-ask before it ships

Finding an over-ask once is good. Never shipping one is better. Every read-only Augenmaß command exits non-zero on a bad outcome, so the same engine that explains a problem can also fail a commit or a build before the problem reaches the registrar.

This page shows two placements: a pre-commit hook (stops it on your machine) and a CI gate (stops it for the whole team). Both rely only on documented exit codes; see the exit-code contract in `COMMANDS.md` and `AGENTS.md`.

## The exit codes you are gating on

- `check <body>` exits 1 on an over-ask or a blocking format error, 0 when the body is clean and ready to register.
- `audit --request <file> --purpose <id>` exits 1 on an over-ask against the named purpose baseline.
- `validate dcql <input>` exits 1 on a blocking DCQL error (duplicate ids, dangling `credential_sets` references, claim paths whose shape does not match the credential format).
- `verify presentation`, `verify trust`, `verify status` exit 1 when not verified, untrusted, or revoked.
- `x509-hash <input> --client-id <id>` exits 1 when the claimed client_id does not match the leaf certificate.

Read-only commands that only describe (`inspect`, `decode`, `baselines`, `list`, `generate`) exit 0; they are for inspection, not gating.

## Prerequisite: the binary on PATH

The hook and CI examples call a bare `augenmass`. Make it available first, either by installing the Claude Code plugin (which puts the bundled binary on PATH inside a session) or by building the CLI and putting it on PATH:

```sh
cargo build --release
# add ./target/release to PATH, or copy ./target/release/augenmass somewhere on it
```

## Pre-commit hook

Refuse to commit a registration body that over-asks. Save this as `.git/hooks/pre-commit` (or wire it into your hook manager) and make it executable.

```sh
#!/usr/bin/env sh
# Block a commit if any staged registration body over-asks or is malformed.
set -e

staged=$(git diff --cached --name-only --diff-filter=ACM | grep -E 'registration.*\.json$' || true)

for body in $staged; do
  echo "augenmass check: $body"
  augenmass check "$body"
done
```

`augenmass check` exits non-zero on the first over-ask or format error, and `set -e` turns that into a failed commit. The output names which claims exceeded the purpose, so the fix is in front of you. Adjust the `grep` pattern to match how your repository names registration bodies.

## CI gate

Fail the pipeline on a proportionality regression. This GitHub Actions job builds the CLI once and runs the checks; the same commands work in any CI system.

```yaml
name: proportionality
on: [push, pull_request]

jobs:
  augenmass:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Build the CLI
        run: cargo build --release
      - name: Gate on over-ask and a well-formed request
        run: |
          ./target/release/augenmass check registration.json
          ./target/release/augenmass validate dcql request.json
          ./target/release/augenmass audit --request request.json --purpose age_gate_18
```

Any non-zero exit fails the step, and the job fails. Pin the build step to a release of the binary if you would rather not compile in CI.

## Let the agent close the loop

A failing gate tells you something is wrong; the skill tells you what to do about it. When the hook or the CI job reports an over-ask, ask the skill to read the same body and propose the proportionate version: "this registration failed the over-ask check; explain why and generate a body that asks only for what the purpose needs." Because the gate and the skill run the same engine, the fix that passes the agent passes the build.

That is the point of giving the agent the tool plus the context: not only to repair an over-ask after the fact, but to make the proportionate version the easy path, so the next one does not happen.
