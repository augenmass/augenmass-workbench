# Guardrails: catch over-ask before it ships

Finding an over-ask once is good. Never shipping one is better. The judgment commands exit non-zero on a bad outcome, so the same engine that explains a problem can also fail a commit or a build before the problem reaches the registrar.

This page shows local placements first: a pre-commit hook and a local verification gate. A remote CI recipe is included as an opt-in pattern for teams that approve runner spend. All examples rely only on documented exit codes; see the exit-code contract in `COMMANDS.md` and `AGENTS.md`.

## The exit codes you are gating on

- `check <body>` exits 1 on an over-ask or a blocking format error, 0 when the body is clean and ready to register.
- `audit --request <file> --purpose <id>` exits 1 on an over-ask against the named purpose baseline.
- On main (not in the 0.4.1 binaries), `check` and `audit` exit 3 when no judged claim asks for too much but a requested claim could not be judged (NOT EVALUATED), for example a credential format or type the baseline does not model. `audit` also exits 3 for a request that would be OK and whose DCQL query has a member that OpenID4VP 1.0 does not define at its level and that resembles a defined one, for example `claim` for `claims`: a wallet ignores a member it does not know, so the request may ask for something else than its author meant. A gate that fails on any non-zero code also fails on 3; a script that tests for exit code 1 only needs a case for 3. An unknown purpose id is a usage error with exit code 2.
- `validate dcql <input>` exits 1 on a blocking DCQL error (duplicate ids, dangling `credential_sets` references, claim paths whose shape does not match the credential format).
- `verify presentation`, `verify request`, `verify trust`, `verify status` exit 1 when not verified, unbound, untrusted, or revoked.
- `x509-hash <input> --client-id <id>` exits 1 when the claimed client_id does not match the leaf certificate.

Read-only commands that only describe local inputs (`inspect`, `decode`, `baselines`, `generate`) exit 0 when inputs are valid; network reads such as `list` can fail if the target is unavailable.

## Prerequisite: the binary on PATH

The hook and CI examples call a bare `augenmass`. Make it available first by building the CLI and putting it on PATH, or call the binary by its explicit path:

```sh
cargo build --release --locked
# add ./target/release to PATH, or copy ./target/release/augenmass somewhere on it
```

On Windows PowerShell, the built binary is `.\target\release\augenmass.exe`.
From Windows Git Bash, use `./target/release/augenmass.exe`.

You can also install from the repo into a local Cargo root:

```sh
cargo install --locked --path . --bin augenmass --root "$HOME/.local"
```

## Pre-commit hook

Refuse to commit a registration body that over-asks. This example is a POSIX hook for macOS, Linux, or Windows Git Bash. Save it as `.git/hooks/pre-commit` (or wire it into your hook manager) and make it executable.

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

## Local verification gate

For this repository, the default team gate is local:

```sh
just verify
just ci-credit-guard
```

`just verify` runs formatting, clippy, tests, and deterministic fixture checks.
`just ci-credit-guard` fails if any workflow other than one meeting the strict
`ubuntu-latest` profile can run on branch pushes or pull-request activity. Today
that is only `.github/workflows/check.yml`: GitHub-hosted `ubuntu-latest`,
read-only permissions, no secrets. The paid-runner workflows (`ci.yml`,
`blacksmith-smoke.yml`, `release.yml`) stay manual or tag-only, so their runner
budget stays under explicit human control (see `docs/RELEASE.md`).

## Optional remote CI gate

Fail the pipeline on a proportionality regression only when the team has approved remote runner spend. Use a manual workflow rather than `push` or `pull_request` triggers for private repositories:

```yaml
name: proportionality
on:
  workflow_dispatch:

jobs:
  augenmass:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Build the CLI
        run: cargo build --release --locked
      - name: Gate on over-ask and a well-formed request
        run: |
          ./target/release/augenmass check registration.json
          ./target/release/augenmass validate dcql request.json
          ./target/release/augenmass audit --request request.json --purpose age_gate_18
```

Any non-zero exit fails the step, and the job fails. Pin the build step to a release of the binary if you would rather not compile in CI.

## Let the agent close the loop

A failing gate tells you something is wrong; the skill tells you what to do about it. When the hook or the CI job reports an over-ask, ask the skill to read the same body and propose the proportionate version: "this registration failed the over-ask check; explain why and generate a body that asks only for what the purpose needs." Because the gate and the skill run the same engine, the fix that passes the agent passes the build.

That is the point of giving the agent the tool plus the context: not only to fix an over-ask after the fact, but to make the proportionate version the easy path, so the next one does not happen.
