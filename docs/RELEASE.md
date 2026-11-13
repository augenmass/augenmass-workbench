# Release and platform support

Augenmaß Workbench ships as one Rust CLI (`augenmass`) and one agent plugin
bundle with both Claude Code and Codex manifests. The bundle carries a small
launcher under `plugins/augenmass-workbench/bin/augenmass` plus per-target
native binaries under target-triple subdirectories.

## Current support status

- Source build: intended for the native release targets with Rust 1.92 or newer;
  other Rust platforms are unproven.
- Plugin bundle in this repository: Claude Code and Codex manifests are present;
  the committed launcher selects bundled binaries for macOS Apple Silicon,
  macOS Intel, Linux x64, and Windows x64.
- Release workflow: builds native archives for Linux x86_64, Windows x86_64,
  macOS Intel, and macOS Apple Silicon when a `v*` tag is pushed or the workflow
  is run manually.
- Linux arm64: not yet in the release matrix.

The local macOS machine is not the proof for Linux or Windows. Native GitHub
Actions jobs are the proof because this crate pulls in C-backed crypto and SQLite
dependencies.

## Check workflow (push and pull request)

`.github/workflows/check.yml` is the only workflow that runs automatically: on
pushes to `main`, on pull requests against `main`, and through
`workflow_dispatch`. It runs one job on GitHub-hosted `ubuntu-latest`, which is
free for a public repository, and it never runs on Blacksmith or macOS runners.
It checks out the code with `actions/checkout` pinned to a full commit SHA and
`persist-credentials: false`, installs the toolchain from `rust-toolchain.toml`,
and runs:

```sh
./scripts/ci-credit-guard.sh
./scripts/ci-credit-guard-cases.sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo install cargo-audit --locked --version 0.23.0
cargo audit --deny unsound --deny yanked \
  --ignore RUSTSEC-2026-0459 --ignore RUSTSEC-2026-0387 \
  --ignore RUSTSEC-2023-0071 --ignore RUSTSEC-2023-0126 \
  --ignore RUSTSEC-2026-0255
```

The accepted advisories and their removal conditions are listed under
"Dependency audit" below and next to each `--ignore` in the workflow.

## CI gate

`.github/workflows/ci.yml` is manual-only through `workflow_dispatch`, so normal
pushes do not spend runner credits on the paid runners it uses. When you
explicitly run it, it uses:

- `blacksmith-2vcpu-ubuntu-2404` for Linux x64
- `blacksmith-2vcpu-windows-2025` for Windows x64
- `blacksmith-6vcpu-macos-15` for macOS Apple Silicon
- `macos-15-intel` for macOS Intel

Each job installs Rust 1.92, then runs:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release --locked
```

That matrix is intentionally native. It checks the OSes users actually run
instead of pretending that a local cross-check from macOS is equivalent.

## Blacksmith smoke

`.github/workflows/blacksmith-smoke.yml` is a manual-only trial gate for the
Blacksmith runner account. It does not publish artifacts and does not run on
normal pushes or pull requests. The current matrix is:

- `linux-x64` on `blacksmith-2vcpu-ubuntu-2404`
- `windows-x64` on `blacksmith-2vcpu-windows-2025`
- `macos-arm64` on `blacksmith-6vcpu-macos-15`

Use the default `debug-build` scope first to prove the org integration and basic
native compilation without spending release-build minutes. The `test` and
`release-build` scopes are deliberate follow-ups. Blacksmith's macOS runners are
Apple Silicon, so this gate proves macOS arm64 behavior; keep the Intel macOS
release target in `.github/workflows/release.yml` until a separate Intel proof is
chosen.

Run the local guard and its regression cases before changing or pushing
workflow files:

```sh
just ci-credit-guard
just ci-credit-guard-cases
```

The guard matches lines; it does not parse YAML or GitHub expressions. Its
rules are written so that a workflow it cannot classify fails (fail closed).

For every workflow, before classification:

- the file holds only printable ASCII, tabs, and LF line breaks; a carriage
  return, NEL, or Unicode line separator is a line break to YAML but not to
  the guard, so it fails;
- the first non-comment line is at column 0: under an indented root mapping a
  column-0 line can be text inside a multi-line scalar, so that layout fails;
- every non-comment line at column 0 is a plain top-level key (`name`,
  `run-name`, `on`, `permissions`, `env`, `defaults`, `concurrency`, `jobs`),
  and `on:` occurs exactly once, as a block;
- inside `on:` only the plain block keys `push:`, `pull_request:`, and
  `workflow_dispatch:` are allowed, each once; `push` holds a `branches:` or
  `tags:` block, `pull_request` a `branches:` block, and those hold `- name`
  items. Quoted, escaped, spaced, or explicit (`?`) keys, flow values such as
  `branches: [main]` or `pull_request: {}`, anchors, aliases, event lists,
  `branches-ignore`, `pull_request_target`, `schedule`, and `workflow_run` fail;
- `workflow_dispatch` is present, and a `push` trigger carries a filter.

A workflow with `pull_request` or `push.branches` is automatic (today only
`check.yml`) and must also meet a strict profile:

- an expression start marker `${{` appears only on a line that equals,
  character for character, an entry of the allow-list in
  `scripts/ci-credit-guard.sh` (today one line, the `concurrency.group` of
  `check.yml`), on any line, comments and block scalar contents included;
- no `if:` key (it is an implicit expression), no backslash on any line (YAML
  escapes could spell an expression or a key), and no reference to `secrets`
  or `GITHUB_TOKEN` in any letter case;
- plain block YAML: outside block scalar contents every line is `key:`,
  `key: value`, or a `- ` item, with a plain key and no space before the
  colon; quoted, explicit, and merge keys, flow mappings or sequences,
  anchors, aliases, tags, multi-line quoted scalars, block scalar indentation
  indicators, and multiple documents fail instead of being parsed;
- no key starting with `GITHUB_`, `RUNNER_`, `ACTIONS_`, or `INPUT_`, so no
  environment override of runner settings or action inputs;
- every job runs on the literal `ubuntu-latest` and has `timeout-minutes`;
- permissions are declared once, at the top level, and grant only `read` or
  `none`; job-level permissions and inline values such as `write-all` fail;
- the only action is `actions/checkout` pinned to a full commit SHA; reusable
  workflows and other actions fail. Each checkout step sets
  `persist-credentials: false` in its own `with:` block, and that block holds
  no other input than `fetch-depth` (no `repository`, `ref`, `token`,
  `ssh-key`, or `github-server-url`).

The guard checks workflow files only. It makes no claim about what a `run`
step executes at run time (repository scripts, build scripts, writes to
`GITHUB_ENV` or `GITHUB_PATH`); for that code the bound is the read-only token
and the absence of secrets. A future automatic workflow that needs another
expression must add its exact line to the allow-list on purpose.

Every other workflow stays manual or tag-only: `ci.yml` and
`blacksmith-smoke.yml` run only through `workflow_dispatch`, and the only push
trigger they or `release.yml` may carry is a tag-only release trigger, currently
`v*`, so a release can still be cut deliberately. `just ci-credit-guard-cases`
(`./scripts/ci-credit-guard-cases.sh`) runs the committed regression cases
under `tests/ci-credit-guard/`: 71 cases, allowed workflows under `pass/` and
one rejected form per file under `fail/`.

## Dependency audit

`check.yml` runs `cargo audit --deny unsound --deny yanked`, so a vulnerability,
an unsound crate, or a yanked crate fails the run unless its advisory is
accepted below. Unmaintained warnings are reported but do not fail the run.

Accepted advisories (measured with `cargo audit` 0.23.0 on 2026-11-13, after
the lockfile refresh). Each needs a major-version upgrade, which a lockfile
refresh cannot make. Remove the `--ignore` in the same change as the upgrade.

| Advisory | Crate | Kind | Path into this repository | Removal condition |
| --- | --- | --- | --- | --- |
| RUSTSEC-2026-0459 | libsqlite3-sys 0.28.0 | vulnerability (SQLite CVE) | rusqlite 0.31 (clone and cache stores) | rusqlite upgraded to a release on libsqlite3-sys 0.39 or newer |
| RUSTSEC-2026-0387 | crypto-bigint 0.3.2 and 0.5.5 | vulnerability (timing) | rsa 0.6 (ssi 0.16); elliptic-curve 0.13 (p256, the josekit fork) | ssi, p256, and josekit moved to crypto-bigint 0.7.6 or newer |
| RUSTSEC-2023-0071 | rsa 0.6.1 | vulnerability (Marvin attack) | ssi-jwk 0.4 (ssi 0.16) | ssi upgraded off rsa 0.6 |
| RUSTSEC-2023-0126 | im 15.1.0 | unsound | linked-data, json-ld (ssi 0.16) | ssi upgraded off im 15 |
| RUSTSEC-2026-0255 | sized-chunks 0.6.5 | unsound | im 15 (ssi 0.16) | ssi upgraded off im 15 |

Unmaintained, reported only: bitmaps, clear_on_drop, derivative, im,
proc-macro-error, serde_cbor, sized-chunks, smallstr.

## Release archives

`.github/workflows/release.yml` builds these archives:

- `augenmass-v<version>-x86_64-unknown-linux-gnu.tar.gz`
- `augenmass-v<version>-x86_64-pc-windows-msvc.zip`
- `augenmass-v<version>-x86_64-apple-darwin.tar.gz`
- `augenmass-v<version>-aarch64-apple-darwin.tar.gz`

The release workflow uses Blacksmith runners for Linux x64, Windows x64, macOS
Apple Silicon, and the publish job. The remaining Intel Mac artifact uses
GitHub's `macos-15-intel` runner because Blacksmith macOS runners are Apple
Silicon. Both the CI and release workflows remain manual/tag-only; they still do
not run on ordinary pushes or pull-request activity. Only `check.yml` does, on
GitHub-hosted `ubuntu-latest`.

The workflow, local host smoke, and Docker Linux archive smoke all use
`scripts/package-release-archive.sh` for the package layout.

Every packaged archive now has two sidecars:

- `<archive>.sha256`: a standard SHA-256 checksum line for the archive.
- `<archive>.manifest.json`: target, package name, archive hash, binary name,
  binary hash, actual build host, layout-only/native-execution flags, git
  commit, dirty flag, Rust compiler version/host, and GitHub ref/run id when
  built in Actions.

`release-archive-smoke` requires and verifies those sidecars by default, then
extracts the archive and runs the packaged binary against the packaged docs,
examples, and fixtures. The only escape hatch is
`AUGENMASS_ALLOW_MISSING_RELEASE_SIDECARS=1`, reserved for legacy archives. On a
tag push (`v*`), the workflow uploads the archives and both sidecars to a GitHub
release. Tag pushes spend runner minutes and should happen only after explicit
approval. On manual dispatch, it publishes workflow artifacts only. Tag builds
fail unless the tag name matches `v$(Cargo.toml version)`.

## v0.3.0 release proof

Published release `v0.3.0` is available at:

```text
https://github.com/augenmass/augenmass-workbench/releases/tag/v0.3.0
```

The signed tag `v0.3.0` points at commit
`ee6956b0d62d59890822bba448ad669b12809db9`, the merged, GPG-signed head of the
reviewed branch. The tag release run `28899942757` passed all four native build,
package, and archive-smoke jobs (Linux x64, Windows x64, macOS Apple Silicon,
macOS Intel) and the publish job.

The release carries twelve assets: four native CLI archives plus a `.sha256`
checksum and a `.manifest.json` sidecar for each. Every archive manifest records
`gitCommit` `ee6956b0d62d59890822bba448ad669b12809db9`, `gitDirty` `false`,
`layoutOnly` `false`, and `nativeExecution` `true`, so each binary is a native
build of the tagged commit with no local modifications. The archives are:

```text
augenmass-v0.3.0-x86_64-unknown-linux-gnu.tar.gz
augenmass-v0.3.0-x86_64-pc-windows-msvc.zip
augenmass-v0.3.0-x86_64-apple-darwin.tar.gz
augenmass-v0.3.0-aarch64-apple-darwin.tar.gz
```

The committed plugin bundle under `plugins/augenmass-workbench/bin` was rebuilt
from these release archives by `scripts/assemble-plugin-bundle.sh`, which checks
every archive and binary hash against its sidecar and rejects layout-only or
non-native manifests before copying. The release archive is the canonical binary
source; the plugin bundle is assembled from it.

macOS notarization was not performed for v0.3.0, so the published archives are
unsigned, consistent with the loose CLI archive limitation noted in the next
section. Verify the release checksum and approve the binary locally if Gatekeeper
or Windows blocks it.

## macOS signing and notarization

macOS notarization is local and manual-only for now; it does not run from normal
CI and does not spend remote runner minutes. The machine running it needs:

- a Developer ID Application identity in Keychain
- a Developer ID Installer identity in Keychain for signed/stapled `.pkg`
  installers
- a validated `notarytool` Keychain profile, defaulting to `augenmass-notary`
- Xcode command-line tools with `codesign`, `notarytool`, `spctl`, and `zip`

Create the notary profile once with the Apple ID that belongs to the Developer
Program team:

```sh
xcrun notarytool store-credentials augenmass-notary \
  --apple-id "<apple-id-email>" \
  --team-id "<team-id>"
```

Check that the profile is reachable before a release run:

```sh
xcrun notarytool history --keychain-profile augenmass-notary
```

Then produce a signed and notarized macOS ZIP for the host target:

```sh
just macos-notarize
just macos-notarization-status
```

For an explicit target:

```sh
just macos-notarize-target aarch64-apple-darwin
just macos-notarization-status-target aarch64-apple-darwin
just macos-notarize-target x86_64-apple-darwin
just macos-notarization-status-target x86_64-apple-darwin
```

`scripts/macos-sign-notarize.sh` builds the target, copies the binary into a
staging directory, signs it with Developer ID plus hardened runtime and
timestamp, packages a ZIP with the normal release layout and sidecars, runs
`release-archive-smoke`, submits the ZIP with `xcrun notarytool --wait`, stores
the notary log, and writes `notarization-proof.json` under
`dist/macos-notarization/<target>/`.

The default signing identity is auto-detected when exactly one
`Developer ID Application` identity exists. Override it with:

```sh
export AUGENMASS_MACOS_CODESIGN_IDENTITY="Developer ID Application: Name (TEAMID)"
export AUGENMASS_NOTARY_PROFILE=augenmass-notary
```

On the first command-line signing run, macOS may ask whether `codesign` can use
the Developer ID private key. Approve that prompt locally. For headless runs,
grant Apple command-line tools access to signing keys in the login keychain:

```sh
security set-key-partition-list -S apple-tool:,apple: -s \
  ~/Library/Keychains/login.keychain-db
```

To narrow the grant, first find the private-key label:

```sh
security find-key -s -t private ~/Library/Keychains/login.keychain-db
```

Then add `-l "<private-key-label>"` to the partition-list command. The
private-key label can differ from the certificate identity; for example, the
certificate can be `Developer ID Application: Name (TEAMID)` while the key label
is just `Name`.

That command prompts for the Mac login/keychain password; never put that
password in chat, CI logs, or repo files. If `codesign` hangs, the notarization
script times it out after `AUGENMASS_CODESIGN_TIMEOUT` seconds, default `60`,
and prints the recovery command.

ZIP submissions are accepted by Apple's notary service, but this standalone CLI
archive is not stapled. `xcrun stapler` staples app bundles, disk images, and
signed flat installer packages, not the current loose CLI ZIP layout. If we need
offline stapling later, add a signed `.pkg` or `.dmg` lane, which will also need
a Developer ID Installer certificate for `.pkg`. On this machine,
`Developer ID Application: Reza Shokri (B4F7YTTM6C)` and the `augenmass-notary`
profile produced an accepted `aarch64-apple-darwin` ZIP submission on
2026-06-24:

```text
submission: fc22e9a4-a21d-4c85-a5e6-7d0372c2f30f
archive: dist/macos-notarization/aarch64-apple-darwin/augenmass-v0.2.0-aarch64-apple-darwin.zip
notaryStatus: Accepted
spctlAccepted: false
stapled: false
```

That is a valid Apple notarization acceptance for the submitted ZIP. It is not
the same as a stapled installer proof.

For a stapled/offline-verifiable installer, install a Developer ID Installer
identity and run:

```sh
security find-identity -v | grep "Developer ID Installer"
just macos-pkg-notarize
just macos-pkg-notarization-status
```

The `.pkg` lane signs the CLI with Developer ID Application, builds a flat
installer for `/usr/local/bin/augenmass`, signs the package with Developer ID
Installer, submits it to Apple's notary service, staples the ticket, and verifies
with `pkgutil --check-signature`, `xcrun stapler validate`, and
`spctl --assess --type install`.

On this machine, `Developer ID Installer: Reza Shokri (B4F7YTTM6C)` produced a
stapled `aarch64-apple-darwin` package on 2026-06-25:

```text
submission: 97385b9c-4c7c-4cb3-ae46-aeff800b3534
pkg: dist/macos-pkg/aarch64-apple-darwin/augenmass-v0.2.0-aarch64-apple-darwin.pkg
notaryStatus: Accepted
stapled: true
spctlAccepted: true
```

The proof gate is:

```sh
just macos-pkg-notarization-status
```

It checks the local proof JSON, then verifies the package again with
`pkgutil --check-signature`, `xcrun stapler validate`, and
`spctl --assess --type install`.

Published release `v0.2.0` is available at:

```text
https://github.com/augenmass/augenmass-workbench/releases/tag/v0.2.0
```

It contains native CLI archives plus `.sha256` and `.manifest.json` sidecars for
Linux x64, Windows x64, macOS Apple Silicon, and macOS Intel. The tag release
run `28103514119` passed all native build/package/smoke jobs and the publish
job. The release archive is the canonical binary source; the committed plugin
bundle is assembled from those release archives so the skill can run on the
supported desktop targets without a local source build.

## Cutting a release

Run the local gate first:

```sh
just verify
just ci-credit-guard
just demo-run
just install-smoke
just plugin-bundle-freshness
just codex-plugin-smoke
just release-archive-smoke
just release-zip-layout-smoke
just docker-release-archive-smoke-linux
just shipping-smoke
just platform-smoke
```

Refresh the plugin bundle from release archives after the release exists:

```sh
just bundle
git status --short
```

`just bundle` reads the native release archives and sidecars, rejects layout-only
archives, verifies archive and binary hashes, then writes the target-specific
plugin binaries plus `bin/manifest.json`.
`just plugin-bundle-freshness` verifies the bundle manifest version, launcher
version, and each committed target-binary hash. Set
`AUGENMASS_STRICT_LOCAL_PLUGIN_BUILD=1` only when you explicitly want to compare
the current-host target against a local rebuild; release-built binaries may not
be byte-identical to a local build because build paths can differ.

Then tag from a clean tree:

```sh
git tag v0.3.0
git push origin v0.3.0
```

That tag push starts the release workflow and spends runner minutes. For the
presentation-prep phase, keep release proof local with
`just docker-release-archive-smoke-linux` and do not push a `v*` tag unless the
runner spend has been approved.

After the release workflow finishes, install or test the platform archive on a
machine matching the target. The plugin marketplace bundle remains a separate
artifact from the CLI release archives.

`just ci-credit-guard`, `just install-smoke`, `just demo-run`,
`just plugin-demo-run`, `just plugin-bundle-freshness`,
`just claude-plugin-smoke`, `just codex-plugin-smoke`, `just serve-smoke`,
`just release-archive-smoke`, `just release-zip-layout-smoke`,
`just shipping-smoke`, `just cloudflare-containers-typecheck`,
`just deployed-cache-guard-smoke`, `just cache-public-bind-guard-smoke`,
`just deployed-cache-smoke`,
`just deployed-cache-smoke-required`, `just hosted-release-proof`,
`just sandbox-readiness-proof`, `just platform-smoke`, and
`just platform-smoke-strict` are local. They do not start GitHub Actions.
`ci-credit-guard` proves the workflow trigger invariant: normal branch pushes
and pull-request activity start only `check.yml`, on GitHub-hosted
`ubuntu-latest` with read-only permissions and no secrets; no paid-runner
workflow can start that way.
`install-smoke` proves a fresh source install into a temporary local root.
`claude-plugin-smoke` proves local Claude Code marketplace installation in a
temporary `HOME`.
`codex-plugin-smoke` proves local Codex marketplace installation in a temporary
`CODEX_HOME`.
`serve-smoke` proves the verifier-in-a-box runtime over loopback HTTP: session
minting, JAR fetch, JSON/HTML trace, plaintext rejection, and redaction. It
honors `AUGENMASS_BIN` for native source/release binaries and otherwise uses the
bundled plugin launcher.
`public-sandbox-snapshot` is a live-data report for presentation prep, not a
release gate; it fetches public sandbox reads and prints aggregate counts/ETags
without credentialed writes.
`release-archive-smoke` builds the host release archive, extracts it, then runs
the packaged binary against packaged docs, examples, and fixtures. It also
requires and checks `<archive>.sha256` and `<archive>.manifest.json`, including
the archive/binary hashes and the `layoutOnly` / `nativeExecution` claim.
`release-zip-layout-smoke` builds a Windows-style `.zip` package layout from the
host release binary renamed to `augenmass.exe`, extracts it, and runs the same
archive smoke. On non-Windows hosts it proves zip packaging and self-contained
layout only; it is not native Windows execution proof. Its manifest is marked
`layoutOnly: true`, `nativeExecution: false`, and records the actual host that
produced the renamed binary. On a native Windows host, the same script marks the
archive as native execution proof.
`docker-release-archive-smoke-linux` builds Linux arm64 and amd64 archives
inside Docker, runs the archive smoke inside the matching Linux container, and
exports the resulting archives to:

- `dist/docker-release-archive-smoke/linux-arm64/augenmass-v<version>-aarch64-unknown-linux-gnu.tar.gz`
- `dist/docker-release-archive-smoke/linux-amd64/augenmass-v<version>-x86_64-unknown-linux-gnu.tar.gz`

The exported Docker archive directories include the matching `.sha256` and
`.manifest.json` sidecars. The export is atomic: the script builds into a temp
directory, requires the archive and both sidecars, verifies the checksum and
manifest, including the host-passed git commit and dirty flag, and then replaces the public
`dist/docker-release-archive-smoke/<platform>` folder. The executable smoke runs
inside the matching Linux container before export.

`plugin-only-smoke` copies only the plugin bundle to a temp directory and runs
no-file commands from outside the checkout, so marketplace-style first-run
behavior is proved without `fixtures/` or `examples/`.
`shipping-smoke` covers the plugin bundle, the plugin-only first-run path, the
`serve` runtime smoke, the live cached-sandbox path, the public sandbox snapshot,
the optional Cloudflare Containers adapter typecheck, and the Docker backend.
`deployed-cache-guard-smoke` is a no-network local guard that proves required
hosted-cache proof refuses `http://`, loopback, and private-IP API bases.
`cache-public-bind-guard-smoke` is a no-network local guard that proves public
cache binds refuse missing admin tokens, empty RP allowlists, unsafe upstreams,
and `--max-entries 0` before listening.
`deployed-cache-smoke` is opt-in for a Railway/VPS cache URL and skips cleanly
when `AUGENMASS_DEPLOYED_CACHE_API_BASE` is unset.
`deployed-cache-smoke-required` is the hosted-readiness gate; it fails unless
`AUGENMASS_DEPLOYED_CACHE_API_BASE` is an `https://` non-local hosted URL and
`AUGENMASS_DEPLOYED_CACHE_ADMIN_TOKEN` is set. `hosted-release-proof` is the
same required hosted gate. `sandbox-readiness-proof` is the required live sandbox
gate. `cloudflare-containers-typecheck` typechecks the optional Cloudflare
Containers Worker adapter without deploying it, and is included in
`shipping-smoke`. `platform-smoke` checks the host target and any locally
available cross-targets; by default it skips Linux or Windows targets, including
Linux arm64, when the Rust target or required cross C/MSVC toolchain is missing.
`platform-smoke-strict` turns those skips into failures for a release machine
where every configured target must be present.

Runtime smokes that touch a running server or hosted cache (`serve-smoke`,
`live-cache-smoke`, `deployed-cache-smoke`, `deployed-cache-smoke-required`,
`live-sandbox-smoke`) resolve the CLI as: script-specific override, then
`AUGENMASS_BIN`, then the bundled plugin launcher. `demo-run` is also portable: it
resolves `AUGENMASS_DEMO_BIN`, then
`AUGENMASS_BIN`, then the bundled launcher. Plugin-bundle gates (`plugin-smoke`,
`plugin-demo-run`) intentionally stay bound to the committed plugin artifact.

For the plugin-free local CLI release proof without spending runner credits, run:

```sh
just local-cli-release-proof
```

That uses the native release binary through `AUGENMASS_BIN` for the demo,
serve, and live-cache smokes; if `AUGENMASS_BIN` is unset, the helper resolves
`./target/release/augenmass` and then `./target/release/augenmass.exe`. It also
proves source install, host archive, Windows-style zip layout, platform probes,
Linux Docker cache images, and Linux release archives. It avoids the committed
plugin bundle, so it is the right proof when checking CLI portability from source
or release archives.

For the presenter plugin proof, run:

```sh
just presenter-plugin-proof
```

That checks the committed platform-aware plugin bundle, the plugin-only
first-run path, local Claude Code/Codex marketplace installs, and manifest/hash
freshness of the bundled target binaries. It is intentionally separate from the
plugin-free CLI proof.

For the strongest presenter-machine proof, run:

```sh
just local-release-proof
```

It composes `local-cli-release-proof` and `presenter-plugin-proof`. It still does
not replace a native Linux host check outside Docker, and it does not prove
native Windows execution. Those need native runners or manual machines.

For a no-runner-credit Linux archive proof only, run:

```sh
just docker-release-archive-smoke-linux
```

## Plugin bundle layout

The plugin launcher paths are:

```text
plugins/augenmass-workbench/bin/augenmass
plugins/augenmass-workbench/bin/augenmass.cmd
plugins/augenmass-workbench/bin/augenmass.ps1
```

The bundled target binaries are:

```text
plugins/augenmass-workbench/bin/aarch64-apple-darwin/augenmass
plugins/augenmass-workbench/bin/x86_64-apple-darwin/augenmass
plugins/augenmass-workbench/bin/x86_64-unknown-linux-gnu/augenmass
plugins/augenmass-workbench/bin/x86_64-pc-windows-msvc/augenmass.exe
```

They are unsigned bundled binaries. If macOS Gatekeeper or Windows blocks a
binary, verify the release checksum first, then either approve it manually
(macOS System Settings -> Privacy & Security -> Open Anyway; Windows Properties
-> Unblock or PowerShell `Unblock-File`) or build from source and set
`AUGENMASS_BIN`.
