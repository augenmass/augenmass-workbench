# Release and platform support

Augenmaß Workbench ships as one Rust CLI (`augenmass`) and one agent plugin
bundle with both Claude Code and Codex manifests. The bundle carries the same CLI
under `plugins/augenmass-workbench/bin`.

## Current support status

- Source build: intended for the native release targets with Rust 1.92 or newer;
  other Rust platforms are unproven.
- Plugin bundle in this repository: Claude Code and Codex manifests are present;
  the committed bundled binary is macOS Apple Silicon only because it is a
  Mach-O arm64 executable.
- Release workflow: builds native archives for Linux x86_64, Windows x86_64,
  macOS Intel, and macOS Apple Silicon when a `v*` tag is pushed or the workflow
  is run manually.
- Linux arm64: not yet in the release matrix.

The local macOS machine is not the proof for Linux or Windows. Native GitHub
Actions jobs are the proof because this crate pulls in C-backed crypto and SQLite
dependencies.

## CI gate

`.github/workflows/ci.yml` is manual-only through `workflow_dispatch`, so normal
pushes do not spend private-repo runner credits. When you explicitly run it, it
uses:

- `ubuntu-latest`
- `macos-13`
- `macos-14`
- `windows-latest`

Each job installs Rust 1.92, then runs:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release --locked
```

That matrix is intentionally native. It checks the OSes users actually run
instead of pretending that a local cross-check from macOS is equivalent.

Run the local guard before changing or pushing workflow files:

```sh
just ci-credit-guard
```

It fails if a workflow can run on normal branch pushes or pull-request activity.
The only allowed push trigger is a tag-only release trigger, currently `v*`, so a
release can still be cut deliberately without making every branch push spend
runner credits.

## Release archives

`.github/workflows/release.yml` builds these archives:

- `augenmass-v<version>-x86_64-unknown-linux-gnu.tar.gz`
- `augenmass-v<version>-x86_64-pc-windows-msvc.zip`
- `augenmass-v<version>-x86_64-apple-darwin.tar.gz`
- `augenmass-v<version>-aarch64-apple-darwin.tar.gz`

The workflow, local host smoke, and Docker Linux archive smoke all use
`scripts/package-release-archive.sh` for the package layout.

On a tag push (`v*`), the workflow uploads the archives to a GitHub release.
Tag pushes spend runner minutes and should happen only after explicit approval.
On manual dispatch, it publishes workflow artifacts only.

## Cutting a release

Run the local gate first:

```sh
just verify
just ci-credit-guard
just demo-run
just install-smoke
just codex-plugin-smoke
just release-archive-smoke
just release-zip-layout-smoke
just docker-release-archive-smoke-linux
just shipping-smoke
just platform-smoke
```

Refresh the plugin bundle on an Apple Silicon Mac before tagging:

```sh
just bundle
git status --short
```

`just bundle` refuses to overwrite the committed plugin binary unless the host
target is `aarch64-apple-darwin`, because the current plugin bundle is a private
preview artifact for macOS Apple Silicon.

Then tag from a clean tree:

```sh
git tag v0.2.0
git push origin v0.2.0
```

That tag push starts the release workflow and spends runner minutes. For the
presentation-prep phase, keep release proof local with
`just docker-release-archive-smoke-linux` and do not push a `v*` tag unless the
runner spend has been approved.

After the release workflow finishes, install or test the platform archive on a
machine matching the target. The plugin marketplace bundle remains a separate
artifact from the CLI release archives.

`just ci-credit-guard`, `just install-smoke`, `just demo-run`, `just plugin-demo-run`,
`just claude-plugin-smoke`, `just codex-plugin-smoke`, `just serve-smoke`,
`just release-archive-smoke`, `just release-zip-layout-smoke`, `just shipping-smoke`,
`just deployed-cache-smoke`, `just deployed-cache-smoke-required`,
`just hosted-release-proof`, `just sandbox-readiness-proof`, `just platform-smoke`,
and `just platform-smoke-strict` are local. They do not
start GitHub Actions.
`ci-credit-guard` proves the workflow trigger invariant: normal branch pushes
and pull-request activity cannot start GitHub Actions.
`install-smoke` proves a fresh source install into a temporary local root.
`claude-plugin-smoke` proves local Claude Code marketplace installation in a
temporary `HOME`.
`codex-plugin-smoke` proves local Codex marketplace installation in a temporary
`CODEX_HOME`.
`serve-smoke` proves the verifier-in-a-box runtime over loopback HTTP: session
minting, JAR fetch, JSON/HTML trace, plaintext rejection, and redaction. It
honors `AUGENMASS_BIN` for native source/release binaries and otherwise uses the
bundled plugin binary.
`public-sandbox-snapshot` is a live-data report for presentation prep, not a
release gate; it fetches public sandbox reads and prints aggregate counts/ETags
without credentialed writes.
`release-archive-smoke` builds the host release archive, extracts it, then runs
the packaged binary against packaged docs, examples, and fixtures.
`release-zip-layout-smoke` builds a Windows-style `.zip` package layout from the
host release binary renamed to `augenmass.exe`, extracts it, and runs the same
archive smoke. On non-Windows hosts it proves zip packaging and self-contained
layout only; it is not native Windows execution proof.
`docker-release-archive-smoke-linux` builds Linux arm64 and amd64 archives
inside Docker, runs the archive smoke inside the matching Linux container, and
exports the resulting archives to:

- `dist/docker-release-archive-smoke/linux-arm64/augenmass-v<version>-aarch64-unknown-linux-gnu.tar.gz`
- `dist/docker-release-archive-smoke/linux-amd64/augenmass-v<version>-x86_64-unknown-linux-gnu.tar.gz`

`plugin-only-smoke` copies only the plugin bundle to a temp directory and runs
no-file commands from outside the checkout, so marketplace-style first-run
behavior is proved without `fixtures/` or `examples/`.
`shipping-smoke` covers the plugin bundle, the plugin-only first-run path, the
`serve` runtime smoke, the live cached-sandbox path, the public sandbox snapshot,
and the Docker backend.
`deployed-cache-smoke` is opt-in for a Railway/VPS cache URL and skips cleanly
when `AUGENMASS_DEPLOYED_CACHE_API_BASE` is unset.
`deployed-cache-smoke-required` is the hosted-readiness gate; it fails without
`AUGENMASS_DEPLOYED_CACHE_API_BASE` and
`AUGENMASS_DEPLOYED_CACHE_ADMIN_TOKEN`. `hosted-release-proof` is the same
required hosted gate. `sandbox-readiness-proof` is the required live sandbox
gate. `cloudflare-containers-typecheck` typechecks the optional Cloudflare
Containers Worker adapter without deploying it. `platform-smoke` checks the host target and any locally available
cross-targets; by default it skips Linux or Windows targets, including Linux
arm64, when the Rust target or required cross C/MSVC toolchain is missing.
`platform-smoke-strict` turns those skips into failures for a release machine
where every configured target must be present.

Runtime smokes that touch a running server or hosted cache (`serve-smoke`,
`live-cache-smoke`, `deployed-cache-smoke`, `deployed-cache-smoke-required`,
`live-sandbox-smoke`) resolve the CLI as: script-specific override, then
`AUGENMASS_BIN`, then the bundled plugin binary. `demo-run` is also portable: it
resolves `AUGENMASS_DEMO_BIN`, then
`AUGENMASS_BIN`, then the bundled binary. Plugin-bundle gates (`plugin-smoke`,
`plugin-demo-run`) intentionally stay bound to the committed plugin binary.

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

That checks the committed macOS Apple Silicon plugin bundle, the plugin-only
first-run path, and local Claude Code/Codex marketplace installs. It is
intentionally separate from the plugin-free CLI proof.

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

## Plugin bundle caveat

The plugin path is:

```sh
plugins/augenmass-workbench/bin/augenmass
```

That binary is committed so the private plugin preview works without a local
build on the presenter machine. It is not yet a multi-platform bundle. Until
plugin packaging learns platform-specific binaries, non-macOS-ARM users should
install the skill for guidance and set `AUGENMASS_BIN` to a CLI built from source
or downloaded from a release archive.
