# Release and platform support

Augenmaß Workbench ships as one Rust CLI (`augenmass`) and one agent plugin
bundle with both Claude Code and Codex manifests. The bundle carries the same CLI
under `plugins/augenmass-workbench/bin`.

## Current support status

- Source build: supported on platforms with Rust 1.92 or newer.
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

## Release archives

`.github/workflows/release.yml` builds these archives:

- `augenmass-v<version>-x86_64-unknown-linux-gnu.tar.gz`
- `augenmass-v<version>-x86_64-pc-windows-msvc.zip`
- `augenmass-v<version>-x86_64-apple-darwin.tar.gz`
- `augenmass-v<version>-aarch64-apple-darwin.tar.gz`

The workflow, local host smoke, and Docker Linux archive smoke all use
`scripts/package-release-archive.sh` for the package layout.

On a tag push (`v*`), the workflow uploads the archives to a GitHub release.
On manual dispatch, it publishes workflow artifacts only.

## Cutting a release

Run the local gate first:

```sh
just verify
just demo-run
just install-smoke
just codex-plugin-smoke
just release-archive-smoke
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

After the release workflow finishes, install or test the platform archive on a
machine matching the target. The plugin marketplace bundle remains a separate
artifact from the CLI release archives.

`just install-smoke`, `just demo-run`, `just plugin-demo-run`,
`just claude-plugin-smoke`, `just codex-plugin-smoke`, `just serve-smoke`,
`just release-archive-smoke`, `just shipping-smoke`,
`just deployed-cache-smoke`, and `just platform-smoke` are local. They do not
start GitHub Actions.
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
`docker-release-archive-smoke-linux` builds Linux arm64 and amd64 archives
inside Docker, runs the archive smoke inside the matching Linux container, and
exports the resulting archives to:

- `dist/docker-release-archive-smoke/linux-arm64/augenmass-v<version>-aarch64-unknown-linux-gnu.tar.gz`
- `dist/docker-release-archive-smoke/linux-amd64/augenmass-v<version>-x86_64-unknown-linux-gnu.tar.gz`

`shipping-smoke` covers the plugin bundle, the `serve` runtime smoke, the live
cached-sandbox path, and the Docker backend. `deployed-cache-smoke` is opt-in for
a Railway/VPS cache URL and skips cleanly when `AUGENMASS_DEPLOYED_CACHE_API_BASE`
is unset. `deployed-cache-smoke-required` is the hosted-readiness gate; it fails
without `AUGENMASS_DEPLOYED_CACHE_API_BASE`. `platform-smoke` checks the host
target and any locally available cross-targets; by default it skips Linux or
Windows targets when the required cross C/MSVC toolchain is missing. Set
`AUGENMASS_STRICT_PLATFORM_SMOKE=1` on a release machine if missing targets
should fail the gate.

Runtime smokes that touch a running server or hosted cache (`serve-smoke`,
`live-cache-smoke`, `deployed-cache-smoke`, `deployed-cache-smoke-required`,
`live-sandbox-smoke`) resolve the CLI as: script-specific override, then
`AUGENMASS_BIN`, then the bundled plugin binary. `demo-run` is also portable: it
resolves `AUGENMASS_DEMO_BIN`, then
`AUGENMASS_BIN`, then the bundled binary. Plugin-bundle gates (`plugin-smoke`,
`plugin-demo-run`) intentionally stay bound to the committed plugin binary.

For the strongest local proof without spending runner credits, run:

```sh
just local-release-proof
```

That adds the source-install smoke, release-archive smoke, and explicit Docker
builds and runtime checks for `linux/arm64` and `linux/amd64` using
`AUGENMASS_DOCKER_PLATFORM`. It proves the cache backend container and the
standalone Linux archive layout on those Linux platforms inside Docker. It still
does not replace a native Linux host check outside Docker, and it does not prove
the Windows archive. Those need native runners or manual machines.

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
