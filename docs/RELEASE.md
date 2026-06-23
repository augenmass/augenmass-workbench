# Release and platform support

Augenmaß Workbench ships as one Rust CLI (`augenmass`) and one Claude Code
plugin bundle that carries the same CLI under `plugins/augenmass-workbench/bin`.

## Current support status

- Source build: supported on platforms with Rust 1.92 or newer.
- Plugin bundle in this repository: macOS Apple Silicon, because the committed
  bundled binary is a Mach-O arm64 executable.
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

On a tag push (`v*`), the workflow uploads the archives to a GitHub release.
On manual dispatch, it publishes workflow artifacts only.

## Cutting a release

Run the local gate first:

```sh
just verify
just demo-run
just install-smoke
just release-archive-smoke
just shipping-smoke
just platform-smoke
```

Refresh the plugin bundle on an Apple Silicon Mac before tagging:

```sh
just bundle
git status --short
```

Then tag from a clean tree:

```sh
git tag v0.2.0
git push origin v0.2.0
```

After the release workflow finishes, install or test the platform archive on a
machine matching the target. The plugin marketplace bundle remains a separate
artifact from the CLI release archives.

`just install-smoke`, `just release-archive-smoke`, `just shipping-smoke`, and
`just platform-smoke` are local. They do not start GitHub Actions.
`install-smoke` proves a fresh source install into a temporary local root.
`release-archive-smoke` builds the host release archive, extracts it, then runs
the packaged binary against packaged docs, examples, and fixtures.
`shipping-smoke` covers the plugin bundle, the live cached-sandbox path, and the
Docker backend. `platform-smoke` checks the host target and any locally available
cross-targets; by default it skips Linux or Windows targets when the required
cross C/MSVC toolchain is missing. Set
`AUGENMASS_STRICT_PLATFORM_SMOKE=1` on a release machine if missing targets
should fail the gate.

For the strongest local proof without spending runner credits, run:

```sh
just local-release-proof
```

That adds the source-install smoke, release-archive smoke, and explicit Docker
builds and runtime checks for `linux/arm64` and `linux/amd64` using
`AUGENMASS_DOCKER_PLATFORM`. It proves the cache backend container on those
Linux platforms, but it still does not prove the standalone native Linux archive
or the Windows archive. Those need native runners or manual machines.

## Plugin bundle caveat

The plugin path is:

```sh
plugins/augenmass-workbench/bin/augenmass
```

That binary is committed so the private Claude Code plugin preview works without
a local build on the presenter machine. It is not yet a multi-platform bundle.
Until plugin packaging learns platform-specific binaries, non-macOS-ARM users
should install the skill for guidance and build the CLI from source or download a
release archive.
