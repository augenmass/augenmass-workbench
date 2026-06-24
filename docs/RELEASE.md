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

## CI gate

`.github/workflows/ci.yml` is manual-only through `workflow_dispatch`, so normal
pushes do not spend private-repo runner credits. When you explicitly run it, it
uses:

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

The release workflow uses Blacksmith runners for Linux x64, Windows x64, macOS
Apple Silicon, and the publish job. The remaining Intel Mac artifact uses
GitHub's `macos-15-intel` runner because Blacksmith macOS runners are Apple
Silicon. Both the CI and release workflows remain manual/tag-only; they still do
not run on ordinary pushes or pull-request activity.

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

## macOS signing and notarization

macOS notarization is local and manual-only for now; it does not run from normal
CI and does not spend remote runner minutes. The machine running it needs:

- a Developer ID Application identity in Keychain
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
and pull-request activity cannot start GitHub Actions.
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

They are unsigned preview binaries. If macOS Gatekeeper or Windows blocks a
binary, verify the release checksum first, then either approve it manually
(macOS System Settings -> Privacy & Security -> Open Anyway; Windows Properties
-> Unblock or PowerShell `Unblock-File`) or build from source and set
`AUGENMASS_BIN`.
