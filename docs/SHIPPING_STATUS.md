# Shipping status

Last local verification: 2026-06-25.

This page is the short operator verdict for the Workbench as it stands before the
EUDI On presentation. It is deliberately practical: what is proven, what can be
shown, and what still needs caution.

## Current verdict

The Workbench is demo-ready as a Rust CLI plus Claude Code/Codex skill on the
current Apple Silicon macOS development machine. The core flows are not slideware:
artifact inspection, over-ask checking, cryptographic verification, evidence
replay, live verifier debugging, cached-sandbox reads, cache prewarming, and the
Dockerized cache backend all have local proof gates. The hosted Railway cache is
also deployed and smoke-tested for the presentation path.

The strongest presentation path is skill first, CLI underneath:

1. Ask the skill what an unknown EUDI artifact is.
2. Have it decode and explain the artifact without leaking raw secrets.
3. Show an over-ask request being blocked with a cited legal basis.
4. Verify a real committed PID presentation fixture and hostile variants.
5. Use `serve --relay augenmass` for the live wallet-interaction debugger with
   a real phone wallet over `https://wallet.augenmass.tech`.
6. Use `cache serve`, `cache warm`, and `cache status` to keep sandbox reads stable
   and inspect what is cached.

## Proven locally

The standard gate passed:

```sh
just verify
```

That covers formatting, clippy, all Rust tests, and the deterministic demo proof
commands. Keep the exact test count in the Cargo output rather than this status
page; this note should describe what the gate proves, not become stale whenever
one focused test is added.

The local shipping gate passed:

```sh
just shipping-smoke
```

This is a local shipping gate, not a hosted deployment proof. It includes one
optional deployed-cache check that exits cleanly when no hosted cache URL is
configured; hosted readiness is proven only by
`just deployed-cache-smoke-required` / `just hosted-release-proof`.

That proves:

- GitHub Actions workflows cannot start on normal branch pushes or pull-request
  activity. CI is manual-only, and release publishing is tag-only.
- The bundled plugin launcher is present, executable, current, and exposes the
  advertised command surfaces through both Claude Code and Codex metadata checks.
- `just plugin-bundle-freshness` verifies the plugin bundle manifest, version,
  launcher, and every committed target-binary hash.
- The repo-local Claude Code marketplace validates with `--strict`, installs
  `augenmass-workbench@augenmass` in a temporary `HOME`, and reports it enabled.
- The repo-local Codex marketplace installs `augenmass-workbench@augenmass` in a
  temporary `CODEX_HOME` and reports it enabled.
- The bundled `serve` runtime starts over loopback HTTP, mints a session, serves
  the signed request object, exposes JSON/HTML trace endpoints, rejects a
  plaintext `direct_post` with HTTP 422, and keeps the unauthenticated trace
  redacted.
- The live public sandbox cache path works against
  `https://sandbox.eudi-wallet.org/api`.
- The schema endpoint fetched `113804` bytes from the public sandbox, then served
  a cache hit.
- The public sandbox snapshot gate saw 558 registration certificates across 90
  relying parties, with newest public entries on 2026-06-23 and the configured RP
  still returning one registration.
- The configured RP
  `2af138a8-59ea-4a84-aea3-666cafdb1369` returned one cached-sandbox
  registration.
- `cache warm` prewarmed schema metadata, schema vocabularies, and that RP's
  registration list through the cache refresh API, with JSON shape checks on
  warmed bodies.
- Registration read-through is RP-allowlisted by default. The local and Docker
  smokes allow the configured demo RP and prove a synthetic unlisted RP is
  rejected with `403` before it can consume cache rows.
- Stale fallback works with a deliberately broken upstream, returning the cached
  registration response with `x-augenmass-cache: STALE`.
- The Docker cache image builds locally, runs as uid `10001`, can write `/data`,
  exposes `/api/health`, protects admin status without a token, and fetches
  `schema-metadata` through the container with a `MISS` followed by a `HIT`.
  It then restarts the container on the same Docker volume and proves the cached
  schema is still a `HIT`.

No remote GitHub Actions run is required for these gates.

The local source-install gate is:

```sh
just install-smoke
```

It installs the CLI into a temporary local Cargo root, runs the installed
binary, and proves the first-run path without relying on the plugin bundle.

The local release-archive gate is:

```sh
just release-archive-smoke
just release-zip-layout-smoke
```

`release-archive-smoke` builds a host archive, extracts it, and runs the
packaged binary only against packaged docs, examples, and fixtures.
It also verifies the generated `.sha256` checksum sidecar and
`.manifest.json` archive/binary/provenance manifest. Those sidecars are required
by default; missing sidecars are allowed only with the explicit legacy escape
hatch `AUGENMASS_ALLOW_MISSING_RELEASE_SIDECARS=1`.
`release-zip-layout-smoke` exercises the Windows-style `.zip` layout locally
without claiming native Windows execution unless it is run on Windows. Its
manifest is marked `layoutOnly: true` and `nativeExecution: false` on this macOS
host.

The local platform probe is:

```sh
just platform-smoke
just platform-smoke-strict
```

It checks the host target and any installed cross-targets that have the required
local C/MSVC toolchain. On this macOS development machine, native macOS builds
are locally provable; Linux and Windows are skipped unless their cross toolchains
are installed. `platform-smoke-strict` flips those skips into failures and is
the gate to use on a machine where every configured target is expected to be
present. A skipped target is not counted as proven.

The strongest local release proof is:

```sh
just local-cli-release-proof
just presenter-plugin-proof
just plugin-bundle-freshness
just local-release-proof
```

These release proofs run fail-fast preflights before the long build/test work.
`local-cli-release-proof` is plugin-free and uses the native release binary for
demo, serve, live cache, install, archive, zip-layout, platform, and Docker
checks. It resolves the Unix binary and the Windows `.exe` fallback.
`presenter-plugin-proof` checks the committed platform-aware plugin bundle, its
manifest/hash freshness, and local Claude Code/Codex marketplace installs.
`local-release-proof` composes both.

Current 2026-06-24 status: the shorter `shipping-smoke` passed from a clean
pushed tree at commit `de06e38`, and the targeted deployed-cache status CLI
script fix at `d13da9f` passed `deployed-cache-guard-smoke`,
`deployed-cache-smoke` in skip mode, and `live-cache-smoke`. The latest
code-bearing checkpoint `435956f` passed `just verify` and `just shipping-smoke`
before push, including the new `evidence assert-live` command and refreshed
plugin bundle. Packaging checkpoint `f7e5f5b` then passed native archive smoke,
Windows zip-layout smoke, platform smoke, and Docker Linux arm64 release archive
smoke. Later checkpoint `9b4bfea` passed local Docker runtime proof for
`linux/amd64`, then passed the clean-provenance Linux amd64 release-archive
export and smoke gate from the same clean commit.

Latest code-bearing checkpoint: commit `435956f` added
`evidence assert-live`, the post-capture proof gate for completed encrypted
phone-wallet runs. Before it was committed and pushed, the exact tree passed:

```sh
cargo test --test cli evidence_assert_live
cargo test --lib commands::evidence
just plugin-smoke
just plugin-only-smoke
just plugin-bundle-freshness
just verify
just shipping-smoke
```

That historical run refreshed the then-current macOS Apple Silicon plugin
binary, proved the new evidence command through CLI tests and plugin help,
exercised live public sandbox reads, and built the local Docker cache image.
GitHub Actions remained manual/tag-only; no remote CI run was started by the
push.

The most recent clean-provenance local Linux archive proofs passed for arm64 and
amd64 on 2026-06-24:

```sh
just docker-release-archive-smoke-arm64
just docker-release-archive-smoke-amd64
```

They exported and smoke-tested:

- `dist/docker-release-archive-smoke/linux-arm64/augenmass-v0.2.0-aarch64-unknown-linux-gnu.tar.gz`
- `dist/docker-release-archive-smoke/linux-amd64/augenmass-v0.2.0-x86_64-unknown-linux-gnu.tar.gz`

The exported archive directory includes matching `.sha256` and `.manifest.json`
sidecars. The arm64 manifest records commit
`f7e5f5b0c7ee5fc5b2be4310012a83d03f5cf7d6`; the amd64 manifest records commit
`9b4bfea277de12ca6d727e649bd01f98080aa36f`. Both Linux manifests record
`gitDirty: false`, `layoutOnly: false`, and `nativeExecution: true`. The host
macOS archive and Windows layout-only zip manifests from the same packaging
checkpoint also record `gitDirty: false`; the Windows zip remains
`layoutOnly: true` and `nativeExecution: false`. The Docker export script
publishes archive directories atomically only after archive smoke has passed.
The `dist/` directory is ignored, so these generated archives and sidecars are
local proof outputs, not committed release artifacts.

Latest docs-and-demo rehearsal pass on 2026-06-24 added the phone-wallet proof
runbook and passed:

```sh
git diff --check
just plugin-smoke
just plugin-only-smoke
just demo-proof
just public-sandbox-snapshot
just live-cache-smoke
```

The same pass ran `just live-sandbox-smoke`, which skipped because
`AUGENMASS_OIDC_TOKEN_URL`, `AUGENMASS_USERNAME`, and `AUGENMASS_PASSWORD` are
not configured, and ran `just deployed-cache-smoke`, which skipped at that time
because `AUGENMASS_DEPLOYED_CACHE_API_BASE` was not configured. The hosted cache
was proven later on Railway; live sandbox credentials are still required before
claiming the live sandbox path is configured.

Latest distribution pass on 2026-06-24 added a plugin-local
`reference/phone-wallet-proof.md` copy so marketplace/plugin-only installs have
the same phone proof checklist even without the root `docs/` directory. It
passed:

```sh
git diff --check
just plugin-smoke
just plugin-only-smoke
just release-archive-smoke
just release-zip-layout-smoke
```

The archive smoke now asserts that `docs/PHONE_WALLET_PROOF.md` is present in
release archives. The plugin smokes assert that the plugin-local phone proof
reference is present and contains the `--unsafe-debug-artifacts` /
`evidence assert-live` path.

Latest platform/runtime refresh on 2026-06-24 passed:

```sh
just install-smoke
just platform-smoke
just docker-smoke
just docker-smoke-arm64
```

`platform-smoke` passed for `aarch64-apple-darwin` and
`x86_64-apple-darwin`. It skipped `x86_64-unknown-linux-gnu`,
`aarch64-unknown-linux-gnu`, and `x86_64-pc-windows-msvc` because those Rust
targets are not installed on this machine, so native Linux and Windows execution
remain unproven here. Both Docker runtime smokes passed locally, including
non-root uid `10001`, writable `/data`, admin-token protection, cache
`MISS`/`HIT`, RP allowlist blocking, and persistence across container restart.
An explicit `linux/amd64` Docker runtime smoke also passed locally on
2026-06-24:

```sh
just docker-smoke-amd64
```

That proves the cache backend container can build and run as Linux amd64 under
the local Docker environment. The subsequent
`just docker-release-archive-smoke-amd64` run also built, exported, extracted,
and smoked the Linux amd64 release archive inside Docker with clean git
provenance.

Latest hosted-cache deployment proof on 2026-06-24:

```sh
AUGENMASS_DEPLOYED_CACHE_API_BASE=https://cache.augenmass.tech/api \
AUGENMASS_DEPLOYED_CACHE_ADMIN_TOKEN=<token> \
  just deployed-cache-smoke-required
```

Railway project `augenmass-workbench-cache`, service `cache`, deployed
successfully with a `/data` volume, non-loopback bind, admin token, demo RP
allowlist, the public sandbox upstream, and custom domain
`https://cache.augenmass.tech`. DNS is propagated and the Railway certificate is
valid. The hosted smoke passed twice: first with a schema `MISS`, then with a
schema `HIT`. `cache status` showed three warmed entries for schema metadata,
schema vocabularies, and the configured demo RP registration list. The admin
token is set in Railway and is not committed.

Latest hosted-relay deployment proof on 2026-06-25:

- Railway project: `augenmass-workbench-cache`
- Service: `relay`
- Deployment: `b790a2bb-ee76-4f5d-b860-3629c5b367d3`
- Status: `SUCCESS`
- Runtime log: `augenmass relay listening addr=0.0.0.0:8080`
- Volume: none; the relay is stateless.
- Custom domain: `https://wallet.augenmass.tech`
- DNS: `wallet.augenmass.tech` CNAME resolves to `gu10iony.up.railway.app`.
- Domain verification: Railway TXT verification is true.
- Certificate: valid Railway ECDSA certificate for `wallet.augenmass.tech`.

The public health endpoint returned the relay health JSON:

```sh
curl --max-time 20 -i https://wallet.augenmass.tech/healthz
```

The required hosted proof passed:

```sh
just hosted-relay-proof
```

It started local `augenmass serve`, opened a temporary run through the deployed
relay, proved the public request object is forwarded byte-for-byte, proved
public trace/inspect routes are not exposed, rejected plaintext `direct_post`
with HTTP 422 through the relay, and confirmed the local trace stayed redacted.
The relay auth token is set in Railway and mirrored locally only in
`.env.relay.local`, which is gitignored.

## Presentation-safe surfaces

These are good to show on stage or in a recording:

- `inspect`: identify SD-JWT VC, mdoc, JAR, credential offer, status list, DCQL,
  and registration bodies.
- `check` and `audit`: block over-asking and explain the minimal alternative.
- `doctor`: catch verifier/JAR mistakes such as `x5c` shape and `client_id`
  binding problems.
- `verify presentation`, `verify trust`, and `verify status-list`: prove good
  fixtures and reject hostile ones.
- `serve`: live verifier-in-a-box with redacted traces by default.
- `serve --relay augenmass`: hosted phone-wallet ingress. The public relay
  carries only `/request/<session>` and `/response/<session>`; trace, inspect,
  session APIs, evidence, and unsafe debug artifacts stay on localhost.
- `relay-smoke`: local proof for the hosted relay path. It compares local and
  relayed request objects byte-for-byte, proves public trace/inspect return
  `404`, rejects plaintext `direct_post`, and checks relay logs for forbidden
  sentinels.
- `serve-smoke`: a local runtime proof for the verifier-in-a-box without a phone
  wallet; it exercises session minting, JAR fetch, trace endpoints, plaintext
  rejection, and redaction. It honors `AUGENMASS_BIN` for native source or
  release binaries.
- `evidence export`, `evidence verify`, `evidence replay`, and
  `evidence assert-live`: signed, projector-safe replay of captured local debug
  artifacts, plus a post-capture gate that proves a completed encrypted
  phone-wallet run before we claim one.
- Real phone-wallet proof: on 2026-06-25, `serve --relay augenmass --age-only`
  with the registrar-issued leaf completed against the sandbox iOS and Android
  wallets. The workbench traces reached `REQUEST_OBJECT_FETCHED`,
  `RESPONSE_RECEIVED`, `RESPONSE_DECRYPTED`, `VERIFIED`, and
  `OVER_ASK_ANALYZED`; exported bundles passed `evidence verify` and
  `evidence assert-live`. Android showed a visible "Data sent successfully"
  screen. iOS logged `PresentationSuccess`; a post-success blank/white-screen
  UI issue belongs to the wallet UI, not the verifier protocol path.
- `cache serve`, `cache warm`, and `cache status`: a small backend for stable
  cached-sandbox reads plus an operator view of the protected cache inventory.
- `public-sandbox-snapshot`: a no-credentials live-data report for presentation
  and website prep. It prints aggregate sandbox counts, ETags, newest entries,
  and top relying parties without printing JWT/CWT bodies.
- `register --target cached-sandbox`: dry-run symmetry only; confirmed writes are
  refused because cached-sandbox is read-only.
- `live-sandbox-smoke`: a credential-gated, non-mutating rehearsal for the real
  sandbox path. It generates the body for the exact relying party being listed,
  skips without credentials, and only performs a confirmed write when
  `AUGENMASS_LIVE_SANDBOX_WRITE=1` is set.
- `live-sandbox-smoke-required`: the same rehearsal in required mode. It fails
  if sandbox credentials are missing, so it is the proof to use before claiming
  the live sandbox path is configured.
- `sandbox-readiness-proof`: release-checklist alias for
  `live-sandbox-smoke-required`.
- `deployed-cache-smoke`: an opt-in hosted-cache proof. It skips without
  `AUGENMASS_DEPLOYED_CACHE_API_BASE`; with a Railway/VPS URL it checks health,
  public cached reads, CLI `cached-sandbox`, and admin/warm protection when an
  admin token is provided.
- `deployed-cache-guard-smoke`: a no-network local guard that proves required
  hosted-cache proof rejects `http://`, loopback, and private-IP API bases.
- `deployed-relay-smoke`: an opt-in hosted-relay proof. It skips without
  `AUGENMASS_DEPLOYED_RELAY_BASE`; with a hosted relay URL and token it checks
  health, request-object forwarding, public trace/inspect refusal, plaintext
  rejection, and local trace redaction.
- `deployed-relay-guard-smoke`: a no-network local guard that proves required
  hosted-relay proof rejects `http://`, `ws://`, loopback, and private-IP bases.
- `cache-public-bind-guard-smoke`: a no-network local guard that proves
  `cache serve --host 0.0.0.0` refuses missing admin tokens, empty RP allowlists,
  unsafe upstreams, and `--max-entries 0` before it starts listening.
- `cloudflare-containers-typecheck`: a local proof that the optional Cloudflare
  Containers Worker adapter still compiles without deploying it.
- `deployed-cache-smoke-required`: the hosted-readiness proof. It fails without
  both an `https://` non-local hosted cache URL and
  `AUGENMASS_DEPLOYED_CACHE_ADMIN_TOKEN`, then proves public reads, protected
  status, authenticated warm, and warmed entries.
- `hosted-release-proof`: release-checklist alias for
  `deployed-cache-smoke-required`.
- `hosted-relay-proof`: release-checklist alias for required hosted relay proof.
  It passed against `https://wallet.augenmass.tech` on 2026-06-25.

## Backend deployment verdict

Best simple deployment target: Railway or a small VPS/container host. Railway is
now proven for the current presentation cache backend and hosted wallet relay.

The Docker image has the right shape for Railway:

- It respects `PORT`.
- It stores SQLite under `/data`.
- Its entrypoint prepares the database directory, then runs the server process as
  non-root uid `10001`.
- It should be deployed with a persistent volume and
  `AUGENMASS_CACHE_ADMIN_TOKEN`; non-loopback binds now refuse to start without
  that token.
- Non-loopback binds also refuse unsafe upstream URLs and empty RP allowlists
  unless the operator uses the explicit unsafe opt-ins.
- It bounds stored rows with `AUGENMASS_CACHE_MAX_ENTRIES` / `--max-entries`
  and evicts the oldest entries after the cap is reached.
- It bounds registration-certificate read-through with
  `AUGENMASS_CACHE_ALLOWED_RPS` / `--allowed-rp`; the CLI default is the demo
  RP, and unlisted RPs get `403`.
- It coalesces concurrent misses for the same cache key, so public readers do
  not stampede the sandbox upstream.
- The local Docker smoke verifies the server process uid and that uid `10001`
  can write to `/data`.
- The local public-bind guard smoke verifies a shared bind refuses unsafe deploy
  configuration before it listens.

The current hosted cache is:

```sh
AUGENMASS_CACHE_API_BASE=https://cache.augenmass.tech/api
```

Use the Railway admin token only for `cache warm`, `cache status`, and required
hosted proof gates. Do not put it in demos, slides, or committed files.

The current hosted relay service is deployed and proven:

```sh
AUGENMASS_RELAY=augenmass
AUGENMASS_RELAY_TOKEN=<token>
```

`https://wallet.augenmass.tech/healthz` returns the relay health JSON, and
`just hosted-relay-proof` passed against the public domain. The relay remains a
wallet-only ingress: phone wallets can reach request/response endpoints, while
trace, inspect, evidence, session APIs, and unsafe debug artifacts stay local.

Cloudflare Containers now have an optional Worker adapter under
`deploy/cloudflare-containers/`, proven locally with
`just cloudflare-containers-typecheck`. The caveat is persistence: Cloudflare
Container disk is ephemeral, so Railway, Fly.io, Render, or a VPS with a
persistent `/data` volume remain the best simple hosted cache targets for this
release. Vercel still needs a function-shaped adapter and storage decision.

To revalidate the hosted cache locally:

```sh
AUGENMASS_DEPLOYED_CACHE_API_BASE=https://cache.augenmass.tech/api \
AUGENMASS_DEPLOYED_CACHE_ADMIN_TOKEN=<token> \
  just deployed-cache-smoke-required
```

## Cross-platform status

Proven:

- macOS Apple Silicon source build and test.
- macOS Apple Silicon source install into an isolated local Cargo root.
- macOS Apple Silicon bundled plugin launcher and native target binary.
- Installed-plugin no-file first run, by copying only the plugin bundle to a
  temp directory and running generated/stdin commands without `fixtures/` or
  `examples/`.
- macOS Intel target check from the Apple Silicon development machine when the
  `x86_64-apple-darwin` Rust target is installed.
- Linux arm64 container build and runtime for the cache backend.
- Linux amd64 container build and runtime for the cache backend, including a
  full `cargo build --release --locked` inside the amd64 Docker build and the
  same health, uid, writable `/data`, and admin-token checks.
- Linux arm64 release archive built inside Docker, extracted inside Linux, and
  run against packaged docs, examples, and fixtures, with clean git provenance in
  the manifest.
- Linux amd64 release archive built inside Docker, extracted inside Linux, and
  run against packaged docs, examples, and fixtures, with clean git provenance in
  the manifest.
- Native Blacksmith debug builds on Linux x64, Windows x64, and macOS arm64.
  The pushed workflow `Blacksmith Smoke` ran manually on commit `812248e` with
  `scope=debug-build` and passed as run `28100757840`: macOS arm64 completed in
  `59s`, Linux x64 in `1m27s`, and Windows x64 in `2m19s`. This proves the
  Blacksmith org integration, runner labels, Rust toolchain install, and native
  workspace compilation on all three OS families without enabling push or PR
  triggers.
- Native release archives for Linux x64, Windows x64, macOS Apple Silicon, and
  macOS Intel. `Release Binaries` ran manually on commit `5bda20f` as run
  `28102488586`; all four build jobs compiled, packaged, extracted, executed the
  packaged binary against the packaged docs/examples/fixtures, verified
  sidecars, and uploaded workflow artifacts. Windows x64 passed after
  `release-archive-smoke.sh` was fixed to prefer `augenmass.exe` on Windows
  filesystems. Timings: macOS arm64 `1m43s`, Linux x64 `3m35s`, Windows x64
  `5m42s`, macOS Intel `12m19s`.
- Published release `v0.2.0` at
  `https://github.com/augenmass/augenmass-workbench/releases/tag/v0.2.0`.
  The tag-triggered release run `28103514119` passed Linux x64, Windows x64,
  macOS Apple Silicon, macOS Intel, and the publish job, producing 12 release
  assets: four native CLI archives, four SHA-256 sidecars, and four provenance
  manifests.
- Published-asset install proof on the presenter Mac: the macOS Apple Silicon
  archive was downloaded back from the GitHub release, its `.sha256` sidecar
  verified, the archive extracted, the binary printed `augenmass 0.2.0`, and
  `scripts/release-archive-smoke.sh` passed against that downloaded archive.
- Multi-platform plugin bundle assembled from the published `v0.2.0` release
  archives: macOS Apple Silicon, macOS Intel, Linux x64, and Windows x64 target
  binaries are present under `plugins/augenmass-workbench/bin/<target>/`, with
  launcher selection and `bin/manifest.json` hashes generated by
  `scripts/assemble-plugin-bundle.sh`.

Latest plugin packaging checkpoint `b653710` passed:

```sh
git diff --check
bash -n plugins/augenmass-workbench/bin/augenmass scripts/assemble-plugin-bundle.sh scripts/plugin-smoke.sh scripts/plugin-only-smoke.sh scripts/plugin-bundle-freshness.sh scripts/local-release-preflight.sh
just plugin-smoke
just plugin-only-smoke
just plugin-bundle-freshness
just presenter-plugin-proof
```

That proof installs through both local Claude Code and Codex marketplace smokes,
runs generated/stdin commands from a plugin-only copy, and runs the demo sequence
through the bundled launcher.

macOS notarization checkpoint `fc22e9a4-a21d-4c85-a5e6-7d0372c2f30f` passed
for the local Apple Silicon ZIP:

```sh
just macos-notarize
just macos-notarization-status
```

The proof is local under
`dist/macos-notarization/aarch64-apple-darwin/notarization-proof.json`, with
`notaryStatus: Accepted`, `stapled: false`, and `spctlAccepted: false`. This is
Apple notarization acceptance for the submitted standalone CLI ZIP. It is not a
stapled offline installer proof; a `.pkg` lane needs a Developer ID Installer
certificate.

macOS stapled installer checkpoint `97385b9c-4c7c-4cb3-ae46-aeff800b3534`
passed for the local Apple Silicon package:

```sh
just macos-pkg-notarize
just macos-pkg-notarization-status
```

The proof is local under
`dist/macos-pkg/aarch64-apple-darwin/pkg-notarization-proof.json`, with
`notaryStatus: Accepted`, `stapled: true`, and `spctlAccepted: true`.
`pkgutil --check-signature` reports a package signed by
`Developer ID Installer: Reza Shokri (B4F7YTTM6C)`, `xcrun stapler validate`
passes, and `spctl --assess --type install` accepts it as
`source=Notarized Developer ID`.

Not yet fully proven:

- macOS Intel notarization has not been run from this machine yet.
- macOS ZIPs are accepted by Apple's notary service but are not stapled; use
  the stapled `.pkg` for the polished Apple Silicon macOS install path.
- macOS Intel `.pkg` notarization has not been run from this machine yet.
- Windows binaries are not code-signed.

The code is Rust-only, and native release archives are now proven for the main
desktop targets. The shipped plugin bundle now carries a launcher plus target
binaries for the supported desktop targets. Runtime smokes still allow
`AUGENMASS_BIN` for source-built or separately trusted binaries, and `demo-run`
can use `AUGENMASS_DEMO_BIN` for a one-off native demo binary. Unsigned preview
binaries may require manual OS approval after checksum verification.

## Remaining polish

- Optional auditor-grade extension: repeat the phone-wallet proof with a PID
  issuer `--trust-anchor` and `--live-status` once the sandbox trust/status
  material is stable enough to claim issuer anchoring and revocation status.
- Keep the known-good phone-wallet proof local or in a private evidence store.
  The exported bundles and raw debug artifacts are sensitive and intentionally
  ignored by git.
- Keep GitHub CI manual-only unless runner-minute spending is explicitly
  approved.
- If the public sandbox is unstable, prewarm the cache with:

```sh
augenmass cache serve --db ./presenter-cache.sqlite --ttl-secs 315360000 \
  --allowed-rp 2af138a8-59ea-4a84-aea3-666cafdb1369
augenmass cache warm --api-base http://127.0.0.1:8081/api --rp 2af138a8-59ea-4a84-aea3-666cafdb1369
augenmass cache status --api-base http://127.0.0.1:8081/api
```

For the latest public sandbox aggregate before a demo or website update:

```sh
just public-sandbox-snapshot
```

Last observed snapshot from this checkout:

- Captured at: `2026-06-24T03:05:36Z`
- Schema metadata: `113804` bytes, ETag
  `W/"1bc8c-WSRXyNo0svH/T001YeId4arFQcA"`
- Schema vocabularies: `1001` bytes, ETag
  `W/"3e9-7cccrHF9AzPEgRK9rDobOq2RzgI"`
- Registration certificates: `558` entries, `90` distinct relying parties,
  `3904849` bytes, ETag `W/"3b9551-SHeTwplNjFePA2Q4hUP1jbHPXFU"`
- Created-at range: `2026-01-16T11:43:41.554Z` to
  `2026-06-23T16:02:23.831Z`
- Configured demo RP `2af138a8-59ea-4a84-aea3-666cafdb1369`: `1`
  certificate, `6412` bytes, ETag `W/"190c-xdqSnhRlnpiTOm1GTAroSgPCrAs"`,
  newest `2026-06-02T20:03:35.028Z`
- Highest-volume relying party in the public list:
  `8b366b67-4ab3-4613-9a70-de0b88ba938a` with `315` certificates.
