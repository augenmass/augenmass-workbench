# Shipping status

Last local verification: 2026-06-24.

This page is the short operator verdict for the Workbench as it stands before the
EUDI On presentation. It is deliberately practical: what is proven, what can be
shown, and what still needs caution.

## Current verdict

The Workbench is demo-ready as a Rust CLI plus Claude Code/Codex skill on the
current Apple Silicon macOS development machine. The core flows are not slideware:
artifact inspection, over-ask checking, cryptographic verification, evidence
replay, live verifier debugging, cached-sandbox reads, cache prewarming, and the
Dockerized cache backend all have local proof gates.

The strongest presentation path is skill first, CLI underneath:

1. Ask the skill what an unknown EUDI artifact is.
2. Have it decode and explain the artifact without leaking raw secrets.
3. Show an over-ask request being blocked with a cited legal basis.
4. Verify a real committed PID presentation fixture and hostile variants.
5. Use `serve` for the live wallet-interaction debugger if the phone/network
   setup is ready.
6. Use `cache serve` plus `cache warm` to keep sandbox reads stable.

## Proven locally

The standard gate passed:

```sh
just verify
```

That covers formatting, clippy, all Rust tests, and the deterministic demo proof
commands. At the time of this status note, the suite includes:

- 46 unit tests.
- 43 CLI integration tests.
- 9 cache integration tests.
- 5 demo-proof integration tests.
- 1 serve integration test.

The local shipping gate passed:

```sh
just shipping-smoke
```

That proves:

- GitHub Actions workflows cannot start on normal branch pushes or pull-request
  activity. CI is manual-only, and release publishing is tag-only.
- The bundled plugin binary is present, executable, current, and exposes the
  advertised command surfaces through both Claude Code and Codex metadata checks.
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
just local-release-proof
```

This gate passed locally on 2026-06-24. Both local release proofs now run
fail-fast preflights before the long build/test work. `local-cli-release-proof`
is plugin-free and uses the native release binary for demo, serve, live cache,
install, archive, zip-layout, platform, and Docker checks. It resolves the Unix
binary and the Windows `.exe` fallback. `presenter-plugin-proof` checks the
committed macOS Apple Silicon plugin bundle and local Claude Code/Codex
marketplace installs. `local-release-proof` composes both. Together they cover
the deterministic Rust gates, the GitHub Actions runner-credit guard,
source-install smoke, release-archive smoke, Windows-style zip layout smoke,
plugin smoke, live cached-sandbox smoke, platform smoke, and explicit Docker
cache-backend builds/runs for `linux/arm64` and `linux/amd64`, plus Docker-built
Linux release archives smoke-tested inside matching Linux containers. They still
do not replace native Windows testing or a native Linux host check outside
Docker.

The most recent local Linux archive proof also passed separately on 2026-06-24:

```sh
just docker-release-archive-smoke-linux
```

It exported and smoke-tested:

- `dist/docker-release-archive-smoke/linux-arm64/augenmass-v0.2.0-aarch64-unknown-linux-gnu.tar.gz`
- `dist/docker-release-archive-smoke/linux-amd64/augenmass-v0.2.0-x86_64-unknown-linux-gnu.tar.gz`

Those exported archive directories now include matching `.sha256` and
`.manifest.json` sidecars, and the Docker export script now publishes them
atomically only after archive smoke has passed.

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
- `serve-smoke`: a local runtime proof for the verifier-in-a-box without a phone
  wallet; it exercises session minting, JAR fetch, trace endpoints, plaintext
  rejection, and redaction. It honors `AUGENMASS_BIN` for native source or
  release binaries.
- `evidence export`, `evidence verify`, and `evidence replay`: signed,
  projector-safe replay of captured local debug artifacts.
- `cache serve` and `cache warm`: a small backend for stable cached-sandbox reads.
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
- `deployed-cache-smoke-required`: the hosted-readiness proof. It fails without
  both a deployed cache URL and `AUGENMASS_DEPLOYED_CACHE_ADMIN_TOKEN`, then
  proves public reads, protected status, authenticated warm, and warmed entries.
- `hosted-release-proof`: release-checklist alias for
  `deployed-cache-smoke-required`.

## Backend deployment verdict

Best simple deployment target: Railway or a small VPS/container host.

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

Cloudflare Containers now have an optional Worker adapter under
`deploy/cloudflare-containers/`, proven locally with
`just cloudflare-containers-typecheck`. The caveat is persistence: Cloudflare
Container disk is ephemeral, so Railway, Fly.io, Render, or a VPS with a
persistent `/data` volume remain the best simple hosted cache targets for this
release. Vercel still needs a function-shaped adapter and storage decision.

No hosted cache URL is committed here. Once a Railway or VPS service exists,
validate it locally with:

```sh
AUGENMASS_DEPLOYED_CACHE_API_BASE=https://cache.example/api \
AUGENMASS_DEPLOYED_CACHE_ADMIN_TOKEN=<token> \
  just deployed-cache-smoke-required
```

## Cross-platform status

Proven:

- macOS Apple Silicon source build and test.
- macOS Apple Silicon source install into an isolated local Cargo root.
- macOS Apple Silicon bundled plugin binary.
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
  run against packaged docs, examples, and fixtures.
- Linux amd64 release archive built inside Docker, extracted inside Linux, and
  run against packaged docs, examples, and fixtures.

Not yet fully proven:

- Native Windows execution on Windows. The zip package layout is locally
  smoke-tested, but the Windows binary itself still needs Windows.
- Native Linux release archive outside Docker or a native Linux host runner.
- Multi-platform plugin bundle; non-macOS-ARM agent users should set
  `AUGENMASS_BIN` to a native CLI binary.

The code is Rust-only, but the shipped plugin binary is currently a macOS
Apple Silicon artifact. Treat broader platform support as source-build and
container-capable until native release archives are built and manually tested.
Runtime smokes can still be reused on those platforms by setting
`AUGENMASS_BIN` to the native binary, and `demo-run` can use
`AUGENMASS_DEMO_BIN` for a one-off native demo binary. Plugin-bundle smokes
remain Apple Silicon until the plugin bundle grows platform-specific binaries.

## Remaining polish

- Record a live wallet run with `serve` if network/public URL setup cooperates.
- Build and manually test native Linux and Windows archives before claiming
  one-command install on those platforms.
- Keep GitHub CI manual-only unless runner-minute spending is explicitly
  approved.
- If the public sandbox is unstable, prewarm the cache with:

```sh
augenmass cache serve --db ./presenter-cache.sqlite --ttl-secs 315360000 \
  --allowed-rp 2af138a8-59ea-4a84-aea3-666cafdb1369
augenmass cache warm --api-base http://127.0.0.1:8081/api --rp 2af138a8-59ea-4a84-aea3-666cafdb1369
```

For the latest public sandbox aggregate before a demo or website update:

```sh
just public-sandbox-snapshot
```

Last observed snapshot from this checkout:

- Captured at: `2026-06-24T00:28:00Z`
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
