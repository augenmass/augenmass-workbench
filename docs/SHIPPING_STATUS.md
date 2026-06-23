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
- 8 cache integration tests.
- 5 demo-proof integration tests.
- 1 serve integration test.

The local shipping gate passed:

```sh
just shipping-smoke
```

That proves:

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
- The configured RP
  `2af138a8-59ea-4a84-aea3-666cafdb1369` returned one cached-sandbox
  registration.
- `cache warm` prewarmed schema metadata, schema vocabularies, and that RP's
  registration list through the cache refresh API, with JSON shape checks on
  warmed bodies.
- Stale fallback works with a deliberately broken upstream, returning the cached
  registration response with `x-augenmass-cache: STALE`.
- The Docker cache image builds locally, runs as uid `10001`, can write `/data`,
  exposes `/api/health`, and protects admin status without a token.

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
```

It builds a host archive, extracts it, and runs the packaged binary only against
packaged docs, examples, and fixtures.

The local platform probe is:

```sh
just platform-smoke
```

It checks the host target and any installed cross-targets that have the required
local C/MSVC toolchain. On this macOS development machine, native macOS builds
are locally provable; Linux and Windows are skipped unless their cross toolchains
are installed or strict mode is enabled on a release machine.

The strongest local release proof is:

```sh
just local-release-proof
```

This gate passed locally on 2026-06-24. It combines the deterministic Rust
gates, source-install smoke, release-archive smoke, plugin smoke, live
cached-sandbox smoke, platform smoke, and explicit Docker cache-backend
builds/runs for `linux/arm64` and `linux/amd64`, plus Docker-built Linux
release archives smoke-tested inside matching Linux containers. It still does
not replace native Windows testing or a native Linux host check outside Docker.

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
  rejection, and redaction.
- `evidence export`, `evidence verify`, and `evidence replay`: signed,
  projector-safe replay of captured local debug artifacts.
- `cache serve` and `cache warm`: a small backend for stable cached-sandbox reads.
- `register --target cached-sandbox`: dry-run symmetry only; confirmed writes are
  refused because cached-sandbox is read-only.
- `live-sandbox-smoke`: a credential-gated, non-mutating rehearsal for the real
  sandbox path. It skips without credentials and only performs a confirmed write
  when `AUGENMASS_LIVE_SANDBOX_WRITE=1` is set.
- `deployed-cache-smoke`: an opt-in hosted-cache proof. It skips without
  `AUGENMASS_DEPLOYED_CACHE_API_BASE`; with a Railway/VPS URL it checks health,
  public cached reads, CLI `cached-sandbox`, and admin/warm protection when an
  admin token is provided.

## Backend deployment verdict

Best simple deployment target: Railway or a small VPS/container host.

The Docker image has the right shape for Railway:

- It respects `PORT`.
- It stores SQLite under `/data`.
- It runs as non-root uid `10001`.
- It should be deployed with a persistent volume and
  `AUGENMASS_CACHE_ADMIN_TOKEN`; non-loopback binds now refuse to start without
  that token.

Cloudflare Workers and Vercel are not the best fit for the current Rust binary
plus SQLite backend. They would need either a rewrite against their storage model
or a separate adapter. For this release, keep the cache backend as a container.

No hosted cache URL is committed here. Once a Railway or VPS service exists,
validate it locally with:

```sh
AUGENMASS_DEPLOYED_CACHE_API_BASE=https://cache.example/api \
AUGENMASS_DEPLOYED_CACHE_ADMIN_TOKEN=<token> \
  just deployed-cache-smoke
```

## Cross-platform status

Proven:

- macOS Apple Silicon source build and test.
- macOS Apple Silicon source install into an isolated local Cargo root.
- macOS Apple Silicon bundled plugin binary.
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

- Native Windows binary on Windows.
- Native Linux release archive outside Docker or a native Linux host runner.
- Multi-platform plugin bundle; non-macOS-ARM agent users should set
  `AUGENMASS_BIN` to a native CLI binary.

The code is Rust-only, but the shipped plugin binary is currently a macOS
Apple Silicon artifact. Treat broader platform support as source-build and
container-capable until native release archives are built and manually tested.

## Remaining polish

- Record a live wallet run with `serve` if network/public URL setup cooperates.
- Build and manually test native Linux and Windows archives before claiming
  one-command install on those platforms.
- Keep GitHub CI manual-only unless runner-minute spending is explicitly
  approved.
- If the public sandbox is unstable, prewarm the cache with:

```sh
augenmass cache serve --db ./presenter-cache.sqlite --ttl-secs 315360000
augenmass cache warm --api-base http://127.0.0.1:8081/api --rp 2af138a8-59ea-4a84-aea3-666cafdb1369
```
