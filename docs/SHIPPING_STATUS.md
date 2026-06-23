# Shipping status

Last local verification: 2026-06-23.

This page is the short operator verdict for the Workbench as it stands before the
EUDI On presentation. It is deliberately practical: what is proven, what can be
shown, and what still needs caution.

## Current verdict

The Workbench is demo-ready as a Rust CLI plus Claude Code skill on the current
Apple Silicon macOS development machine. The core flows are not slideware:
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

- 41 unit tests.
- 43 CLI integration tests.
- 7 cache integration tests.
- 5 demo-proof integration tests.
- 1 serve integration test.

The local shipping gate passed:

```sh
just shipping-smoke
```

That proves:

- The bundled Claude Code plugin binary is present, executable, current, and
  exposes the advertised command surfaces.
- The live public sandbox cache path works against
  `https://sandbox.eudi-wallet.org/api`.
- The schema endpoint fetched `113804` bytes from the public sandbox, then served
  a cache hit.
- The configured RP
  `2af138a8-59ea-4a84-aea3-666cafdb1369` returned one cached-sandbox
  registration.
- `cache warm` prewarmed schema metadata, schema vocabularies, and that RP's
  registration list through the cache refresh API.
- Stale fallback works with a deliberately broken upstream, returning the cached
  registration response with `x-augenmass-cache: STALE`.
- The Docker cache image builds locally, runs as uid `10001`, can write `/data`,
  exposes `/api/health`, and protects admin status without a token.

No remote GitHub Actions run is required for these gates.

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
- `evidence export`, `evidence verify`, and `evidence replay`: signed,
  projector-safe replay of captured local debug artifacts.
- `cache serve` and `cache warm`: a small backend for stable cached-sandbox reads.
- `register --target cached-sandbox`: dry-run symmetry only; confirmed writes are
  refused because cached-sandbox is read-only.

## Backend deployment verdict

Best simple deployment target: Railway or a small VPS/container host.

The Docker image has the right shape for Railway:

- It respects `PORT`.
- It stores SQLite under `/data`.
- It runs as non-root uid `10001`.
- It should be deployed with a persistent volume and
  `AUGENMASS_CACHE_ADMIN_TOKEN`.

Cloudflare Workers and Vercel are not the best fit for the current Rust binary
plus SQLite backend. They would need either a rewrite against their storage model
or a separate adapter. For this release, keep the cache backend as a container.

## Cross-platform status

Proven:

- macOS Apple Silicon source build and test.
- macOS Apple Silicon bundled plugin binary.
- Linux container build and runtime for the cache backend.

Not yet fully proven:

- Native Windows binary.
- Native Linux release archive outside Docker.
- Claude Code plugin bundle on Windows or Linux.

The code is Rust-only, but the shipped plugin binary is currently a macOS
Apple Silicon artifact. Treat broader platform support as source-build capable
until native release archives are built and manually tested.

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
