# Deploying hosted Augenmass backends

This guide covers the deployable parts of Augenmaß Workbench:

- `augenmass cache serve`: a persistent cached-sandbox backend for stable public
  sandbox reads.
- `augenmass-relay`: a stateless wallet-only relay so a phone wallet can reach
  a local `augenmass serve` run over HTTPS.

The rest of the workbench is a local CLI and skill. Static artifact commands run
offline.

## Cached sandbox backend

## What the backend does

`cache serve` is a read-through mirror for the public sandbox GET routes:

- `GET /api/schema-metadata`
- `GET /api/schema-metadata/vocabularies`
- `GET /api/registration-certificates?rp=<id>`

It stores successful upstream responses in SQLite, returns fresh local hits, and
falls back to stale data if a refresh fails. It does not cache writes. It exposes
`/api/health` for deploy health checks. If `cache serve` binds to loopback, the
admin token is optional for local-only work. If it binds to a non-loopback
address such as `0.0.0.0`, `AUGENMASS_CACHE_ADMIN_TOKEN` or `--admin-token` is
required before the server starts. When set, `/api/cache/status` and
`/api/cache/refresh` require
`Authorization: Bearer <token>` or `x-augenmass-cache-admin: <token>`.
The cache is bounded by `AUGENMASS_CACHE_MAX_ENTRIES` / `--max-entries`
(default `512`); after that, the oldest rows are evicted.
Concurrent misses for the same cache key are coalesced, so public readers do not
stampede the sandbox upstream. If a stale entry exists while another request is
refreshing the same key, the stale entry is served.

The cache stores public sandbox responses only. It still deserves a persistent
database and an admin token because refresh and status expose operational
control.

Registration-certificate read-through is RP-allowlisted. The CLI defaults to the
demo RP (`2af138a8-59ea-4a84-aea3-666cafdb1369`); add more with
`AUGENMASS_CACHE_ALLOWED_RPS` or repeated `--allowed-rp <id>`. Unlisted RP reads
and refreshes return `403` before the upstream is contacted, which protects
prewarmed demo entries from public cache churn.
On non-loopback binds, an empty RP allowlist is refused unless `--allow-any-rp`
or `AUGENMASS_CACHE_ALLOW_ANY_RP=1` is explicitly set.

Upstream response bodies are capped at 5 MiB while they are being read. If an
upstream crosses that cap, the refresh is refused before the full body is
downloaded; existing stale cache entries can still be served.
On non-loopback binds, the upstream must use `https`, must not contain URL
userinfo, query strings, or fragments, and must not point directly at loopback,
private, link-local, documentation, multicast, or metadata IP ranges unless
`--unsafe-upstream` / `AUGENMASS_CACHE_UNSAFE_UPSTREAM=1` is explicitly set.

## Runtime configuration

The server can be configured with flags or environment variables.

| Setting | Env | Default |
|---|---|---|
| Database path | `AUGENMASS_CACHE_DB` | `./augenmass-cache.sqlite` |
| Bind host | `AUGENMASS_CACHE_HOST` | `127.0.0.1` |
| Port | `AUGENMASS_CACHE_PORT`, then `PORT` | `8081` |
| Upstream API base | `AUGENMASS_CACHE_UPSTREAM` | `https://sandbox.eudi-wallet.org/api` |
| Freshness window | `AUGENMASS_CACHE_TTL_SECS` | `3600` |
| Upstream timeout | `AUGENMASS_CACHE_TIMEOUT_SECS` | `10` |
| Max cached entries | `AUGENMASS_CACHE_MAX_ENTRIES` | `512` |
| Admin token | `AUGENMASS_CACHE_ADMIN_TOKEN` | unset for loopback; required for non-loopback binds |
| Allowed registration RPs | `AUGENMASS_CACHE_ALLOWED_RPS` | `2af138a8-59ea-4a84-aea3-666cafdb1369` |
| Allow any registration RP | `AUGENMASS_CACHE_ALLOW_ANY_RP` | `false` |
| Allow unsafe upstream on public bind | `AUGENMASS_CACHE_UNSAFE_UPSTREAM` | `false` |

Local run:

```sh
augenmass cache serve
```

Public or platform run:

```sh
AUGENMASS_CACHE_ADMIN_TOKEN=<token> \
AUGENMASS_CACHE_ALLOWED_RPS=2af138a8-59ea-4a84-aea3-666cafdb1369 \
augenmass cache serve --host 0.0.0.0 --port ${PORT:-8081} --db /data/augenmass-cache.sqlite
```

Use the deployed cache from the CLI:

```sh
AUGENMASS_CACHE_API_BASE=https://cache.example/api \
  augenmass list --target cached-sandbox --rp 2af138a8-59ea-4a84-aea3-666cafdb1369
```

## Prewarm a cache

Prewarming gives a presentation a stable view even if the upstream sandbox is
slow or briefly unavailable.

First check the live public sandbox aggregate so you know what you are caching:

```sh
just public-sandbox-snapshot
```

```sh
RP=2af138a8-59ea-4a84-aea3-666cafdb1369
TOKEN=<token>
BASE=https://cache.example/api

augenmass cache warm --api-base "$BASE" --admin-token "$TOKEN" --rp "$RP"
augenmass cache status --api-base "$BASE" --admin-token "$TOKEN"
AUGENMASS_CACHE_API_BASE="$BASE" \
  augenmass list --target cached-sandbox --rp "$RP"
```

Each cached response carries provenance headers:

- `x-augenmass-cache`: `MISS`, `HIT`, `REFRESHED`, or `STALE`
- `x-augenmass-cache-key`
- `x-augenmass-cache-fetched-at`
- `x-augenmass-cache-sha256`

Full upstream URLs are intentionally not exposed on public cached responses.
They are visible through protected `/api/cache/status` for operators.

## Railway

Railway is the best hosted fit for the current backend. The repository includes
a `Dockerfile` and `railway.json`, so Railway can build the Rust binary into a
container, inject `PORT`, and health-check `/api/health`.

Recommended Railway variables:

```sh
AUGENMASS_CACHE_ADMIN_TOKEN=<secret>
AUGENMASS_CACHE_DB=/data/augenmass-cache.sqlite
AUGENMASS_CACHE_HOST=0.0.0.0
AUGENMASS_CACHE_MAX_ENTRIES=512
AUGENMASS_CACHE_TTL_SECS=3600
AUGENMASS_CACHE_TIMEOUT_SECS=10
AUGENMASS_CACHE_UPSTREAM=https://sandbox.eudi-wallet.org/api
AUGENMASS_CACHE_ALLOWED_RPS=2af138a8-59ea-4a84-aea3-666cafdb1369
```

Pre-deploy checklist:

- Attach a persistent volume mounted at `/data`.
- Set `AUGENMASS_CACHE_ADMIN_TOKEN` to a long random value.
- Set `AUGENMASS_CACHE_ALLOWED_RPS` to the relying party ids you will demo.
- Leave `AUGENMASS_CACHE_PORT` unset so Railway's injected `PORT` wins.
- Keep the upstream on the default `https://sandbox.eudi-wallet.org/api`.
- Run `just cache-public-bind-guard-smoke` locally before deploying.

Do not set `AUGENMASS_CACHE_PORT` on Railway; let Railway inject `PORT` and let
the CLI use that value. `.env.example` is for local development and includes a
fixed cache port, so do not copy it wholesale into Railway variables.
Do not add a Dockerfile `VOLUME` instruction for `/data`; Railway rejects Docker
`VOLUME` directives and expects the platform volume to be attached separately.

`AUGENMASS_CACHE_ADMIN_TOKEN` is mandatory for this Railway shape. Without it,
the server refuses the non-loopback bind and the health check fails. That is
intentional: do not make public refresh/status unauthenticated.

Attach a persistent volume at `/data`. Without a volume, the service still runs,
but the cache is rebuilt after each redeploy.

The Docker image entrypoint prepares the configured database directory, fixes its
ownership for uid `10001`, then starts the server as uid `10001`. Do not remove
the admin token to work around a volume problem; a public bind without
`AUGENMASS_CACHE_ADMIN_TOKEN` is intentionally refused at startup. The local
`docker-smoke` gate verifies the server process uid and `/data` writability.

Railway references:

- https://docs.railway.com/guides/axum
- https://docs.railway.com/builds/dockerfiles
- https://docs.railway.com/deployments/healthchecks

### Current Railway proof

The presentation cache backend is deployed on Railway:

- Project: `augenmass-workbench-cache`
- Service: `cache`
- Domain: `https://cache.augenmass.tech`
- Railway fallback domain: `https://cache-production-c33f.up.railway.app`
- API base: `https://cache.augenmass.tech/api`
- Volume: mounted at `/data`

The service uses the demo RP allowlist
`2af138a8-59ea-4a84-aea3-666cafdb1369`, persistent SQLite at
`/data/augenmass-cache.sqlite`, and a long presentation TTL. The admin token is
set in Railway and is not committed to this repository.

On 2026-06-24, the hosted proof passed:

```sh
AUGENMASS_DEPLOYED_CACHE_API_BASE=https://cache.augenmass.tech/api \
AUGENMASS_DEPLOYED_CACHE_ADMIN_TOKEN=<token> \
  just deployed-cache-smoke-required
```

That proof checked health, public cached reads, the CLI `cached-sandbox` path,
admin status protection, authenticated status access, RP allowlist blocking, and
authenticated cache warming. A second run returned `schema fetch: HIT`.
`cache status` showed three warmed entries: schema metadata, schema
vocabularies, and the configured demo RP registration list. The custom domain
had propagated DNS and a valid Railway certificate before the hosted proof was
run against it.

## Hosted wallet relay

The hosted relay is separate from the cache backend. It does not need SQLite or
a Railway volume. It forwards only the wallet-facing endpoints for a temporary
run:

- `GET /r/<run-id>/request/<session>`
- `POST /r/<run-id>/response/<session>`

Trace, inspect, `/api/trace`, `/api/sessions`, and unsafe debug artifacts are
not public relay routes. The operator keeps using the local `open` URL printed
by `augenmass serve`; the phone wallet uses the temporary `public` URL printed
for that run.

The repository includes relay-specific deploy files:

- `Dockerfile.relay`
- `railway.relay.json`

Recommended Railway variables:

```sh
AUGENMASS_RELAY_AUTH_TOKEN=<secret>
AUGENMASS_RELAY_PUBLIC_BASE=https://wallet.augenmass.tech
AUGENMASS_RELAY_HOST=0.0.0.0
RUST_LOG=warn,augenmass_relay=info
```

Do not set `AUGENMASS_RELAY_PORT` on Railway; let Railway inject `PORT`. The
relay refuses non-loopback binds unless `AUGENMASS_RELAY_AUTH_TOKEN` and
`AUGENMASS_RELAY_PUBLIC_BASE` are set.

Local proof before deploying:

```sh
just relay-smoke
./scripts/relay-source-guard.sh
```

Hosted proof after deploying and attaching the custom domain:

```sh
AUGENMASS_DEPLOYED_RELAY_BASE=https://wallet.augenmass.tech \
AUGENMASS_DEPLOYED_RELAY_TOKEN=<secret> \
  just hosted-relay-proof
```

On 2026-06-25, the Railway relay at `https://wallet.augenmass.tech` had
propagated DNS, a valid certificate, and passed `just hosted-relay-proof`
against the public domain. That proof checks health, byte-for-byte request
object forwarding, public trace/inspect refusal, plaintext `direct_post`
rejection, and local trace redaction.

Do not claim phone-wallet ingress is ready until the hosted proof passes against
the actual public domain.

### Deploying with `railway up`

Both Railway services are tarball deploys: `source.repo` is `null` on each, so
there is no GitHub autodeploy. Every release is an explicit `railway up` from a
local checkout of the tagged commit.

`railway up` builds whatever `railway.json` resolves at the repository root and
has no `--config` or `--dockerfile` flag. The root `railway.json` is the cache
manifest (`Dockerfile`, health check `/api/health`), so a plain
`railway up --service <relay-service>` builds the cache image for the relay
service and then fails the relay's `/healthz` health check.

To deploy the relay, put the relay manifest at the root first, ideally in a
throwaway worktree so the tracked `railway.json` is never dirtied:

```sh
git worktree add ../augenmass-relay-deploy <tag-or-commit>
cd ../augenmass-relay-deploy
cp railway.relay.json railway.json
railway up --service <relay-service>
cd -
git worktree remove ../augenmass-relay-deploy
```

The cache service deploys normally with the committed root manifest:

```sh
railway up --service cache
```

Health endpoints to verify after each deploy:

- cache: `https://cache.augenmass.tech/api/health`
- relay: `https://wallet.augenmass.tech/healthz`

As of 2026-07-08 both services were redeployed to v0.3.0 content (commit
`88c03d0`) and reported healthy.

## Docker or VPS

The cache Docker image builds the release binary with the lockfile, installs
only runtime CA certificates, writes cache data under `/data`, and runs as a
non-root user.

```sh
docker build -t augenmass-cache .

docker run --rm \
  -p 8081:8081 \
  -v "$PWD/data:/data" \
  -e AUGENMASS_CACHE_ADMIN_TOKEN=<secret> \
  -e AUGENMASS_CACHE_ALLOWED_RPS=2af138a8-59ea-4a84-aea3-666cafdb1369 \
  augenmass-cache
```

For a VPS, put the container behind TLS, keep `/data` on persistent storage, and
set an admin token before exposing the service. Public reads are intentional;
admin refresh and status are not.

Local container proof:

```sh
just docker-smoke
```

That builds the Docker image, runs the cache backend, checks `/api/health`, checks
that the process runs as the non-root uid `10001`, verifies that cache status
requires the admin token, then fetches `schema-metadata` through the container
and proves the first response is a `MISS` and the second is a `HIT`. The smoke
also starts the container with the demo RP allowlisted and proves an unlisted RP
read returns `403`. It then restarts the container against the same Docker
volume and proves the cached schema is still a `HIT`, so `/data` persistence is
exercised locally.

Live cache proof:

```sh
just live-cache-smoke
```

That starts a local cache server with an admin token, fetches public sandbox
data, proves `MISS` and `HIT`, reads registrations through
`list --target cached-sandbox`, runs `cache warm` through the protected refresh
API, validates warmed JSON shape, proves an unlisted RP is blocked with `403`,
then proves stale fallback with an intentionally broken upstream. It uses no
sandbox credentials.

Deployed cache proof, once Railway or a VPS URL exists:

```sh
AUGENMASS_DEPLOYED_CACHE_API_BASE=https://cache.example/api \
AUGENMASS_DEPLOYED_CACHE_ADMIN_TOKEN=<token> \
  just deployed-cache-smoke-required
```

`just hosted-release-proof` is the same required gate with a release-oriented
name.

Without `AUGENMASS_DEPLOYED_CACHE_API_BASE`, the deployed smoke exits cleanly so
local release gates do not depend on a hosted service. With only the API base,
`just deployed-cache-smoke` checks health, public cached reads, and the CLI
`cached-sandbox` path. With the admin token, it also proves `/cache/status` is
protected, verifies authenticated status access through `cache status`, checks any configured allowlist
includes the RP under test, runs `cache warm`, and confirms warmed entries are
visible. Use `just deployed-cache-smoke-required` for current
hosted-deployment readiness; required mode fails unless
`AUGENMASS_DEPLOYED_CACHE_API_BASE` is an `https://` non-local hosted URL and
`AUGENMASS_DEPLOYED_CACHE_ADMIN_TOKEN` is set. To prove persistence across a
hosted restart or redeploy, warm the cache, restart/redeploy the service on the
platform, then rerun
`just deployed-cache-smoke-required` and confirm the warmed entries remain
visible or return as cache hits.

## Fly.io and Render

Fly.io and Render are plausible container hosts for the current backend because
they can run the Docker image as a long-lived service with persistent storage.
Use the same model as Railway: one instance, a persistent disk mounted at `/data`,
TLS at the platform edge, and `AUGENMASS_CACHE_ADMIN_TOKEN` set before public
traffic is routed. SQLite is a single-node cache here; do not run multiple
writers against the same database file.

After deploying either host, prove it from your laptop with:

```sh
AUGENMASS_DEPLOYED_CACHE_API_BASE=https://cache.example/api \
AUGENMASS_DEPLOYED_CACHE_ADMIN_TOKEN=<token> \
  just deployed-cache-smoke-required
```

## Cloudflare

Cloudflare Containers is designed to run the current Docker image behind a
Worker wrapper, but the repository proof today is adapter typecheck only, not a
deployed Cloudflare smoke. The optional adapter in
`deploy/cloudflare-containers/` routes all requests to one named container
instance, passes cache settings and the admin token as container environment
variables, and typechecks locally with:

```sh
just cloudflare-containers-typecheck
```

Deploying it still requires a Workers Paid plan, Docker, Wrangler auth, and a
Worker secret:

```sh
cd deploy/cloudflare-containers
bun install --frozen-lockfile
bunx wrangler secret put AUGENMASS_CACHE_ADMIN_TOKEN
bun run deploy
```

Important caveat: Cloudflare Container disk is ephemeral. The adapter is useful
for a globally reachable cache process, but it is not the strongest persistence
story for a presentation cache unless you also add a Cloudflare-native storage
layer or accept rebuilds after container sleep/restart. Railway, Fly.io, Render,
or a VPS with a persistent `/data` volume remain the simple durable deployment
targets for this release.

Cloudflare references:

- https://developers.cloudflare.com/containers/
- https://developers.cloudflare.com/containers/get-started/

## Vercel

Vercel has an official Rust runtime in beta, but it expects a Vercel Function
entry point using the `vercel_runtime` crate. The current backend is a long-lived
Axum server with a local SQLite file, so Vercel is not the right first deploy
target. A Vercel adapter would need a function-shaped entry point and an external
or platform storage choice.

Vercel references:

- https://vercel.com/docs/functions/runtimes/rust
- https://vercel.com/docs/functions/runtimes

## Shipping verdict

Use Railway or a small VPS for the current backend when persistence matters.
Cloudflare Containers now have a local adapter, but treat it as an optional
edge/container path with ephemeral disk until a Cloudflare-native storage layer
is added. Use Vercel only after a function adapter exists. The Workbench CLI
already knows how to consume any of them through
`AUGENMASS_CACHE_API_BASE`.
