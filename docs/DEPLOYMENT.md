# Deploying the cached sandbox backend

This guide covers the deployable part of Augenmaß Workbench: `augenmass cache
serve`. The rest of the workbench is a local CLI and skill. Static artifact
commands run offline; `cache serve` is the small backend that can keep sandbox
reads stable for demos, audit sessions, and shared team use.

## What the backend does

`cache serve` is a read-through mirror for the public sandbox GET routes:

- `GET /api/schema-metadata`
- `GET /api/schema-metadata/vocabularies`
- `GET /api/registration-certificates?rp=<id>`

It stores successful upstream responses in SQLite, returns fresh local hits, and
falls back to stale data if a refresh fails. It does not cache writes. It exposes
`/api/health` for deploy health checks. If `AUGENMASS_CACHE_ADMIN_TOKEN` is set,
`/api/cache/status` and `/api/cache/refresh` require
`Authorization: Bearer <token>` or `x-augenmass-cache-admin: <token>`.

The cache stores public sandbox responses only. It still deserves a persistent
database and an admin token because refresh and status expose operational
control.

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
| Admin token | `AUGENMASS_CACHE_ADMIN_TOKEN` | unset |

Local run:

```sh
augenmass cache serve
```

Public or platform run:

```sh
AUGENMASS_CACHE_ADMIN_TOKEN=<token> \
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

```sh
RP=2af138a8-59ea-4a84-aea3-666cafdb1369
TOKEN=<token>
BASE=https://cache.example/api

curl -fsS -H "Authorization: Bearer $TOKEN" \
  -X POST "$BASE/cache/refresh?route=schema-metadata"

curl -fsS -H "Authorization: Bearer $TOKEN" \
  -X POST "$BASE/cache/refresh?route=schema-metadata/vocabularies"

curl -fsS -H "Authorization: Bearer $TOKEN" \
  -X POST "$BASE/cache/refresh?route=registration-certificates&rp=$RP"

curl -fsS -H "Authorization: Bearer $TOKEN" "$BASE/cache/status"
```

Each cached response carries provenance headers:

- `x-augenmass-cache`: `MISS`, `HIT`, `REFRESHED`, or `STALE`
- `x-augenmass-cache-key`
- `x-augenmass-cache-fetched-at`
- `x-augenmass-cache-sha256`
- `x-augenmass-cache-upstream`

## Railway

Railway is the best hosted fit for the current backend. The repository includes
a `Dockerfile` and `railway.json`, so Railway can build the Rust binary into a
container, inject `PORT`, and health-check `/api/health`.

Recommended Railway variables:

```sh
AUGENMASS_CACHE_ADMIN_TOKEN=<secret>
AUGENMASS_CACHE_DB=/data/augenmass-cache.sqlite
AUGENMASS_CACHE_HOST=0.0.0.0
AUGENMASS_CACHE_TTL_SECS=3600
AUGENMASS_CACHE_TIMEOUT_SECS=10
AUGENMASS_CACHE_UPSTREAM=https://sandbox.eudi-wallet.org/api
```

Attach a persistent volume at `/data`. Without a volume, the service still runs,
but the cache is rebuilt after each redeploy.

Railway references:

- https://docs.railway.com/guides/axum
- https://docs.railway.com/builds/dockerfiles
- https://docs.railway.com/deployments/healthchecks

## Docker or VPS

The Docker image builds the release binary with the lockfile, installs only
runtime CA certificates, writes cache data under `/data`, and runs as a non-root
user.

```sh
docker build -t augenmass-cache .

docker run --rm \
  -p 8081:8081 \
  -v "$PWD/data:/data" \
  -e AUGENMASS_CACHE_ADMIN_TOKEN=<secret> \
  augenmass-cache
```

For a VPS, put the container behind TLS, keep `/data` on persistent storage, and
set an admin token before exposing the service. Public reads are intentional;
admin refresh and status are not.

## Cloudflare

Cloudflare Workers support Rust through `workers-rs`, and Cloudflare D1 provides
SQLite-like serverless storage. That is a good future fit for an edge-native
cache, but it is not a drop-in deployment for the current Axum plus rusqlite
binary. A Cloudflare version should be a separate Worker adapter using D1,
Durable Objects, or KV and the same cache semantics.

Cloudflare references:

- https://developers.cloudflare.com/workers/languages/rust/
- https://developers.cloudflare.com/d1/
- https://developers.cloudflare.com/durable-objects/

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

Use Railway or a small VPS for the current backend. Use Cloudflare only after a
Worker adapter exists. Use Vercel only after a function adapter exists. The
Workbench CLI already knows how to consume any of them through
`AUGENMASS_CACHE_API_BASE`.
