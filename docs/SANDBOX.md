# Targets, cache, and sandbox

Augenmaß has three explicit target modes for registrar-shaped reads and writes:
`clone`, `cached-sandbox`, and `sandbox`. Static artifact commands do not need a
target and run offline.

- `clone` is the default mutable local store for safe write rehearsals.
- `cached-sandbox` is a read-only loopback mirror for public sandbox GET routes,
  with provenance headers and stale fallback.
- `sandbox` is the real registrar behind Keycloak, for off-stage rehearsal.

This guide covers what each mode is, how to drive the clone and cache end to end,
the safety rules that apply to writes, and one ecosystem caveat to confirm at
sandbox time.

## Which mode should I use?

| Mode | Network | Credentials | Mutates data | Persistence | Proof gate |
| --- | --- | --- | --- | --- | --- |
| Offline fixtures and artifacts | No | No | No | None | `just plugin-only-smoke`, `just fixture-command-proofs` |
| `clone` | Loopback only | No | Yes, local SQLite only | `augenmass-clone.sqlite` | `just clone-smoke` via `just verify` |
| Local `cached-sandbox` | Public sandbox GETs | No | No | `augenmass-cache.sqlite` | `just live-cache-smoke` |
| Deployed cache/proxy | Public sandbox GETs through your backend | Admin token for status and refresh | No | Hosted SQLite volume | `just deployed-cache-smoke-required` after deployment |
| `sandbox` | Real sandbox registrar | Keycloak credentials | Yes, live registrar when explicitly confirmed | Sandbox-owned | `just live-sandbox-smoke` with credentials |
| `serve` wallet debugger | Loopback plus optional public tunnel | No by default; wallet presents to local verifier | No registrar writes | Redacted in memory; optional local unsafe artifacts | `just serve-smoke` |

Use offline commands for first contact, `clone` for safe write rehearsal,
`cached-sandbox` for stable public reads, `sandbox` only for credentialed
off-stage rehearsal, and `serve` when the actual wallet exchange is the thing
under test.

## The clone target

The clone is a registrar-compatible local store: an axum HTTP server backed by SQLite, started with `augenmass clone serve`. It speaks the same registration endpoints as the real registrar, so the same `register` and `list` code paths exercise it. It does no signing, no auth, and no x5c. It stores payload-only JWTs: each stored certificate is `header.payload.fixture`, where the header is `{"typ":"rc-wrp+jwt","alg":"none"}`.

An unsigned, payload-only store is sound here because nothing in the workbench verifies a registration-certificate signature on either side. Every read path (`decode regcert`, `list`, the over-ask engine) decodes the payload only; there is no client-side crypto on the write path or the read path. The clone therefore reproduces the data shape the tool cares about (the WRPRC payload) without pretending to be a certificate authority. It is a faithful target for rehearsing the proportionality gate and the read-back loop, not a security model.

### Endpoints

The clone serves the registrar-compatible routes under its API base, both bare and under an `/api` prefix:

- `POST /registration-certificates` and `POST /api/registration-certificates`: write a registration.
- `GET /registration-certificates` and `GET /api/registration-certificates`: read registrations back.

### Running `clone serve`

```
augenmass clone serve
```

Flags (verified):

- `--db <DB>`: SQLite file path. Default `./augenmass-clone.sqlite`.
- `--port <PORT>`: listen port. Default `8080`.

So the default server listens on `http://127.0.0.1:8080` and persists to `./augenmass-clone.sqlite` in the current directory.

### AUGENMASS_CLONE_API_BASE

`register --target clone` and `list --target clone` resolve the clone URL from the `AUGENMASS_CLONE_API_BASE` environment variable, defaulting to `http://127.0.0.1:8080/api`. That default matches `clone serve` on its default port, so with no configuration at all the two halves line up.

If you serve on a non-default port, point both halves at it. For port 9090:

```
augenmass clone serve --port 9090
AUGENMASS_CLONE_API_BASE=http://127.0.0.1:9090/api augenmass list --target clone
```

The variable is documented in `.env.example` at the repo root; copy that to `.env` only if you want to override the defaults.

## The sandbox target

The `sandbox` target talks to the real registrar over HTTP. It is a rehearsal path: you use it to confirm a body the clone already accepted will be taken by the live registrar, off-stage, before any demo. It is not a production deployment path.

### Authentication: Keycloak resource-owner password grant

The sandbox registrar sits behind Keycloak. The tool obtains a bearer token with the OAuth 2.0 resource-owner password grant (`grant_type=password`). The `client_id` it sends is hardcoded to `swagger`. This matters: `swagger` is the client that works against the sandbox; substituting a project-specific client_id fails with `invalid_client`. You do not configure the client_id, you only supply the user credentials and the token endpoint.

### Environment variables

The sandbox path reads these (see `.env.example`):

- `AUGENMASS_API_BASE`: the registrar API base. Default `https://sandbox.eudi-wallet.org/api`.
- `AUGENMASS_OIDC_TOKEN_URL`: the Keycloak token endpoint. Required for `--target sandbox`.
- `AUGENMASS_USERNAME`: the resource-owner username. Required for `--target sandbox`.
- `AUGENMASS_PASSWORD`: the resource-owner password. Required for `--target sandbox`.
- `AUGENMASS_OIDC_CLIENT_SECRET`: optional; sent only when set.
- `AUGENMASS_UNSAFE_SANDBOX_URLS`: optional unsafe development escape hatch.
  Leave it unset or `0` for real sandbox work.

If `AUGENMASS_OIDC_TOKEN_URL`, `AUGENMASS_USERNAME`, or `AUGENMASS_PASSWORD` is missing, the command fails with a message naming the missing variable, so a misconfigured sandbox run never silently degrades into an anonymous one.

Sandbox API and token URLs must use `https` and must not contain URL userinfo,
query strings, or fragments. Loopback `http` is accepted only when
`AUGENMASS_UNSAFE_SANDBOX_URLS=1`, which is for isolated local development, not
for real credentials.

### Rehearsal-only posture

Because the sandbox is live and credential-bound, treat it as a dress rehearsal: prove the body locally against the clone first, then run sandbox once to confirm acceptance. Keep the credentials in `.env`, never on the command line or in shell history.

## The cached-sandbox target

The cached-sandbox target is a server-side read-through mirror for public sandbox
GET routes. It is deliberately separate from the clone. The clone is mutable and
offline; cached-sandbox is read-only and exists so a demo, audit, or small shared
backend can keep a stable view of the sandbox even when the upstream is slow,
drifting, or briefly unreachable.

Responses are capped at 5 MiB while streaming from the upstream. Oversized
responses are refused before being stored, and an existing stale response can
still be used when a refresh fails.
The cache is also bounded: after `AUGENMASS_CACHE_MAX_ENTRIES` / `--max-entries`
is reached, the oldest cached rows are evicted.

Run it with:

```
augenmass cache serve
```

Flags (verified):

- `--db <DB>`: SQLite file path. Default `./augenmass-cache.sqlite`.
- `--host <HOST>`: bind host. Default `127.0.0.1`. Use `0.0.0.0` only behind TLS or a private network.
- `--port <PORT>`: listen port. `AUGENMASS_CACHE_PORT` wins, then `PORT`, then `8081`.
- `--upstream <URL>`: sandbox API base. Default `https://sandbox.eudi-wallet.org/api`.
- `--ttl-secs <SECS>`: freshness window for cached responses. Default `3600`.
- `--timeout-secs <SECS>`: upstream request timeout. Default `10`.
- `--max-entries <N>`: maximum stored entries before oldest rows are evicted. Default `512`.
- `--admin-token <TOKEN>`: protect status and refresh endpoints.
- `--allowed-rp <RP>`: restrict registration-certificate read-through to named RP ids. Repeat it, or set comma-separated `AUGENMASS_CACHE_ALLOWED_RPS`. Defaults to the demo RP.
- `--allow-any-rp`: unsafe opt-in that allows any syntactically valid RP. Do
  not use it for shared or hosted demos.
- `--unsafe-upstream`: unsafe opt-in that permits non-https or private upstreams
  on public binds. Use only in isolated development.

The default server listens on `http://127.0.0.1:8081/api`. Point the CLI at it
with `AUGENMASS_CACHE_API_BASE`, or use the default:

```
AUGENMASS_CACHE_API_BASE=http://127.0.0.1:8081/api augenmass list --target cached-sandbox
```

### Cached routes

The cache mirrors successful upstream responses for these public GET routes:

- `GET /api/schema-metadata`
- `GET /api/schema-metadata/vocabularies`
- `GET /api/registration-certificates?rp=<id>`

It also exposes cache metadata:

- `GET /api/health`: public health check for deploy platforms.
- `GET /api/cache/status`: list cached entries, upstream URL, fetch time, size,
  SHA-256, and the configured max-entry cap.
- `POST /api/cache/refresh?route=schema-metadata`
- `POST /api/cache/refresh?route=schema-metadata/vocabularies`
- `POST /api/cache/refresh?route=registration-certificates&rp=<id>`

If `AUGENMASS_CACHE_ADMIN_TOKEN` or `--admin-token` is set, `cache/status` and
`cache/refresh` require either `Authorization: Bearer <token>` or
`x-augenmass-cache-admin: <token>`. The read-through registrar routes and
`/api/health` stay public because `list --target cached-sandbox` depends on
them. Loopback binds may run without a token for local-only work; non-loopback
binds such as `0.0.0.0` refuse to start without a token.

Set `--allowed-rp` for each RP you intentionally prewarm. Non-loopback binds
refuse an empty allowlist unless `--allow-any-rp` is explicitly set. Unlisted
`registration-certificates?rp=...` reads and authenticated refreshes return
`403` before the upstream is contacted, so public readers cannot churn the
bounded cache away from the demo RP.

On non-loopback binds, the upstream must use `https`, must not contain URL
userinfo, query strings, or fragments, and must not point directly at loopback,
private, link-local, documentation, multicast, or metadata IP ranges. The
`--unsafe-upstream` escape hatch is for isolated development only.

Every cached response carries provenance headers:

- `x-augenmass-cache`: `MISS`, `HIT`, `REFRESHED`, or `STALE`.
- `x-augenmass-cache-key`: the canonical cache key.
- `x-augenmass-cache-fetched-at`: the upstream fetch time.
- `x-augenmass-cache-sha256`: SHA-256 of the response body.

Full upstream URLs are intentionally not exposed on public cached responses.
They are visible only through `GET /api/cache/status`, which should be protected
with an admin token on shared or deployed instances.

The cache stores only successful upstream responses. If an entry is stale and
the upstream refresh fails, it returns the stale entry with
`x-augenmass-cache: STALE`; if there is no cached entry, it returns a gateway
error instead of fabricating data.

`cached-sandbox` is read-only. `list --target cached-sandbox` reads through the
cache. `register --target cached-sandbox` is useful as a dry-run, but a confirmed
write with `--yes` is refused before any network call. Use `--target sandbox` for
real writes and `--target clone` for offline demo writes.

### Snapshot public sandbox state

Use this before a presentation or website update to learn what the public
sandbox currently exposes, without credentials and without printing JWT/CWT
bodies:

```
just public-sandbox-snapshot
```

The snapshot fetches `schema-metadata`, `schema-metadata/vocabularies`, the
public `registration-certificates` list, and
`registration-certificates?rp=<id>` for the configured relying party. It prints
aggregate facts only: bytes, ETags, rate-limit remaining, registration count,
distinct relying-party count, oldest and newest `createdAt`, configured-RP
count, the five newest registrations, and the top relying parties by certificate
count.

Environment:

```
AUGENMASS_PUBLIC_SANDBOX_API_BASE=https://sandbox.eudi-wallet.org/api
AUGENMASS_PUBLIC_SANDBOX_RP=2af138a8-59ea-4a84-aea3-666cafdb1369
AUGENMASS_PUBLIC_SANDBOX_TIMEOUT_SECS=30
AUGENMASS_PUBLIC_SANDBOX_MAX_BYTES=5242880
AUGENMASS_PUBLIC_SANDBOX_REQUIRE_RP=1
AUGENMASS_PUBLIC_SANDBOX_SNAPSHOT_JSON=
```

By default the snapshot fails if the configured RP has zero public registration
certificates, because that is a presentation-readiness problem. Set
`AUGENMASS_PUBLIC_SANDBOX_REQUIRE_RP=0` to make a zero-count RP informational.

To save a redacted aggregate JSON summary for handoff or website work:

```
AUGENMASS_PUBLIC_SANDBOX_SNAPSHOT_JSON=dist/public-sandbox-snapshot.json \
  just public-sandbox-snapshot
```

The saved summary omits registration JWTs and CWTs. It is still live operational
context, so review it before publishing.

### Prewarm for a presentation

Use a long TTL, warm the three public routes off-stage, then reuse the SQLite DB
on stage:

```
BIN=${AUGENMASS_BIN:-./plugins/augenmass-workbench/bin/augenmass}
RP=2af138a8-59ea-4a84-aea3-666cafdb1369
CACHE=./presenter-cache.sqlite

$BIN cache serve --db "$CACHE" --port 8081 --ttl-secs 315360000 --allowed-rp "$RP"
```

In another shell:

```
BASE=http://127.0.0.1:8081/api
$BIN cache warm --api-base "$BASE" --rp "$RP"
$BIN cache status --api-base "$BASE"
AUGENMASS_CACHE_API_BASE="$BASE" "$BIN" list --target cached-sandbox --rp "$RP"
```

For a shared backend, set an admin token and send it on refresh calls:

```
AUGENMASS_CACHE_ADMIN_TOKEN=<token> \
AUGENMASS_CACHE_ALLOWED_RPS="$RP" \
augenmass cache serve --host 0.0.0.0 --port ${PORT:-8081} --db /data/augenmass-cache.sqlite

augenmass cache warm --api-base https://cache.example/api --admin-token <token> --rp "$RP"
augenmass cache status --api-base https://cache.example/api --admin-token <token>
AUGENMASS_CACHE_API_BASE=https://cache.example/api \
  augenmass list --target cached-sandbox --rp "$RP"
```

## Safety rules (targets)

These guardrails apply to every `register` invocation:

- Dry-run by default. `register` without `--yes` decodes, runs the over-ask and format gate, and prints the verdict, but writes nothing. The output ends with `DRY RUN: nothing written. Re-run with --yes to write to <target>.`
- `--yes` is required to write. It confirms the write after the gate passes.
- `--force` writes past an over-ask warning, and requires `--yes`. Without `--force`, an over-asking body is refused (exit 1) on every target. A blocking format error is fatal regardless of `--force`.
- Demo fixtures and defaults use relying party id `2af138a8-59ea-4a84-aea3-666cafdb1369` ("Hackathon - Reza"). That id is the default for `--rp` on `list` and for `--rp` on `generate regbody`, and it is the `rpId` in `examples/min.json` and `examples/over.json`. Do not reuse it for a user's production relying party.
- One relying party per entity, many certificates under it. Never mint additional relying parties; add certificates to the existing one.
- Secrets hygiene. Never log, echo, or commit tokens, certs, or keys. The repo gitignores `.env*`, `secrets*.md`, `*.sqlite`, and `*signing-key*`. Review staged changes before any git operation.

## Worked clone walkthrough

This sequence is verified against the real binary. Open two shells, both at the repo root.

Shell 1: start the clone and leave it running.

```
augenmass clone serve
```

It prints its listen address, for example `clone target listening on http://127.0.0.1:8080/api`.

Shell 2: dry-run first (default), then write the proportionate body.

```
augenmass register examples/min.json --target clone
```

```
OK: no over-ask, no format errors. examples/min.json is ready to register.
DRY RUN: nothing written. Re-run with --yes to write to clone.
```

Now write it:

```
augenmass register examples/min.json --target clone --yes
```

```
OK: no over-ask, no format errors. examples/min.json is ready to register.
Writing to clone under RP 2af138a8-59ea-4a84-aea3-666cafdb1369...
Wrote registration 6272cc79-fec7-4e10-804d-3a52e6a6d8c5 to clone.
```

Read it back:

```
augenmass list --target clone
```

```
1 registration(s) for RP 2af138a8-59ea-4a84-aea3-666cafdb1369 on clone:

- 6272cc79-fec7-4e10-804d-3a52e6a6d8c5  purpose: "Age verification"
    claims: age_equal_or_over.18
```

(The registration id is generated per write, so yours will differ.)

### The over-ask refusal

`examples/over.json` declares the same age-verification purpose but requests six attributes (`given_name`, `family_name`, `birthdate`, `address.resident_street`, `address.resident_city`, `nationalities`). Even with `--yes`, the write is refused:

```
augenmass register examples/over.json --target clone --yes
```

```
OVER-ASK: Over-ask vs purpose: 6 of 6 requested claims exceed the stated purpose.
Purpose: Age verification   Baseline: Age gate (over 18)

Requested claims:
  [over]  given_name                   Registered, but beyond what the stated purpose needs.
  [over]  family_name                  Registered, but beyond what the stated purpose needs.
  [over]  birthdate                    Registered, but beyond what the stated purpose needs.
  [over]  address.resident_street      Registered, but beyond what the stated purpose needs.
  [over]  address.resident_city        Registered, but beyond what the stated purpose needs.
  [over]  nationalities                Registered, but beyond what the stated purpose needs.

Over-asking 6 claim(s) beyond the stated purpose.

Suggested minimal request:
  age_equal_or_over.18

Legal basis:
  eIDAS Regulation (EU) 2024/1183, Art. 5b(3)
    Relying parties shall not request users to provide data other than that indicated for their intended use.
  GDPR (EU) 2016/679, Art. 5(1)(c)
    Personal data shall be adequate, relevant and limited to what is necessary (data minimisation).
  EUDI ARF, registration certificate, RPRC_07
    The wallet verifies requested attributes are within the registration certificate and notifies the user otherwise.

Refusing to write: this request over-asks (see above). Re-run with --yes --force to write it anyway.
```

The command exits 1, so CI catches it. To deliberately write the over-asking body anyway you must add `--force`:

```
augenmass register examples/over.json --target clone --yes --force
```

That reprints the same verdict, then writes with an explicit warning (`Warning: writing an over-asking registration because --force was given.`) and exits 0. Use `--force` only when over-asking is intentional and justified; the default refusal is the point of the gate.

The same gate runs before a confirmed write to any target, so a body that the clone refuses will be refused against the sandbox too. Prove proportionality locally, then rehearse against the sandbox.

For a read-only sandbox rehearsal that skips cleanly when credentials are not
configured, run:

```sh
just live-sandbox-smoke
```

It generates a proportionate body for the exact `AUGENMASS_SMOKE_RP` under test
(defaulting to the demo RP), checks the local guardrail, dry-runs
`register --target sandbox`, and reads the same relying party with
`list --target sandbox`. It does not perform a confirmed write unless
`AUGENMASS_LIVE_SANDBOX_WRITE=1` is explicitly set.

To make missing credentials fail instead of skip, run:

```sh
just live-sandbox-smoke-required
```

`just sandbox-readiness-proof` is the same required gate with a presentation
checklist name. Only required mode proves that the live sandbox path is
configured on this machine.

## Caveat to verify at sandbox time: VCT URN vs @IsUrl

`examples/min.json` and `examples/over.json` set the credential vct to the German PID URN `urn:eudi:pid:de:1`, which is correct: a vct can be a URN, not only a URL. Some registrar DTO validators have been seen to annotate that field as a URL (an `@IsUrl`-style constraint), which would reject a valid URN. The local clone does not enforce this, so a body that passes the clone can still be refused by the live registrar on a vct-format technicality.

When you first rehearse against `--target sandbox`, confirm the registrar accepts the URN vct. If it rejects `urn:eudi:pid:de:1` as not a URL, that is a registrar-side validation bug, not a problem with the body; the URN is the spec-correct value. Note it as an ecosystem trap rather than relaxing the body, and raise it with the registrar.
