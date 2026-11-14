# Targets, cache, and sandbox

Augenmaß has three explicit target modes for registrar-shaped reads and writes:
`clone`, `cached-sandbox`, and `sandbox`. Static artifact commands do not need a
target and run offline.

- `clone` is the default mutable local store for safe write rehearsals.
- `cached-sandbox` is a read-only loopback mirror for public sandbox GET routes,
  with provenance headers and stale fallback.
- `sandbox` is the real registrar behind Keycloak, for off-stage rehearsal.

The landing page of the German sandbox registrar (`sandbox.eudi-wallet.org`,
read on 13 November 2026) says that testing in it is possible until 19 November
2026, that the new wallet app version then no longer accepts certificates from
it, and that it admits no new users; after that date, the `sandbox` target, the
`cached-sandbox` reads, and the live sandbox smokes on this page may stop
working against it. The section
[After 19 November 2026](#after-19-november-2026) says what keeps working in
the Workbench, what does not, and what was not tested.

The tool repeats this notice in one line on stderr whenever it falls back to
the built-in registrar address `https://sandbox.eudi-wallet.org/api` without
explicit configuration: `list --target sandbox` and a confirmed
`register --target sandbox --yes` print it when neither `AUGENMASS_API_BASE`
nor `API_BASE` is set, and `cache serve` prints it when neither `--upstream`
nor `AUGENMASS_CACHE_UPSTREAM` is set. A variable set to the built-in address
counts as configuration and prints nothing. `augenmass serve` prints a
`registration` startup line that names the source of its bundled registration
certificate (`fixtures/regcert/rc-by-id.json`, issued by the German sandbox
registrar) followed by the same notice. Standard output does not change, also
with `--json`, and the notice adds no network request. For example, without any
configuration:

```
augenmass list --target sandbox --rp x
```

```
note: --target sandbox uses the built-in registrar https://sandbox.eudi-wallet.org/api because AUGENMASS_API_BASE is not set. The landing page of the German sandbox registrar (sandbox.eudi-wallet.org, read on 13 November 2026) says that testing in it is possible until 19 November 2026, that the new wallet app version then no longer accepts certificates from it, and that it admits no new users.
Error: AUGENMASS_OIDC_TOKEN_URL is required for --target sandbox
```

This guide covers what each mode is, how to drive the clone and cache end to end,
the safety rules that apply to writes, and one ecosystem caveat to confirm at
sandbox time.

## Which mode should I use?

| Mode | Network | Credentials | Mutates data | Persistence | Proof gate |
| --- | --- | --- | --- | --- | --- |
| Offline fixtures and artifacts | No | No | No | None | `just plugin-only-smoke`, `just demo-proof`, `just verify` |
| `clone` | Loopback only | No | Yes, local SQLite only | `augenmass-clone.sqlite` | Covered by `just verify` and `cargo test --test cli` |
| Local `cached-sandbox` | Public sandbox GETs | No | No | `augenmass-cache.sqlite` | `just live-cache-smoke` |
| Deployed cache/proxy | Public sandbox GETs through your backend | Admin token for status and refresh | No | Hosted SQLite volume | `just deployed-cache-smoke-required` after deployment |
| `sandbox` | Real sandbox registrar | Keycloak credentials | Yes, live registrar when explicitly confirmed | Sandbox-owned | `just live-sandbox-smoke` with credentials |
| `serve` wallet debugger | Loopback plus optional public tunnel | No by default; wallet presents to local verifier | No registrar writes | Redacted in memory; optional local unsafe artifacts | `just serve-smoke` for runtime, `evidence assert-live` for a captured phone run |

Use offline commands for first contact, `clone` for safe write rehearsal,
`cached-sandbox` for stable public reads, `sandbox` only for credentialed
off-stage rehearsal, and `serve` when the actual wallet exchange is the thing
under test. The `serve-smoke` gate proves the verifier runtime without a phone
wallet. A specific phone-wallet environment is proven only after following
`docs/PHONE_WALLET_PROOF.md` and passing `evidence assert-live` on the captured
bundle.

## After 19 November 2026

The notice at the top of this page gives what the landing page of the German
sandbox registrar says about 19 November 2026. This section says what keeps
working in the Workbench after that date, what does not or may not, and what
was not tested.

### What the EUDI Hub says

The EUDI Hub has a page on sandbox migration at
`https://eudi-hub.gov.de/en/start/sandbox-migration` (undated, read on 13
November 2026). It says: "The new EUDI Hub Sandbox is now open in beta." The
date 19 November 2026 in this section is taken from the landing page of the
German sandbox registrar (see the notice at the top of this page).

The EUDI Hub's page says three things that matter for the rest of this section:

1. The old certificates work "only as long as you don't update the Wallet Sandbox app. After an update, the old certificates will no longer work."
2. A transfer does not happen automatically: "automatic transfer isn't possible. Please reconfigure your credential requests and credential issuances in the EUDI Hub Sandbox. Then create your certificates based on the new configuration."
3. The EUDI Hub is used through its web interface: "For now, you can only use the EUDI Hub through the web interface. We plan to provide an API in early 2027."

If your verifier sends a registration certificate issued by the German sandbox
registrar (`sandbox.eudi-wallet.org`), the notice at the top of this page is
about that certificate: the registrar's landing page says that testing in it
is possible until 19 November 2026 and that the new wallet app version then no
longer accepts certificates from it.

The EUDI Hub's page has the full text and may have changed since the read
date.

### What keeps working

- The static artifact commands need no target and no registrar (the row
  "Offline fixtures and artifacts" in the table above). They are not affected.
- The `clone` target is a local store on loopback and keeps working. It speaks
  the registration endpoints of the German sandbox registrar, so it rehearses
  writes in that shape only.
- A request can be checked against a registration certificate offline with
  `audit --request <request> --cert <certificate>`. The certificate is given as
  a compact JWT, as a JSON entry with `id` and `jwt`, or as a list with exactly
  one such entry. A decoded payload (a plain JSON object) is not accepted: the
  command stops with `Error: decode registration certificate` and exit 1, and
  prints no verdict line. The cause printed under that error varies with the
  input, for example `invalid base64url payload` or `not a compact JWT`. The
  certificate is decoded, not verified.

The fixture `fixtures/hub-shape/registration-hub-shape.jwt` is a synthetic
registration certificate (see "What was not tested" below). Decode it:

```
augenmass decode regcert fixtures/hub-shape/registration-hub-shape.jwt
```

```
WRPRC registration certificate (payload-only, no signature verified)
Registration certificate: payload decoded; signature, issuer and revocation status not verified.
  purpose: "Example Bottle Shop: confirm the buyer is over 18"
  privacy_policy: https://bottles.example.org/privacy
  support_uri: support@bottles.example.org
  credentials: 1
    format dc+sd-jwt  vct urn:eudi:pid:de:1
      claim age_equal_or_over.18
      claim address.postal_code
```

Audit a request against it, exit 0:

```
augenmass audit --request examples/age-minimal-request-sdjwt.json --purpose age_gate_18 --cert fixtures/hub-shape/registration-hub-shape.jwt
```

```
OK: Minimal: all 1 requested claims are within purpose and registration.
Registration certificate: payload decoded; signature, issuer and revocation status not verified.
Registration purpose: Example Bottle Shop: confirm the buyer is over 18   Baseline: Age gate (over 18)

Requested claims:
  [ok]  age_equal_or_over.18         Within the purpose-minimal baseline.
```

Version 0.4.1 labels the third line `Purpose:` where version 0.5.0 says
`Registration purpose:`; the rest of this output is the same.

A request with a claim outside the certificate exits 1, with a row that names
the registered scope. The recipe
[The wallet reports over-asking: reproduce it offline](COMMANDS.md#the-wallet-reports-over-asking-reproduce-it-offline)
shows how to read such rows.

### What to run on a new registration certificate

These steps are for a new registration certificate, such as one issued by the
EUDI Hub. They start when you have that certificate as a file in one of the
forms listed under [What keeps working](#what-keeps-working). The Workbench
has no step inside the EUDI Hub; point 2 under
[What the EUDI Hub says](#what-the-eudi-hub-says) gives what its page says
about transfer. Run the steps in this order:

1. Decode it with `augenmass decode regcert <certificate>`. Check that the
   purpose, the privacy policy, the support contact and every claim path are
   the ones meant. Each `claim` line is one registered path, with its segments
   joined by dots (`--json` prints each path as a list of its segments). Watch
   for a line that joins two claims that were meant to be separate:
   `claim given_name.family_name` is one path, where one line for `given_name`
   and one line for `family_name` were meant. The recipe
   [The wallet reports over-asking: reproduce it offline](COMMANDS.md#the-wallet-reports-over-asking-reproduce-it-offline)
   works through this case.
2. Audit the request that the verifier sends against it with
   `augenmass audit --request <request> --purpose <id> --cert <certificate>`.
   `<request>` is DCQL JSON; the recipe says how to get it out of a signed
   request object. `<id>` is one of the ids that `augenmass baselines` lists.
   Any other id (a mistyped one, for example) is a usage error: the command
   prints `error: unknown purpose '<id>'` with the valid ids on stderr,
   compares nothing and exits 2. Correct the id and run this step again.
3. On exit 1, read the first line and the rows as steps 2 and 3 of the recipe
   describe. Only the rows that name the registered scope are about the
   certificate.
4. On exit 3, the first line starts with `NOT EVALUATED`. No judged claim asks
   for too much, but something could not be judged, so this is not an OK. A
   row that starts with `[n/a]` names a claim that was not judged and says
   why, for example that the purpose baseline does not model the requested
   credential type. A block `Authoring warnings:` names a member of the
   request that OpenID4VP 1.0 does not define at its level and that resembles
   a defined one, `claim` for `claims` for example; a wallet that does not
   know such a member ignores it. The recipe describes both cases.
5. On exit 0, read the `OK` line:
   - `OK: Minimal: all N requested claims are within purpose and registration.`
     Every requested claim is covered by the certificate under the
     Workbench's rules and is within the purpose baseline.
   - `OK: No claims requested.` The request asks for no claim (its
     credentials carry no `claims`), and the format and type of each
     requested credential are registered.

   Neither line says that the request and the certificate are identical; the
   limits of the recipe say how to compare the paths by hand.
6. Repeat steps 1 to 5 whenever the request or the certificate changes.

Version 0.4.1 differs in steps 2, 4 and 5. It has no exit code 3:
a request written with `claim` for `claims` gets `OK: No claims requested.`
and exit 0 there, and a claim of a credential type that the baseline does not
model is judged by its name as if it were a PID claim. A mistyped `<id>` is no
error there: the run prints `note: unknown purpose` on stderr and skips the
purpose comparison, and when every claim is covered its first line is
`OK: Within registered scope; purpose not evaluated (no baseline supplied).`
with exit 0, which says nothing about the purpose.

Neither command needs a phone, a wallet app or a registrar, so both can run
before a test device is updated (see point 1 under
[What the EUDI Hub says](#what-the-eudi-hub-says)). This order was not run on a
certificate issued by the EUDI Hub, and `serve` cannot carry the new
certificate to a phone; the two parts below give both limits.

### What does not, or may not

- The `sandbox` target and the `cached-sandbox` reads use the German sandbox
  registrar and may stop working against it, as the notice at the top of this
  page says. The Workbench has no target for the EUDI Hub.
- `serve` embeds the registration certificate bundled with the binary
  (`fixtures/regcert/rc-by-id.json`, issued by the German sandbox registrar) in
  every request and has no option to load another one; `--key` and `--leaf` set
  the signing key and its leaf certificate only. Phone tests with `serve` are
  therefore not covered once the wallet app no longer accepts certificates from
  that registrar.
- `check` and `register` read a registration body in the shape of the German
  sandbox registrar; see the scope note under [`check`](COMMANDS.md#check).

### What was not tested

- Nothing in the Workbench was run on a certificate issued by the EUDI Hub;
  this project had none.
- The fixture `fixtures/hub-shape/registration-hub-shape.jwt` is synthetic. Its
  field names come from the EUDI Hub's public source repository
  (`https://gitlab.opencode.de/bmi/eudi-wallet/eudi-hub-de-public`, snapshot
  "Public release 2026-09-09", read on 13 November 2026). Every value is
  invented, and so is the type of every value the Workbench does not read.
  Whether a certificate issued by the EUDI Hub has this shape was not checked.
- From a registration certificate the Workbench reads `purpose`,
  `privacy_policy`, `support_uri` and `credentials` (format, type, claim
  paths). It ignores every other field, `values` and `intended_use_id`
  included.
- How the EUDI Hub hands out a certificate was not read: its portal needs a
  login. `audit --cert` reads a compact JWT or a JSON entry that carries one
  under `jwt`; any other form has to be brought into one of these first.
- No phone wallet was used for anything in this section.

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
- `--upstream <URL>`: sandbox API base (env `AUGENMASS_CACHE_UPSTREAM`). Default `https://sandbox.eudi-wallet.org/api`; when neither the flag nor the variable is set, `cache serve` prints the sandbox registrar notice on stderr at startup.
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

The plugin path above is the bundled launcher. It selects the native target
binary for supported platforms unless `AUGENMASS_BIN` is set.

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
- `--force` writes past an over-ask warning, or past a body that could not be evaluated, and requires `--yes`. From version 0.5.0 on, `--force` without `--yes` is a usage error (exit 2). Without `--force`, an over-asking body is refused (exit 1) on every target. A blocking format error is fatal regardless of `--force`.
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
Registration certificate: payload decoded; signature, issuer and revocation status not verified.

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
Registration purpose: Age verification   Baseline: Age gate (over 18)

Requested claims:
  [over]  given_name                   Registered, but beyond what the stated purpose needs.
  [over]  family_name                  Registered, but beyond what the stated purpose needs.
  [over]  birthdate                    Registered, but beyond what the stated purpose needs.
  [over]  address.resident_street      Registered, but beyond what the stated purpose needs.
  [over]  address.resident_city        Registered, but beyond what the stated purpose needs.
  [over]  nationalities                Registered, but beyond what the stated purpose needs.

Over-asking 6 claim(s) beyond the stated purpose.

Suggested minimal request (dc+sd-jwt, urn:eudi:pid:de:1), as claim paths:
  ["age_equal_or_over", "18"]

Legal basis:
  Regulation (EU) No 910/2014, Article 5b(3)
    Relying parties shall not request users to provide any data other than that indicated pursuant to paragraph 2, point (c).
  GDPR (EU) 2016/679, Art. 5(1)(c)
    Personal data shall be: [...] (c) adequate, relevant and limited to what is necessary in relation to the purposes for which they are processed (‘data minimisation’);
  EUDI ARF, registration certificate, RPRC_21
    After receiving a presentation request from a Relying Party, a Wallet Unit SHALL verify that all attributes requested in the request are included in the list of attributes in the registration certificate included in the same request. If the outcome of the verification is negative, the Wallet Unit SHALL, when asking for User approval according to RPA_07, warn the User that the Relying Party is requesting more information than it has registered. In addition, the Wallet Provider SHALL determine, based on its risk analysis and security policy, whether the Wallet Unit must a) enable the User to approve (or reject) the presentation of all requested attributes, including the non-registered ones, b) enable the User to approve (or reject) the presentation of the registered attributes only, or c) reject the presentation of all requested attributes.

Refusing to write: this request over-asks (see above). Re-run with --yes --force to write it anyway.
```

The command exits 1, so CI catches it. To deliberately write the over-asking body anyway you must add `--force`:

```
augenmass register examples/over.json --target clone --yes --force
```

That reprints the same verdict, then writes with an explicit warning (`Warning: writing an over-asking registration because --force was given.`; from version 0.5.0 on the line continues with `A forced write that succeeds exits 0.`) and exits 0. Use `--force` only when over-asking is intentional and justified; the default refusal is the point of the gate.

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
