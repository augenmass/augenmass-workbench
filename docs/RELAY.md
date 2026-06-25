# Hosted wallet relay

`augenmass serve` can now use a hosted relay so a phone wallet can reach the
local verifier without putting the whole debugger on the public internet.

The relay is intentionally narrow. It forwards only the two OpenID4VP endpoints
the wallet needs:

- `GET /request/<session>`
- `POST /response/<session>`

Everything else stays on localhost: the landing page, inspector, trace JSON,
session list, evidence export, and unsafe debug artifacts. The hosted relay is a
byte-forwarding tunnel, not a verifier. It does not decrypt wallet payloads,
does not store forwarded bodies, and logs only route, status, byte counts,
latency, and a short run id.

## Operator flow

For the presentation relay:

```sh
export AUGENMASS_RELAY_TOKEN=<relay-create-token>
augenmass serve --relay augenmass
```

`--relay augenmass` resolves to:

```text
wss://wallet.augenmass.tech/_relay/tunnel
```

Set `AUGENMASS_RELAY_URL` to override that alias for staging or local tests.
The CLI starts the verifier on loopback, connects outbound to the relay, and
prints two URLs:

- `open`: the local operator UI. Use this on the laptop for the QR, trace, and
  inspect pages.
- `public`: the temporary relay URL baked into the wallet request object and
  response URI.

The operator does not open the public URL directly except to prove the wallet
endpoints. Public trace and inspect routes intentionally return `404`.

## Why not a full tunnel?

A transparent tunnel would make `/trace/<session>`, `/api/trace/<session>`,
`/api/sessions`, and any future debug endpoint reachable by anyone holding the
run URL. Those endpoints are redacted, but they are still debug surfaces with
timing and metadata. The relay keeps the strongest demo posture: the phone gets
only the wallet protocol endpoints; the human debugger remains local.

## Relay server

The server binary is `augenmass-relay`.

Local run:

```sh
AUGENMASS_RELAY_AUTH_TOKEN=local-token \
AUGENMASS_RELAY_HOST=127.0.0.1 \
AUGENMASS_RELAY_PORT=8082 \
  augenmass-relay
```

Public run:

```sh
AUGENMASS_RELAY_AUTH_TOKEN=<secret> \
AUGENMASS_RELAY_PUBLIC_BASE=https://wallet.augenmass.tech \
AUGENMASS_RELAY_HOST=0.0.0.0 \
PORT=8082 \
  augenmass-relay
```

On non-loopback binds the relay refuses to start unless both
`AUGENMASS_RELAY_AUTH_TOKEN` and `AUGENMASS_RELAY_PUBLIC_BASE` are set. This is
deliberate: an unauthenticated public tunnel-creation endpoint is an open proxy
and DoS target.

Runtime limits are configurable:

| Env | Default | Meaning |
|---|---:|---|
| `AUGENMASS_RELAY_BODY_LIMIT_BYTES` | `1048576` | Max forwarded request/response body; also clamped below the WebSocket hard cap. |
| `AUGENMASS_RELAY_MAX_INFLIGHT` | `32` | Per-run concurrent forwarded wallet requests. |
| `AUGENMASS_RELAY_REQ_TIMEOUT_SECS` | `30` | Timeout waiting for local `serve` to answer a forwarded request. |
| `AUGENMASS_RELAY_RUN_TTL_SECS` | `600` | Default run TTL, clamped to the hard maximum. |
| `AUGENMASS_RELAY_MAX_RUNS` | `256` | Concurrent live runs. |
| `AUGENMASS_RELAY_RATE_WINDOW_SECS` | `60` | Per-IP rate-limit window. |
| `AUGENMASS_RELAY_MAX_TUNNEL_CREATES_PER_WINDOW` | `60` | Per-IP tunnel creations per window. |
| `AUGENMASS_RELAY_MAX_FORWARD_REQUESTS_PER_WINDOW` | `600` | Per-IP wallet forwards per window. |

The relay health check is:

```text
GET /healthz
```

## Railway shape

The repo includes relay-specific deploy files so the cache service and relay
service do not get mixed up:

- `Dockerfile.relay`
- `railway.relay.json`

Recommended Railway variables:

```sh
AUGENMASS_RELAY_AUTH_TOKEN=<secret>
AUGENMASS_RELAY_PUBLIC_BASE=https://wallet.augenmass.tech
AUGENMASS_RELAY_HOST=0.0.0.0
RUST_LOG=warn,augenmass_relay=info
```

Leave `AUGENMASS_RELAY_PORT` unset on Railway so the platform-injected `PORT`
wins. The relay is stateless, so it does not need a Railway volume.

## Proof gates

Local proof:

```sh
just relay-smoke
```

That gate starts a local relay, starts `augenmass serve` through it, mints a
session, verifies the local and relayed request object are byte-identical,
proves trace/inspect are not public, rejects plaintext `direct_post`, verifies
the local trace is redacted, and checks relay logs for forbidden sentinels.

Source guard:

```sh
./scripts/relay-source-guard.sh
```

This keeps obvious future mistakes out of the relay path: lossy body decoding,
request-URI trace logging, and public trace/inspect/debug routes.

Hosted proof after deploying:

```sh
AUGENMASS_DEPLOYED_RELAY_BASE=https://wallet.augenmass.tech \
AUGENMASS_DEPLOYED_RELAY_TOKEN=<secret> \
  just hosted-relay-proof
```

Do not claim the hosted phone-wallet ingress is ready until that proof passes
against the real domain.
