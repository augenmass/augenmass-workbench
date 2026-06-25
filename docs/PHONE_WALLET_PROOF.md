# Phone wallet proof runbook

This is the rehearsal path for proving a real wallet interaction, not just the
loopback smoke. It turns one `augenmass serve` session into a redacted evidence
bundle and then makes the claim testable with `evidence assert-live`.

Use this when the demo story says "a real phone wallet presented to our
verifier." If any required step below is missing, say the verifier runtime is
proven by `serve-smoke`, but the specific phone-wallet environment is not yet
proven.

The examples use a Unix-like shell. On Windows, use the native
`augenmass.exe`, PowerShell variable syntax, and a private workspace for any
unsafe capture directory.

## What this proves

`evidence assert-live` proves that a captured session reached the encrypted
phone-wallet spine:

- the wallet fetched the signed request object: `REQUEST_OBJECT_FETCHED`
- the wallet posted an encrypted `direct_post.jwt`: `RESPONSE_RECEIVED`
- the verifier decrypted the JWE response: `RESPONSE_DECRYPTED`
- the SD-JWT VC presentation verified offline: `VERIFIED`

It does not prove issuer trust anchoring, live status, or that the wallet
disclosed no more than the purpose allowed. Use the live trace, `--trust-anchor`,
`--status-signer`, `--live-status`, and the over-ask inspector for those claims.

## Before the phone scan

Run the local runtime proof first. It needs no phone and no sandbox credentials:

```sh
just serve-smoke
```

Refresh the public sandbox aggregate if the presentation mentions the current
sandbox registry:

```sh
just public-sandbox-snapshot
```

If the presentation will mention issuer trust or live revocation material for
the current Bundesdruckerei preprod PID provider, check that the public material
is still reachable and parseable before the phone scan:

```sh
just bundesdruckerei-preprod-material-smoke
```

If the presentation depends on stable sandbox reads, start and warm the local
cached-sandbox mirror before the live segment:

```sh
BIN=${AUGENMASS_BIN:-./plugins/augenmass-workbench/bin/augenmass}
RP=2af138a8-59ea-4a84-aea3-666cafdb1369
CACHE=./presenter-cache.sqlite

$BIN cache serve --db "$CACHE" --port 8081 --ttl-secs 315360000 --allowed-rp "$RP"
```

`./plugins/augenmass-workbench/bin/augenmass` is the bundled launcher. It picks
the native plugin binary for supported targets unless `AUGENMASS_BIN` points to
a separately trusted binary.

In another shell:

```sh
BIN=${AUGENMASS_BIN:-./plugins/augenmass-workbench/bin/augenmass}
RP=2af138a8-59ea-4a84-aea3-666cafdb1369
BASE=http://127.0.0.1:8081/api
$BIN cache warm --api-base "$BASE" --rp "$RP"
$BIN cache status --api-base "$BASE"
AUGENMASS_CACHE_API_BASE="$BASE" $BIN list --target cached-sandbox --rp "$RP"
```

Do not use `sandbox` writes on stage. `cached-sandbox` is read-only and is the
right target for stable public reads.

## Choose the public URL

The phone must be able to reach the verifier URL. `127.0.0.1` only works when
the wallet runs on the same machine, which a phone does not.

On the same Wi-Fi network, use the laptop's LAN IP:

```sh
PUBLIC_URL=http://192.0.2.10:8080/
```

For a venue network where the phone cannot reach the laptop directly, prefer
the hosted wallet-only relay:

```sh
export AUGENMASS_RELAY_TOKEN=<relay-token>
```

`augenmass serve --relay augenmass` then prints a temporary
`https://wallet.augenmass.tech/r/<run-id>/` public URL. That public URL forwards
only `GET /request/<session>` and `POST /response/<session>`; trace, inspect,
evidence, and unsafe debug artifacts stay on localhost.

If you use a different HTTPS tunnel, set `PUBLIC_URL` to that tunnel base URL.
It must end in `/`. Do not put secrets in the URL.

## Start the verifier

For a safe, redacted live demo without raw capture:

```sh
BIN=${AUGENMASS_BIN:-./plugins/augenmass-workbench/bin/augenmass}

$BIN serve --host 0.0.0.0 --public-url "$PUBLIC_URL"
```

For a proof bundle, opt in to local sensitive capture:

```sh
BIN=${AUGENMASS_BIN:-./plugins/augenmass-workbench/bin/augenmass}
RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)
DEBUG_DIR=./debug-out/$RUN_ID

$BIN serve \
  --relay augenmass \
  --unsafe-debug-artifacts "$DEBUG_DIR"
```

For the smallest stage-safe request, add `--age-only`. It asks only for the
German PID predicate `age_equal_or_over.18` and is the preferred presentation
profile when a sandbox wallet cannot satisfy the named event-check-in request:

```sh
$BIN serve \
  --relay augenmass \
  --age-only \
  --unsafe-debug-artifacts "$DEBUG_DIR"
```

`--unsafe-debug-artifacts` writes raw wallet material, decrypted response
material when available, and the per-session response-encryption key to local
disk. It is never served over HTTP, but it is sensitive. Do not screen-share the
directory, paste its files, or commit it.

If you need the verifier identity to match a registrar-issued registration, pass
the real relying-party key and leaf certificate:

```sh
$BIN serve \
  --relay augenmass \
  --key rp-private.pem.key \
  --leaf rp-leaf.pem \
  --age-only \
  --unsafe-debug-artifacts "$DEBUG_DIR"
```

If you also need to claim issuer trust and live revocation status, add the trust
anchor and live status check:

```sh
$BIN serve \
  --host 0.0.0.0 \
  --public-url "$PUBLIC_URL" \
  --key rp-private.pem.key \
  --leaf rp-leaf.pem \
  --trust-anchor pid-issuer-anchor.pem \
  --status-signer pid-status-signer.pem \
  --live-status \
  --unsafe-debug-artifacts "$DEBUG_DIR"
```

For the current Bundesdruckerei preprod sandbox PID provider, the issuer trust
anchor and status-list signer are separate certificates. The provider root page
links both: `certificates/root-ca.crt` for `--trust-anchor`, and
`certificates/signer.crt` for `--status-signer`. The
`bundesdruckerei-preprod-material-smoke` target checks those URLs plus the BMI
trustlist JWT without needing a phone, but it does not prove a completed wallet
presentation.

Without `--key` and `--leaf`, the tool uses a throwaway development certificate.
That is fine for proving the debugger mechanics, but do not claim it proves the
registered relying-party identity.

## Capture the wallet run

Open the printed URL on the laptop, scan the QR with the phone wallet, and watch
the terminal or `/trace/<session>`.

The live trace should reach at least:

```text
SESSION_CREATED
REQUEST_BUILT
REQUEST_OBJECT_FETCHED
RESPONSE_RECEIVED
RESPONSE_DECRYPTED
VERIFIED
```

If the trace ends in `REJECTED` or `ERROR`, keep the trace as a debugging
artifact, but do not present it as a proven successful phone-wallet run.

## Export and prove the bundle

Stop the server after the wallet exchange. The unsafe capture directory contains
one subdirectory per session. Pick the session that reached `VERIFIED`:

```sh
find "$DEBUG_DIR" -mindepth 1 -maxdepth 1 -type d
```

Export the session:

```sh
SESSION_DIR="$DEBUG_DIR/<session-id>"
BUNDLE=./dist/phone-wallet-evidence-$RUN_ID.json

mkdir -p ./dist
$BIN evidence export "$SESSION_DIR" --out "$BUNDLE"
```

Verify and replay it:

```sh
$BIN evidence verify "$BUNDLE"
$BIN evidence replay "$BUNDLE"
```

Require the completed encrypted phone-wallet spine:

```sh
$BIN evidence assert-live "$BUNDLE"
```

or with the just wrapper:

```sh
just wallet-evidence-proof "$BUNDLE"
```

Only after that command succeeds should the demo claim be: "this captured bundle
proves a completed encrypted phone-wallet presentation to the workbench
verifier." Add separate wording for trust/status/over-ask only if those steps
were explicitly configured and observed.

If you have the PID issuer anchor and the status signer certificate/public key,
re-run the captured presentation through the explicit trust/status gate. The
tool can safely fetch the referenced status-list token from the captured
credential URI:

```sh
$BIN evidence prove-trust-status "$BUNDLE" \
  --trust-anchor pid-issuer-anchor.pem \
  --fetch-status-token \
  --status-key pid-status-signer.pem
```

That command uses the captured nonce, audience, vct, timestamp, and decrypted
authorization response from the bundle. It prints only redacted proof metadata
and disclosed claim keys, not wallet claim values. Use it together with
`evidence assert-live`: one proves the phone exchange, the other proves the
captured presentation under explicit trust/status inputs. For fully offline
proof, replace `--fetch-status-token` with `--status-token status-list.jwt`.

The combined just wrapper runs both gates in order:

```sh
just wallet-trust-status-proof "$BUNDLE" pid-issuer-anchor.pem pid-status-signer.pem
```

For the current Bundesdruckerei preprod sandbox PID provider, the repository
also ships a provider-specific wrapper. It fetches the current root CA and
status-list signer from the provider, then runs `evidence assert-live` and
`evidence prove-trust-status --fetch-status-token`:

```sh
just bundesdruckerei-wallet-trust-status-proof "$BUNDLE"
```

Use the Bundesdruckerei wrapper only when the captured bundle came from that
preprod PID issuer. It is an operator convenience around the same explicit
proof gates, not a generic trust anchor.

## Known-good demo result

On 2026-06-25, the staged phone flow was proven with the hosted wallet-only
relay, the registrar-issued leaf, and the age-only request:

```sh
$BIN serve \
  --relay augenmass \
  --key ../secrets/rp.key \
  --leaf fixtures/certs/access-leaf.pem \
  --age-only \
  --unsafe-debug-artifacts "$DEBUG_DIR"
```

Two real sandbox-wallet sessions reached the full encrypted wallet spine. A
later rehearsal in the same venue setup confirmed the flow again with both
wallet families: iOS reached `PresentationSuccess` in the wallet logs and the
workbench trace reached `VERIFIED`; Android showed "Data sent successfully" and
the wallet log recorded "Verifier accepted the response."

```text
SESSION_CREATED
REQUEST_BUILT
REQUEST_OBJECT_FETCHED
RESPONSE_RECEIVED
RESPONSE_DECRYPTED
VERIFIED
OVER_ASK_ANALYZED
```

The exported bundles passed `evidence verify`, `evidence assert-live`, and the
Bundesdruckerei preprod `wallet-trust-status` proof wrapper with a freshly
fetched status-list token. Those bundles are intentionally not committed because
they are marked `sensitive: true`; keep them local or in a private evidence
store only.

This known-good proof supports the stage claim that a real phone wallet
completed an encrypted OpenID4VP presentation to the workbench verifier through
the hosted relay, that the workbench decrypted and verified the presentation
with holder binding, and that the captured presentation re-verifies under the
current Bundesdruckerei preprod issuer trust/status material. It does not prove
that the original live trace executed `serve --live-status`; the status proof is
the post-capture `evidence prove-trust-status --fetch-status-token` gate.

If a wallet response fails with `KbTimeInvalid: ... premature claim`, update to
commit `4f152cd` or newer. That release accepts a tightly bounded 5-second
future clock skew for freshly minted KB-JWTs while keeping the 300-second
freshness window.

## What to say if it does not complete

- If the phone cannot open the URL: the `--public-url` is unreachable from the
  phone. Use the LAN IP or a tunnel, and keep the trailing `/`.
- If the wallet fetched the request but no response arrived: check wallet UI
  consent, network reachability back to `POST /response/<session>`, and whether
  the tunnel supports POST bodies.
- If decryption fails: this is usually a stale response, wrong session, or a
  wallet that did not encrypt to this run's ephemeral key. Start a fresh session.
- If verification fails: use the rejection reason in the trace, then run
  `doctor` on the request and `verify presentation` on extracted material only
  in a private local workspace.
- If no `evidence assert-live` bundle exists: say the live debugger runtime is
  proven by `serve-smoke`, but the real phone-wallet proof is still pending.

## Handling after the demo

The source session directory and exported bundle are sensitive. Keep them in a
private local workspace or encrypted storage, and remove them before publishing
release artifacts:

```sh
rm -rf ./debug-out
```

Do not commit `debug-out/`, `dist/phone-wallet-evidence-*.json`, private keys,
leaf certificates, tunnel tokens, or sandbox credentials.
