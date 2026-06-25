# Phone wallet proof checklist

Use this when the user wants to prove that a real phone wallet completed an
encrypted presentation to the workbench verifier. The loopback smoke proves the
runtime; this checklist proves a specific captured phone run.

If the full repository checkout is available, the longer operator runbook is
`docs/PHONE_WALLET_PROOF.md`. If only the plugin is installed, this reference is
the checklist to follow.

## Claim boundary

`evidence assert-live` proves the captured session reached:

- `REQUEST_OBJECT_FETCHED`: the wallet fetched the signed request object
- `RESPONSE_RECEIVED`: the wallet posted an encrypted `direct_post.jwt`
- `RESPONSE_DECRYPTED`: the verifier decrypted the JWE response
- `VERIFIED`: the SD-JWT VC presentation verified offline

It does not prove issuer trust, live revocation status, or legal over-ask
analysis. When the captured request contains explicit DCQL claim paths, replay
can separately report wallet over-disclosure as a redacted auditor signal.
Claim stronger trust/status/over-ask results only when the trace shows the
explicit steps and the run used the required inputs, such as `--trust-anchor`,
`--status-signer`, and `--live-status`.

## Preflight

Run the verifier runtime smoke when the repository checkout is available:

```sh
just serve-smoke
```

Resolve the binary. In plugin-only installs, use the bundled launcher; it picks
the native target binary for macOS Apple Silicon, macOS Intel, Linux x64, or
Windows x64. If the platform is unsupported or the user does not want to approve
an unsigned preview binary, ask them to set `AUGENMASS_BIN` to a native build or
release archive:

```sh
AUGENMASS=${AUGENMASS_BIN:-augenmass}
$AUGENMASS serve --help
$AUGENMASS evidence assert-live --help
```

Pick a public URL the phone can actually reach. `127.0.0.1` is wrong for a
separate phone. Use the laptop LAN IP on trusted Wi-Fi, or an HTTPS tunnel:

```sh
PUBLIC_URL=http://192.0.2.10:8080/
```

The URL must end in `/`.

## Start the verifier

For a redacted live demo with no raw capture:

```sh
$AUGENMASS serve --host 0.0.0.0 --public-url "$PUBLIC_URL"
```

For a proof bundle, opt in to local sensitive capture:

```sh
RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)
DEBUG_DIR=./debug-out/$RUN_ID

$AUGENMASS serve \
  --host 0.0.0.0 \
  --public-url "$PUBLIC_URL" \
  --unsafe-debug-artifacts "$DEBUG_DIR"
```

If the verifier identity must match a registered relying party, pass the real
private key and leaf certificate:

```sh
$AUGENMASS serve \
  --host 0.0.0.0 \
  --public-url "$PUBLIC_URL" \
  --key rp-private.pem.key \
  --leaf rp-leaf.pem \
  --unsafe-debug-artifacts "$DEBUG_DIR"
```

If the demo also needs issuer trust and live revocation status:

```sh
$AUGENMASS serve \
  --host 0.0.0.0 \
  --public-url "$PUBLIC_URL" \
  --key rp-private.pem.key \
  --leaf rp-leaf.pem \
  --trust-anchor pid-issuer-anchor.pem \
  --status-signer pid-status-signer.pem \
  --live-status \
  --unsafe-debug-artifacts "$DEBUG_DIR"
```

Without `--key` and `--leaf`, `serve` uses a throwaway development certificate.
That proves the debugger mechanics, not the registered relying-party identity.

## Capture and prove

Open the printed URL, scan the QR with the phone wallet, and watch the console
or `/trace/<session>`. A successful run should reach:

```text
SESSION_CREATED
REQUEST_BUILT
REQUEST_OBJECT_FETCHED
RESPONSE_RECEIVED
RESPONSE_DECRYPTED
VERIFIED
```

Stop the server after the exchange. Pick the session directory that reached
`VERIFIED`, export it, verify it, replay it, and require the live-wallet spine:

```sh
SESSION_DIR="$DEBUG_DIR/<session-id>"
BUNDLE=./dist/phone-wallet-evidence-$RUN_ID.json

mkdir -p ./dist
$AUGENMASS evidence export "$SESSION_DIR" --out "$BUNDLE"
$AUGENMASS evidence verify "$BUNDLE"
$AUGENMASS evidence replay "$BUNDLE"
$AUGENMASS evidence assert-live "$BUNDLE"
```

Only after `evidence assert-live` succeeds should the answer say the captured
bundle proves a completed encrypted phone-wallet presentation. If the trace ends
in `REJECTED` or `ERROR`, keep it as a debugging artifact, not as proof of a
successful demo.

If a wallet retries the response after a successful POST, unsafe artifacts keep
the first canonical capture and write later duplicates with a suffix such as
`direct-post-2.body`. Export the session normally; the proof path uses the first
canonical capture.

If you also have the PID issuer anchor and the status signer certificate/public
key, run the explicit trust/status gate. The tool can safely fetch the
referenced status-list token from the captured credential URI:

```sh
$AUGENMASS evidence prove-trust-status "$BUNDLE" \
  --trust-anchor pid-issuer-anchor.pem \
  --fetch-status-token \
  --status-key pid-status-signer.pem
```

Use both claims together: `assert-live` proves the completed phone-wallet
exchange, while `prove-trust-status` proves the captured presentation under the
supplied trust/status inputs. The proof output stays redacted. For fully offline
proof, replace `--fetch-status-token` with `--status-token status-list.jwt`.

In a full repository checkout, the combined wrapper is:

```sh
just wallet-trust-status-proof "$BUNDLE" pid-issuer-anchor.pem pid-status-signer.pem
```

For a bundle captured from the current Bundesdruckerei preprod sandbox PID
issuer, the repository also has a provider-specific wrapper. It fetches the
current provider root CA and status-list signer, then runs the completed-wallet
and trust/status gates:

```sh
just bundesdruckerei-wallet-trust-status-proof "$BUNDLE"
```

## Handling sensitive material

`--unsafe-debug-artifacts` writes raw wallet material, decrypted response
material when available, and the per-session response-encryption key to local
disk. It is never served over HTTP, but it is sensitive.

Do not screen-share the artifact directory, paste its files, or commit it. Keep
it in a private local workspace or encrypted storage. Remove it before
publishing release artifacts:

```sh
rm -rf ./debug-out
```
