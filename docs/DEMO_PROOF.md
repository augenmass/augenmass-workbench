# Demo proof gate

`just demo-proof` is the fast, offline proof gate for the presentation story. It
does not replace `just verify`; it gives the agents and presenter a small set of
commands that are stable enough to rehearse and safe enough to run without
sandbox credentials, secrets, or a live wallet.

It covers three surfaces:

1. `tests/demo_proof.rs`: the agent-first command story.
   - Identify EUDI artifacts with `inspect`: SD-JWT VC, OpenID4VP JAR, and mdoc.
   - Show the over-ask guard with `check` and `audit`, including the legal basis.
   - Show fix guidance with `doctor`, `x509-hash`, and the registration body
     format gate.
   - Verify offline crypto fixtures: a valid presentation succeeds, a wrong
     nonce fails, and a revoked status-list index fails.
   - Prove demo target safety: `cached-sandbox` dry-run works, confirmed writes
     are refused, and `serve` / `cache serve` expose their safety flags.
2. `tests/serve.rs`: the live wallet debugger request side.
   - Starts the real Axum router on an ephemeral port.
   - Confirms the landing page, signed request object content type, session
     listing, JSON trace, and HTML trace.
3. `tests/cache.rs`: the cached-sandbox mirror.
   - Confirms cache provenance headers, hit/miss behavior, forced refresh
     validation, and stale fallback when the upstream is unavailable.

Use this gate when changing pitch, skill, or demo wording. If the wording says
"ask the agent to debug this JAR" or "show the over-ask guard", the corresponding
command should remain inside this proof set or be added here before shipping.

Run the full release gate before pushing:

```sh
just demo-proof
just verify
```

## Local shipping smoke

`just shipping-smoke` is the local proof gate for the parts that `demo-proof`
does not touch. It avoids remote GitHub Actions runner minutes.

It runs:

- `just plugin-smoke`: checks the Claude Code plugin bundle, the executable
  bundled binary, the hook, the skill wording for the key command surfaces, and a
  small fixture-backed command sequence.
- `just live-cache-smoke`: starts `cache serve`, reaches the public sandbox API,
  proves admin-token protection, proves `MISS` then `HIT`, reads the configured
  relying party through `list --target cached-sandbox`, then restarts the cache
  with a broken upstream and proves stale fallback.
- `just docker-smoke`: builds the Docker image locally, runs the cache backend
  container, checks `/api/health`, verifies it runs as uid `10001`, and proves
  admin-token protection.

Use the smaller gates when you are only touching one surface:

```sh
just plugin-smoke
just live-cache-smoke
just docker-smoke
```

`live-cache-smoke` intentionally touches `https://sandbox.eudi-wallet.org/api`.
It does not use sandbox credentials. `docker-smoke` requires a running Docker
daemon. Neither gate starts remote GitHub CI.

## Stable rehearsal sequence

`just demo-run` runs the offline presentation sequence from the bundled plugin
binary. It uses only committed fixtures and treats the intentional findings as
successful proof points, so no sandbox credentials or phone wallet are needed.

The sequence is:

```sh
./plugins/augenmass-workbench/bin/augenmass --version
./plugins/augenmass-workbench/bin/augenmass inspect fixtures/requests/eudiplo-request.jwt
sh -c './plugins/augenmass-workbench/bin/augenmass doctor examples/bad-request.json; code=$?; test "$code" -eq 1'
./plugins/augenmass-workbench/bin/augenmass decode regcert fixtures/regcert/rc-by-id.json
sh -c './plugins/augenmass-workbench/bin/augenmass audit --request minimal --purpose age_gate_18 --cert fixtures/regcert/rc-by-id.json; code=$?; test "$code" -eq 1'
./plugins/augenmass-workbench/bin/augenmass check examples/min.json
sh -c './plugins/augenmass-workbench/bin/augenmass check examples/over.json; code=$?; test "$code" -eq 1'
./plugins/augenmass-workbench/bin/augenmass verify presentation fixtures/presentations/erica-vp-VALID.sdjwt --nonce b4ba2623-76a2-486b-a1f6-f1656025d07b --aud https://self-issued.me/v2 --now 1780435200 --trust-anchor fixtures/certs/erica-trust-anchor.pem
sh -c './plugins/augenmass-workbench/bin/augenmass verify presentation fixtures/presentations/synthetic-pid-with-status.sdjwt --nonce b4ba2623-76a2-486b-a1f6-f1656025d07b --aud https://self-issued.me/v2 --now 1780435200 --trust-anchor fixtures/certs/synthetic-pid-anchor.pem --status-token fixtures/status/status-list-REVOKED.jwt --status-key fixtures/status/status-list-verify-key.pub.pem; code=$?; test "$code" -eq 1'
```

Good narration anchors:

- `Detected: OpenID4VP authorization request (JAR)`
- `response_mode: direct_post.jwt`
- `DOCTOR-X5C-STRING` and `DOCTOR-CLIENT-ID-X509HASH`
- `OVER-ASK` with `Suggested minimal request: age_equal_or_over.18`
- `OK: no over-ask, no format errors`
- `VERIFIED`, `holder binding: true`, and `trust anchored: true`
- `REJECTED [Revoked]: credential is revoked`

Avoid for the five-minute proof: live `sandbox`, `--live-status`, full phone-wallet
scans, and `--unsafe-debug-artifacts`. Those are real capabilities, but they are
the parts most likely to depend on credentials, network, or device state.
