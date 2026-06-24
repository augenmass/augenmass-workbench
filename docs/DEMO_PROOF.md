# Demo proof gate

`just demo-proof` is the fast, offline proof gate for the presentation story. It
does not replace `just verify`; it gives the agents and presenter a small set of
commands that are stable enough to rehearse and safe enough to run without
sandbox credentials, secrets, or a live wallet.

It covers four surfaces:

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
3. `just serve-smoke`: the bundled CLI runtime over loopback HTTP.
   - Starts `augenmass serve --quiet` on a throwaway port.
   - Mints a session through the landing page, fetches the signed request
     object, and reads the JSON/HTML trace endpoints.
   - Posts a synthetic plaintext `direct_post` and proves it is rejected with
     HTTP 422 while the unauthenticated trace stays redacted.
4. `tests/cache.rs`: the cached-sandbox mirror.
   - Confirms cache provenance headers, hit/miss behavior, forced refresh
     validation, and stale fallback when the upstream is unavailable.

Use this gate when changing pitch, skill, or demo wording. If the wording says
"ask the agent to debug this JAR" or "show the over-ask guard", the corresponding
command should remain inside this proof set or be added here before shipping.

## Skill transcript proof

For the presentation, narrate this as an agent-assisted workflow first. The
commands are the proof underneath, not the story the audience has to operate.

| User prompt | Internal command proof | Reviewer-facing summary |
| --- | --- | --- |
| `What is this wallet request, and why might it fail?` | `inspect fixtures/requests/eudiplo-request.jwt`, then `doctor examples/bad-request.json` | "This is an OpenID4VP request. The shape that often breaks wallets is the signed request metadata: `x5c` must be an array, and `client_id` must match the certificate hash." |
| `Is this age-check registration over-asking?` | `check examples/over.json`, then `check examples/min.json` | "The over-broad body asks for name, birthdate, address, and nationality when the purpose only needs proof of being over 18. The fixed body asks only for `age_equal_or_over.18`." |
| `Can we trust this presentation and catch revocation?` | `verify presentation fixtures/presentations/erica-vp-VALID.sdjwt ...`, then the synthetic revoked fixture | "The valid fixture verifies with holder binding and trust anchoring. The revoked fixture fails closed, which is exactly what an auditor wants to see." |
| `How would we debug this with a real phone wallet?` | `serve --help`, `evidence assert-live --help`, `just serve-smoke`, `cache serve --help`, and `tests/serve.rs` | "`serve` runs a verifier-in-a-box. It traces request, JAR fetch, response, decrypt, verify, trust, status, and over-ask with redacted traces by default; `evidence assert-live` is the post-capture gate for proving a completed encrypted phone-wallet run." |

Run the full release gate before pushing:

```sh
just demo-proof
just verify
```

## Local shipping smoke

`just shipping-smoke` is the local proof gate for the parts that `demo-proof`
does not touch. It avoids remote GitHub Actions runner minutes.

It runs:

- `just plugin-smoke`: checks the Claude Code and Codex plugin metadata, the
  executable bundled binary, the hook, the skill wording for the key command
  surfaces, and a small fixture-backed command sequence.
- `just plugin-bundle-freshness`: on macOS Apple Silicon, rebuilds the locked
  release binary and fails unless the committed plugin binary is byte-for-byte
  identical.
- `just plugin-only-smoke`: copies only the plugin bundle to a temporary
  directory and proves generated/stdin first-run commands without a full checkout
  or `fixtures/` / `examples/`.
- `just claude-plugin-smoke`: validates the Claude Code plugin and marketplace
  manifests with `--strict`, installs the plugin from this checkout in a
  temporary `HOME`, and confirms it is enabled.
- `just codex-plugin-smoke`: installs the repo-local Codex marketplace and plugin
  into a temporary `CODEX_HOME`, then confirms the plugin is enabled.
- `just serve-smoke`: starts the resolved `augenmass serve` runtime over
  loopback HTTP, checks health, session minting, JAR fetch, JSON trace, HTML
  trace, plaintext `direct_post` rejection, and trace redaction. It defaults to
  the bundled plugin binary and honors `AUGENMASS_BIN` for native source or
  release binaries.
- `augenmass evidence assert-live <bundle.json>` or
  `just wallet-evidence-proof <bundle.json>`: post-capture proof for a real
  phone-wallet run. It is intentionally not part of `shipping-smoke`, because it
  requires a captured `serve --unsafe-debug-artifacts` session from an actual
  wallet interaction. Use `docs/PHONE_WALLET_PROOF.md` as the operator checklist
  for producing that bundle.
- `just live-cache-smoke`: starts `cache serve`, reaches the public sandbox API,
  proves admin-token protection, proves `MISS` then `HIT`, reads the configured
  relying party through `list --target cached-sandbox`, prewarms with
  `cache warm`, renders the protected inventory through `cache status`, proves an
  unlisted RP is blocked with `403`, then restarts the cache with a broken
  upstream and proves stale fallback.
- `just public-sandbox-snapshot`: live-data snapshot for presentation prep. It
  fetches public sandbox reads without credentials and prints aggregate counts,
  ETags, latest registrations, and top relying parties without printing JWT/CWT
  bodies.
- `just deployed-cache-smoke`: optional hosted-backend proof. It skips when no
  deployed cache URL is configured, or checks a Railway/VPS cache URL with
  health, public cached reads, CLI `cached-sandbox`, and protected admin/warm
  checks when `AUGENMASS_DEPLOYED_CACHE_ADMIN_TOKEN` is set.
- Current Railway presentation cache:
  `https://cache-production-c33f.up.railway.app/api`. On 2026-06-24,
  `just deployed-cache-smoke-required` passed against it with the Railway admin
  token, then passed again with `schema fetch: HIT`.
- `just deployed-cache-guard-smoke`: no-network local guard proving required
  hosted-cache proof refuses `http://`, loopback, and private-IP API bases.
- `just cache-public-bind-guard-smoke`: no-network local guard proving
  public cache binds refuse missing admin tokens, empty RP allowlists, unsafe
  upstreams, and `--max-entries 0` before listening.
- `just cloudflare-containers-typecheck`: proves the optional Cloudflare
  Containers Worker adapter compiles locally without deploying it.
- `just docker-smoke`: builds the Docker image locally, runs the cache backend
  container, checks `/api/health`, verifies it runs as uid `10001`, and proves
  admin-token protection.

The required hosted/live gates are intentionally separate from `shipping-smoke`
because they need environment-specific secrets or more time:

- `just deployed-cache-smoke-required` / `just hosted-release-proof`: hosted
  cache readiness. These fail unless `AUGENMASS_DEPLOYED_CACHE_API_BASE` points
  at an `https://` non-local hosted cache backend and
  `AUGENMASS_DEPLOYED_CACHE_ADMIN_TOKEN` is set.
- `just live-sandbox-smoke-required` / `just sandbox-readiness-proof`: live
  sandbox readiness. These fail unless sandbox credentials are configured, then
  run the non-mutating sandbox rehearsal for the selected relying party.
- `just docker-smoke-no-cache`: the Docker runtime smoke with Docker layer cache
  disabled, useful as a final pre-demo burn-in.

Use the smaller gates when you are only touching one surface:

```sh
just plugin-smoke
just plugin-only-smoke
just claude-plugin-smoke
just codex-plugin-smoke
just serve-smoke
just live-cache-smoke
just public-sandbox-snapshot
just deployed-cache-guard-smoke
just cache-public-bind-guard-smoke
just deployed-cache-smoke
just deployed-cache-smoke-required
just hosted-release-proof
just cloudflare-containers-typecheck
just live-sandbox-smoke
just live-sandbox-smoke-required
just sandbox-readiness-proof
just docker-smoke
just docker-smoke-no-cache
```

`live-cache-smoke` intentionally touches `https://sandbox.eudi-wallet.org/api`.
It does not use sandbox credentials. `live-sandbox-smoke` skips without
credentials, dry-runs sandbox registration when credentials are present, and
only writes if `AUGENMASS_LIVE_SANDBOX_WRITE=1` is set. The Docker smokes
require a running Docker daemon. None of these gates starts remote GitHub CI.

## Stable rehearsal sequence

`just demo-run` runs the offline presentation sequence from the resolved CLI
binary: `AUGENMASS_DEMO_BIN`, then `AUGENMASS_BIN`, then the bundled plugin
binary. Use `just plugin-demo-run` when you specifically want to prove the
private-preview plugin artifact. The sequence uses only committed fixtures and
treats the intentional findings as successful proof points, so no sandbox
credentials or phone wallet are needed.

The sequence is:

```sh
./scripts/demo-run.sh
```

Good narration anchors:

- `Detected: OpenID4VP authorization request (JAR)`
- `response_mode: direct_post.jwt`
- `DOCTOR-X5C-STRING` and `DOCTOR-CLIENT-ID-X509HASH`
- `OVER-ASK` with `Suggested minimal request: age_equal_or_over.18`
- `OK: no over-ask, no format errors`
- `VERIFIED`, `holder binding: true`, and `trust anchored: true`
- `REJECTED [Revoked]: credential is revoked`

Avoid for the five-minute proof unless rehearsed immediately beforehand: live
`sandbox`, `--live-status`, full phone-wallet scans, and
`--unsafe-debug-artifacts`. Those are real capabilities, but they are the parts
most likely to depend on credentials, network, or device state. If a real phone
run is used, gate the claim with `docs/PHONE_WALLET_PROOF.md` and
`evidence assert-live`.
