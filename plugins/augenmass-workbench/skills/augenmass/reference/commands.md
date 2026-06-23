# Augenmaß Workbench: command reference

Natural-language intents mapped to exact `augenmass` commands. Every command below was verified against the real binary (`augenmass 0.2.0`). Examples use `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass"` so they run from inside the skill; substitute a local build such as `./target/debug/augenmass` when working in the repo directly.

## Conventions that apply everywhere

Input ergonomics: artifact arguments such as `<INPUT>`, `<BODY>`, and `<REQUEST>` accept a file path, an inline value, or `-` for stdin. So `... check examples/min.json`, `... check '{"rpId":...}'`, and `cat body.json | ... check -` are all equivalent. `audit --request` accepts `minimal`, `overask`, a DCQL file, inline DCQL JSON, or `-`; `--cert` is a file path.

The `--json` flag: available on read-only commands that render machine output. It emits JSON instead of the text rendering, for agents and CI. Add it to `inspect`, `decode`, `check`, `audit`, `baselines`, `verify`, `x509-hash`, `generate`, `doctor`, `evidence verify`, `evidence replay`, or `list` invocations.

Exit codes: commands exit non-zero on the "bad" outcome so they gate cleanly in CI. The clean outcome is exit 0. See the exit-code column on each command and the summary table at the end.

Defaults worth knowing before you type a command:
- `register` and `list` default to `--target clone` (the local store), not the sandbox.
- `register` is a dry-run by default; it writes only with `--yes`, and writes past an over-ask only with `--yes --force`.
- Demo fixtures and defaults use relying party id `2af138a8-59ea-4a84-aea3-666cafdb1369` ("Hackathon - Reza"). Do not reuse that id for a user's production relying party.
- `verify presentation` and `verify trust` use the system clock unless you pass `--now <unix-seconds>` for deterministic verification (the fixtures verify at `--now 1780435200`).
- `audit` defaults to `--request minimal --purpose event_checkin`.
- `verify presentation`, `audit`, and `generate dcql`/`generate regbody` default the expected vct to the German PID (`urn:eudi:pid:de:1`); override with `--vct` where the flag exists.

## UNDERSTAND: figure out what an artifact is and read it offline

`inspect` sniffs the artifact type and dispatches; `decode` is the type-pinned form when you already know what you hold. Neither verifies a signature.

| Intent (plain English) | Command |
| --- | --- |
| What is this blob? Auto-detect and decode anything. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" inspect <input>` |
| Same, as JSON for a script or agent. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" inspect --json <input>` |
| Read a JWT/JWS (header + payload), no verification. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" decode jwt <input>` |
| Read an SD-JWT VC: issuer claims, disclosures, KB-JWT, resolved view. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" decode sd-jwt <input>` |
| Read a WRPRC registration certificate (payload-only). | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" decode regcert <input>` |
| Read an OpenID4VP authorization request / signed JAR. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" decode request <input>` |
| Read an OpenID4VCI credential offer (URI or JSON). | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" decode offer <input>` |
| Read a token status list token. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" decode status-list <input>` |
| Read an ISO 18013-5 mdoc (mso_mdoc): namespaces, elements, issuerAuth (COSE alg + x5chain), and the MSO. Decode only. CBOR, hex, or base64. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" decode mdoc <input>` |
| Validate a DCQL query: unique ids, credential_sets references, and per-format claim paths (mdoc [namespace, element] vs SD-JWT). Exits non-zero on a blocking error. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" validate dcql <input>` |

Exit code: 0 on a successful decode. These commands are for reading, not gating.

Example:

```sh
"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" inspect fixtures/presentations/erica-vp-VALID.sdjwt
# Detected: SD-JWT VC presentation ... vct: urn:eudi:pid:de:1, disclosed claims: 2
```

## PROPORTIONALITY: catch over-asking and format mistakes (the core engine)

This is the spine: `check` gates a registration body before you write it, `audit` lints a DCQL/OpenID4VP request, and `baselines` shows the curated purpose baselines plus the legal basis cited on every over-ask finding.

| Intent (plain English) | Command | Exit on "bad" |
| --- | --- | --- |
| Is this registration body safe to write? (over-ask + format gate) | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" check <body>` | 1 on over-ask or a blocking format error |
| Same, machine-readable for CI. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" check --json <body>` | 1 (as above) |
| Does this request over-ask for a purpose? (defaults: minimal request, event_checkin) | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" audit --request <minimal\|overask\|FILE\|-> --purpose <id>` | 1 on over-ask |
| Audit a request against a purpose AND the cert's allowed attributes. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" audit --request <FILE> --purpose <id> --cert <CERT>` | 1 on over-ask |
| Audit against a non-default credential type. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" audit --request <FILE> --purpose <id> --vct <VCT>` | 1 on over-ask |
| List all curated purpose baselines and the legal basis. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" baselines` | 0 |
| Show one baseline in detail. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" baselines <id>` | 0 |

Purpose baseline ids for `--purpose` and `baselines <id>`: `age_gate_18`, `event_checkin`, `car_rental`, `bank_kyc`. The `--request` value is `minimal`, `overask`, or a path to a DCQL JSON file.

The legal basis cited on every over-ask finding:
1. eIDAS Regulation (EU) 2024/1183, Art. 5b(3): relying parties shall not request users to provide data other than that indicated for their intended use.
2. GDPR (EU) 2016/679, Art. 5(1)(c): data minimisation (adequate, relevant and limited to what is necessary).
3. EUDI ARF, registration certificate, RPRC_07: the wallet verifies requested attributes are within the registration certificate and notifies the user otherwise.

What `check` catches in a registration body: `claims[].path` must be an array of segments, not a string (`["age_equal_or_over","18"]`, not `"age_equal_or_over.18"`); use `credentials`, not `provided_attestations`; `purpose` is a list of `{lang, content}`, not a bare string; `privacy_policy` must be a valid URL; `support_uri` is any non-empty contact string (do not over-validate it as a URL).

Examples:

```sh
# Gate a body. Exits 1 here: path is a string, not an array.
"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" check examples/bad-path.json
# CHECK-PATH-STRING [blocking]: claims[].path must be an array of segments, not a string.

# Lint an over-broad request against the strictest baseline. Exits 1.
"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" audit --request overask --purpose age_gate_18
```

## CRYPTO: verify signatures, trust, and revocation

Everything here actually checks cryptography (still offline; no network). `verify presentation` is the full flow; `trust`, `status`, and `status-list` are the focused checks. Pass `--now <unix-seconds>` for deterministic, reproducible verification.

| Intent (plain English) | Command | Exit on "bad" |
| --- | --- | --- |
| Verify a presentation end to end (issuer sig, KB-JWT, nonce/aud, vct). | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" verify presentation <p> --nonce <NONCE> --aud <AUD>` | 1 if not verified |
| Same, deterministic clock, specific vct, tighter freshness. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" verify presentation <p> --nonce <NONCE> --aud <AUD> --now <SECS> --vct <VCT> --max-age <SECS>` | 1 if not verified |
| Verify a presentation and anchor the issuer to a trust anchor. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" verify presentation <p> --nonce <NONCE> --aud <AUD> --trust-anchor <PEM>` | 1 if not verified / untrusted |
| Verify a presentation and check revocation in one shot. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" verify presentation <p> --nonce <NONCE> --aud <AUD> --status-token <TOKEN> --status-key <PEM>` | 1 if not verified / revoked |
| Does the issuer chain to this trust anchor? | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" verify trust <p> --anchor <PEM>` | 1 if untrusted |
| Is this presentation revoked, per a status-list token? | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" verify status <p> --token <TOKEN> --key <PEM>` | 1 if revoked / error |
| Verify a status-list token and read one index. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" verify status-list --token <TOKEN> --key <PEM> --index <N>` | 1 if revoked at that index / error |
| Compute the x509_hash client_id binding from a cert or JAR. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" x509-hash <input>` | 0 |
| Check a claimed client_id against the computed binding. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" x509-hash <input> --client-id <CLAIMED>` | 1 on mismatch |

`verify presentation` requires `--nonce` and `--aud`. Optional flags: `--vct` (defaults to German PID), `--max-age` (KB-JWT freshness window in seconds, default 300), `--now` (verification clock in Unix seconds; omit for the system clock), `--trust-anchor`, plus the paired `--status-token`/`--status-key`. `verify trust` requires `--anchor` and accepts `--now`. `verify status` requires `--token` and `--key`. `verify status-list` requires `--token`, `--key`, and `--index`.

`x509-hash` input is a JAR (its x5c leaf), a PEM certificate, or base64 DER, given as a file/inline/`-`. The client_id format is `x509_hash:<base64url(SHA-256(leaf-cert-DER))>`. Use this command to compute the value a signed request must set as its `client_id`.

Examples:

```sh
# Full presentation verification, deterministic clock. Exits 0.
"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" verify presentation fixtures/presentations/erica-vp-VALID.sdjwt \
  --nonce b4ba2623-76a2-486b-a1f6-f1656025d07b \
  --aud https://self-issued.me/v2 \
  --now 1780435200

# Read index 42 of a status list (revoked in the REVOKED fixture). Exits 1.
"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" verify status-list \
  --token fixtures/status/status-list-REVOKED.jwt \
  --key fixtures/status/status-list-verify-key.pub.pem \
  --index 42

# Compute the binding a JAR's client_id must equal.
"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" x509-hash fixtures/certs/access-leaf.pem
# x509_hash: VE3qp3vLVkU8JyVmXkjL7CSDVxVoTFdTv5fAEwmjKOI
```

## PRODUCE: generate a proportionate registration body or a DCQL query

| Intent (plain English) | Command |
| --- | --- |
| Generate a proportionate registration body (the age check by default). | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" generate regbody` |
| Generate an intentionally over-broad body (to demo what `check` catches). | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" generate regbody --over-broad` |
| Generate a body with your own RP id, purpose, and contacts. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" generate regbody --rp <RP> --purpose <TEXT> --support-uri <CONTACT> --privacy-policy <URL>` |
| Build a DCQL query from claim paths. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" generate dcql --claim <path>` |
| Build a DCQL query from several claims. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" generate dcql --claim <path> --claim <path>` |

`generate regbody` defaults: `--use-case age-check` (the only current value), `--rp 2af138a8-59ea-4a84-aea3-666cafdb1369`, `--support-uri support@example.com`, `--privacy-policy https://example.com/privacy`, `--purpose "Age verification"`. The `--over-broad` flag produces a body that `check` rejects with exit 1, useful for demos and tests.

`generate dcql` requires at least one `--claim`. A claim path is dotted or slashed and repeatable, e.g. `--claim age_equal_or_over.18`.

Example pipeline (generate, then gate):

```sh
"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" generate regbody --over-broad \
  | "${CLAUDE_PLUGIN_ROOT}/bin/augenmass" check -
# exits 1: the over-broad body over-asks
```

## DIAGNOSE: triage a verifier signed request / JAR

| Intent (plain English) | Command | Exit on "bad" |
| --- | --- | --- |
| Why is my signed request / JAR rejected? (x5c, client_id gotchas) | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" doctor <request>` | 1 if findings |
| Same, machine-readable. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" doctor --json <request>` | 1 if findings |

`doctor` inspects an OpenID4VP signed request (the JAR, a different document from the registration body) and flags the traps that get requests rejected: `x5c` must be a list of strings even for a single cert; `client_id` must be `x509_hash:<base64url(SHA-256(leaf-cert-DER))>` (compute it with `x509-hash`); set `Content-Type: application/json` on every POST. It exits 1 when it finds problems and 0 when the request is clean.

## DEBUG: run a verifier-in-a-box and trace a live wallet interaction

`serve` runs a local OpenID4VP verifier for the German PID profile so a real EUDI wallet can present to it, and records the whole exchange as a per-session trace. It is the one command that debugs the live wallet-to-verifier flow rather than a static artifact, and it runs until interrupted (Ctrl-C). It is zero-config: with no flags it mints a throwaway development certificate, so the `client_id` is not the registered identity (pass `--key` and `--leaf` together for the real registrar leaf).

| Intent (plain English) | Command | Notes |
| --- | --- | --- |
| Run the wallet-interaction debugger (zero-config). | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" serve` | Throwaway dev cert; runs until Ctrl-C |
| Sign with the real registrar leaf so client_id matches. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" serve --key <KEY> --leaf <LEAF>` | Pass both together |
| Enforce issuer trust and live revocation. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" serve --trust-anchor <PEM> --live-status` | `--live-status` needs a trust anchor |
| Make it reachable from a phone wallet. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" serve --host 0.0.0.0 --public-url <URL>` | `--public-url` must end in `/` and be reachable from the phone |
| Suppress the live console trace. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" serve --quiet` | Still served at `/trace/:id` and `/api/trace/:id` |
| Capture full-fidelity local artifacts. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" serve --unsafe-debug-artifacts <DIR>` | UNSAFE, local only, never served over HTTP |

Flags (all optional, each with an env var where noted): `--port` (`PORT`, default 8080), `--host` (`HOST`, default 127.0.0.1), `--public-url` (`PUBLIC_URL`, default `http://127.0.0.1:8080/`, must end in `/`), `--key` (`RP_KEY_PATH`, EC private key PEM), `--leaf` (`RP_LEAF_PATH`, leaf cert PEM), `--purpose` (`PURPOSE`, default `event_checkin`), `--trust-anchor` (`TRUST_ANCHOR_PATH`, PID issuer anchor PEM; when set, the response path rejects issuers that do not chain to it), `--live-status` (`LIVE_STATUS`, default false; resolve the token-status-list over the network and reject revoked/suspended, only effective with a trust anchor), `--quiet` (suppress the live console trace), and `--unsafe-debug-artifacts <DIR>` (`AUGENMASS_UNSAFE_DEBUG_ARTIFACTS`, off by default). This command does not use `--json` and does not exit on its own.

HTTP endpoints: `GET /` (landing page and QR/deep-link), `GET /request/:id` (the signed JAR, content-type `application/oauth-authz-req+jwt`), `POST /response/:id` (the wallet's `direct_post.jwt`, returning JSON `{ status: "verified" | "rejected", reason?, inspect, trace }`), `GET /inspect/:id` (the over-ask inspector, with a `?demo=overask` variant), `GET /trace/:id` (the HTML timeline, auto-refreshing while in flight), `GET /api/trace/:id` (the trace as JSON), `GET /api/sessions` (the sessions seen this run), and `GET /health`.

Trace event codes, in typical order: `SESSION_CREATED`, `REQUEST_BUILT`, `REQUEST_OBJECT_FETCHED`, `RESPONSE_RECEIVED`, `RESPONSE_DECRYPTED`, `VERIFIED` or `REJECTED`, `STATUS_CHECKED` (only with `--live-status` plus a trust anchor), `OVER_ASK_ANALYZED`, plus `NOTE` and `ERROR`. Each event carries (camelCase JSON keys) `seq`, `at`, `atUnixMs`, `kind`, `code`, `level` (`info`/`good`/`warn`/`bad`), a one-line `summary`, and an optional redacted `detail` with shape, field names, lengths, hashes, claim keys, and reject reasons, but not raw POST bodies, decrypted payloads, or disclosed claim values. Raw material is available only through `--unsafe-debug-artifacts <DIR>`, written locally and never served over HTTP. The trace is available three ways: live on the console (ANSI color only when stderr is a TTY), the browser timeline, and JSON.

Example:

```sh
# Run it, then open the printed URL and scan the QR with a wallet.
"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" serve
# augenmass serve: wallet-interaction debugger
#   open      : http://127.0.0.1:8080/
#   client_id : x509_hash:...
#   ...        SESSION_CREATED / REQUEST_BUILT / REQUEST_OBJECT_FETCHED / ...
```

## EVIDENCE: export and replay local audit bundles

`evidence` consumes one `serve --unsafe-debug-artifacts` session directory. The source directory and bundle are sensitive because they can contain raw wallet material and the verifier session private response key. Verification and replay output stay redacted.

| Intent (plain English) | Command | Exit on "bad" |
| --- | --- | --- |
| Export one unsafe debug session directory into a bundle. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" evidence export <session-dir> --out <bundle.json>` | 1 if the source manifest or artifacts are invalid |
| Export and sign with ES256. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" evidence export <session-dir> --out <bundle.json> --signing-key <pem>` | 1 if export or signing fails |
| Verify hashes, replay determinism, and optional signature. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" evidence verify <bundle.json>` | 1 on mismatch |
| Verify against a supplied public key. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" evidence verify <bundle.json> --verify-key <pem>` | 1 on mismatch |
| Render the projector-safe replay timeline. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" evidence replay <bundle.json>` | 1 on invalid bundle |

`evidence export` writes a JSON bundle with `kind: "augenmass-evidence-bundle"`, `schemaVersion: 1`, `payloadSha256`, `sensitive: true`, raw artifacts as base64url-no-pad entries, a deterministic redacted `replayTrace`, and a machine-readable `caveats` list of handling restrictions. `evidence verify` checks each entry length and SHA-256, regenerates the replay trace, checks the canonical payload hash, and verifies the optional ES256 signature. `evidence replay` performs the same verification first, then prints only the redacted timeline.

When the capture contains `direct-post.body`, `session-enc-key.jwk`, `verification-context.json`, and an encrypted response, replay decrypts and verifies the SD-JWT VC offline against the captured nonce, audience, vct, clock, and freshness window. It does not claim trust anchoring or live-status replay.

Example:

```sh
"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" evidence export ./debug-out/<session> --out evidence.json
"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" evidence verify evidence.json
"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" evidence replay evidence.json
```

## WRITE AND TARGETS: register under guardrails, read back, run local target servers

These are the explicit live target commands. Writes are dry-run by default.

| Intent (plain English) | Command | Notes |
| --- | --- | --- |
| Dry-run a write to the local clone (default target). | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" register <body>` | Prints what would happen; writes nothing |
| Actually write to the local clone. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" register <body> --yes` | Refuses (exit 1) on over-ask; bails on blocking format errors |
| Write past an over-ask warning (deliberate). | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" register <body> --yes --force` | `--force` requires `--yes` |
| Rehearse a write against the real registrar sandbox. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" register <body> --target sandbox --yes` | Off-stage; uses the sandbox env (see below) |
| List registrations for the default relying party (clone). | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" list` | Defaults `--target clone`, `--rp 2af138a8-...` |
| List for a specific RP, from cached-sandbox, or from sandbox. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" list --target cached-sandbox --rp <RP>` | Decoded payloads |
| Run the local registrar-compatible store. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" clone serve` | Defaults `--db ./augenmass-clone.sqlite`, `--port 8080` |
| Run the clone on another port / db file. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" clone serve --port <PORT> --db <FILE>` | |
| Run the read-through cached-sandbox mirror. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" cache serve` | Defaults `--db ./augenmass-cache.sqlite`, `--host 127.0.0.1`, `--port 8081`, `--upstream https://sandbox.eudi-wallet.org/api`, `--timeout-secs 10` |
| Prewarm the cached-sandbox mirror. | `"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" cache warm --api-base <BASE> --rp <RP>` | Add `--admin-token <TOKEN>` if the backend protects refresh endpoints |

`register` defaults: `--target clone`, dry-run unless `--yes`. The guardrails: it refuses with exit 1 on over-ask unless you add `--force`, and it bails on blocking format errors regardless. `--target` accepts `clone`, `cached-sandbox`, or `sandbox`; `cached-sandbox` is read-only and refuses confirmed writes before any network call.

`list` defaults: `--target clone`, `--rp 2af138a8-59ea-4a84-aea3-666cafdb1369`. One relying party per entity, many certificates: write only under that RP and never mint extra relying parties.

Clone vs cached-sandbox vs sandbox: `clone` is a local store (no signing, no auth, no x5c) that stores payload-only JWTs and serves the registrar-compatible endpoints; its base is `AUGENMASS_CLONE_API_BASE` (default `http://127.0.0.1:8080/api`). `cached-sandbox` is a read-only mirror served by `cache serve`; its base is `AUGENMASS_CACHE_API_BASE` (default `http://127.0.0.1:8081/api`) and responses carry cache provenance headers. For deploys, bind it with `--host 0.0.0.0`, keep a persistent `--db`, and set `AUGENMASS_CACHE_ADMIN_TOKEN` so `/api/cache/status` and `/api/cache/refresh` require a bearer token. `sandbox` is the real registrar reached over OAuth; it reads `AUGENMASS_API_BASE` (default `https://sandbox.eudi-wallet.org/api`), `AUGENMASS_OIDC_TOKEN_URL`, `AUGENMASS_USERNAME`, `AUGENMASS_PASSWORD`, and the optional `AUGENMASS_OIDC_CLIENT_SECRET`. Never log, echo, or commit tokens, certs, or keys.

Example:

```sh
# Terminal 1: bring up the local store.
"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" clone serve --port 8080

# Terminal 2: write a clean body, then read it back.
"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" register examples/min.json --yes
"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" list
```

## Exit codes at a glance

| Command | Exit 0 (clean) | Exit 1 (bad) |
| --- | --- | --- |
| `inspect`, `decode`, `baselines` | success | (read-only; no gating) |
| `check` | no over-ask, no blocking format error | over-ask or a blocking format error |
| `audit` | within the purpose baseline | over-ask |
| `verify presentation` | verified | not verified |
| `verify trust` | trusted (chains to anchor) | untrusted |
| `verify status` | not revoked | revoked or error |
| `verify status-list` | index not revoked | index revoked or error |
| `x509-hash` (no `--client-id`) | computed | (no comparison) |
| `x509-hash --client-id` | match | mismatch |
| `doctor` | no findings | findings |
| `evidence verify`, `evidence replay` | bundle valid | hash, replay, or signature mismatch |
| `serve` | runs until Ctrl-C | (server; no gating) |
| `register` | dry-run or write succeeds | over-ask without `--force`, or a blocking format error |
| `list`, `generate`, `clone serve`, `cache serve` | success | (no gating) |

Read-only commands that render machine output accept `--json`. Verified against `augenmass 0.2.0`.
