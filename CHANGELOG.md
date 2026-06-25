# Changelog

All notable changes to the Augenmaß Workbench are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

House style note: this file does not carry release dates. The project does not
imply wall-clock timing for releases.

## [Unreleased]

- Nothing yet.

## [0.3.0]

This is the live-wallet proof release. It promotes Augenmaß from an offline
artifact and registrar guardrail toolkit into a demonstrable EUDI Wallet
workbench: a real phone wallet can scan a QR, fetch the signed OpenID4VP request,
post an encrypted response through the hosted relay, and leave behind a redacted
evidence bundle that can be verified later. The macOS plugin binaries are
refreshed from this branch; Linux and Windows plugin binaries still point at the
published `v0.2.0` release until the next full multi-platform rebuild.

### Added

- Hosted wallet-only relay support (`serve --relay augenmass`) for real phone
  demos through `wallet.augenmass.tech`. The relay forwards only the OpenID4VP
  phone endpoints and keeps trace, inspect, evidence, session APIs, and unsafe
  debug artifacts on localhost.
- Real iOS and Android sandbox-wallet proof. Both wallets completed the
  OpenID4VP flow against `serve --relay augenmass --age-only` with the
  registrar-issued leaf; exported bundles passed `evidence verify` and
  `evidence assert-live`.
- Strict live evidence proof: `evidence assert-live` now proves the request
  object fetch, encrypted response receipt, JWE decryption, and offline
  presentation verification before a phone-wallet run can be claimed as proven.
- Wallet over-disclosure replay signal. When a captured request contains
  explicit DCQL claim paths, evidence replay can compare requested keys to
  disclosed keys and reports `walletOverDisclosureAnalyzed` separately from
  issuer trust, live status, and legal over-ask proof.
- Post-capture trust/status proof path with `evidence prove-trust-status` and
  the Bundesdruckerei preprod helper wrapper for the current sandbox PID
  material.
- Hosted and local sandbox cache proof: the cache backend can be warmed and used
  as a stable read-through mirror for public sandbox reads, with Railway
  deployment proof and a protected status surface.
- Plugin/skill documentation for the new phone-proof workflow, including
  plugin-only references so marketplace installs can guide an agent without the
  full repository checkout.

### Changed

- The macOS plugin bundle binaries are refreshed from the current release branch
  and now print `augenmass 0.3.0`.
- Documentation now treats `0.3.0` as the presentation/demo release line and
  keeps `v0.2.0` as the published cross-platform binary baseline for Linux and
  Windows until a full rebuild happens.
- `serve --unsafe-debug-artifacts` keeps the first canonical artifact when a
  wallet retries the response after success, and writes later captures with a
  suffix such as `direct-post-2.body`.

### Fixed

- iOS wallet KB-JWT clock-skew tolerance for small future `iat` values.
- Evidence replay mismatch after duplicate wallet POSTs by preserving the first
  canonical unsafe artifact.
- Stale macOS plugin binary behavior: the committed macOS plugin launcher now
  accepts the newest phone proof bundle and reports `walletOverDisclosureAnalyzed`.

### Security

- The hosted relay uses an operator token for run creation and is wallet-only by
  default, reducing the public attack surface.
- Trace and evidence docs now explicitly separate projector-safe redacted output
  from sensitive local bundles and raw unsafe artifacts.

### Known Caveats

- Linux and Windows plugin target binaries remain `v0.2.0` release binaries in
  this mixed bundle.
- The hosted relay is suitable for controlled demos and operator use; a broader
  public service needs operational policy, monitoring, and abuse controls.
- The proof bundles are sensitive and intentionally not committed.

## [0.2.0]

Version 2 grows the workbench from an audit, debug, and repair helper into a
single cohesive command-line toolkit over the whole EUDI Wallet artifact surface,
for developers and auditors alike. The v1 workbench shipped six commands
(`generate`, `check`, `doctor`, `register`, `list`, `clone`) and used only part
of the engine. Version 2 surfaces the entire `augenmass-core` engine behind one
CLI and adds net-new offline decoders. It also adds `serve`, a live
wallet-interaction debugger so a real EUDI wallet can present to the tool over
OpenID4VP and the whole exchange is traced. Static artifact commands run fully
offline. Explicit live surfaces are network by nature: registrar targets, the
cached-sandbox mirror, and the live wallet-interaction debugger.

### Added

- `plugin-only-smoke`: copies only the plugin bundle to a temporary directory
  and runs no-file generated/stdin workflows from outside the checkout, proving
  marketplace-style first-run behavior without `fixtures/` or `examples/`.
- Universal `inspect <input>`: sniff any common EUDI artifact and decode it
  ("what is this?"). It detects the type, then dispatches to the right decoder.
  Recognised types include SD-JWT VC presentation, WRPRC registration certificate
  (typ `rc-wrp+jwt`), OpenID4VP authorization request and signed JAR
  (typ `oauth-authz-req+jwt`), OpenID4VCI credential offer
  (`openid-credential-offer://` URI or JSON), OpenID4VP request URI
  (`openid4vp://`), token status list (typ `statuslist+jwt`), DCQL query (bare or
  wrapped under `dcql_query`), registrar registration body, X.509 certificate
  (PEM), and generic JWT/JWS.
- Targeted `decode` subcommands for when you already know the type:
  `decode jwt`, `decode sd-jwt`, `decode regcert`, `decode request`,
  `decode offer`, `decode status-list`, and `decode mdoc`. These decode without
  verifying any signature.
- `validate dcql`: validate a DCQL query beyond what the typed parse enforces.
  It checks that credential ids are unique, that every `credential_sets` option
  references a known credential id, and that each claim path matches its
  credential format (an `mso_mdoc` path must be `[namespace, element]`, two
  strings; an SD-JWT path must be an array of string, null, or integer segments,
  not a dotted string). Each finding has a stable id, a severity, and a fix; the
  command exits non-zero on a blocking error so it gates CI. JSON via `--json`.
- `decode mdoc`: decode an ISO/IEC 18013-5 mdoc (`mso_mdoc`), the other major
  EUDI credential format alongside SD-JWT VC. It accepts a `DeviceResponse`, a
  single `Document`, an `IssuerSigned`, or a bare `MobileSecurityObject`, given as
  raw CBOR bytes, hex, or base64/base64url, and surfaces the document type, the
  disclosed namespaces and elements (with nested CBOR rendered as JSON and large
  byte values such as a portrait shown as a length-tagged hex preview), the issuer
  authentication (the COSE_Sign1 algorithm and the X.509 chain, whose leaf
  `x509_hash` the engine computes), and the Mobile Security Object (validity
  window, per-namespace value-digest counts, and device key). `inspect` detects an
  mdoc given as hex or base64. Decode only: the COSE signature is not verified and
  value digests are not recomputed (the output says so).
- `audit` command: lint an OpenID4VP request for over-asking against a curated
  purpose baseline. Takes `--request` (the value `minimal`, the value `overask`,
  or a path to a DCQL JSON file; defaults to `minimal`), `--purpose` (one of
  `age_gate_18`, `event_checkin`, `car_rental`, `bank_kyc`; defaults to
  `event_checkin`), an optional `--cert` (a registration certificate as compact
  JWT, entity JSON, or array), and an optional `--vct` override. Exits non-zero on
  over-ask so it works as a CI gate.
- `baselines [<id>]` command: list the curated purpose baselines and the legal
  basis cited on every over-ask finding, or show one baseline in detail. The four
  baselines are `age_gate_18` (age_equal_or_over.18), `event_checkin` (given_name,
  family_name, age_equal_or_over.18), `car_rental` (given_name, family_name,
  age_equal_or_over.21), and `bank_kyc` (given_name, family_name, birthdate, and
  the four address.resident_* fields).
- Cryptographic `verify` subcommands, surfacing the engine's verification, trust,
  and status modules:
  - `verify presentation <input> --nonce <NONCE> --aud <AUD>`: verify an SD-JWT VC
    presentation end to end (issuer signature, KB-JWT, nonce and audience binding,
    vct). Supports `--vct`, `--max-age` (KB-JWT freshness, default 300 seconds),
    `--now` (an injectable verification clock in Unix seconds), `--trust-anchor`
    (anchor the issuer to a PEM rather than the leaf key), and inline revocation
    via `--status-token` plus `--status-key`.
  - `verify trust <input> --anchor <ANCHOR>`: check whether the presentation's
    issuer chains to a trust anchor, with `--now` for the validity window.
  - `verify status <input> --token <TOKEN> --key <KEY>`: check a presentation's
    revocation status against a status-list token, fail-closed and offline.
  - `verify status-list --token <TOKEN> --key <KEY> --index <INDEX>`: verify a
    status-list token and read one index directly.
- `x509-hash <input>`: compute the `x509_hash:<base64url(SHA-256(leaf-cert-DER))>`
  client_id binding from a JAR's x5c leaf, a PEM certificate, or base64 DER. Pass
  `--client-id` to compare against a claimed value; mismatch exits non-zero.
- `generate dcql --claim <path> ...`: build a DCQL query from one or more claim
  paths (dotted or slashed, repeatable). Joins `generate regbody`, which now
  carries flags for `--use-case` (age-check), `--over-broad`, `--rp`,
  `--support-uri`, `--privacy-policy`, and `--purpose`.
- Global `--json` flag on the read-only commands: emit machine-readable JSON
  instead of the text rendering, for agents and CI.
- Input ergonomics across every artifact argument: each accepts a file path, an
  inline value, or `-` for stdin.
- The full `augenmass-core` engine is now surfaced. v1 used only the inspector,
  regcert, and pid modules; v2 also exposes disclosure (SD-JWT disclosed claims),
  verify (SD-JWT VC and KB-JWT verification with an injectable clock), status
  (token status list revocation), trust (X.509 leaf chains-to-anchor plus validity
  window), and crypto (JWE decrypt, x5c to JWK, leaf_cert_hash).
- `serve`: a live wallet-interaction debugger (a verifier-in-a-box). It runs a
  local OpenID4VP verifier for the German PID profile (x509_hash client_id, signed
  request object by reference, `direct_post.jwt` ECDH-ES encrypted response, the
  registration certificate embedded as `verifier_info`) so a real EUDI wallet can
  present to it, and records the whole exchange as a per-session trace:
  SESSION_CREATED, REQUEST_BUILT, REQUEST_OBJECT_FETCHED, RESPONSE_RECEIVED,
  RESPONSE_DECRYPTED, VERIFIED or REJECTED, STATUS_CHECKED (with `--live-status`
  and a trust anchor), and OVER_ASK_ANALYZED. The trace is redacted by default
  (shape and digests only; no raw bodies, no disclosed claim values). The trace is
  available three ways: live on the console
  (color-coded on a TTY), as a browser timeline at `/trace/<session>` that
  refreshes while the exchange is in flight, and as JSON at
  `/api/trace/<session>`; `/api/sessions` lists the sessions seen this run. Flags:
  `--port`, `--host`, `--public-url`, `--key` and `--leaf` (sign with the real
  registrar leaf so the client_id matches the registration; otherwise a throwaway
  development certificate is used), `--purpose`, `--trust-anchor` (enforce PID
  issuer trust), `--live-status` (resolve token-status-list revocation over the
  network), `--quiet`, and `--unsafe-debug-artifacts` (opt-in, off by default:
  write full-fidelity raw wallet material to local disk for private debugging,
  never served over HTTP). This is the headline new capability: the tool now
  debugs the actual wallet interaction, not just static artifacts. It is adapted
  from the verifier project's `verifier-service`, reusing the same engine.
- `evidence` command group: export, verify, and replay local audit bundles from
  `serve --unsafe-debug-artifacts` session directories. `evidence export
  <session-dir> --out <bundle.json>` writes a sensitive JSON bundle with raw local
  artifacts, canonical entry hashes, a deterministic redacted replay trace, and an
  optional ES256 signature via `--signing-key`. `evidence verify <bundle.json>`
  checks entry lengths, entry hashes, replay determinism, the canonical payload
  hash, and the optional signature (with `--verify-key` when supplied). `evidence
  replay <bundle.json>` renders the projector-safe timeline and never prints raw
  wallet material. When the capture contains `direct-post.body`,
  `session-enc-key.jwk`, `verification-context.json`, and an encrypted response,
  replay decrypts and verifies the SD-JWT VC offline against the captured nonce,
  audience, vct, clock, and freshness window.
- `cache serve`: a server-side read-through cached-sandbox mirror for public
  sandbox GET routes. It stores successful upstream responses in SQLite with a
  bounded entry cap, exposes public provenance headers (`x-augenmass-cache`, cache
  key, fetched-at, and SHA-256), serves fresh hits locally, and falls back to
  stale cached data when a refresh fails. Full upstream URLs stay in protected
  cache status instead of public response headers. `list --target cached-sandbox`
  reads through it, while confirmed writes to `--target cached-sandbox` are
  refused before any network call.
- Deployable cache backend hardening: `cache serve` now supports explicit bind
  host, `PORT`, persistent database path, upstream timeout, TTL, max entries,
  public health check, and optional admin-token protection for cache status and
  refresh endpoints. The repository includes a Dockerfile and Railway
  configuration for the current Axum plus SQLite backend.
- Native CI and release automation: GitHub Actions now offers a manual fmt,
  clippy, test, and release-build matrix on Linux, Windows, and macOS runners,
  with release archives for Linux x86_64, Windows x86_64, macOS Intel, and macOS
  Apple Silicon. The CI gate is manual-only to conserve private-repo runner
  minutes.
- `just ci-credit-guard`: a local workflow-trigger guard that fails if GitHub
  Actions can run on normal branch pushes or pull-request activity. The only
  allowed push trigger is the deliberate tag-only release path.
- Cache deployment proof is stricter: `deployed-cache-smoke-required` now
  requires an admin token, and Docker smoke restarts the cache container against
  the same volume to prove cached data survives a container restart.
- `just release-zip-layout-smoke`: a local no-runner-credit check for the
  Windows-style `.zip` archive layout. It proves packaging/extraction mechanics
  without claiming native Windows execution unless run on Windows.
- Local release proof is split into plugin-free CLI proof
  (`local-cli-release-proof`) and presenter plugin proof
  (`presenter-plugin-proof`), with `local-release-proof` composing both.
- `platform-smoke` now includes Linux arm64 in its default probe list and skips
  it when the target or cross C toolchain is not installed.
- `just demo-proof`, `just demo-run`, and `docs/DEMO_PROOF.md`: a focused,
  offline proof gate and rehearsal sequence for the agent-first presentation
  story. It pins the stable commands for artifact identification, over-ask
  guardrails, JAR fix guidance, offline crypto verification, safe demo
  targets, the request-side wallet debugger, and the cached-sandbox mirror.

### Changed

- The verification engine is renamed and vendored into this repository as the
  `augenmass-core` crate. It was reused as-is from the verifier project and is
  HTTP-free and pure.
- Commands are regrouped into clear families: UNDERSTAND (`inspect`, `decode`),
  PROPORTIONALITY (`check`, `audit`, `baselines`), CRYPTO (`verify`, `x509-hash`),
  PRODUCE (`generate`), DIAGNOSE (`doctor`, `validate`), DEBUG (`serve`),
  EVIDENCE (`evidence`), and WRITE (`register`, `list`, `clone`).
- `check` now gates a registrar registration body before a write on both over-ask
  and format. It catches the registrar DTO traps: `claims[].path` must be an array
  of segments (`["age_equal_or_over","18"]`, not the string `"age_equal_or_over.18"`);
  use `credentials`, not `provided_attestations`; `purpose` is a list of
  `{lang, content}`, not a bare string; `privacy_policy` must be a valid URL;
  `support_uri` is any non-empty contact string (email, phone, or URL) and is not
  over-validated as a URL. It exits non-zero on over-ask or a blocking format
  error, 0 when clean.
- `doctor` continues to diagnose verifier signed-request and JAR gotchas: x5c must
  be a list of strings even for a single cert; `client_id` must be the
  `x509_hash:` binding (compute it with `x509-hash`); set
  `Content-Type: application/json` on every POST. Exits non-zero when it finds
  issues.
- `register`, `list`, and `clone` are retained with the same guardrails. `register`
  is a dry-run by default, requires `--yes` to write, and requires `--force` to
  write past an over-ask warning; it refuses (non-zero) on over-ask without
  `--force` and bails on blocking format errors. Both `register` and `list` take a
  `--target` of `clone` (the local registrar-compatible store, the default),
  `cached-sandbox` (read-only cached sandbox reads), or `sandbox` (the real
  registrar, rehearsal only). Writes are scoped to one relying party; the tool
  never mints extra relying parties.

### Notes

- Offline and deterministic where it matters: artifact decoding,
  proportionality, generation, and offline verification run without network
  calls. Verification accepts an injectable clock (`--now`) so results are
  reproducible against the committed fixtures. Live surfaces are explicit:
  registrar targets, `cache serve`, and `serve`. `serve` is network by nature (a
  real wallet connects to it); its verification logic is the same offline engine,
  exercised by an integration test on an ephemeral port and a unit test against
  the committed oracle fixtures.
- `serve` hardening (after an adversarial review of the new code): the
  credential-controlled status-list URI fetch is guarded against SSRF (https
  only, redirects disabled, a request timeout, and a deny list for loopback,
  private, link-local, and other non-public addresses); a status-list transport
  or signature failure is reported and traced as an infrastructure error, never
  as a revocation; a revoked or suspended credential emits an explicit REJECTED
  trace event so the timeline ends red; a multi-credential `vp_token` is flagged
  loudly rather than silently reduced to the last presentation; the startup
  banner always prints the real bind address and warns when `--public-url` does
  not match it; and `--public-url` is normalised to end in '/'.
- `serve` live-status fetch hardening (second pass): the fetch is now pinned to
  the addresses vetted before connecting, so reqwest no longer re-resolves the
  hostname at connect time; this closes the DNS-rebinding / TOCTOU window between
  the IP check and the connection. The non-public deny list now normalises
  IPv4-mapped IPv6 (so `::ffff:127.0.0.1` and `::ffff:169.254.169.254` are denied)
  and adds the CGNAT range `100.64.0.0/10`. The response body is read under a size
  cap rather than unbounded.
- `serve` trace is redacted by default: the unauthenticated `/api/trace/<session>`
  and the browser timeline no longer carry the raw POST body or decrypted claim
  values. The received response and the decrypted payload are recorded as shape
  only (length, SHA-256, field names, `vp_token` presence and shape), and
  `VERIFIED` lists disclosed claim keys only.
- `serve` rejects a plaintext `direct_post`: the verifier advertises the encrypted
  `direct_post.jwt` profile, so an unencrypted response is refused (HTTP 422) and
  traced as `REJECTED` rather than verified.
- `serve --unsafe-debug-artifacts <dir>` (opt-in, off by default): writes
  full-fidelity local debug artifacts (raw `direct_post` body, decrypted response
  when an encrypted wallet response is decrypted, per-session private key, signed
  request object, decoded request payload, and verification replay context) to
  `<dir>/<session>/` with owner-only permissions on Unix (dirs `0700`, files
  `0600`) and a sensitive-marked `debug-manifest.json` carrying platform handling
  caveats, recorded in the trace as `ARTIFACT_SAVED` with file name, label,
  length, SHA-256, and the redaction fields `unsafeDebugArtifacts`,
  `pathRedacted`, `redacted`, and `redaction`. Never served over HTTP. This
  restores raw-material debugging for developers who explicitly opt in, after the
  default trace was made safe.
- `serve` now mints a fresh ephemeral response-encryption key per Authorization
  Request, advertised in that request's client metadata, used once, and dropped
  after the response is processed (and on the reject and malformed-parse paths).
  No response-encryption key is shared across sessions. This aligns with HAIP's
  preference for a per-request ephemeral key and does not affect the offline
  `verify` commands.
- Licensed under Apache-2.0. Open source, framed as a developer tool.
- Honest scope. `verify trust` checks that a leaf chains to a supplied anchor
  within its validity window; it is not full X.509 path validation. The decoders
  cover SD-JWT VC, ISO 18013-5 mdoc (structure only; the COSE signature and value
  digests are not verified), WRPRC, OpenID4VP request/JAR, credential offer,
  status list, DCQL, registration body, X.509 PEM, and generic JWT/JWS.
  Cryptographic mdoc verification (COSE_Sign1 plus value-digest matching plus
  device binding) is later work, mirrored on the SD-JWT side by `verify`. The
  curated baselines are deliberate taste judgments, not Rulebook derivations.

## [0.1.0]

Initial hackathon release. This was the seed workbench: a Claude Code oriented
skill and Rust CLI around the registrar workflow and over-ask guardrail.

### Added

- `generate`: create a proportionate registration body.
- `check`: catch over-asking and registrar body shape mistakes before writes.
- `doctor`: diagnose signed request and JAR gotchas.
- `register`: guarded registrar write path with dry-run by default.
- `list`: read registrations back for a relying party.
- `clone`: run a local registrar-compatible store for offline rehearsal.

### Notes

- Focused on the winning hackathon story: an agent can explain why a relying
  party is asking for too much data and produce the smaller, safer version.
- The deeper verifier engine, live wallet debugger, hosted relay, evidence
  replay, cache backend, and cross-platform plugin bundle arrived later.
