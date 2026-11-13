# Changelog

All notable changes to the Augenmaß Workbench are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

House style note: this file does not carry release dates. The project does not
imply wall-clock timing for releases.

## [Unreleased]

## [0.4.0]

This release adds request signature verification (`verify request`), compares
requested and registered claims as claims path pointers, segment by segment,
and states that a registration certificate is decoded and not verified.

### Added

- `verify request`: full JAR (JWT-Secured Authorization Request) signature
  verification, the request-side counterpart to `verify presentation` and the
  first v0.4.0 roadmap item. It proves the request was signed by the key in its
  `x5c` leaf (ES256 only; `none` and any alg-confusion attempt are rejected
  before any key handling), that an `x509_hash` `client_id` binds to that leaf,
  and, with `--anchor`, that the leaf chains directly to a trust anchor within
  its validity window. Missing `client_id` or any scheme other than `x509_hash`
  rejects with `JarClientIdUnbound`; a mismatched `x509_hash` value rejects with
  `JarClientIdMismatch`. `--now` pins the verification clock (anchor windows and
  the request `exp`/`nbf`); it exits 1 when not verified, unbound, untrusted, or
  expired, and emits `--json`. The check lives in the pure engine as
  `augenmass_core::jar` (a new module beside `verify` and `trust`), reusing the
  P-256 primitives and `trust::leaf_der_trusted_at` (a new leaf-DER anchoring
  helper shared with the SD-JWT issuer path). New fixture:
  `fixtures/certs/eudiplo-verifier-leaf.pem` (the captured request's self-signed
  leaf, used as a self-anchor). Deferred: non-ES256 algorithms, key resolution
  other than the `x5c` leaf, full RFC 5280 path validation, and support for any
  client identity scheme beyond `x509_hash`.
- Claim path test vectors: `fixtures/claim-paths/path-vectors.json`, one case
  per coverage rule (pointer cases for SD-JWT VC and mdoc paths, credential
  cases for format and type matching, requests without `claims`, and
  `claim_sets`), each with the format, the registered paths, the requested
  path, the expected result (`covered`, `not_covered`, or `invalid`), a reason
  and the OpenID4VP section. Invented names only; Apache-2.0, and the header
  states that other tools may reuse the set. `tests/claim_paths.rs` runs it and
  checks, for every registration fixture in the repository, that a request of
  exactly its registered claims is never flagged.
- Honest notice for registration certificates: `audit --cert`, `decode
  regcert`, `inspect` on a certificate, and a non-empty `list` print
  `Registration certificate: payload decoded; signature, issuer and revocation
  status not verified.` (for `audit` right under the verdict line, on the OK
  and the over-ask path). The JSON of `audit`, `decode regcert` and `inspect`
  carries `registration_certificate`: `{"decoded": true, "signature_verified":
  false, "issuer_verified": false, "revocation_checked": false}`, and `null` on
  an `audit` without `--cert`, whose verdict keeps saying `registration not
  evaluated`.
- `check` (and the `register` gate): new blocking findings `CHECK-CLAIM-PATH`
  (a credential without a non-empty `claims[]`, or a path that is not a claims
  path pointer: a boolean, a negative or fractional number, an empty array,
  or for mso_mdoc anything but two strings),
  `CHECK-CREDENTIAL-META` (no `format`, or no valid `vct_values` for SD-JWT VC
  or `doctype_value` for mso_mdoc), and `CHECK-UNREADABLE-REQUEST`. Before, a
  body such as `["birthdate", true]` skipped the over-ask guardrail and passed
  with exit 0.

### Fixed

- Registration comparison (`audit --cert`, `check`, `serve`): a request is now
  compared with the registration as OpenID4VP 1.0 claims path pointers,
  segment by segment and never as joined strings. Before, the decoder dropped
  `null` segments and registration matching compared dotted strings, so a
  request identical to its registration with `["nationalities", null]` was
  flagged as over-asking, a registered `["address"]` did not cover
  `["address", "locality"]`, one segment `"address.locality"` matched
  `["address", "locality"]`, and a request for another credential type passed
  because all registered credentials were merged. Now: an equal path is
  covered (`null` included); a registered `null` covers a requested index; a
  registered object covers its members; a requested `null` under a registered
  index, a parent of a registered member, `"0"` against `0`, and a dotted
  segment are not covered; mdoc paths are covered only by an equal
  `[namespace, element]` of two strings, and an mdoc path of another shape
  (`[namespace, null]`, an integer element, one or three components) is
  invalid and covers nothing, even an equal registered path (OpenID4VP 1.0
  section 7.2.1). The credential is matched by format and type first
  (`vct_values`, `doctype_value`); a request accepting several types must be
  within the registration for each; a request without a type, an empty or
  invalid registered path, and a registered credential with malformed type
  metadata authorize nothing. A credential requested without `claims` is
  within the registration when its type is registered and otherwise gets one
  row beyond it; so does a credential whose `claim_sets` select no claim
  (`[[]]`), since its mandatory claims are still presented. With `claim_sets`,
  only claims named in some combination are audited (every declared claim
  when a combination names an unknown id); with `credential_sets`, only
  credentials named in some option are audited (every credential when an
  option names an unknown id), so an unselected credential is no longer
  flagged. Engine: `regcert::PathSeg`, `parse_claim_path`,
  `valid_claim_path`, `path_covers`,
  `requested_types`, `RegisteredScope::covers`, and `RegisteredCredential`
  gains `doctype_value`; `claims` keeps typed segments and `fingerprint`
  includes the doctype and typed paths. Purpose: an SD-JWT segment that
  itself contains a dot no longer maps to a nested model key.
- `check` reads each body credential in its own format, type and raw paths
  (before, every body was read as a German PID SD-JWT VC with string
  segments), so `null` and integer segments and mso_mdoc bodies are judged.
- `baselines` text lists a baseline's mdoc elements (`mdoc elements:
  eu.europa.ec.eudi.pid.1/place_of_birth`) as the JSON `mdoc_elements` does.
- The PID claim model has rows and labels for `place_of_birth.region`,
  `place_of_birth.country`, `address.region`, `address.formatted` and
  `address.house_number`, so they appear in the disclosed-vs-withheld rows.
- `bank_kyc` baseline: adds `place_of_birth.locality` and `nationalities`, so a
  request with the German identification set for a natural person (GwG § 11
  Abs. 4 Nr. 1: name, place and date of birth, nationality, address) is no
  longer flagged as over-asking on 2 of 9 claims. The baseline note cites the
  statute and keeps the curated-judgment qualification; passing the check does
  not establish complete identification or AML compliance. Place of birth and
  nationality stay over-asking under `age_gate_18`, `event_checkin`, and
  `car_rental`.
- `bank_kyc` baseline, remaining false positives: every spelling of the GwG
  attributes in the EU PID SD-JWT VC and mdoc encodings is now within the
  baseline in its own format: SD-JWT `place_of_birth.region` and `.country`,
  `address.region`, `address.formatted`, `address.house_number`, the flat
  `birth_place` and `birth_country` of the ERICA fixture, and `nationalities`
  with an element selector (`null` or an index); mdoc `resident_state`,
  `resident_address`, and the structured `place_of_birth` element (new
  baseline field `mdoc_elements`, a list of `[namespace, element]` paths
  compared segment by segment, so a path such as
  `["eu.europa.ec.eudi.pid", "1.place_of_birth"]` does not match). Whole SD-JWT `address` and `place_of_birth`
  objects, spellings of the other format, other namespaces, and attributes
  outside the list stay over-asking.
- Over-ask audit of EU PID mdoc requests: a `mso_mdoc` path
  `["eu.europa.ec.eudi.pid.1", element]` is now judged for purpose under the
  matching claim-model key (`given_name`, `family_name`, `birth_date`,
  `nationality`, `resident_street`, `resident_city`, `resident_postal_code`,
  `resident_country`, and the legacy text element `birth_place`), so for example
  an mdoc `given_name` is no longer flagged under `bank_kyc`, `event_checkin`, or
  `car_rental`. New engine function `inspector::canonical_claim_key`. The
  mapping is format-aware: an mdoc path without a claim-model key (another
  namespace, `age_over_NN`, the structured `place_of_birth`) is judged only
  against the baseline's `mdoc_elements`, never against a model key, so an
  mdoc path such as `["address", "resident_city"]` cannot borrow an SD-JWT
  spelling. Registration and over-disclosure matching still compare raw
  paths, so an alias never authorizes a path in another format or another
  SD-JWT path (`address.locality` does not authorize a disclosed
  `address.resident_city`), and every requested path keeps its own verdict row
  (`counts.requested` is unchanged). The disclosed-vs-withheld rows map
  disclosed SD-JWT keys to model keys as well. A disclosed member of a
  requested object or array, or an element of an array requested with a
  wildcard, is no longer reported as over-disclosed.
- Article 5b(3) quotation: the over-ask legal basis now quotes Regulation (EU)
  No 910/2014, Article 5b(3) verbatim ("Relying parties shall not request
  users to provide any data other than that indicated pursuant to paragraph 2,
  point (c).") and names the amended act instead of the amending Regulation
  (EU) 2024/1183. The other two legal-basis entries are unchanged.
- A DCQL query whose `credential_sets` carry an empty option (`"options":
  [[]]`) is rejected as malformed by `audit --request` and `inspect`, the
  offline replay of an evidence bundle skips its over-disclosure analysis as
  for any query it cannot parse, and `validate dcql` reports it as
  the blocking finding `DCQL-SET-OPTION-EMPTY`. OpenID4VP 1.0 section 6.2
  requires every option to name at least one credential query. Before, such
  a query was accepted, no credential was selected, and the audit judged
  nothing and exited 0.

These fixes ship in the 0.4.0 CLI and its release archives. The plugin
binaries committed under `plugins/augenmass-workbench/` are unchanged at this
tag and keep the old `bank_kyc` baseline, the old mdoc behaviour, the old
Article 5b(3) wording (binary and skill reference files), and the old
dependency set until the plugin bundle is rebuilt from the 0.4.0 release
archives.

### Security

- `Cargo.lock` refreshed within the existing manifest requirements
  (`CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback cargo update`; 186 lock
  changes, among them rustls 0.23.46, rustls-webpki 0.103.17, webpki-roots
  1.0.12, h2 0.4.20, quinn-proto 0.11.19, tokio 1.54.1, and anyhow 1.0.104).
  No manifest, no `rust-toolchain.toml`, and no direct dependency major version
  changed, and no `--precise` downgrade was needed: every resolved package
  declares a `rust-version` of 1.92 or lower. `cargo audit` went from 20
  vulnerabilities and 14 warnings to 4 vulnerabilities and 10 warnings (8
  unmaintained, 2 unsound, 0 yanked). The remaining advisories need major
  upgrades and are deferred: RUSTSEC-2026-0459 (libsqlite3-sys 0.28 via rusqlite
  0.31), RUSTSEC-2026-0387 (crypto-bigint 0.3 and 0.5 via rsa 0.6 and
  elliptic-curve 0.13), RUSTSEC-2023-0071 (rsa 0.6 via ssi 0.16), and the
  unsound RUSTSEC-2023-0126 (im 15) and RUSTSEC-2026-0255 (sized-chunks 0.6),
  both via ssi 0.16. Each is listed with its removal condition in
  `docs/RELEASE.md`, "Dependency audit".

### Changed

- `decode regcert`, `inspect` and `audit --cert` refuse a registrar list with
  more than one entry and name the ids; before, the first entry was used
  silently. A list with one entry still works.
- New `.github/workflows/check.yml`: format, clippy, locked tests, and
  `cargo audit --deny unsound --deny yanked` (with one documented `--ignore` per
  accepted advisory) on pushes to `main`, on pull requests against `main`, and
  on demand, on GitHub-hosted `ubuntu-latest` only. `ci.yml` and
  `blacksmith-smoke.yml` stay manual, and `release.yml` stays tag-only.
- `scripts/ci-credit-guard.sh` allows branch-push and pull-request triggers only
  for a workflow that meets a strict profile (literal `ubuntu-latest` runners,
  one top-level read-only permissions block, no secret or token reference, only
  a SHA-pinned `actions/checkout` where each checkout step sets
  `persist-credentials: false` in its own `with:` block and passes no other
  input than `fetch-depth`, a job timeout, plain block YAML). The rule is
  fail-closed and checked line by line, without parsing expressions: in such
  a workflow `${{` may appear only on a line that equals an entry of a short
  allow-list in the guard, and `if:` keys, backslashes, quoted or spaced keys,
  and keys starting with `GITHUB_`, `RUNNER_`, `ACTIONS_`, or `INPUT_` are
  rejected. For every workflow, the top-level keys and the `on:` block must use
  a small plain block grammar (`push`, `pull_request`, `workflow_dispatch`,
  with `branches:` or `tags:` lists), so quoted, escaped, or spaced event keys,
  flow values, event lists, and an inline `on: push` cannot change the
  classification. Every workflow must also start its root mapping at column 0
  and hold only printable ASCII, tabs, and LF line breaks, so neither an
  indented root with a multi-line scalar nor a carriage return or Unicode line
  separator can hide structure from the line matcher.
  `scripts/ci-credit-guard-cases.sh` (`just
  ci-credit-guard-cases`) runs 71 committed regression cases under
  `tests/ci-credit-guard/`.
- Docs: `docs/RELEASE.md`, `docs/GUARDRAILS.md`, `docs/SHIPPING_STATUS.md`, and
  `AGENTS.md` describe the new automatic workflow. `docs/SHIPPING_STATUS.md` no
  longer lists third-party registration counts or another relying party's
  identifier, and `README.md` no longer advertises the macOS `.pkg`.

## [0.3.0]

This is the live-wallet proof release. It promotes Augenmaß from an offline
artifact and registrar guardrail toolkit into a demonstrable EUDI Wallet
workbench: a real phone wallet can scan a QR, fetch the signed OpenID4VP request,
post an encrypted response through the hosted relay, and leave behind a redacted
evidence bundle that can be verified later. The macOS plugin binaries are
refreshed from this branch, and the Linux/Windows plugin binaries are refreshed
from the same `v0.3.0` release workflow artifacts.

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

- The plugin bundle binaries are refreshed from the current release branch for
  macOS Apple Silicon, macOS Intel, Linux x64, and Windows x64; each target now
  prints `augenmass 0.3.0`.
- Documentation now treats `0.3.0` as the presentation/demo release line.
- `serve --unsafe-debug-artifacts` keeps the first canonical artifact when a
  wallet retries the response after success, and writes later captures with a
  suffix such as `direct-post-2.body`.

### Fixed

- iOS wallet KB-JWT clock-skew tolerance for small future `iat` values.
- Evidence replay mismatch after duplicate wallet POSTs by preserving the first
  canonical unsafe artifact.
- Stale macOS plugin binary behavior: the committed macOS plugin launcher now
  accepts the newest phone proof bundle and reports `walletOverDisclosureAnalyzed`.
- Stale Linux and Windows plugin binary behavior: bundled non-macOS targets now
  come from the same `v0.3.0` workflow artifacts as the release line, not the
  older `v0.2.0` release.

### Security

- The hosted relay uses an operator token for run creation and is wallet-only by
  default, reducing the public attack surface.
- Trace and evidence docs now explicitly separate projector-safe redacted output
  from sensitive local bundles and raw unsafe artifacts.

### Known Caveats

- The hosted relay is suitable for controlled demos and operator use; a broader
  public service needs operational policy, monitoring, and abuse controls.
- The proof bundles are sensitive and intentionally not committed.
- The token-status-list signer is operator-supplied trust material. The status
  signer used by `serve --status-signer` and `evidence prove-trust-status
  --status-key` is not cryptographically bound to the issuer trust anchor
  (`--trust-anchor`): the verifier trusts whatever signer the operator passes, so
  a signer that matches a forged status list will verify it. This is intentional
  and real-world-consistent (the Bundesdruckerei preprod PID provider signs its
  status list with a key deliberately separate from the issuer root); anchoring
  the status signer to the issuer is a later step. See the code caveat in
  `crates/augenmass-core/src/status.rs:21-27`.

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
