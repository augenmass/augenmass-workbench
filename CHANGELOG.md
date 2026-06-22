# Changelog

All notable changes to the Augenmaß Workbench are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

House style note: this file does not carry release dates. The project does not
imply wall-clock timing for releases.

## [Unreleased] / [0.2.0]

Version 2 grows the workbench from an audit, debug, and repair helper into a
single cohesive command-line toolkit over the whole EUDI Wallet artifact surface,
for developers and auditors alike. The v1 workbench shipped six commands
(`generate`, `check`, `doctor`, `register`, `list`, `clone`) and used only part
of the engine. Version 2 surfaces the entire `augenmass-core` engine behind one
CLI and adds net-new offline decoders. Everything except the registrar write path
runs fully offline.

### Added

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
  `decode offer`, and `decode status-list`. These decode without verifying any
  signature.
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

### Changed

- The verification engine is renamed and vendored into this repository as the
  `augenmass-core` crate. It was reused as-is from the verifier project and is
  HTTP-free and pure.
- Commands are regrouped into clear families: UNDERSTAND (`inspect`, `decode`),
  PROPORTIONALITY (`check`, `audit`, `baselines`), CRYPTO (`verify`, `x509-hash`),
  PRODUCE (`generate`), DIAGNOSE (`doctor`), and WRITE (`register`, `list`,
  `clone`).
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
  `--target` of `clone` (the local registrar-compatible store, the default) or
  `sandbox` (the real registrar, rehearsal only). Writes are scoped to one relying
  party; the tool never mints extra relying parties.

### Notes

- Offline and deterministic: every command except the registrar write path runs
  fully offline, with no network calls. Verification accepts an injectable clock
  (`--now`) so results are reproducible against the committed fixtures.
- Licensed under Apache-2.0. Open source, framed as a developer tool.
- Honest scope. `verify trust` checks that a leaf chains to a supplied anchor
  within its validity window; it is not full X.509 path validation. mdoc (ISO/IEC
  18013-5) is not yet decoded; the decoders cover SD-JWT VC, WRPRC, OpenID4VP
  request/JAR, credential offer, status list, DCQL, registration body, X.509 PEM,
  and generic JWT/JWS. The curated baselines are deliberate taste judgments, not
  Rulebook derivations.
