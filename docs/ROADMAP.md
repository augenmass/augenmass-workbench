# Augenmaß Workbench: Roadmap

This is the forward roadmap for the `augenmass` CLI after the `v0.3.0` release. It
names the next verifier and auditor capabilities and, for each, what it is, why it
matters for EUDI Wallet relying-party tooling, and what already exists in the
codebase to build on. It is a statement of direction, not a specification. Each
item gets its own numbered, parallelization-annotated plan when it is scheduled.

`v0.3.0` already covers a lot of ground: decode and inspect for every common EUDI
artifact (SD-JWT VC, ISO 18013-5 mdoc, WRPRC registration certificate,
OpenID4VP request / JAR, OpenID4VCI credential offer, token status list, DCQL),
the over-ask engine (`check`, `audit`, `baselines`), end-to-end SD-JWT VC
cryptographic verification (`verify presentation`, `verify trust`,
`verify status`, `verify status-list`, `x509-hash`), guard-railed registrar
writes (`register`, `list`, `clone`, `cache`), the live wallet-interaction
debugger (`serve`), local evidence bundles (`evidence`), and the hosted relay and
cached-sandbox surfaces. The items below extend that base.

Two properties of the engine shape the whole roadmap. `augenmass-core` is
HTTP-free and its verification clock is injectable, so every decoder and verifier
stays deterministic and CI-reproducible against committed fixtures; anything that
touches the network stays in the shell (`clone`, `cache`, `serve`). New
capabilities are expected to keep that split.

## Suggested order

The order is a build-on-existing sequence, not a commitment; the items are
independent enough to be picked up on their own.

| # | Capability | Builds on | Effort |
|---|---|---|---|
| 1 | mdoc cryptographic verification | `decode mdoc` (`src/mdoc.rs`), the `verify` command group, `augenmass-core` crypto/trust | L |
| 2 | Full JAR signature verification | `doctor`, `decode request`, `x509-hash`, `augenmass-core` crypto | M |
| 3 | ETSI trust-list parse and validate | `verify trust`, `augenmass-core` trust, `../external/test-trust-lists` | M |
| 4 | presentation_definition decode and PE -> DCQL | the PE sniffer in `decode request`, `src/dcql.rs`, `audit` / `validate dcql` | M |
| 5 | OpenID4VCI issuer and wallet metadata inspection | `decode offer`, the artifact sniffer, the `--json` contract | M |
| 6 | SARIF output for `check` and `audit` | the structured findings in `check` / `audit` / `doctor` / `validate dcql` | S-M |

The first two items close the gap between decoding an artifact and verifying it,
mirroring what `verify presentation` already does for SD-JWT VC. The trust-list
item then feeds real published anchors into all of the verify paths. The PE
conversion and the OpenID4VCI metadata inspection widen protocol coverage, and
SARIF sharpens the CI integration the guardrail story depends on.

## 1. mdoc cryptographic verification

Verify an ISO/IEC 18013-5 mdoc the way `verify presentation` verifies an SD-JWT
VC: the issuer `COSE_Sign1` signature, the value-digest match, and device
binding.

Today `decode mdoc` (`src/mdoc.rs`) reads the structure only. The module says so
in its own header, the output prints "COSE signature and value digests are NOT
verified", and the JSON carries `"signatureVerified": false`. This item closes
that gap so the mdoc side reaches parity with the SD-JWT VC verify commands. The
verification has three parts:

- COSE signature: reconstruct the `Sig_structure` over the protected header and
  the `MobileSecurityObjectBytes` payload, and verify it against the public key
  of the `x5chain` leaf.
- Value-digest match: recompute the digest of each `IssuerSignedItemBytes` and
  compare it to the matching entry in the MSO `valueDigests`, so a disclosed
  element cannot have been altered after issuance.
- Device binding: check the MSO `deviceKey` against the `deviceSigned` /
  `deviceAuth` in a `DeviceResponse`, so the presenting device is the one the
  credential was bound to.

Why it matters: mdoc / `mso_mdoc` is the other major EUDI credential format
alongside SD-JWT VC (mDL and friends). A verifier tool that can decode an mdoc but
only cryptographically verify an SD-JWT VC has an asymmetric trust story; an
auditor needs the same "is this actually valid" answer for both formats.

What exists to build on:

- `src/mdoc.rs` already extracts everything the verifier consumes: the
  `COSE_Sign1` algorithm from the protected header, the `x5chain` (with the leaf
  `x509_hash` computed through `src/x509util.rs`), the MSO `validityInfo`, the
  per-namespace `valueDigests`, and the `deviceKey`.
- `crates/augenmass-core` does the analogous SD-JWT work: `crypto.rs` (ES256),
  `verify.rs` (`verify presentation`), `trust.rs` (leaf chains to anchor), and
  `status.rs` (fail-closed revocation). COSE ES256 is the same P-256 ECDSA
  primitive, so the signing math already lives in the engine.
- The `verify` command group (`src/commands/verify.rs`) is the natural home: a
  `verify mdoc` subcommand mirrors `verify presentation`, including the injectable
  clock (`--now`) for deterministic fixtures and optional `--trust-anchor` and
  status checks.
- Fixtures already exist: `fixtures/mdoc/issuer-signed.hex` (a real mDL
  `IssuerSigned`) and `fixtures/mdoc/device-response.hex`.

Effort: L. The decode and the ES256 primitive are already in place, but the
CBOR/COSE detail (`Sig_structure` reconstruction, tag-24 handling, and the
MAC-versus-signature `DeviceAuth` options) makes this the largest item.

## 2. Full JAR signature verification

Status: implemented as `verify request` (`augenmass_core::jar`). The paragraphs
below are the original scoping; the shipped command verifies the ES256 signature
over the request object against the `x5c` leaf (rejecting `none` and
alg-confusion), checks the `x509_hash` `client_id` binding, and, with `--anchor`,
chains the leaf to a trust anchor. Deferred for a later pass: non-ES256
algorithms, key resolution other than the `x5c` leaf (`kid`/`jwks`/DID), full RFC
5280 path validation, and `client_id` schemes other than `x509_hash`.

Verify the signature on a JWT-Secured Authorization Request (JAR), not just decode
and lint it.

`decode request` and `doctor` read and lint the JAR (`typ`, `alg`, the `x5c`
shape, the `client_id` `x509_hash` binding, `response_mode`), and `x509-hash`
computes the binding from the `x5c` leaf, but nothing verifies the JWS signature
over the request object itself. This item adds the verifier-request-side analog of
`verify presentation`: prove the request was actually signed by the key in its
`x5c` leaf, that the leaf chains to a trust anchor, and that the `client_id` binds
to that leaf.

Why it matters: a wallet, and a wallet debugger, must not act on an authorization
request it cannot authenticate. The `x509_hash` `client_id` scheme ties the
request's identity to the leaf certificate; verifying the JAR signature is what
makes that binding meaningful rather than decorative. It is the request-side
counterpart to verifying a presentation.

What exists to build on:

- `src/commands/doctor.rs` and `src/commands/decode.rs` already parse the JAR
  header and `x5c` and surface the `client_id` and its scheme.
- `src/commands/x509hash.rs` and `src/x509util.rs` already compute and check the
  `x509_hash:<base64url(SHA-256(leaf-cert-DER))>` binding.
- `crates/augenmass-core/crypto.rs` verifies ES256 JWS, and `src/jose.rs` handles
  compact JOSE decoding.
- `crates/augenmass-core/trust.rs` already does leaf-chains-to-anchor, shared with
  the mdoc chain check (item 1) and the trust-list anchors (item 3).
- Fixtures: `fixtures/requests/eudiplo-request.jwt` (a real signed JAR) plus the
  leaf and anchor material under `fixtures/certs`.

Effort: M. The pieces (JWS verify, leaf extraction, binding check, chain to
anchor) all exist; this item composes them into one JAR-verify path and decides
how strictly to treat a missing, self-signed, or otherwise unanchored `x5c`.

## 3. ETSI trust-list parse and validate

Parse an ETSI trusted list into the trust-anchor source the verify commands
already consume, validated against the sandbox fixtures in
`../external/test-trust-lists`.

The verify commands take trust anchors as hand-supplied PEM today
(`verify trust --anchor`, `verify presentation --trust-anchor`). A live EUDI
ecosystem does not hand you a PEM; it publishes signed trusted lists. This item
parses those lists (PID providers, wallet providers, registrars, relying-party
certificate providers) into the anchor set the verifiers use, and validates a list
against its schema and signature before trusting it.

Why it matters: trust in the EUDI ecosystem is list-driven. Which PID issuers are
genuine, which relying parties are registered, and which wallet providers are
recognized are all answered by trusted lists, not by a PEM a user pasted in. An
auditor tool that can only verify against a manually supplied anchor cannot answer
"is this issuer on the list the Member State actually publishes".

What exists to build on:

- `crates/augenmass-core/trust.rs` already turns anchors into a
  chains-to-anchor decision; a trust-list parser feeds that set instead of a
  single PEM.
- The fixtures are already in the tree at `../external/test-trust-lists`: JSON
  trusted lists for PID provider, wallet provider, registrar, and WRPAC / WRPRC
  providers, plus JSON schemas and JAdES (ES256) signatures. They target the ETSI
  trusted-list format (TS 119 612) and the relying-party registration attributes
  it carries (TS 119 475).
- The engine already validates JSON artifacts and ES256 signatures, so the
  schema-check and JAdES-verify steps reuse existing primitives.

Effort: M. The parsing and the schema and signature validation are bounded; the
design work is mapping list entries, with their service and status fields, onto
the anchor and registration inputs the rest of the tool expects.

## 4. presentation_definition decode and PE -> DCQL conversion

Decode a legacy Presentation Exchange `presentation_definition` and convert it to
DCQL so the whole proportionality engine works on older requests.

DCQL is the current OpenID4VP query language, and everything in the tool (`audit`,
`validate dcql`, `generate dcql`, the over-ask inspector) speaks it. Older
verifier stacks still send Presentation Exchange (`presentation_definition` with
`input_descriptors`). The sniffer already recognizes these: `inspect` and
`decode request` detect `presentation_definition` and label it "legacy PE", then
stop. This item decodes the PE structure and converts it into an equivalent DCQL
query.

Why it matters: a request the tool can label but not analyze is a blind spot in
the over-ask engine, the core IP. Converting PE to DCQL means a legacy request
gets the same over-ask audit, the same DCQL validation, and the same
minimal-request suggestion as a modern one, with the same cited legal basis
(eIDAS Art. 5b(3), GDPR Art. 5(1)(c), ARF RPRC_07).

What exists to build on:

- `src/artifact.rs` and `src/commands/decode.rs` already detect
  `presentation_definition` and route it as the request `query` field
  (`decode request` reads `dcql_query` or `presentation_definition` into
  `query`).
- `src/dcql.rs` is the typed DCQL model the conversion targets; `validate dcql`
  and `audit` consume it directly.
- Once converted, no downstream work is needed: `audit --request`,
  `validate dcql`, and the inspector already accept DCQL.

Effort: M. The conversion is a focused mapping of `input_descriptors`,
`constraints.fields` JSONPath, and `format` onto DCQL credentials and claim paths;
the edge cases (JSONPath shapes that do not map cleanly, submission requirements)
are what its own plan will scope.

## 5. OpenID4VCI issuer and wallet metadata inspection

Inspect the issuer and wallet metadata behind a credential offer, not just the
offer itself.

`decode offer` reads an OpenID4VCI credential offer: the `credential_issuer` and
the `credential_configuration_ids` it proposes. The offer is a pointer; the
substance is in the issuer metadata (`.well-known/openid-credential-issuer`), the
authorization-server metadata, and the wallet metadata. This item decodes and
inspects that metadata: the offered credential configurations and formats, the
cryptographic binding methods, and the endpoints and capabilities each side
advertises.

Why it matters: to debug an issuance flow, or to judge whether an issuer and a
wallet are compatible, you need the metadata, not just the offer. It rounds out the
ecosystem coverage; the tool already inspects the presentation side (requests,
presentations, status, trust), and this extends the same "what is this, and is it
well-formed" treatment to the issuance side.

What exists to build on:

- `src/commands/decode.rs` (`decode offer`) and `src/artifact.rs` already parse
  the credential offer and sniff `credential_configuration_ids`, so the step from
  offer to metadata has a starting point.
- The metadata is JSON, which the tool already decodes and renders
  (`src/render.rs`, `src/output.rs`), and the `--json` contract for CI already
  exists.
- Network fetches, when the metadata is resolved by URL rather than supplied as a
  file, belong in the shell alongside `clone`, `cache`, and `serve`, keeping
  `augenmass-core` HTTP-free; an offline mode that inspects a supplied metadata
  document keeps the deterministic-fixture story intact.

Effort: M. The parsing and rendering are routine; the scope is deciding how much
of the OpenID4VCI metadata surface to model, and whether to fetch metadata or only
inspect supplied documents.

## 6. SARIF output for `check` and `audit`

Emit the `check` and `audit` findings as SARIF so an over-ask surfaces as a
code-scanning alert in CI. This is the last un-ported idea carried over from an
earlier codex experiment.

`check`, `audit`, `doctor`, and `validate dcql` already produce structured
findings with stable ids, severities, and fixes, and already emit `--json`. SARIF
(Static Analysis Results Interchange Format) is the JSON schema that GitHub code
scanning and other CI dashboards ingest. This item maps the existing findings onto
SARIF results: the finding id as the rule id, the severity as the level, and the
message and fix as the result text, so an over-ask or a malformed registration
shows up where a security finding normally would.

Why it matters: the tool's guardrail story (`README.md`, `docs/GUARDRAILS.md`) is
that an over-ask should fail the build rather than reach the registrar. SARIF makes
that finding first-class in the same dashboard a team already watches for security
issues, instead of a non-zero exit and a log line. It raises the visibility of a
proportionality violation to match its legal weight (eIDAS Art. 5b(3),
GDPR Art. 5(1)(c), ARF RPRC_07).

What exists to build on:

- `src/output.rs` and the per-command JSON already carry the finding shape (id,
  severity, message, fix) for `check` (`src/commands/check.rs`,
  `src/checkbody.rs`), `audit`, `doctor`, and `validate dcql`.
- The exit-code contract is already CI-shaped; SARIF is an additional output
  format over the same findings, not new analysis.

Effort: S to M. The finding data already exists; the work is a faithful SARIF
serialization (rules, results, levels, locations) and deciding what a "location"
means for an artifact that is a token or a JSON body rather than a source file.

## When an item is picked up

Each item above becomes its own plan when scheduled: numbered steps with
parallelization annotations, the fixtures it verifies against, and the exit-code
and `--json` (or SARIF) contract it adds. Sizes here are effort (S / M / L / XL),
not schedule. The consistent target is that a new verifier stays deterministic and
offline in `augenmass-core`, keeps network behavior in the shell, and ships with
committed fixtures so it is reproducible in CI.
