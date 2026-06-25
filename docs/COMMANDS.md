# Augenmaß Workbench: Command Reference

This is the complete reference for the `augenmass` CLI. Every command, subcommand, flag, exit code, and example here is verified against the built binary (`augenmass 0.2.0`) and the committed fixtures under `fixtures/`. Every example runs as written from the repository root.

Augenmaß Workbench is a developer and auditor toolkit for the EUDI Wallet ecosystem. It decodes and inspects every common artifact (SD-JWT VC, ISO 18013-5 mdoc, registration certificate, authorization request/JAR, credential offer, status list, DCQL), audits requests for over-asking against curated purpose baselines and a cited legal basis, verifies presentations cryptographically, writes registrations under guardrails, and live-debugs the wallet-to-verifier exchange. Static artifact commands run fully offline; live surfaces are explicit: registrar targets (`clone`, `cached-sandbox`, `sandbox`), the cache server, and the live wallet-interaction debugger (`serve`).

## How to read this reference

Commands are grouped by intent:

- **UNDERSTAND**: figure out what an artifact is and read its contents (`inspect`, `decode`).
- **PROPORTIONALITY**: the over-ask engine, the core of the tool (`check`, `audit`, `baselines`).
- **CRYPTO**: signature, trust, and revocation verification, plus the x509_hash binding (`verify`, `x509-hash`).
- **PRODUCE**: generate proportionate artifacts (`generate`).
- **DIAGNOSE**: find verifier signed-request gotchas (`doctor`).
- **DEBUG**: a live wallet-interaction debugger, a verifier-in-a-box a real wallet presents to (`serve`).
- **EVIDENCE**: export, verify, and replay local audit bundles from unsafe debug artifacts (`evidence`).
- **WRITE AND TARGETS**: guard-railed registrar writes and reads, plus the local clone store and cached-sandbox mirror (`register`, `list`, `clone`, `cache`).

## Global flag: `--json`

Commands that render structured output accept `--json` to emit machine-readable JSON instead of the text rendering. This is the contract for agents and CI. The flag is accepted both before the command and as a trailing flag on the command itself; both forms are equivalent:

```
augenmass --json check examples/min.json
augenmass check examples/min.json --json
```

The text rendering goes to stdout. With `--json`, the structured object goes to stdout instead. Server commands document their own output and do not use JSON-oriented rendering.

## Input ergonomics: file path, inline value, or stdin

The core artifact parameter on the judgment commands accepts three input forms:

- a **file path**: `augenmass inspect fixtures/presentations/erica-vp-VALID.sdjwt`
- an **inline value**: the artifact passed directly as the argument (a compact JWT string, an `openid4vp://` URI, inline JSON, a PEM block)
- **stdin** via `-`: `cat fixtures/presentations/erica-vp-VALID.sdjwt | augenmass inspect -`

Where a command takes a key or anchor (`--key`, `--anchor`, `--token`, `--status-key`), that input is read the same way: a file path or an inline value. `audit --cert` is a certificate file path.

## Exit codes

Commands exit non-zero on the "bad" outcome so they slot into CI without extra parsing:

| Command | Exit 1 (non-zero) when | Exit 0 when |
|---|---|---|
| `check` | over-ask or a blocking format error | clean |
| `audit` | over-ask vs the purpose baseline | within baseline |
| `verify presentation` | not verified (signature, KB-JWT, nonce/aud, vct, freshness, or any requested trust/status check fails) | verified |
| `verify trust` | issuer does not chain to an anchor, or the validity window fails | trusted |
| `verify status` | revoked, or an error resolving status (fail-closed) | valid |
| `verify status-list` | the read index is revoked, or verification errors | the index is valid |
| `x509-hash --client-id` | the claimed `client_id` does not match the computed binding | match (or no `--client-id` given) |
| `doctor` | any blocking finding | no findings |
| `evidence verify` / `evidence replay` | bundle hashes, replay determinism, or signature verification fails | bundle is valid |
| `evidence assert-live` | bundle invalid, terminal failure, or missing live-wallet event spine | bundle proves encrypted response receipt, decryption, and offline presentation verification |
| `evidence prove-trust-status` | bundle invalid, issuer untrusted, status token invalid, or credential revoked/suspended | captured presentation verifies with explicit issuer trust and status inputs |
| `register` | over-ask without `--force`, or a blocking format error | clean (dry-run or written) |

Commands that purely read and render (`inspect`, `decode`, `baselines`, `generate`, `list`) exit 0 on success. `evidence export` exits non-zero when the source manifest or artifacts are invalid.

---

# UNDERSTAND

## `inspect`

Auto-detect an artifact and decode it. This is the "what is this?" entry point: it sniffs the type, then dispatches to the right decoder. No signature is verified.

```
Usage: augenmass inspect [OPTIONS] <INPUT>
```

Arguments:

- `<INPUT>`: a file path, an inline value, or `-` for stdin.

Options:

- `--json`: emit JSON instead of the text rendering.
- `-h, --help`: print help.

It recognises SD-JWT VC presentations, ISO 18013-5 mdoc artifacts (hex or base64), WRPRC registration certificates, OpenID4VP authorization requests / JARs, OpenID4VP request URIs (`openid4vp://`), OpenID4VCI credential offers, token status lists, DCQL queries, registrar registration bodies, X.509 PEM certificates, and generic JWT/JWS.

Exit code: 0 on success.

Example:

```
augenmass inspect fixtures/presentations/erica-vp-VALID.sdjwt
```

```
Detected: SD-JWT VC presentation
SD-JWT VC presentation (no signature verified)
  vct: urn:eudi:pid:de:1
  issuer alg: ES256
  holder binding (KB-JWT): true
  disclosed claims: 2

Disclosed claims:
  family_name = Mustermann
  given_name = Erika

Key Binding JWT:
  nonce: b4ba2623-76a2-486b-a1f6-f1656025d07b
  aud: https://self-issued.me/v2
```

The same auto-detection works on a status list, a JAR, a registration certificate entry, and from stdin:

```
augenmass inspect fixtures/status/status-list-CLEAR.jwt
augenmass inspect fixtures/requests/eudiplo-request.jwt
augenmass inspect fixtures/regcert/rc-by-id.json
cat fixtures/presentations/erica-vp-VALID.sdjwt | augenmass inspect -
```

## `decode`

Decode a specific artifact type when you already know what it is. No signature verification. Use `decode` (not `inspect`) when you want to force a particular decoder, for example to read a JWT generically rather than as its sniffed type.

```
Usage: augenmass decode [OPTIONS] <COMMAND>
```

Subcommands: `jwt`, `sd-jwt`, `regcert`, `request`, `offer`, `status-list`, `mdoc`.

Options on the `decode` group: `--json`, `-h, --help`.

### `decode jwt`

Decode a JWT/JWS into its header and payload (and report whether a signature segment is present).

```
Usage: augenmass decode jwt [OPTIONS] <INPUT>
```

Arguments: `<INPUT>` (file path, inline value, or `-`).

Exit code: 0 on a parseable JWT.

Example (decoding the signed request fixture as a generic JWT):

```
augenmass decode jwt fixtures/requests/eudiplo-request.jwt
```

```
JWT / JWS (no signature verified)
  typ: oauth-authz-req+jwt
  alg: ES256
  segments: 3   signature present: true

Header:
  {
    "typ": "oauth-authz-req+jwt",
    "alg": "ES256",
    "x5c": [ ... ],
    "kid": "7a3cea9f-611a-4d49-bc95-d2ef3ba6ebea-active"
  }
Payload:
  { ... }
```

### `decode sd-jwt`

Decode an SD-JWT VC: issuer claims, disclosures, KB-JWT, and the resolved (disclosed) view.

```
Usage: augenmass decode sd-jwt [OPTIONS] <INPUT>
```

Arguments: `<INPUT>` (file path, inline value, or `-`).

Exit code: 0 on success.

Example:

```
augenmass decode sd-jwt fixtures/presentations/erica-vp-VALID.sdjwt
```

```
SD-JWT VC presentation (no signature verified)
  vct: urn:eudi:pid:de:1
  issuer alg: ES256
  holder binding (KB-JWT): true
  disclosed claims: 2

Disclosed claims:
  family_name = Mustermann
  given_name = Erika

Key Binding JWT:
  nonce: b4ba2623-76a2-486b-a1f6-f1656025d07b
  aud: https://self-issued.me/v2
```

### `decode regcert`

Decode a WRPRC registration certificate (`typ rc-wrp+jwt`), payload-only. The input is a compact registration-certificate JWT, or a registrar entry that wraps one under a `jwt` field.

```
Usage: augenmass decode regcert [OPTIONS] <INPUT>
```

Arguments: `<INPUT>` (file path, inline value, or `-`).

Exit code: 0 on success.

Use `fixtures/regcert/rc-by-id.json`, which is a registrar entry carrying a real compact certificate under `jwt`:

```
augenmass decode regcert fixtures/regcert/rc-by-id.json
```

```
WRPRC registration certificate (payload-only, no signature verified)
  purpose: "Demonstration: age-over-18 verification for an event check-in."
  privacy_policy: https://example.org/privacy
  support_uri: https://example.org/support
  credentials: 1
    format dc+sd-jwt  vct urn:eudi:pid:de:1
      claim given_name
      claim family_name
      claim age_equal_or_over.18
```

Note: `fixtures/regcert/rc-payload.json` is a raw payload view (a plain JSON object), not a compact JWT, so it is not a valid input to `decode regcert`.

### `decode request`

Decode an OpenID4VP authorization request, either a signed JAR (`typ oauth-authz-req+jwt`) or a plain request object.

```
Usage: augenmass decode request [OPTIONS] <INPUT>
```

Arguments: `<INPUT>` (file path, inline value, or `-`).

Exit code: 0 on success.

Example:

```
augenmass decode request fixtures/requests/eudiplo-request.jwt
```

```
OpenID4VP authorization request / JAR (no signature verified)
  typ: oauth-authz-req+jwt
  alg: ES256
  x5c present: true
  client_id: x509_hash:7zvIjJaM1KQPpN7IZBuVLuh8anw1gcbZ0a6Wj3M9i4w
  client_id scheme: x509_hash
  response_type: vp_token
  response_mode: direct_post.jwt
  nonce: b4ba2623-76a2-486b-a1f6-f1656025d07b
  state: f6d6d27a-adc9-40f5-baee-27be994d65ec
  query: dcql_query present
```

### `decode offer`

Decode an OpenID4VCI credential offer (an `openid-credential-offer://` URI or its JSON form). It also reads the OpenID4VP request URI form (`openid4vp://`) used to hand a verifier request to a wallet.

```
Usage: augenmass decode offer [OPTIONS] <INPUT>
```

Arguments: `<INPUT>` (file path, inline value, or `-`).

Exit code: 0 on success.

The committed offer fixtures carry an `openid4vp://` request URI, so the decoder renders it as a request URI:

```
augenmass decode offer fixtures/offers/eudiplo-offer-uri.txt
```

```
OpenID4VP request URI
  scheme: openid4vp
  client_id: x509_hash:7zvIjJaM1KQPpN7IZBuVLuh8anw1gcbZ0a6Wj3M9i4w
  request_uri: http://localhost:3002/presentations/f6d6d27a-adc9-40f5-baee-27be994d65ec/oid4vp/request
  request_uri_method: get
```

The JSON form (`fixtures/offers/eudiplo-offer.json`, which holds the same URI under `uri`) decodes identically.

### `decode status-list`

Decode a token status list token (`typ statuslist+jwt`): issuer, subject, bits per entry, and list size. No signature is verified here; use `verify status-list` to verify the signature and read a specific index.

```
Usage: augenmass decode status-list [OPTIONS] <INPUT>
```

Arguments: `<INPUT>` (file path, inline value, or `-`).

Exit code: 0 on success.

Example:

```
augenmass decode status-list fixtures/status/status-list-CLEAR.jwt
```

```
Token status list (no signature verified)
  typ: statuslist+jwt
  alg: ES256
  iss: https://verifier.example/status
  sub: https://verifier.example/status/pid-de/1
  bits per entry: 1
  compressed list length (base64 chars): 16

To read a specific index and verify the signature, use:
  augenmass verify status-list --token <file> --key <pem> --index <n>
```

### `decode mdoc`

Decode an ISO/IEC 18013-5 mdoc (`mso_mdoc`), the other major EUDI credential format alongside SD-JWT VC. It accepts a `DeviceResponse`, a single `Document`, an `IssuerSigned`, or a bare `MobileSecurityObject`, given as raw CBOR bytes, hex, or base64/base64url. It surfaces the document type, the disclosed namespaces and elements (nested CBOR is rendered as JSON; a large byte value such as a portrait is shown as a length-tagged hex preview), the issuer authentication (the COSE_Sign1 algorithm and the X.509 chain, whose leaf `x509_hash` the engine computes), and the Mobile Security Object (validity window, per-namespace value-digest counts, and device key).

This is decode only: the COSE signature is not verified and value digests are not recomputed. The output and the JSON `signatureVerified: false` say so.

```
Usage: augenmass decode mdoc [OPTIONS] <INPUT>
```

Arguments: `<INPUT>` (file path with raw or hex/base64 CBOR, inline hex/base64, or `-`).

Exit code: 0 on success.

Example:

```
augenmass decode mdoc fixtures/mdoc/issuer-signed.hex
```

```
Decoded mdoc (IssuerSigned)
Note: structure decoded only; COSE signature and value digests are NOT verified.
namespace org.iso.18013.5.1 (6 element(s)):
  family_name = Doe
  ...
issuerAuth alg: ES256
issuerAuth x5chain: 1 cert(s), leaf subject C=US,CN=utopia ds, x509_hash t5eY67wMr7QGaDtgp1rXjfc1vDU14xFR2w4t_Eu5jTs
MSO:
  version: 1.0
  digestAlgorithm: SHA-256
  docType: org.iso.18013.5.1.mDL
  ...
```

---

# PROPORTIONALITY

This is the core of the tool: the same over-ask engine that audits the EUDI registry helps a developer avoid over-asking before they register. Every over-ask finding cites a legal basis (see `baselines`).

## `check`

Gate a registrar registration body before a write. It runs two evaluations at once: over-ask (requested claims vs the purpose-minimal baseline) and registration-body format (the registrar DTO shape). It is the pre-write gate that `register` runs internally.

```
Usage: augenmass check [OPTIONS] <BODY>
```

Arguments:

- `<BODY>`: a registration body as a file path, inline JSON, or `-` for stdin.

Options: `--json`, `-h, --help`.

Format findings this command catches (grounded in the registrar DTO):

- `claims[].path` must be an **array** of segments, not a string (`["age_equal_or_over","18"]`, not `"age_equal_or_over.18"`).
- requested claims live under `credentials`, not `provided_attestations`.
- `purpose` is a list of `{lang, content}` objects, not a bare string.
- `privacy_policy` must be a valid URL.
- `support_uri` is any non-empty contact string (email, phone, or URL); it is not over-validated as a URL.

Exit code: 1 on over-ask or a blocking format error; 0 if clean.

Clean body:

```
augenmass check examples/min.json
```

```
OK: no over-ask, no format errors. examples/min.json is ready to register.
```

Over-ask body (exit 1). The text rendering lists each requested claim, the suggested minimal request, and the legal basis:

```
augenmass check examples/over.json
```

```
OVER-ASK: Over-ask vs purpose: 6 of 6 requested claims exceed the stated purpose.
Purpose: Age verification   Baseline: Age gate (over 18)

Requested claims:
  [over]  given_name                   Registered, but beyond what the stated purpose needs.
  ...
Suggested minimal request:
  age_equal_or_over.18

Legal basis:
  eIDAS Regulation (EU) 2024/1183, Art. 5b(3)
    Relying parties shall not request users to provide data other than that indicated for their intended use.
  GDPR (EU) 2016/679, Art. 5(1)(c)
    Personal data shall be adequate, relevant and limited to what is necessary (data minimisation).
  EUDI ARF, registration certificate, RPRC_07
    The wallet verifies requested attributes are within the registration certificate and notifies the user otherwise.
```

Blocking format error (exit 1):

```
augenmass check examples/bad-path.json
```

```
Format findings:
  CHECK-PATH-STRING [blocking]: claims[].path must be an array of segments, not a string.
    Fix: Change "path": "age_equal_or_over" to "path": ["age_equal_or_over", "18"].
```

JSON shape (for CI and agents): the object exposes `overAsk`, `blockingFormatError`, `block`, and a `report` with per-claim `status` and `rationale`:

```
augenmass check examples/min.json --json
```

## `audit`

Audit an OpenID4VP request for over-asking against a purpose baseline. Unlike `check`, this lints a request (its DCQL), not a registration body. With `--cert` it also confirms the requested claims sit within a registration certificate.

```
Usage: augenmass audit [OPTIONS]
```

Options:

- `--request <REQUEST>`: `"minimal"`, `"overask"`, a DCQL JSON file, inline DCQL JSON, or `-` for stdin. Bare DCQL and wrappers under `dcql_query` are accepted. Default `minimal`. The two keywords are built-in synthetic requests; the minimal one asks for `given_name`, `family_name`, `age_equal_or_over.18`, and the overask one asks for a broad PID set.
- `--purpose <PURPOSE>`: purpose baseline id (`age_gate_18`, `event_checkin`, `car_rental`, `bank_kyc`). Default `event_checkin`.
- `--cert <CERT>`: path to a registration certificate (compact JWT, entity JSON, or array) to cross-check the request against.
- `--vct <VCT>`: override the expected `vct` (defaults to the German PID, `urn:eudi:pid:de:1`).
- `--json`, `-h, --help`.

Exit code: 1 on over-ask vs the chosen baseline; 0 otherwise.

Clean (the built-in minimal request is within the `event_checkin` baseline), exit 0:

```
augenmass audit --request minimal --purpose event_checkin
```

```
OK: Within the purpose-minimal baseline; registration not evaluated.
Purpose: not stated   Baseline: Event check-in

Requested claims:
  [ok]  given_name                   Within the purpose-minimal baseline.
  [ok]  family_name                  Within the purpose-minimal baseline.
  [ok]  age_equal_or_over.18         Within the purpose-minimal baseline.
```

Over-ask. The same minimal request audited against the much tighter `age_gate_18` baseline flags `given_name` and `family_name`, exit 1:

```
augenmass audit --request minimal --purpose age_gate_18
```

```
OVER-ASK: Over-ask vs purpose: 2 of 3 requested claims exceed the stated purpose.
Purpose: not stated   Baseline: Age gate (over 18)

Requested claims:
  [over]  given_name                   Beyond what the stated purpose needs; registration not evaluated.
  [over]  family_name                  Beyond what the stated purpose needs; registration not evaluated.
  [ok]  age_equal_or_over.18         Within the purpose-minimal baseline.
```

Audit a real DCQL file against a baseline:

```
augenmass audit --request fixtures/dcql/eudiplo-haip-pid-de.dcql.json --purpose age_gate_18
```

## `baselines`

List the curated purpose baselines and the legal basis, or show one baseline in detail. These baselines are curated taste judgments, not Rulebook derivations; they are the yardstick `check` and `audit` measure against.

```
Usage: augenmass baselines [OPTIONS] [ID]
```

Arguments:

- `[ID]`: a baseline id to show in detail. Omit to list all.

Options: `--json`, `-h, --help`.

The four baselines:

- `age_gate_18` ("Age gate (over 18)"): `age_equal_or_over.18`
- `event_checkin` ("Event check-in"): `given_name`, `family_name`, `age_equal_or_over.18`
- `car_rental` ("Car rental (over 21, named)"): `given_name`, `family_name`, `age_equal_or_over.21`
- `bank_kyc` ("Bank onboarding (KYC)"): `given_name`, `family_name`, `birthdate`, `address.resident_street`, `address.resident_city`, `address.resident_postal_code`, `address.resident_country`

Exit code: 0 on success.

List all (also prints the legal basis cited on every over-ask finding):

```
augenmass baselines
```

Show one as JSON:

```
augenmass baselines age_gate_18 --json
```

```
{
  "id": "age_gate_18",
  "label": "Age gate (over 18)",
  "minimal_keys": [
    "age_equal_or_over.18"
  ],
  "note": "Curated minimal baseline (a taste judgment, not a Rulebook derivation)."
}
```

### Legal basis (cited verbatim on every over-ask finding)

1. eIDAS Regulation (EU) 2024/1183, Art. 5b(3): "Relying parties shall not request users to provide data other than that indicated for their intended use."
2. GDPR (EU) 2016/679, Art. 5(1)(c): data minimisation ("adequate, relevant and limited to what is necessary").
3. EUDI ARF, registration certificate, RPRC_07: the wallet verifies requested attributes are within the registration certificate and notifies the user otherwise.

---

# CRYPTO

These commands actually verify signatures and chains, using the vendored `augenmass-core` engine. They run offline; you provide the anchors, keys, and tokens. The verification clock is injectable via `--now` so fixtures verify deterministically. For the committed presentation fixtures, use `--now 1780435200`.

## `verify presentation`

Verify an SD-JWT VC presentation end to end: issuer signature, KB-JWT (holder binding), the nonce and audience echoed by the KB-JWT, the credential `vct`, and KB-JWT freshness. Optionally also anchor the issuer to a trust anchor and check revocation.

```
Usage: augenmass verify presentation [OPTIONS] --nonce <NONCE> --aud <AUD> <INPUT>
```

Arguments:

- `<INPUT>`: the presentation (`SD-JWT VC ~ ... ~ KB-JWT`) as a file path, inline value, or `-`.

Options:

- `--nonce <NONCE>` (required): the Authorization Request nonce the KB-JWT must echo.
- `--aud <AUD>` (required): the audience the KB-JWT must bind to (the verifier `client_id`).
- `--vct <VCT>`: the expected credential `vct` (defaults to the German PID).
- `--max-age <MAX_AGE>`: KB-JWT freshness window in seconds. Default `300`.
- `--now <NOW>`: verification clock in Unix seconds; omit to use the system clock.
- `--trust-anchor <TRUST_ANCHOR>`: a trust anchor PEM to anchor the issuer (optional; otherwise the leaf key is used).
- `--status-token <STATUS_TOKEN>`: a status-list token to check revocation against (needs `--status-key`).
- `--status-key <STATUS_KEY>`: the status-signer public key PEM (needs `--status-token`).
- `--json`, `-h, --help`.

Exit code: 1 if any check fails (signature, KB-JWT, nonce, audience, vct, freshness, or a requested trust/status check); 0 if verified.

Verified, exit 0:

```
augenmass verify presentation fixtures/presentations/erica-vp-VALID.sdjwt \
  --nonce b4ba2623-76a2-486b-a1f6-f1656025d07b \
  --aud https://self-issued.me/v2 \
  --now 1780435200
```

```
VERIFIED
  vct: urn:eudi:pid:de:1
  holder binding: true
  trust anchored: false
  status checked: false
  disclosed claims:
    family_name = Mustermann
    given_name = Erika
```

Rejected. The wrong-nonce fixture fails the KB-JWT nonce check, exit 1:

```
augenmass verify presentation fixtures/presentations/erica-vp-WRONG_NONCE.sdjwt \
  --nonce b4ba2623-76a2-486b-a1f6-f1656025d07b \
  --aud https://self-issued.me/v2 \
  --now 1780435200
```

```
REJECTED [NonceMismatch]: KB-JWT nonce does not match the request
```

The negative fixtures each exercise one failure mode: `erica-vp-WRONG_AUDIENCE.sdjwt` (audience), `erica-vp-MISSING_HOLDER_BINDING.sdjwt` (no KB-JWT), `erica-vp-EXPIRED.sdjwt` (freshness), `erica-vp-OVER_DISCLOSURE.sdjwt` (disclosures beyond what was requested).

Full verification in one call: anchor the issuer and check revocation at the same time:

```
augenmass verify presentation fixtures/presentations/synthetic-pid-with-status.sdjwt \
  --nonce b4ba2623-76a2-486b-a1f6-f1656025d07b \
  --aud https://self-issued.me/v2 \
  --now 1780435200 \
  --trust-anchor fixtures/certs/synthetic-pid-anchor.pem \
  --status-token fixtures/status/status-list-CLEAR.jwt \
  --status-key fixtures/status/status-list-verify-key.pub.pem
```

## `verify trust`

Check whether a presentation's issuer chains to a trust anchor and falls inside the certificate validity window. This is a leaf-chains-to-anchor check plus a validity-window check, not full RFC 5280 path validation.

```
Usage: augenmass verify trust [OPTIONS] --anchor <ANCHOR> <INPUT>
```

Arguments:

- `<INPUT>`: the presentation as a file path, inline value, or `-`.

Options:

- `--anchor <ANCHOR>` (required): trust anchor PEM (one or more certificates), as a file path or inline.
- `--now <NOW>`: verification clock in Unix seconds; omit to use the system clock.
- `--json`, `-h, --help`.

Exit code: 1 if the issuer does not chain to an anchor or the validity window fails; 0 if trusted.

Example (ERICA's leaf chains to `erica-trust-anchor.pem`), exit 0:

```
augenmass verify trust fixtures/presentations/erica-vp-VALID.sdjwt \
  --anchor fixtures/certs/erica-trust-anchor.pem \
  --now 1780435200
```

```
TRUSTED: the issuer chains to one of 1 anchor(s).
```

## `verify status`

Check a presentation's revocation status against a status-list token. The status check is fail-closed and offline: it reads the index the credential points at and reports it.

```
Usage: augenmass verify status [OPTIONS] --token <TOKEN> --key <KEY> <INPUT>
```

Arguments:

- `<INPUT>`: the presentation as a file path, inline value, or `-`.

Options:

- `--token <TOKEN>` (required): the status-list token (`statuslist+jwt`), as a file path or inline.
- `--key <KEY>` (required): the status-signer public key (SPKI or certificate PEM).
- `--json`, `-h, --help`.

Exit code: 1 if revoked or on a status-resolution error; 0 if valid.

Valid against the clear list, exit 0:

```
augenmass verify status fixtures/presentations/synthetic-pid-with-status.sdjwt \
  --token fixtures/status/status-list-CLEAR.jwt \
  --key fixtures/status/status-list-verify-key.pub.pem
```

```
VALID
```

Revoked against the revoked list (the credential's index is flagged), exit 1:

```
augenmass verify status fixtures/presentations/synthetic-pid-with-status.sdjwt \
  --token fixtures/status/status-list-REVOKED.jwt \
  --key fixtures/status/status-list-verify-key.pub.pem
```

```
REVOKED
```

## `verify status-list`

Verify a status-list token's signature and read a specific index directly, without a presentation. Useful when you have a status list and an index in hand.

```
Usage: augenmass verify status-list [OPTIONS] --token <TOKEN> --key <KEY> --index <INDEX>
```

Options:

- `--token <TOKEN>` (required): the status-list token (`statuslist+jwt`), as a file path or inline.
- `--key <KEY>` (required): the status-signer public key (SPKI or certificate PEM).
- `--index <INDEX>` (required): the status index to read.
- `--json`, `-h, --help`.

Exit code: 1 if the index is revoked or verification errors; 0 if the index is valid.

The committed status lists hold 256 entries, 1 bit each; index 42 is revoked in the REVOKED list. Reading index 42, exit 1:

```
augenmass verify status-list \
  --token fixtures/status/status-list-REVOKED.jwt \
  --key fixtures/status/status-list-verify-key.pub.pem \
  --index 42
```

```
REVOKED
```

Reading a clear index (0) in the same list, exit 0:

```
augenmass verify status-list \
  --token fixtures/status/status-list-REVOKED.jwt \
  --key fixtures/status/status-list-verify-key.pub.pem \
  --index 0
```

```
VALID
```

## `x509-hash`

Compute the `x509_hash` `client_id` binding (`x509_hash:<base64url(SHA-256(leaf-cert-DER))>`) and, optionally, check a claimed `client_id` against it. Input is a JAR (its x5c leaf is extracted), a PEM certificate, or base64 DER.

```
Usage: augenmass x509-hash [OPTIONS] <INPUT>
```

Arguments:

- `<INPUT>`: a JAR (its x5c leaf), a PEM certificate, or base64 DER; as a file path, inline value, or `-`.

Options:

- `--client-id <CLIENT_ID>`: a claimed `client_id` to compare against the computed binding.
- `--json`, `-h, --help`.

Exit code: with `--client-id`, 1 on mismatch and 0 on match; without `--client-id`, 0 (compute only).

Compute from a leaf PEM (the `access-leaf.pem` binding):

```
augenmass x509-hash fixtures/certs/access-leaf.pem
```

```
x509_hash:   VE3qp3vLVkU8JyVmXkjL7CSDVxVoTFdTv5fAEwmjKOI
client_id:   x509_hash:VE3qp3vLVkU8JyVmXkjL7CSDVxVoTFdTv5fAEwmjKOI
subject:     CN=Hackathon - Reza,...,O=Hackathon - Reza,C=DE
issuer:      CN=German Registrar,C=DE
serial:      2D:DD:F5:FD:92:86:B2:A2
```

Compute from a JAR (the leaf is pulled out of x5c). The eudiplo JAR binds to `x509_hash:7zvIjJaM1KQPpN7IZBuVLuh8anw1gcbZ0a6Wj3M9i4w`:

```
augenmass x509-hash fixtures/requests/eudiplo-request.jwt
```

Check a claimed `client_id`, match (exit 0):

```
augenmass x509-hash fixtures/certs/access-leaf.pem \
  --client-id x509_hash:VE3qp3vLVkU8JyVmXkjL7CSDVxVoTFdTv5fAEwmjKOI
```

```
MATCH: x509_hash:VE3qp3vLVkU8JyVmXkjL7CSDVxVoTFdTv5fAEwmjKOI matches the computed binding.
```

Check a claimed `client_id`, mismatch (exit 1):

```
augenmass x509-hash fixtures/certs/access-leaf.pem --client-id x509_hash:WRONGHASH
```

```
MISMATCH: claimed client_id
  x509_hash:WRONGHASH
does not equal the computed
  x509_hash:VE3qp3vLVkU8JyVmXkjL7CSDVxVoTFdTv5fAEwmjKOI
```

---

# PRODUCE

## `generate`

Produce a proportionate registration body or a DCQL query.

```
Usage: augenmass generate [OPTIONS] <COMMAND>
```

Subcommands: `regbody`, `dcql`. Options on the group: `--json`, `-h, --help`.

### `generate regbody`

Emit a registrar registration body. By default it produces the proportionate age check: a single `age_equal_or_over.18` claim with `format dc+sd-jwt` and the German PID `vct`. The output passes `check` cleanly.

```
Usage: augenmass generate regbody [OPTIONS]
```

Options:

- `--use-case <USE_CASE>`: default `age-check`; the only accepted value is `age-check`.
- `--over-broad`: emit an intentionally over-broad body (useful to demonstrate `check`/`register` refusing an over-ask).
- `--rp <RP>`: the relying-party id. Default `2af138a8-59ea-4a84-aea3-666cafdb1369` (our relying party, "Hackathon - Reza").
- `--support-uri <SUPPORT_URI>`: default `support@example.com`.
- `--privacy-policy <PRIVACY_POLICY>`: default `https://example.com/privacy`.
- `--purpose <PURPOSE>`: default `Age verification`.
- `--json`, `-h, --help`.

Exit code: 0 on success.

Default proportionate body:

```
augenmass generate regbody
```

```
{
  "rpId": "2af138a8-59ea-4a84-aea3-666cafdb1369",
  "support_uri": "support@example.com",
  "privacy_policy": "https://example.com/privacy",
  "purpose": [
    { "lang": "en", "content": "Age verification" }
  ],
  "credentials": [
    {
      "format": "dc+sd-jwt",
      "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
      "claims": [
        { "path": ["age_equal_or_over", "18"] }
      ]
    }
  ]
}
```

Note the correct shapes: `path` is an array, claims live under `credentials`, and `purpose` is a list of `{lang, content}`. Generate then immediately gate it:

```
augenmass generate regbody | augenmass check -
```

Demonstrate the over-ask path end to end (this body fails the gate, so `register` would refuse it without `--force`):

```
augenmass generate regbody --over-broad | augenmass check -
```

Override the contact and purpose fields:

```
augenmass generate regbody \
  --support-uri "https://example.org/support" \
  --privacy-policy "https://example.org/privacy" \
  --purpose "Age gate for venue entry"
```

### `generate dcql`

Build a DCQL query from one or more claim paths. The `--claim` flag is repeatable; paths may be dotted or slashed and are expanded into segment arrays.

```
Usage: augenmass generate dcql [OPTIONS] --claim <CLAIMS>
```

Options:

- `--claim <CLAIMS>` (required, repeatable): a claim path, for example `--claim age_equal_or_over.18`.
- `--json`, `-h, --help`.

Exit code: 0 on success.

Single claim:

```
augenmass generate dcql --claim age_equal_or_over.18
```

```
{
  "credentials": [
    {
      "id": "pid",
      "format": "dc+sd-jwt",
      "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
      "claims": [
        { "path": ["age_equal_or_over", "18"] }
      ]
    }
  ]
}
```

Multiple claims (a flat path becomes a single-element array, a dotted path becomes a multi-element array):

```
augenmass generate dcql --claim given_name --claim age_equal_or_over.18
```

Feed the result straight into an audit:

```
augenmass generate dcql --claim given_name --claim family_name --claim age_equal_or_over.18 \
  | augenmass audit --request - --purpose event_checkin
```

---

# DIAGNOSE

## `doctor`

Diagnose verifier signed-request / JAR gotchas. This is a different document from a registration body: it lints the request a verifier sends a wallet. Input is request JSON or a compact JWT.

```
Usage: augenmass doctor [OPTIONS] <REQUEST>
```

Arguments:

- `<REQUEST>`: request JSON or a compact JWT, as a file path, inline value, or `-`.

Options: `--json`, `-h, --help`.

Findings this command catches:

- `x5c` must be a **list** of strings, even for a single certificate.
- `client_id` must be in the `x509_hash:<base64url(SHA-256(leaf-cert-DER))>` form. Compute it with `augenmass x509-hash`.
- (Reminder it prints on the clean path) set `Content-Type: application/json` on every POST.

Exit code: 1 if there are blocking findings; 0 if none.

Clean JAR, exit 0:

```
augenmass doctor fixtures/requests/eudiplo-request.jwt
```

```
OK: no signed-request gotchas found.
Set Content-Type: application/json on every POST; the client does this for you.
```

A malformed request (exit 1). The `examples/bad-request.json` fixture has `x5c` as a bare string and a non-`x509_hash` `client_id`:

```
augenmass doctor examples/bad-request.json
```

```
Signed-request findings:
  DOCTOR-X5C-STRING [blocking]: x5c must be a list of strings, even for a single certificate.
    Fix: Wrap the certificate in an array: "x5c": ["MIIB..."].
  DOCTOR-CLIENT-ID-X509HASH [blocking]: client_id must be in the x509_hash form.
    Fix: Use "client_id": "x509_hash:<base64url(SHA-256(leaf-cert-DER))>". Compute it with `augenmass x509-hash`.
```

## `validate dcql`

Validate a DCQL query beyond what the typed parse enforces, so a developer can catch the mistakes that make a wallet reject or mis-handle a request. It accepts a bare query or one wrapped under `dcql_query`, as a file path, inline value, or `-`.

```
Usage: augenmass validate dcql [OPTIONS] <INPUT>
```

Options: `--json`, `-h, --help`.

Checks (each finding has a stable id, a severity, and a fix):

- `DCQL-CREDENTIALS-MISSING` / `DCQL-CREDENTIALS-EMPTY`: there must be a non-empty `credentials` array.
- `DCQL-CRED-ID-MISSING` / `DCQL-CRED-ID-DUPLICATE`: every credential needs a unique string `id`.
- `DCQL-CRED-FORMAT-MISSING` / `DCQL-CRED-FORMAT-UNKNOWN`: a `format` is required; an unrecognized one warns.
- `DCQL-PATH-NOT-ARRAY`: a claim `path` is a JSON array of segments, not a dotted string.
- `DCQL-MDOC-PATH`: an `mso_mdoc` path must be `[namespace, element]` (two strings).
- `DCQL-SDJWT-PATH`: an SD-JWT path's segments must be strings, null (all array elements), or integer indices.
- `DCQL-SET-REF-DANGLING` (and the `DCQL-SET-*` shape checks): every id referenced in a `credential_sets` option must match a `credentials[].id`.

Exit code: 1 if there is a blocking finding; 0 otherwise (warnings do not block).

Clean query, exit 0:

```
augenmass validate dcql fixtures/dcql/eudiplo-haip-pid-de.dcql.json
```

```
DCQL VALID: no structural or reference issues found.
```

A query with a duplicate id, a bad mdoc path, and a dangling set reference (exit 1):

```
augenmass validate dcql '{"credentials":[{"id":"a","format":"mso_mdoc","claims":[{"path":["org.iso.18013.5.1"]}]},{"id":"a","format":"dc+sd-jwt"}],"credential_sets":[{"options":[["missing"]]}]}'
```

```
DCQL findings:
  DCQL-CRED-ID-DUPLICATE [blocking]: duplicate credential id 'a'
    Fix: credential ids must be unique within a DCQL query
  DCQL-MDOC-PATH [blocking]: credentials[0].claims[0].path for mso_mdoc must be [namespace, element] (two strings), got 1 segment(s)
    Fix: use a two-string path, e.g. ["org.iso.18013.5.1", "family_name"]
  DCQL-SET-REF-DANGLING [blocking]: credential_sets[0] references unknown credential id 'missing'
    Fix: every id in a credential_set option must match a credentials[].id

DCQL INVALID: at least one blocking error above.
```

---

# DEBUG

## `serve`

Run a live wallet-interaction debugger: a local OpenID4VP verifier (a verifier-in-a-box) for the German PID profile, so a real EUDI wallet can present to it (scan the QR, follow the deep link), and trace the whole exchange end to end. Unlike the other commands, which read static artifacts, `serve` debugs the actual wallet-to-verifier flow. The German PID profile it speaks: `vct urn:eudi:pid:de:1`, format `dc+sd-jwt`, response_mode `direct_post.jwt`, response encryption ECDH-ES (A128GCM or A256GCM), and the registration certificate embedded as array-shaped `verifier_info` plus `verifier_attestations` for newer stacks.

This command runs until interrupted (Ctrl-C). It is zero-config: with no flags it mints a throwaway development certificate, so the verifier runs without a registrar-issued leaf. The `client_id` is then not the registered identity; pass `--key` and `--leaf` together to sign with the real registrar leaf so the `client_id` matches the registered identity.

`serve` is one of the explicit live surfaces in the tool: a real wallet connects to it, and `--live-status` resolves a status list over the network.

```
Usage: augenmass serve [OPTIONS]
```

Options (all optional):

- `--port <PORT>` (env `PORT`): the listen port. Default `8080`.
- `--host <HOST>` (env `HOST`): the host/interface to bind. Default `127.0.0.1`.
- `--public-url <PUBLIC_URL>` (env `PUBLIC_URL`): the public base URL baked into the `request_uri` and `response_uri` the wallet uses. It must end in `/`. Default `http://127.0.0.1:8080/`.
- `--key <KEY>` (env `RP_KEY_PATH`): an EC private key PEM (PKCS#8 or SEC1) for the registrar-issued leaf. Pass it together with `--leaf`.
- `--leaf <LEAF>` (env `RP_LEAF_PATH`): the leaf certificate PEM matching `--key`. Pass it together with `--key`.
- `--purpose <PURPOSE>` (env `PURPOSE`): the purpose baseline id for the over-ask inspector. Default `event_checkin`.
- `--trust-anchor <TRUST_ANCHOR>` (env `TRUST_ANCHOR_PATH`): a PID issuer trust anchor PEM. When set, the response path rejects issuers that do not chain to it; when unset, issuer trust is not enforced.
- `--status-signer <STATUS_SIGNER>` (env `STATUS_SIGNER_PATH`): a PEM certificate or public key that verifies token-status-list signatures. If omitted, live status falls back to the trust-anchor key for single-signer fixtures; real PID providers usually need this explicitly.
- `--live-status` (env `LIVE_STATUS`): resolve the token-status-list over the network on the response path and reject a revoked or suspended PID. Default `false` (offline-friendly). Only takes effect when `--trust-anchor` is also set; use `--status-signer` when revocation is signed by a dedicated key.
- `--quiet`: suppress the live per-step trace on the console. The trace still records and is served at `/trace/<session>` and `/api/trace/<session>`.
- `--unsafe-debug-artifacts <UNSAFE_DEBUG_ARTIFACTS>` (env `AUGENMASS_UNSAFE_DEBUG_ARTIFACTS`): opt-in, off by default. Write full-fidelity debug artifacts for each session under `<dir>/<session>/`: the raw `direct_post` body, the decrypted authorization response when an encrypted wallet response is decrypted, the per-session private encryption key, the signed request object (JAR), the decoded request payload, and a verification context (`nonce`, `aud`, `vct`, clock, freshness window), plus a `debug-manifest.json` marked sensitive. On Unix, directories are tightened to `0700` and files to `0600`; on Windows, store them only in a private profile or encrypted workspace until native ACL hardening is added. UNSAFE: this writes raw wallet material, including personal data, to local disk in the clear. It is never served over HTTP; the trace records the file name, a label, the length, a SHA-256, and the redaction fields `unsafeDebugArtifacts`, `pathRedacted`, `redacted`, and `redaction`, never a path or a value.
- `--relay <RELAY>` (env `AUGENMASS_RELAY`): publish only the wallet request/response endpoints through a hosted relay. Use `--relay augenmass` for the default hosted alias (`wss://wallet.augenmass.tech/_relay/tunnel` unless `AUGENMASS_RELAY_URL` overrides it), or pass a `ws://` / `wss://` control URL.
- `--relay-token <RELAY_TOKEN>` (env `AUGENMASS_RELAY_TOKEN`): bearer token for the hosted relay control connection. Prefer the environment variable so the token does not appear in shell history.
- `--relay-ttl <RELAY_TTL>` (env `AUGENMASS_RELAY_TTL`): requested relay run lifetime in seconds. The relay clamps it to its configured maximum.
- `--relay-optional` (env `AUGENMASS_RELAY_OPTIONAL`): continue local-only if relay setup fails. Use this only when fallback is acceptable; for a real phone demo, let relay failure fail fast.
- `--age-only` (env `AUGENMASS_SERVE_AGE_ONLY`): request only `age_equal_or_over.18`. This is the safest live-demo profile when a sandbox wallet cannot satisfy the named event-check-in query (`given_name`, `family_name`, and age).

Runtime behavior: this command does not exit on its own and does not use `--json`. It binds the listener and serves until Ctrl-C. On startup it prints the open URL, the computed `client_id`, whether the cert is throwaway or the registrar leaf, whether issuer trust is enforced, whether status checks are live, where the trace is served, and whether unsafe local debug artifacts are enabled.

```
augenmass serve
```

```
augenmass serve: wallet-interaction debugger
  open         : http://127.0.0.1:8080/
  client_id    : x509_hash:...
  cert         : throwaway (development); set --key + --leaf for the real registrar leaf
  issuer trust : not enforced (set --trust-anchor to anchor PID issuers)
  status check : offline (set --live-status to resolve token-status-list revocation)
  trace        : redacted by default; live on this console; also at <base>/trace/<session> and /api/trace/<session>
  artifacts    : off (set --unsafe-debug-artifacts <dir> to capture raw wallet material locally; UNSAFE)

  Open the URL above, scan the QR with a wallet, and watch the trace below.
```

Hosted relay mode keeps the operator UI local and gives the phone a temporary
public URL for the wallet endpoints only:

```
AUGENMASS_RELAY_TOKEN=<token> augenmass serve --relay augenmass
```

For the smallest phone-wallet demo request, add `--age-only`:

```
AUGENMASS_RELAY_TOKEN=<token> augenmass serve --relay augenmass --age-only
```

```
augenmass serve: wallet-interaction debugger (relay)
  open         : http://127.0.0.1:8080/
  listening    : http://127.0.0.1:8080
  relay        : augenmass
  run          : abcd1234 (TTL 600s)
  public       : https://wallet.augenmass.tech/r/<run-id>/
  scope        : relay carries only /request and /response; trace and evidence stay local
```

In relay mode, the landing page, trace, inspect, session list, and unsafe debug
artifacts remain on the local `open` URL. The public relay URL forwards only
`GET /request/<session>` and `POST /response/<session>`; public trace and
inspect paths return `404`.

### HTTP endpoints

| Method | Path | What it does |
|---|---|---|
| `GET` | `/` | Landing page: mints a fresh session and renders a QR / deep-link to present, plus links to inspect and trace. |
| `GET` | `/request/:id` | The signed request object (the JAR / `request_uri`) the wallet fetches. Content-type `application/oauth-authz-req+jwt`. |
| `POST` | `/response/:id` | The wallet response (`direct_post.jwt`): decrypt, verify, trace. Returns JSON (see below). |
| `GET` | `/inspect/:id` | The over-ask inspector HTML for this session. The `?demo=overask` variant inspects an over-asking request shape. |
| `GET` | `/trace/:id` | The human-readable wallet-interaction timeline (HTML). It auto-refreshes while the exchange is in flight and stays still once the session reaches a terminal outcome. |
| `GET` | `/api/trace/:id` | The same trace as JSON, for programmatic debugging. |
| `GET` | `/api/sessions` | A JSON list of the sessions seen this run. |
| `GET` | `/health` | Health check; returns `{ "status": "ok", "service": "augenmass serve" }`. |

The `POST /response/:id` body is the wallet's `application/x-www-form-urlencoded` authorization response. The response is JSON shaped `{ "status": "verified" | "rejected", "reason"?, "inspect", "trace" }`: `status` is `verified` (HTTP 200) or `rejected` (HTTP 422), `reason` carries the rejection reason when rejected, and `inspect` and `trace` are absolute URLs to this session's inspector and timeline.

When `--relay` is set, only `/request/:id` and `/response/:id` are reachable
through the hosted relay. All other endpoints above stay reachable only through
the local operator base URL.

### Trace event codes

The trace is a per-session, timestamped event log. The JSON uses camelCase keys. Each event has `seq` (a monotonic process-wide sequence number), `at` (local time of day, `HH:MM:SS.mmm`), `atUnixMs` (Unix milliseconds), `kind`, `code` (the stable string below), `level` (`info`, `good`, `warn`, or `bad`), `summary` (a one-line human-legible string), and an optional `detail` carrying the (redacted) artifact at that step. The trace is redacted by default: the JAR header and payload are shown (the verifier's own request object), but the received response and the decrypted payload are recorded as shape only (mode, byte length, SHA-256, field names, `vp_token` presence and shape), never the raw body and never a disclosed claim value, and `VERIFIED` lists disclosed claim keys only. The `/api/sessions` listing gives each session a `session`, an `eventCount`, and the `lastCode`/`lastLevel`/`lastAt` of its most recent event.

The codes, in typical order:

| Code | When |
|---|---|
| `SESSION_CREATED` | A fresh presentation session is minted. |
| `REQUEST_BUILT` | The minimal-disclosure authorization request is built (carries the `nonce`, `client_id`, and DCQL). |
| `REQUEST_OBJECT_FETCHED` | The wallet fetches the signed request object (the JAR); the decoded header and payload are attached. |
| `RESPONSE_RECEIVED` | The wallet posts its response; the trace records its shape (mode, byte length, SHA-256, field names, state), never the raw body. |
| `RESPONSE_DECRYPTED` | The JWE response is decrypted (ECDH-ES); the trace records the payload shape (length, SHA-256, field names, `vp_token` presence and shape), never a disclosed claim value. A plaintext (unencrypted) `direct_post` is refused, not decrypted (see `REJECTED`). |
| `VERIFIED` or `REJECTED` | The SD-JWT VC issuer signature, the KB-JWT holder binding, the nonce and audience, the `vct`, and freshness are checked; on failure the exact reason is recorded. A non-conformant response is also `REJECTED` before verification: a plaintext `direct_post` (the verifier requires the encrypted `direct_post.jwt` profile) returns HTTP 422 and ends the timeline red. |
| `STATUS_CHECKED` | Only with `--live-status` plus issuer trust/status-signer material: the token-status-list is resolved and a revoked or suspended credential is rejected fail-closed. |
| `OVER_ASK_ANALYZED` | What the wallet actually disclosed is run through the over-ask inspector. |
| `NOTE` | An informational annotation. |
| `ERROR` | An error step. |
| `ARTIFACT_SAVED` | Only with `--unsafe-debug-artifacts`: a debug artifact was written to local disk. The detail records the file name, a label, the length, a SHA-256, and the redaction fields `unsafeDebugArtifacts`, `pathRedacted`, `redacted`, and `redaction` only, never a path or a value. |

The same trace is available three ways: live on the console (ANSI color only when stderr is a TTY; suppressed with `--quiet`), the browser timeline at `/trace/:id`, and JSON at `/api/trace/:id`.

### Security and privacy

The trace is redacted by default: no endpoint, including the unauthenticated `/api/trace/:id`, carries the raw POST body, the decrypted payload, or any disclosed claim value. Each session uses a fresh ephemeral response-encryption key, used once and dropped after the response is processed (and on the reject and malformed-parse paths). A plaintext `direct_post` is rejected with HTTP 422 because the verifier advertises the encrypted `direct_post.jwt` profile.

The `--live-status` fetch is hardened against SSRF: it is pinned to the addresses it vetted before connecting (it does not re-resolve the hostname at connect time, which closes the DNS-rebinding window), stays https-only with redirects disabled and a timeout, caps the response body, normalizes IPv4-mapped IPv6 before vetting, and denies loopback, private, link-local, CGNAT, and unique-local targets.

When you need the raw bytes for local debugging, opt in with `--unsafe-debug-artifacts` (UNSAFE, local only, never served over HTTP):

```
augenmass serve --unsafe-debug-artifacts ./debug-out
```

Sign with the real registrar leaf so the `client_id` matches the registered identity, and enforce issuer trust with revocation:

```
augenmass serve --key rp-private.pem.key --leaf rp-leaf.pem \
  --trust-anchor pid-issuer-anchor.pem \
  --status-signer pid-status-signer.pem \
  --live-status
```

Bind on all interfaces so a wallet on a phone can reach the tool (the `--public-url` must be reachable from the phone, not `127.0.0.1`):

```
augenmass serve --host 0.0.0.0 --public-url http://192.0.2.10:8080/
```

---

# EVIDENCE

## `evidence`

Export, verify, and replay local evidence captured by `serve --unsafe-debug-artifacts`. The source directory and the bundle are sensitive because they can contain the raw wallet POST body, decrypted authorization response material, and the verifier session private response key. On Unix, exported bundle files are tightened to `0600`; on Windows, keep them in a private profile or encrypted workspace. The replay command renders only a redacted timeline.

```
Usage: augenmass evidence [OPTIONS] <COMMAND>
```

Subcommands:

- `export`: export one serve unsafe-debug session directory into a portable bundle.
- `verify`: verify bundle hashes, replay determinism, and optional signature.
- `replay`: render the bundle's projector-safe replay timeline.
- `assert-live`: require a bundle to prove a completed encrypted phone-wallet run.
- `prove-trust-status`: re-verify a captured bundle with explicit issuer trust and status inputs.

All subcommands accept `--json`.

## `evidence export`

```
Usage: augenmass evidence export [OPTIONS] --out <OUT> <SESSION_DIR>
```

Arguments:

- `<SESSION_DIR>`: a session directory containing `debug-manifest.json`, for example `./debug-out/<session>`.

Options:

- `--out <OUT>`: output bundle path.
- `--signing-key <SIGNING_KEY>`: optional P-256 PKCS#8 private key PEM for signing the bundle with ES256.

The exported JSON bundle has `kind: "augenmass-evidence-bundle"`, `schemaVersion: 1`, a canonical `payloadSha256`, a `sensitive: true` payload, the raw artifacts as base64url-no-pad entries, a deterministic redacted `replayTrace`, and a machine-readable `caveats` list spelling out the handling restrictions on the captured material. The canonical payload hash excludes wall-clock export time, so the same artifact set produces the same payload hash.

Text output:

```
EVIDENCE BUNDLE EXPORTED
session: <session>
out: <bundle.json>
entries: <n>
payloadSha256: <sha256>
signature: present|absent
sensitive: true
```

## `evidence verify`

```
Usage: augenmass evidence verify [OPTIONS] <BUNDLE>
```

Arguments:

- `<BUNDLE>`: evidence bundle JSON.

Options:

- `--verify-key <VERIFY_KEY>`: optional P-256 public key PEM for signature verification. If omitted, a signed bundle is checked against its embedded public key.

Verification checks every entry length and SHA-256, regenerates the redacted replay trace from the embedded artifacts, checks that it matches the stored replay trace, checks the canonical payload SHA-256, and verifies the optional ES256 signature. It exits non-zero on any mismatch.

Text output:

```
EVIDENCE BUNDLE VALID
session: <session>
entries: <n>
replayEvents: <n>
payloadSha256: <sha256>
signature: absent|valid with embedded key|valid with supplied key
sensitive: true
```

## `evidence replay`

```
Usage: augenmass evidence replay [OPTIONS] <BUNDLE>
```

Arguments and options match `evidence verify`.

Replay first performs the same bundle verification, then prints the redacted timeline. It never writes raw wallet material to stdout. It uses only shape, lengths, SHA-256 digests, field names, artifact labels, and verification outcomes. If the bundle contains `direct-post.body`, `session-enc-key.jwk`, `verification-context.json`, and an encrypted response, replay decrypts the `direct_post.jwt` locally and verifies the SD-JWT VC presentation offline with the captured nonce, audience, vct, clock, and freshness window. Trust anchoring and live status are not claimed by evidence replay unless a later command adds explicit offline inputs for those checks.

## `evidence assert-live`

```
Usage: augenmass evidence assert-live [OPTIONS] <BUNDLE>
```

Arguments and options match `evidence verify`.

`assert-live` first performs the same bundle verification, then fails unless the
redacted replay contains a successful live-wallet spine:
`SESSION_CREATED`, `REQUEST_BUILT`, `REQUEST_OBJECT_FETCHED`,
`RESPONSE_RECEIVED`, `RESPONSE_DECRYPTED`, and a good `VERIFIED` event, with no
`REJECTED` or `ERROR` terminal event. It is the gate to run after a real
phone-wallet session captured with `serve --unsafe-debug-artifacts`.

This command proves the encrypted wallet response was received, decrypted, and
the presentation verified offline against the captured nonce/audience/vct. It
does not claim issuer trust anchoring, live status, or over-ask analysis; use
the live trace and explicit trust/status/over-ask gates for those.

Text output:

```
LIVE WALLET EVIDENCE PROVEN
session: <session>
requiredEvents: SESSION_CREATED, REQUEST_BUILT, REQUEST_OBJECT_FETCHED, RESPONSE_RECEIVED, RESPONSE_DECRYPTED, VERIFIED
replayEvents: <n>
payloadSha256: <sha256>
signature: absent|valid with embedded key|valid with supplied key
redacted: true
notes: trust/status/over-ask are not claimed by evidence assert-live; use the live trace and explicit gates for those.
```

## `evidence prove-trust-status`

```
Usage: augenmass evidence prove-trust-status [OPTIONS] --trust-anchor <TRUST_ANCHOR> --status-key <STATUS_KEY> <BUNDLE>
```

Arguments:

- `<BUNDLE>`: evidence bundle JSON.

Options:

- `--verify-key <VERIFY_KEY>`: optional P-256 public key PEM for signature verification.
- `--trust-anchor <TRUST_ANCHOR>`: PID issuer trust anchor PEM, as a file path or inline PEM.
- `--status-token <STATUS_TOKEN>`: status-list token (`statuslist+jwt`), as a file path or inline compact JWT. Use this for fully offline/reproducible proof.
- `--fetch-status-token`: fetch the status-list token from the credential's captured HTTPS status URI. This uses the same guarded public-address fetch path as `serve --live-status`: HTTPS only, no redirects, non-public IPs refused, DNS pinned after vetting, and a body-size cap.
- `--status-key <STATUS_KEY>`: status-signer public key or certificate PEM, as a file path or inline PEM.

`prove-trust-status` first performs the same bundle verification, then uses the
captured verification context (`nonce`, `aud`, `vct`, timestamp, freshness
window) and captured authorization response to re-run presentation verification
with explicit issuer trust and token-status-list inputs. Exactly one of
`--status-token` or `--fetch-status-token` is required. It prints only safe
metadata: bundle hash, presentation hash, status-token source, booleans, the
status URI hash, and disclosed claim keys. It does not print disclosed claim
values or raw wallet material.

Use it alongside `evidence assert-live`: `assert-live` proves the completed
encrypted phone-wallet exchange, while `prove-trust-status` proves the captured
presentation also verifies under the supplied trust/status material.

Text output:

```text
EVIDENCE TRUST/STATUS PROVEN
session: <session>
payloadSha256: <sha256>
signature: absent|valid with embedded key|valid with supplied key
statusTokenSource: supplied|fetched
presentations: <n>
redacted: true

presentation #1
  sha256: <sha256>
  vct: urn:eudi:pid:de:1
  holder binding: true
  trust anchored: true
  status checked: true
  status-list ref: true
  disclosed keys: <keys>
  status uri sha256: <sha256>
```

Example:

```
augenmass serve --unsafe-debug-artifacts ./debug-out
# After a wallet session, export the session directory:
augenmass evidence export ./debug-out/<session> --out evidence.json
augenmass evidence verify evidence.json
augenmass evidence replay evidence.json
augenmass evidence assert-live evidence.json
augenmass evidence prove-trust-status evidence.json \
  --trust-anchor pid-issuer-anchor.pem \
  --fetch-status-token \
  --status-key pid-status-signer.pem
```

---

# WRITE AND TARGETS

The write surface is guard-railed. There are three target modes: `clone` (a local registrar-compatible store, the default), `cached-sandbox` (a read-only loopback mirror for public sandbox reads), and `sandbox` (the real registrar, rehearsal only). Writes are dry-run by default; `--yes` performs the write; `--force` writes past an over-ask warning and requires `--yes`. Confirmed writes are allowed only for `clone` and `sandbox`; `cached-sandbox` is read-only and refuses `--yes` before any network call. The demo fixtures use relying party id `2af138a8-59ea-4a84-aea3-666cafdb1369`; do not reuse that id for a user's production relying party. For real writes, write only under the relying party the user explicitly names, and never mint extra relying parties. Never log, echo, or commit tokens, certificates, or keys.

The `clone` target is a local axum + SQLite store with no signing, no auth, and no x5c. It stores payload-only JWTs and is sound because every read path decodes payload-only. Its API base is `AUGENMASS_CLONE_API_BASE` (default `http://127.0.0.1:8080/api`). The `cached-sandbox` target reads from `AUGENMASS_CACHE_API_BASE` (default `http://127.0.0.1:8081/api`) and is served by `augenmass cache serve`. The `sandbox` target talks to the real registrar over Keycloak OAuth (resource-owner password grant), configured via `AUGENMASS_API_BASE` (default `https://sandbox.eudi-wallet.org/api`), `AUGENMASS_OIDC_TOKEN_URL`, `AUGENMASS_USERNAME`, `AUGENMASS_PASSWORD`, and the optional `AUGENMASS_OIDC_CLIENT_SECRET`.

The `register` and `list` commands talk to a target over HTTP, so for `--target clone` the clone server must be running (`augenmass clone serve`), and for `--target cached-sandbox` the cache server must be running (`augenmass cache serve`).

## `register`

Write a registration under guardrails. It runs the `check` gate first (over-ask plus format), then, only with `--yes`, performs the write. Without `--yes` it is a dry-run.

```
Usage: augenmass register [OPTIONS] <BODY>
```

Arguments:

- `<BODY>`: a registration body as a file path, inline JSON, or `-` for stdin.

Options:

- `--target <TARGET>`: `clone`, `cached-sandbox`, or `sandbox`. Default `clone`.
- `--yes`: confirm a write. Without this flag the command is a dry-run.
- `--force`: write past an over-ask warning. Requires `--yes`.
- `--json`, `-h, --help`.

Exit code: 1 on over-ask without `--force`, or a blocking format error; 0 on a clean dry-run or a successful write.

Dry-run a clean body to the clone (nothing is written), exit 0:

```
augenmass register examples/min.json --target clone
```

```
OK: no over-ask, no format errors. examples/min.json is ready to register.
DRY RUN: nothing written. Re-run with --yes to write to clone.
```

An over-ask body is refused even with `--yes` (you would need `--force` to override), exit 1:

```
augenmass register examples/over.json --target clone --yes
```

```
OVER-ASK: Over-ask vs purpose: 6 of 6 requested claims exceed the stated purpose.
  ...
Over-asking 6 claim(s) beyond the stated purpose.
```

Actually write a clean body to the running clone (requires `augenmass clone serve`):

```
augenmass register examples/min.json --target clone --yes
```

Dry-run against cached-sandbox is allowed, but a confirmed write is refused:

```
augenmass register examples/min.json --target cached-sandbox
augenmass register examples/min.json --target cached-sandbox --yes
```

## `list`

Read registrations back for one relying party, decoded. It fetches from the target and renders each stored certificate payload-only.

```
Usage: augenmass list [OPTIONS]
```

Options:

- `--target <TARGET>`: `clone`, `cached-sandbox`, or `sandbox`. Default `clone`.
- `--rp <RP>`: the relying-party id. Default `2af138a8-59ea-4a84-aea3-666cafdb1369`.
- `--json`, `-h, --help`.

Exit code: 0 on a successful read.

Example (against the running clone):

```
augenmass list --target clone
```

When the store is empty:

```
No registrations for RP 2af138a8-59ea-4a84-aea3-666cafdb1369 on clone.
```

## `clone serve`

Run the registrar-compatible local clone store. It serves `POST`/`GET /registration-certificates` (and the `/api/...` variants) backed by SQLite, with no signing and no auth. This is the default write target; start it before `register --target clone` or `list --target clone`.

```
Usage: augenmass clone serve [OPTIONS]
```

Options:

- `--db <DB>`: the SQLite database path. Default `./augenmass-clone.sqlite`.
- `--port <PORT>`: the listen port. Default `8080`.
- `--json`, `-h, --help`.

This command runs until interrupted. Start it on the default port:

```
augenmass clone serve
```

Run on a different port and database file:

```
augenmass clone serve --port 9090 --db ./scratch-clone.sqlite
```

With a non-default port, point the read/write commands at it via `AUGENMASS_CLONE_API_BASE`, for example `http://127.0.0.1:9090/api`.

## `cache serve`

Run a read-through cached-sandbox target for public sandbox GET routes.
It mirrors successful upstream responses into SQLite, returns fresh hits from
disk, and falls back to stale cached data if a forced refresh or expired entry
cannot reach the upstream. It evicts the oldest rows after the configured entry
cap is reached, and it never caches writes.

```
Usage: augenmass cache serve [OPTIONS]
```

Options:

- `--db <DB>`: the SQLite database path. Default `./augenmass-cache.sqlite`; env `AUGENMASS_CACHE_DB`.
- `--host <HOST>`: bind host. Default `127.0.0.1`; env `AUGENMASS_CACHE_HOST`. Use `0.0.0.0` only when deploying behind TLS or a private network; non-loopback binds require `--admin-token` or `AUGENMASS_CACHE_ADMIN_TOKEN`.
- `--port <PORT>`: listen port. Env `AUGENMASS_CACHE_PORT` wins, then `PORT`, then default `8081`.
- `--upstream <UPSTREAM>`: the upstream API base. Default `https://sandbox.eudi-wallet.org/api`; env `AUGENMASS_CACHE_UPSTREAM`.
- `--ttl-secs <TTL_SECS>`: freshness window in seconds. Default `3600`; env `AUGENMASS_CACHE_TTL_SECS`.
- `--timeout-secs <TIMEOUT_SECS>`: upstream request timeout in seconds. Default `10`; env `AUGENMASS_CACHE_TIMEOUT_SECS`.
- `--max-entries <MAX_ENTRIES>`: maximum stored cache entries before oldest rows are evicted. Default `512`; env `AUGENMASS_CACHE_MAX_ENTRIES`.
- `--admin-token <ADMIN_TOKEN>`: protect `GET /api/cache/status` and `POST /api/cache/refresh`; env `AUGENMASS_CACHE_ADMIN_TOKEN`.
- `--allowed-rp <ALLOWED_RPS>`: allow registration-certificate read-through for this RP. Repeatable; env `AUGENMASS_CACHE_ALLOWED_RPS` accepts comma-separated values. Default `2af138a8-59ea-4a84-aea3-666cafdb1369`.
- `--allow-any-rp`: explicitly allow any syntactically valid RP. Env `AUGENMASS_CACHE_ALLOW_ANY_RP`. Unsafe for shared deployments.
- `--unsafe-upstream`: permit non-https or private upstreams on public binds. Env `AUGENMASS_CACHE_UNSAFE_UPSTREAM`. Unsafe for shared deployments.
- `-h, --help`.

The cache serves these registrar-shaped read routes:

- `GET /api/schema-metadata`
- `GET /api/schema-metadata/vocabularies`
- `GET /api/registration-certificates?rp=<id>`

It also exposes `GET /api/health`, `GET /api/cache/status`, and forced refresh
via `POST /api/cache/refresh?route=<route>[&rp=<id>]`. If an admin token is
configured, status and refresh require `Authorization: Bearer <token>` or
`x-augenmass-cache-admin: <token>`. Responses carry provenance
headers: `x-augenmass-cache`, `x-augenmass-cache-key`,
`x-augenmass-cache-fetched-at`, and `x-augenmass-cache-sha256`. Full upstream
URLs are available only through protected cache status.
Registration-certificate reads are allowlisted by RP; unlisted RP reads and
authenticated refreshes return `403` before contacting the upstream.
Non-loopback binds refuse to start without an admin token, without a non-empty
RP allowlist unless `--allow-any-rp` is set, or with an unsafe upstream unless
`--unsafe-upstream` is set. Concurrent public misses for the same cache key are
coalesced; if stale data exists while a refresh is already running, the stale
entry is served instead of starting another upstream request.

Example:

```
augenmass cache serve
AUGENMASS_CACHE_API_BASE=http://127.0.0.1:8081/api augenmass list --target cached-sandbox
```

Deploy shape for Railway or a small VPS:

```
AUGENMASS_CACHE_ADMIN_TOKEN=<token> \
AUGENMASS_CACHE_ALLOWED_RPS=2af138a8-59ea-4a84-aea3-666cafdb1369 \
augenmass cache serve --host 0.0.0.0 --port ${PORT:-8081} --db /data/augenmass-cache.sqlite
```

## `cache warm`

Force-refresh the cache server's demo-critical public sandbox routes:
schema metadata, schema vocabularies, and one relying party's registration list.

```
Usage: augenmass cache warm [OPTIONS]
```

Options:

- `--api-base <API_BASE>`: cache API base. Default `http://127.0.0.1:8081/api`; env `AUGENMASS_CACHE_API_BASE`.
- `--admin-token <ADMIN_TOKEN>`: bearer token for protected refresh endpoints; env `AUGENMASS_CACHE_ADMIN_TOKEN`.
- `--rp <RP>`: relying party id whose registration list should be warmed. Default `2af138a8-59ea-4a84-aea3-666cafdb1369`.
- `--timeout-secs <TIMEOUT_SECS>`: HTTP request timeout in seconds. Default `10`; env `AUGENMASS_HTTP_TIMEOUT_SECS`.
- `-h, --help`.

Example:

```
augenmass cache warm \
  --api-base http://127.0.0.1:8081/api \
  --rp 2af138a8-59ea-4a84-aea3-666cafdb1369
```

With an admin token:

```
augenmass cache warm --api-base https://cache.example/api --admin-token <token> --rp <rp-id>
```

Add `--json` for a machine-readable summary of each refreshed route, including
cache disposition, body size, item count where known, and SHA-256. Warmed bodies
must be JSON, and registration warm responses must be arrays whose rows contain
a `jwt`.

## `cache status`

Read the protected cache inventory from a local or deployed cache server.

```
Usage: augenmass cache status [OPTIONS]
```

Options:

- `--api-base <API_BASE>`: cache API base. Default `http://127.0.0.1:8081/api`; env `AUGENMASS_CACHE_API_BASE`.
- `--admin-token <ADMIN_TOKEN>`: bearer token for the protected status endpoint; env `AUGENMASS_CACHE_ADMIN_TOKEN`.
- `--timeout-secs <TIMEOUT_SECS>`: HTTP request timeout in seconds. Default `10`; env `AUGENMASS_HTTP_TIMEOUT_SECS`.
- `-h, --help`.

Example:

```
augenmass cache status --api-base http://127.0.0.1:8081/api --admin-token <token>
```

Text output summarizes the upstream, TTL, max entries, RP allowlist, cached keys,
fetch times, byte sizes, and SHA-256 hashes. Add `--json` to return the server's
raw `augenmass-cache-status` document for agents, scripts, and deployment checks.

---

## Quick end-to-end recipes

Generate a proportionate body, gate it, and (with a running clone) write it:

```
augenmass clone serve            # in one shell
augenmass generate regbody | augenmass check -
augenmass generate regbody | augenmass register - --target clone --yes
augenmass list --target clone
```

Triage an unknown artifact, then verify it fully:

```
augenmass inspect fixtures/presentations/erica-vp-VALID.sdjwt
augenmass verify presentation fixtures/presentations/erica-vp-VALID.sdjwt \
  --nonce b4ba2623-76a2-486b-a1f6-f1656025d07b \
  --aud https://self-issued.me/v2 \
  --now 1780435200 \
  --trust-anchor fixtures/certs/erica-trust-anchor.pem
```

Diagnose a verifier request and confirm its client_id binding:

```
augenmass doctor fixtures/requests/eudiplo-request.jwt
augenmass x509-hash fixtures/requests/eudiplo-request.jwt \
  --client-id x509_hash:7zvIjJaM1KQPpN7IZBuVLuh8anw1gcbZ0a6Wj3M9i4w
```
