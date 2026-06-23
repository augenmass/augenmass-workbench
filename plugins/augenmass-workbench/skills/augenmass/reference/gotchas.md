# EUDI gotchas, and which augenmass command catches each

This is a field guide to the mistakes that quietly break an EUDI Wallet relying-party integration: a registration the registrar rejects, a signed request the wallet refuses, a presentation that fails to verify. Each entry states the mistake, why it happens, the fix, and the exact Augenmaß command that catches it so you find the problem before the registrar or the wallet does.

Two facts to keep straight throughout:

- A registration body (the JSON you POST to the registrar, keyed by `rpId`) and a signed request / JAR (the OpenID4VP `oauth-authz-req+jwt` the verifier sends the wallet) are different documents with different rules. `check` is the gate for registration bodies; `doctor` is the gate for signed requests. Do not run one on the other.
- Static artifact checks below run fully offline. Explicit live surfaces are registrar targets, the cache server, and `serve`. Commands exit non-zero on the bad outcome, so they drop straight into CI.

All commands are shown relative to the repo root with bare `augenmass` for readability. Inside the Claude Code skill, agents should prefer `${CLAUDE_PLUGIN_ROOT}/bin/augenmass` so they run the bundled plugin binary the user installed.

---

## Part 1: registration-body gotchas (caught by `check`)

`check` reads a registrar registration body and reports two kinds of finding: format errors (the registrar DTO shape) and over-ask (proportionality). It exits 1 on a blocking format error or on over-ask, 0 when the body is clean. The examples below use the committed fixtures under `examples/`.

A clean body passes:

```
$ augenmass check examples/min.json
OK: no over-ask, no format errors. examples/min.json is ready to register.
```

### 1.1 claims[].path is a string, not an array

Mistake: writing the claim path as a dotted string.

Why it happens: humans write claim paths as `age_equal_or_over.18` everywhere (in prose, in `generate dcql --claim`, in baseline listings), so it is natural to paste that string straight into the body. The registrar DTO requires an array of path segments. A dotted string is not a one-element-deep path; it is a single literal key that does not exist.

Wrong:

```json
"claims": [
  { "path": "age_equal_or_over.18" }
]
```

Right:

```json
"claims": [
  { "path": ["age_equal_or_over", "18"] }
]
```

Caught by `check`:

```
$ augenmass check examples/bad-path.json
Format findings:
  CHECK-PATH-STRING [blocking]: claims[].path must be an array of segments, not a string.
    Fix: Change "path": "age_equal_or_over" to "path": ["age_equal_or_over", "18"].
```

Exit code 1. `examples/min.json` is the corrected version of `examples/bad-path.json`; diff the two to see the one change.

### 1.2 requested claims under provided_attestations instead of credentials

Mistake: placing the requested credential under a top-level `provided_attestations` key.

Why it happens: the EUDI vocabulary has several attestation-shaped containers, and `provided_attestations` reads like the natural home for "the attestations I want." The registrar reads requested claims from `credentials`, so a body that puts them under `provided_attestations` registers a relying party that requests nothing.

Wrong:

```json
"provided_attestations": [
  { "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
    "claims": [{ "path": ["age_equal_or_over", "18"] }] }
]
```

Right:

```json
"credentials": [
  { "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
    "claims": [{ "path": ["age_equal_or_over", "18"] }] }
]
```

Caught by `check`:

```
CHECK-PROVIDED-ATTESTATIONS [blocking]: Requested claims are under provided_attestations; the registrar reads requests from credentials.
    Fix: Move the requested credential into credentials[], with format, meta, and claims[].path.
```

Exit code 1.

### 1.3 purpose is a bare string, not a list of {lang, content}

Mistake: setting `purpose` to a plain string.

Why it happens: a purpose is conceptually one sentence ("Age verification"), so a string feels right. The registrar wants a localisable list of objects, each with a language tag and the localised text.

Wrong:

```json
"purpose": "Age verification"
```

Right:

```json
"purpose": [
  { "lang": "en", "content": "Age verification" }
]
```

Caught by `check`:

```
CHECK-PURPOSE-SHAPE [blocking]: purpose must be a list of {lang, content} objects, not a string.
    Fix: Use "purpose": [{ "lang": "en", "content": "Age verification" }].
```

Exit code 1.

### 1.4 privacy_policy is not a valid URL

Mistake: putting a label, a path fragment, or a placeholder in `privacy_policy` instead of an absolute URL.

Why it happens: it is a free-text-looking field next to `support_uri`, and `support_uri` accepts non-URL contacts (see 1.5), so it is easy to assume the same latitude applies here. It does not: `privacy_policy` must parse as a valid URL.

Wrong:

```json
"privacy_policy": "see our website"
```

Right:

```json
"privacy_policy": "https://example.com/privacy"
```

Caught by `check`:

```
CHECK-PRIVACY-POLICY-URL [blocking]: privacy_policy must be a valid URL.
    Fix: Set privacy_policy to a URL, for example https://example.com/privacy.
```

Exit code 1.

### 1.5 over-validating support_uri as a URL (it is not)

This is the inverse trap of 1.4. `support_uri` is any non-empty contact string: an email, a phone number, or a URL are all valid. Do not reject it for not being a URL, and do not force it into URL shape. The only thing `check` flags here is emptiness, and only as a warning, not a blocking error.

All accepted:

```json
"support_uri": "support@example.com"
"support_uri": "+49 30 123456"
"support_uri": "https://example.com/support"
```

Empty is a non-blocking warning. The body still reports OK and exits 0:

```
$ augenmass check '{... "support_uri":"" ...}'
Format findings:
  CHECK-SUPPORT-URI-EMPTY [warning]: support_uri is empty. It must be a non-empty contact string (email, phone, or URL are all valid).
    Fix: Set support_uri to any contact, for example support@example.com or https://example.com/support.

OK: no over-ask, no format errors. ... is ready to register.
```

Because the warning is non-blocking, exit code is 0. Treat the empty-support_uri warning as a fill-it-in nudge, not a CI failure.

### 1.6 over-asking for more than the purpose needs

Mistake: requesting attributes beyond what the stated purpose requires (asking for `given_name`, `family_name`, and `birthdate` when the purpose is an age gate).

Why it happens: it is cheaper to request a wide set once than to scope each registration, and PID exposes many attributes. This is the central problem Augenmaß exists to prevent. The legal basis, cited verbatim by the engine:

1. eIDAS Regulation (EU) 2024/1183, Art. 5b(3): "Relying parties shall not request users to provide data other than that indicated for their intended use."
2. GDPR (EU) 2016/679, Art. 5(1)(c): data minimisation ("adequate, relevant and limited to what is necessary").
3. EUDI ARF, registration certificate, RPRC_07: the wallet verifies requested attributes are within the registration certificate and notifies the user otherwise.

Fix: request only the attributes the purpose needs. The curated baselines are the reference for "what is necessary":

- `age_gate_18` (Age gate, over 18): `age_equal_or_over.18`
- `event_checkin` (Event check-in): `given_name`, `family_name`, `age_equal_or_over.18`
- `car_rental` (Car rental, over 21, named): `given_name`, `family_name`, `age_equal_or_over.21`
- `bank_kyc` (Bank onboarding, KYC): `given_name`, `family_name`, `birthdate`, `address.resident_{street,city,postal_code,country}`

Run `augenmass baselines` to print them with the legal basis, or `augenmass baselines age_gate_18` for one in detail.

Caught by `check` (over-ask is reported alongside format findings, and over-ask alone is enough to exit 1). To lint a DCQL request rather than a registration body, use `audit`:

```
augenmass audit --request overask --purpose age_gate_18
```

`audit` exits 1 on over-ask, 0 otherwise. Pass `--request minimal`, `--request overask`, or a path to a DCQL JSON file, and `--purpose` to pick the baseline.

---

## Part 2: signed-request / JAR gotchas (caught by `doctor`)

`doctor` reads an OpenID4VP signed request (the `oauth-authz-req+jwt` JAR, as JSON or as a compact JWT) and reports the gotchas that make a wallet refuse it. It exits 1 if there are findings. These are not the same fields as a registration body; do not run `check` here.

### 2.1 x5c is a string, not a list

Mistake: setting `x5c` to a single base64 cert string.

Why it happens: there is usually exactly one certificate (the leaf), so a single string feels complete. The JOSE header `x5c` is always an array of base64 (DER) certificate strings, one per cert in the chain, even when the chain is a single cert.

Wrong:

```json
"header": { "typ": "oauth-authz-req+jwt", "x5c": "MIIB..." }
```

Right:

```json
"header": { "typ": "oauth-authz-req+jwt", "x5c": ["MIIB..."] }
```

Caught by `doctor`:

```
$ augenmass doctor examples/bad-request.json
Signed-request findings:
  DOCTOR-X5C-STRING [blocking]: x5c must be a list of strings, even for a single certificate.
    Fix: Wrap the certificate in an array: "x5c": ["MIIB..."].
```

### 2.2 client_id is not in x509_hash form

Mistake: using a URL, a DNS name, or any other value as `client_id` when the wallet expects the x509_hash binding.

Why it happens: in many OAuth ecosystems `client_id` is an opaque registered identifier or a URL. The sandbox wallet binds `client_id` to the signing certificate: it must be `x509_hash:<base64url(SHA-256(leaf-cert-DER))>`. Do not hand-build this value; compute it.

Wrong:

```json
"payload": { "client_id": "https://example.com/verifier" }
```

Right (computed, not typed):

```json
"payload": { "client_id": "x509_hash:7zvIjJaM1KQPpN7IZBuVLuh8anw1gcbZ0a6Wj3M9i4w" }
```

Caught by `doctor` (same `examples/bad-request.json` triggers both 2.1 and 2.2):

```
  DOCTOR-CLIENT-ID-X509HASH [blocking]: client_id must be in the x509_hash form.
    Fix: Use "client_id": "x509_hash:<base64url(SHA-256(leaf-cert-DER))>". Compute it with `augenmass x509-hash`.
```

Compute the binding from the JAR (it reads the x5c leaf), or from a PEM cert, or from base64 DER:

```
$ augenmass x509-hash fixtures/requests/eudiplo-request.jwt
x509_hash:   7zvIjJaM1KQPpN7IZBuVLuh8anw1gcbZ0a6Wj3M9i4w
client_id:   x509_hash:7zvIjJaM1KQPpN7IZBuVLuh8anw1gcbZ0a6Wj3M9i4w
subject:     CN=Verifier Fixture Tenant,C=DE
issuer:      CN=Verifier Fixture Tenant,C=DE
serial:      00:DB:A3:5E:73:ED:1F:A1:D2:2B:7A:19:CD:FB:1E:6F:64
```

To assert that a claimed `client_id` matches the cert, pass `--client-id`. It exits 1 on mismatch, 0 on match:

```
$ augenmass x509-hash fixtures/requests/eudiplo-request.jwt --client-id x509_hash:WRONGHASH
...
MISMATCH: claimed client_id
  x509_hash:WRONGHASH
does not equal the computed
  x509_hash:7zvIjJaM1KQPpN7IZBuVLuh8anw1gcbZ0a6Wj3M9i4w
```

### 2.3 missing Content-Type on the POST

Mistake: omitting (or defaulting) the `Content-Type` when POSTing to the registrar or to a verifier endpoint.

Why it happens: some HTTP clients default to `application/x-www-form-urlencoded` or send no type at all. Set `Content-Type: application/json` on every POST. This is a transport gotcha, not something in the document body, so it is a checklist item alongside the `doctor` findings rather than a finding `doctor` emits.

---

## Part 3: ecosystem traps worth knowing

These do not all have a dedicated finding code, but they cause the same class of silent failure, and the relevant decoders (`inspect`, `decode`, `verify`) surface them.

### 3.1 VCT is a URN, not a URL

The German PID `vct` is `urn:eudi:pid:de:1`, a URN, not an `https://` URL. Validation or tooling that assumes every identifier resolves over HTTP will reject a perfectly valid `vct`. The PID model uses `PID_VCT = "urn:eudi:pid:de:1"` and `PID_FORMAT = "dc+sd-jwt"`. When verifying a presentation, `verify presentation` defaults `--vct` to the German PID; override it with `--vct` only when the credential is something else.

Wrong assumption: `vct` must be a dereferenceable URL.

Right: `vct` may be a URN; `urn:eudi:pid:de:1` is correct.

### 3.2 base64url-no-pad vs standard base64

Two different base64 alphabets show up in the same ecosystem. The x509_hash binding and JOSE-side values use base64url without padding (the `7zvI...i4w` form, with `-` and `_`, no trailing `=`). Standard base64 (with `+`, `/`, and `=` padding) is what you get from `openssl base64` and from many cert exports. Mixing them produces a `client_id` that will never match. Always compute the hash with `augenmass x509-hash` rather than re-encoding a digest yourself; it emits the base64url-no-pad form the wallet expects.

### 3.3 client_id_scheme x509_hash only, not x509_san_dns

The sandbox wallet supports the `x509_hash` client_id scheme only. It does not support `x509_san_dns`. A request signed for `x509_san_dns` (binding `client_id` to a DNS SAN in the cert) will be refused even if the certificate and signature are otherwise valid. Stay on `x509_hash` for the sandbox, and use `x509-hash` to produce the matching `client_id`.

### 3.4 mdoc 2-element claim paths vs SD-JWT nested paths

Claim path shape differs by credential format. An mdoc claim path is exactly two elements, `[namespace, element]`. An SD-JWT VC path is a nested array of object keys (for example `["age_equal_or_over", "18"]` or `["address", "resident_city"]`), as deep as the claim nests. Reusing an mdoc-shaped path in an SD-JWT request (or the reverse) selects nothing. Registration bodies in this ecosystem use the SD-JWT nested form; `check` enforces the array shape (see 1.1) but the segments themselves must match the format you are requesting.

### 3.5 nonce and aud binding for the KB-JWT

A presentation's holder-binding JWT (KB-JWT) must echo the Authorization Request `nonce` and bind to the verifier's `client_id` as its audience (`aud`). If either is wrong, the presentation is not bound to your request and must be rejected: a correct signature over the wrong nonce is a replay, and a correct signature for the wrong audience was meant for someone else. Verification fails closed.

Caught by `verify presentation`, which requires both `--nonce` and `--aud` and exits 1 if the binding does not hold. Against the committed fixtures (shared `nonce` `b4ba2623-76a2-486b-a1f6-f1656025d07b`, `aud` `https://self-issued.me/v2`, verification clock `--now 1780435200`):

```
augenmass verify presentation fixtures/presentations/erica-vp-VALID.sdjwt \
  --nonce b4ba2623-76a2-486b-a1f6-f1656025d07b \
  --aud https://self-issued.me/v2 \
  --now 1780435200
```

The fixtures `erica-vp-WRONG_NONCE.sdjwt`, `erica-vp-WRONG_AUDIENCE.sdjwt`, and `erica-vp-MISSING_HOLDER_BINDING.sdjwt` each isolate one binding failure; run the same command against them to see `verify presentation` exit 1. `erica-vp-OVER_DISCLOSURE.sdjwt` and `erica-vp-EXPIRED.sdjwt` cover disclosure and freshness. `verify presentation` accepts `--max-age` (KB-JWT freshness window, default 300 seconds), `--vct`, `--trust-anchor`, and `--status-token` / `--status-key` to fold trust and revocation into one pass.

---

## Part 4: live wallet-interaction debugger gotchas (`serve`)

`augenmass serve` is a verifier-in-a-box: a local OpenID4VP verifier for the German PID profile that a real EUDI wallet presents to, recording the exchange as a per-session trace. It runs until interrupted (Ctrl-C). Unlike the offline commands, it is a network path: a wallet connects to it, and `--live-status` resolves a status list over the network. The traps below are about wiring the wallet to the right verifier, not about a malformed document.

### 4.1 the zero-config client_id is not the registered identity

Mistake: assuming the `client_id` `serve` prints is the one you registered with the sandbox.

Why it happens: `serve` is zero-config. With no flags it mints a throwaway development certificate so it runs without a registrar-issued leaf, and the `client_id` is the `x509_hash` of that throwaway cert, not of your registered leaf. A wallet that pins or checks the registered identity will see a different `client_id`.

Fix: pass `--key` and `--leaf` together (or set `RP_KEY_PATH` and `RP_LEAF_PATH`) to sign with the real registrar-issued leaf, so the `client_id` matches the registered identity. The startup banner says which cert is in use (`throwaway (development)` versus `registrar-issued leaf`).

### 4.2 --public-url must match how the wallet reaches the tool

Mistake: leaving `--public-url` at the `http://127.0.0.1:8080/` default when the wallet runs on a different device (a phone).

Why it happens: the default works when the wallet and the tool share a host. But the `--public-url` is baked into the `request_uri` and `response_uri` the wallet is handed, so `127.0.0.1` tells a phone wallet to call back to itself, and the exchange stalls after the QR scan.

Fix: bind all interfaces and set a base URL the wallet can actually reach. The `--public-url` must end in `/`:

```
augenmass serve --host 0.0.0.0 --public-url http://192.0.2.10:8080/
```

### 4.3 you cannot replay a static or fixture wallet response

Mistake: trying to POST a captured or fixture `direct_post.jwt` to a running `serve` to reproduce a flow.

Why it happens: it is natural to want a static request/response pair for a test. But each `serve` run generates a fresh ephemeral encryption key and a per-session nonce. The wallet must encrypt its response to this run's key and echo this run's nonce, so a response captured from an earlier run will not decrypt (wrong key) or will fail the nonce binding. The trace shows where it breaks: `RESPONSE_DECRYPTED` fails, or `REJECTED` on the nonce.

Fix: drive a live wallet against the running instance rather than replaying a recording. For static, deterministic checks, use `verify presentation` on the captured presentation with the matching `--nonce` and `--aud` instead.

### 4.4 --live-status needs an anchor and supports a single issuer only

Mistake: passing `--live-status` alone, or pointing `--trust-anchor` at a multi-certificate anchor PEM, and expecting live revocation.

Why it happens: `--live-status` reads as a standalone switch, but it only takes effect when a `--trust-anchor` is also set (it is off by default so the service stays offline-friendly). And live status binds the status-list signature to a single issuer anchor key, so a PEM carrying more than one certificate is ambiguous and fails closed rather than silently picking the first.

Fix: set both `--trust-anchor <PEM>` and `--live-status`, and supply a single-issuer anchor PEM. With them set, the trace gains a `STATUS_CHECKED` step and a revoked or suspended credential is rejected fail-closed.

---

## Quick reference: mistake to command

| Mistake | Document | Command | Finding / signal |
| --- | --- | --- | --- |
| `claims[].path` is a string | registration body | `check` | CHECK-PATH-STRING (blocking) |
| claims under `provided_attestations` | registration body | `check` | CHECK-PROVIDED-ATTESTATIONS (blocking) |
| `purpose` is a bare string | registration body | `check` | CHECK-PURPOSE-SHAPE (blocking) |
| `privacy_policy` not a URL | registration body | `check` | CHECK-PRIVACY-POLICY-URL (blocking) |
| `support_uri` empty | registration body | `check` | CHECK-SUPPORT-URI-EMPTY (warning, exit 0) |
| over-asking for attributes | registration body / DCQL | `check` / `audit` | over-ask (exit 1) |
| `x5c` is a string | signed request / JAR | `doctor` | DOCTOR-X5C-STRING (blocking) |
| `client_id` not x509_hash | signed request / JAR | `doctor` | DOCTOR-CLIENT-ID-X509HASH (blocking) |
| compute / verify the binding | leaf cert / JAR | `x509-hash` | MATCH / MISMATCH (exit 1 on mismatch) |
| missing `Content-Type: application/json` | POST transport | checklist | not a body finding |
| `vct` assumed to be a URL | presentation / request | `inspect`, `decode`, `verify presentation` | URN `urn:eudi:pid:de:1` is valid |
| base64 standard vs base64url-no-pad | x5c / hash | `x509-hash` | emits base64url-no-pad |
| `x509_san_dns` on sandbox | signed request / JAR | n/a | sandbox supports `x509_hash` only |
| mdoc vs SD-JWT claim path shape | request / body | `check` (array shape) | format must match credential |
| nonce / aud binding | presentation | `verify presentation` | exit 1 if unbound |
| zero-config client_id is throwaway | live debugger | `serve` | pass `--key` + `--leaf` for the registered identity |
| `--public-url` unreachable from the wallet | live debugger | `serve` | `--host 0.0.0.0` + a reachable `--public-url` ending in `/` |
| replaying a static wallet response | live debugger | `serve` | fresh ephemeral key + nonce per run; drive a live wallet |
| `--live-status` without an anchor or multi-cert anchor | live debugger | `serve` | needs `--trust-anchor`; single issuer anchor only (fails closed) |
