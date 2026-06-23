# Augenmaß Workbench: Artifact Field Guide

A cookbook for developers and auditors working in the EUDI (European Digital Identity) Wallet ecosystem. The premise is simple: you are holding some EUDI artifact, a blob of base64 or a JSON body or a deep link, and you need to know what it is, what is inside it, and whether it is correct. This guide is organized by artifact. For each one you get a one-line "what it is", the command to decode it, the command to verify or audit it where that applies, and the gotchas that actually bite people.

Every command below works as written against the `augenmass` binary. All decoding runs fully offline; only explicit live surfaces touch a network or store: `register`/`list` targets, `clone serve`, `cache serve`, `cache warm`, and `serve` (the live wallet-interaction debugger, where a real wallet connects). Throughout, every artifact argument accepts a file path, an inline value, or `-` for stdin.

If you only remember one command, remember this one:

```
augenmass inspect <input>
```

`inspect` sniffs the artifact type and dispatches to the right decoder. It is the front door for everything below. The per-type `decode` subcommands exist for when you already know the type and want to force it.

Add `--json` to any read-only command for machine-readable output suited to CI and agents.

## Quick artifact index

| You have | What it is | Decode with | Verify/audit with |
| --- | --- | --- | --- |
| `*.sdjwt`, `...~...~...` | SD-JWT VC presentation | `inspect` / `decode sd-jwt` | `verify presentation`, `verify trust`, `verify status` |
| `rc-wrp+jwt` payload | WRPRC registration certificate | `inspect` / `decode regcert` | `audit --cert ...` |
| `oauth-authz-req+jwt` | OpenID4VP authorization request / JAR | `inspect` / `decode request` | `doctor`, `x509-hash` |
| `openid-credential-offer://` | OpenID4VCI credential offer | `inspect` / `decode offer` | (none; offline decode) |
| `openid4vp://` | OpenID4VP request URI | `inspect` / `decode offer` | (resolve `request_uri` then `doctor`) |
| `statuslist+jwt` | Token status list | `inspect` / `decode status-list` | `verify status-list` |
| ISO 18013-5 CBOR, hex, or base64 | mdoc / mso_mdoc credential | `inspect` / `decode mdoc` | decode only |
| DCQL JSON | DCQL query | `inspect` | `audit --request FILE ...` |
| `{ "rpId": ... }` | Registrar registration body | `inspect` | `check`, then `register` |
| PEM cert | X.509 certificate | `inspect` / `decode jwt` (for JWTs) | `x509-hash` |

## SD-JWT VC presentation

What it is: a Verifiable Credential a wallet presents to a verifier, in SD-JWT form: an issuer-signed JWT, a set of `~`-separated disclosures, and a trailing Key Binding JWT (KB-JWT) that proves holder binding to a specific nonce and audience.

Decode it with:

```
augenmass inspect fixtures/presentations/erica-vp-VALID.sdjwt
augenmass decode sd-jwt fixtures/presentations/erica-vp-VALID.sdjwt
```

This shows the `vct`, issuer algorithm, whether a KB-JWT is present, and the disclosed claims, with no signature checked.

Verify it with (this is the end-to-end cryptographic check):

```
augenmass verify presentation fixtures/presentations/erica-vp-VALID.sdjwt \
  --nonce b4ba2623-76a2-486b-a1f6-f1656025d07b \
  --aud https://self-issued.me/v2 \
  --now 1780435200
```

`verify presentation` checks the issuer signature, the KB-JWT (including that it echoes your `--nonce` and binds to your `--aud`), KB-JWT freshness (`--max-age`, default 300 seconds), and the `vct`. It exits 1 if anything fails. Layer on optional checks:

- `--trust-anchor fixtures/certs/erica-trust-anchor.pem` anchors the issuer to a trust anchor instead of trusting the leaf key.
- `--status-token ... --status-key ...` folds revocation into the same run (both flags are required together).
- `--vct` overrides the expected `vct` (it defaults to the German PID, `urn:eudi:pid:de:1`).

Two narrower checks exist as separate commands:

```
augenmass verify trust fixtures/presentations/erica-vp-VALID.sdjwt \
  --anchor fixtures/certs/erica-trust-anchor.pem --now 1780435200

augenmass verify status fixtures/presentations/synthetic-pid-with-status.sdjwt \
  --token fixtures/status/status-list-REVOKED.jwt \
  --key fixtures/status/status-list-verify-key.pub.pem
```

Common gotchas:

- The `vct` can be a URN, not a URL. The German PID is `urn:eudi:pid:de:1`. Do not assume `vct` resolves over HTTP, and do not reject a URN as malformed.
- Verification is clock-sensitive. The committed fixtures verify at `--now 1780435200`. Omit `--now` to use the system clock; with stale or future fixtures, the system clock will make a valid presentation look expired or not-yet-valid.
- `verify trust` does leaf-chains-to-anchor plus a validity-window check, not full RFC 5280 path validation. Treat a TRUSTED result as "the leaf chains to this anchor and is in its validity window", not "the full chain is policy-valid".
- Revocation is fail-closed and offline. `verify status` reads the bit from the status-list token you hand it; it does not fetch anything. If you give it the wrong token or index, it fails closed rather than passing.
- mdoc claim paths differ from SD-JWT paths. An mdoc path is a 2-element `[namespace, element]` (for example `["eu.europa.ec.eudi.pid.1", "given_name"]`), whereas SD-JWT nested claims use deeper segment arrays. Do not flatten one into the other.

## WRPRC registration certificate

What it is: a Wallet Relying Party Registration Certificate (`typ` `rc-wrp+jwt`), the artifact that records which credentials and claims a relying party is registered to request, and why. The workbench decodes the payload only.

Decode it with:

```
augenmass inspect fixtures/regcert/rc-by-id.json
augenmass decode regcert fixtures/regcert/rc-by-id.json
```

This renders the `purpose`, `privacy_policy`, `support_uri`, and the `credentials` array (format, `vct`, and each registered claim).

Audit it with (this is the over-ask check for auditors): decode the certificate to learn its registered scope, then audit a request against both a purpose baseline and the certificate:

```
augenmass audit --request overask --purpose age_gate_18 --cert fixtures/regcert/rc-by-id.json
```

With `--cert`, `audit` reports two distinct over-ask dimensions: claims beyond the stated purpose, and claims outside the relying party's registered scope. It exits 1 on over-ask.

Common gotchas:

- The certificate is decoded payload-only, with no signature verified. Do not treat a clean decode as proof of authenticity. It tells you what the certificate claims, not that it was validly signed.
- `purpose` in the certificate is human-readable text. The audit compares requested claims against a curated baseline, not against the prose. A plausible-sounding purpose string does not make an over-broad claim set proportionate.
- "Registered" is not "proportionate". A claim can be inside the registration scope and still be over-ask for the stated purpose. The audit distinguishes "Registered, but beyond what the stated purpose needs" from "Not in the relying party's registered scope".

## OpenID4VP authorization request / JAR

What it is: the verifier's signed authorization request (a JWT Secured Authorization Request, `typ` `oauth-authz-req+jwt`). It carries the `client_id`, `response_type`, `response_mode`, `nonce`, and the DCQL query, and it is signed with a certificate chain in the `x5c` header.

Decode it with:

```
augenmass inspect fixtures/requests/eudiplo-request.jwt
augenmass decode request fixtures/requests/eudiplo-request.jwt
```

This shows `typ`, `alg`, whether `x5c` is present, the `client_id` and its scheme, `response_type`, `response_mode`, `nonce`, `state`, and whether a DCQL query is present.

Diagnose it with (this is the JAR doctor):

```
augenmass doctor fixtures/requests/eudiplo-request.jwt
```

`doctor` flags the JAR-specific mistakes that make a wallet reject a verifier's request. It exits 1 when it finds blocking issues. Pair it with `x509-hash` to confirm the `client_id` binding (see the X.509 section).

Common gotchas:

- `x5c` must be a LIST of strings, even for a single certificate. A bare string is wrong: write `"x5c": ["MIIB..."]`. `doctor` flags this as `DOCTOR-X5C-STRING`.
- `client_id` must be in the `x509_hash` form: `x509_hash:<base64url(SHA-256(leaf-cert-DER))>`. Compute the correct value with `augenmass x509-hash` rather than by hand. `doctor` flags a non-conforming `client_id` as `DOCTOR-CLIENT-ID-X509HASH`.
- The sandbox wallet only supports `client_id_scheme` `x509_hash`. It does not support `x509_san_dns`. A request that binds via SAN DNS will be rejected even if otherwise well-formed.
- Set `Content-Type: application/json` on every POST in the flow. The workbench's own write path does this for you; hand-rolled clients often forget it.
- base64url-no-pad versus base64-standard matters for `x5c` entries and for the hash inside `client_id`. The `x509_hash` value is base64url. Mixing alphabets or adding padding produces a binding that will not match.

## OpenID4VCI credential offer

What it is: an issuer's offer to issue a credential, delivered as an `openid-credential-offer://` deep link (or the equivalent JSON). It names the credential issuer and the credential configuration ids being offered.

Decode it with:

```
augenmass decode offer 'openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example%22%2C%22credential_configuration_ids%22%3A%5B%22pid%22%5D%7D'
```

This unwraps the URI, shows the `credential_issuer`, and lists the `credential_configuration_ids`. `inspect` recognizes the same input.

There is no signature to verify here; this is an offline decode for reading what the issuer is proposing.

Common gotchas:

- The offer is URL-encoded. Pass the whole deep link as one argument (quote it in the shell), or use a file or `-`. Do not hand-decode the percent-encoding first.
- An offer with `credential_offer_uri` instead of an inline `credential_offer` is a reference, not the offer itself. Decoding the link shows the reference; the actual offer lives at the URI and must be fetched out of band.

## OpenID4VP request URI

What it is: a wallet-invocation deep link (`openid4vp://`) that carries a `client_id` and a `request_uri` pointing at the full signed request, rather than embedding the request inline. This is the artifact a QR code or app link usually encodes.

Decode it with:

```
augenmass inspect "$(cat fixtures/offers/eudiplo-offer-uri.txt)"
augenmass decode offer "$(cat fixtures/offers/eudiplo-offer-uri.txt)"
```

This shows the scheme, the `client_id`, the `request_uri`, and the `request_uri_method` (for example `get`).

To go deeper, fetch the JAR at `request_uri` out of band, then run `doctor` and `x509-hash` on that JWT (see the OpenID4VP request / JAR section).

Common gotchas:

- A request URI is not the request. It is a pointer. The interesting checks (`x5c`, `client_id` binding, DCQL contents) live in the JAR at `request_uri`, which the workbench does not fetch for you.
- The `client_id` in the deep link should match the one in the resolved JAR, and both should be in `x509_hash` form. A mismatch between the link-level `client_id` and the JAR's is a real finding.
- These links arrive percent-encoded. Treat the whole string as one opaque argument.

## Token status list

What it is: a signed bitstring (`typ` `statuslist+jwt`) the issuer or verifier publishes so relying parties can check whether a specific credential index has been revoked, without contacting the issuer per check.

Decode it with:

```
augenmass inspect fixtures/status/status-list-CLEAR.jwt
augenmass decode status-list fixtures/status/status-list-CLEAR.jwt
```

This shows `typ`, `alg`, `iss`, `sub`, bits per entry, and the compressed list length, with no signature checked.

Verify it with (verify the signature and read one index):

```
augenmass verify status-list \
  --token fixtures/status/status-list-REVOKED.jwt \
  --key fixtures/status/status-list-verify-key.pub.pem \
  --index 42
```

`verify status-list` checks the token signature against `--key` and reports the status at `--index`. It exits 1 when the index is REVOKED. In the committed REVOKED fixture, index 42 is revoked (the list has 256 entries, 1 bit each).

Common gotchas:

- The check is fail-closed and offline. A bad token, a wrong key, or a decode failure does not pass silently; it fails. This is correct behavior: an unverifiable status list must not be read as "not revoked".
- The signer key (`--key`) is the status signer's key, which is not necessarily the credential issuer's key. Supply the right SPKI or certificate PEM for the status list, not the issuer's.
- Index off-by-one and bits-per-entry mistakes are easy to make. Read the index you actually care about, and remember entries can be multi-bit even when this fixture is 1-bit.

## DCQL query

What it is: a Digital Credentials Query Language query, the structured statement of which credentials and claims a verifier is requesting. It appears inside an OpenID4VP request and can also stand alone (bare, or wrapped under `dcql_query`).

Decode it with:

```
augenmass inspect fixtures/dcql/eudiplo-haip-pid-de.dcql.json
```

`inspect` lists the requested claims. To produce a clean DCQL query from claim paths:

```
augenmass generate dcql --claim age_equal_or_over.18
```

Audit it with (lint a DCQL request for over-ask against a purpose baseline):

```
augenmass audit --request fixtures/dcql/eudiplo-haip-pid-de.dcql.json --purpose age_gate_18
```

`--request` also accepts the shorthands `minimal` and `overask` for the built-in example requests. Add `--cert` to also check the request against a registration certificate's registered scope. `audit` exits 1 on over-ask.

Common gotchas:

- `claims[].path` is an ARRAY of segments, not a dotted string. Write `["age_equal_or_over", "18"]`, not `"age_equal_or_over.18"`. The CLI accepts dotted or slashed input on `generate dcql --claim` as a convenience and emits the correct array form; the DCQL document itself must use arrays.
- mdoc credentials use 2-element `[namespace, element]` paths; SD-JWT credentials use nested segment arrays. The same claim looks different across formats.
- A query that passes the purpose baseline can still exceed a relying party's registration, and vice versa. Use `--cert` to catch the registration dimension.

## Registrar registration body

What it is: the JSON body a relying party POSTs to the registrar to register what it intends to request. It is keyed by `rpId` and carries `purpose`, `privacy_policy`, `support_uri`, and a `credentials` array.

Produce one with:

```
augenmass generate regbody
augenmass generate regbody --over-broad   # the deliberately bad example
```

The default `generate regbody` emits the proportionate age check (a single `age_equal_or_over.18` claim). Flags let you set `--rp`, `--support-uri`, `--privacy-policy`, and `--purpose`.

Gate it with (this is the pre-write check, the over-ask and format gate):

```
augenmass check examples/min.json     # clean: exits 0
augenmass check examples/over.json     # over-ask: exits 1
augenmass check examples/bad-path.json # format error: exits 1
```

`check` reports both over-ask findings (with legal basis) and blocking format errors. It exits 1 on either, so it works as a CI gate.

Write it with (guard-railed; see Auditor and Developer workflows below):

```
augenmass register examples/min.json                 # dry-run, exits 0
augenmass register examples/min.json --yes           # writes to the local clone
```

Common gotchas (these are exactly what `check` catches):

- `claims[].path` must be an array of segments, not a string. `["age_equal_or_over", "18"]`, not `"age_equal_or_over.18"`. Flagged as `CHECK-PATH-STRING`.
- Use `credentials`, not `provided_attestations`, for the requested claims. The registrar DTO field is `credentials`.
- `purpose` is a list of `{ "lang", "content" }` objects, not a bare string. For example `[{ "lang": "en", "content": "Age verification" }]`.
- `privacy_policy` must be a valid URL.
- `support_uri` is any non-empty contact string: an email, a phone number, or a URL. Do not over-validate it as a URL; an email like `support@example.com` is valid.

## X.509 certificate

What it is: a PEM-encoded certificate, typically the verifier's leaf cert that signs a JAR (and appears in its `x5c`), or a registrar/access leaf. The relevant derived value is the `x509_hash` used to bind a `client_id`.

Decode it with:

```
augenmass inspect fixtures/certs/access-leaf.pem
```

This shows subject, issuer, serial, the computed `x509_hash`, and the `client_id` it implies.

Compute and check the binding with:

```
augenmass x509-hash fixtures/certs/access-leaf.pem
augenmass x509-hash fixtures/certs/access-leaf.pem \
  --client-id x509_hash:VE3qp3vLVkU8JyVmXkjL7CSDVxVoTFdTv5fAEwmjKOI
```

`x509-hash` accepts a PEM cert, base64 DER, or a JAR (it extracts the `x5c` leaf). With `--client-id` it compares a claimed value against the computed binding and exits 1 on mismatch. Against the eudiplo JAR fixture the binding is `x509_hash:7zvIjJaM1KQPpN7IZBuVLuh8anw1gcbZ0a6Wj3M9i4w`.

Common gotchas:

- The binding is `x509_hash:<base64url(SHA-256(leaf-cert-DER))>`. It hashes the leaf certificate's DER bytes, not the PEM text and not a parent cert.
- The hash is base64url with no padding. Standard base64 (with `+`, `/`, or `=`) will not match. This is the same alphabet trap as `x5c`.
- For a JAR, the relevant cert is the leaf, the first entry in the `x5c` list. Hashing the wrong chain element yields a `client_id` the wallet will reject.

## Auditor workflow

You have a relying party's registration certificate and you want to know whether they over-ask, and you have a presentation and you want to verify it end to end.

1. Read the certificate's registered scope.

```
augenmass decode regcert fixtures/regcert/rc-by-id.json
```

2. Audit a candidate request against both the purpose baseline and the registered scope. The two-dimensional output separates "beyond the purpose" from "outside the registration".

```
augenmass audit --request overask --purpose age_gate_18 --cert fixtures/regcert/rc-by-id.json
```

Exit 1 means over-ask; the rendering cites eIDAS Art. 5b(3), GDPR Art. 5(1)(c), and ARF RPRC_07, and suggests the minimal request. To see the baselines and legal basis on their own:

```
augenmass baselines
augenmass baselines age_gate_18
```

3. Verify a presentation end to end: signature, holder binding, nonce/aud, trust anchor, and revocation in one run.

```
augenmass verify presentation fixtures/presentations/synthetic-pid-with-status.sdjwt \
  --nonce b4ba2623-76a2-486b-a1f6-f1656025d07b \
  --aud https://self-issued.me/v2 \
  --now 1780435200 \
  --trust-anchor fixtures/certs/synthetic-pid-anchor.pem \
  --status-token fixtures/status/status-list-CLEAR.jwt \
  --status-key fixtures/status/status-list-verify-key.pub.pem
```

A non-zero exit on any of these commands is the finding. For machine-readable audit evidence, add `--json`.

## Developer workflow

You are building a relying party and want to register without over-asking, and you want to debug a verifier request that the wallet rejects.

1. Generate a proportionate body, check it, register it. The check is the gate; do not skip it.

```
augenmass generate regbody > /tmp/regbody.json
augenmass check /tmp/regbody.json           # exits 1 if over-ask or malformed
augenmass register /tmp/regbody.json         # dry-run first
augenmass register /tmp/regbody.json --yes   # writes to the local clone (default target)
```

Writes are dry-run by default. `--yes` performs the write. The local `clone` target is a registrar-compatible store with no signing and no auth, safe for rehearsal; `--target sandbox` reaches the real registrar and is for off-stage rehearsal only. If `check` flags over-ask but you have a defensible reason, `register --yes --force` writes past the warning, but `--force` requires `--yes` and you should be certain.

To run the local clone store and read registrations back:

```
augenmass clone serve
augenmass list                  # reads back the configured relying party, decoded
```

2. Doctor a failing JAR. Decode it to see the shape, then doctor it for the JAR-specific traps.

```
augenmass decode request fixtures/requests/eudiplo-request.jwt
augenmass doctor fixtures/requests/eudiplo-request.jwt
```

`doctor` exits 1 with `DOCTOR-X5C-STRING` if `x5c` is a bare string instead of a list, and `DOCTOR-CLIENT-ID-X509HASH` if the `client_id` is not in `x509_hash` form. Fix both, remember `Content-Type: application/json` on every POST, and use `client_id_scheme` `x509_hash` (the sandbox wallet supports nothing else).

3. Compute the `x509_hash` for your `client_id`. Never type this by hand.

```
augenmass x509-hash fixtures/requests/eudiplo-request.jwt
```

That prints the binding to put in `client_id`. To assert it in CI, pass `--client-id` and let a non-zero exit fail the build on mismatch:

```
augenmass x509-hash fixtures/requests/eudiplo-request.jwt \
  --client-id x509_hash:7zvIjJaM1KQPpN7IZBuVLuh8anw1gcbZ0a6Wj3M9i4w
```

## Debug a live wallet interaction

The commands above read static artifacts. When you need to debug the actual wallet-to-verifier exchange, `augenmass serve` is a verifier-in-a-box: a local OpenID4VP verifier for the German PID profile (`vct urn:eudi:pid:de:1`, format `dc+sd-jwt`, response_mode `direct_post.jwt`, response encryption ECDH-ES, the registration certificate embedded as `verifier_info`) that a real EUDI wallet presents to. It records the whole exchange as a per-session trace.

Run it (zero-config; it runs until Ctrl-C):

```
augenmass serve
```

Open the printed URL, scan the QR with a wallet, and watch the trace. The trace is available three ways: live on the console (color-coded; suppress it with `--quiet`), as a browser timeline at `/trace/<session>` (it auto-refreshes while the exchange is in flight), and as JSON at `/api/trace/<session>` for programmatic debugging. `/api/sessions` lists every session this run. The session endpoints are `GET /` (landing page and QR), `GET /request/:id` (the signed JAR the wallet fetches, content-type `application/oauth-authz-req+jwt`), `POST /response/:id` (the wallet's `direct_post.jwt`, returning JSON `{ status: "verified" | "rejected", reason?, inspect, trace }`), `GET /inspect/:id` (the over-ask inspector, with a `?demo=overask` variant), and `GET /health`.

The trace event codes, in typical order, are `SESSION_CREATED`, `REQUEST_BUILT`, `REQUEST_OBJECT_FETCHED`, `RESPONSE_RECEIVED`, `RESPONSE_DECRYPTED`, `VERIFIED` or `REJECTED`, `STATUS_CHECKED` (only with `--live-status` and a trust anchor), and `OVER_ASK_ANALYZED`, plus `NOTE` and `ERROR`. The default trace is redacted: it carries decoded request shape, response field names, lengths, SHA-256 digests, claim keys, and reject reasons, but not raw POST bodies, decrypted payloads, or disclosed claim values. Use `--unsafe-debug-artifacts <DIR>` only when you explicitly need full-fidelity local capture; those raw artifacts are written to disk and are never served over HTTP.

Common gotchas:

- Zero-config runs on a throwaway development certificate, so the `client_id` is not the registered sandbox identity. Pass `--key` and `--leaf` together (or set `RP_KEY_PATH` and `RP_LEAF_PATH`) to sign with the real registrar leaf and make the `client_id` match the registration.
- `--public-url` is baked into the `request_uri` and `response_uri`, so it must match how the wallet reaches the tool. For a phone wallet on another device, `127.0.0.1` will not work: bind `--host 0.0.0.0` and set a `--public-url` reachable from the phone, for example `http://192.0.2.10:8080/` (it must end in `/`).
- A static or fixture wallet response cannot be replayed against a running server. Each run generates a fresh ephemeral encryption key and nonce, so the wallet must encrypt to this run's key and echo this run's nonce.
- `--live-status` only takes effect when a `--trust-anchor` is also set, and currently supports a single issuer anchor; a multi-certificate anchor PEM fails closed.

## CI notes

Every command in this guide exits non-zero on the "bad" outcome, so you can wire them straight into a pipeline: `check` and `audit` exit 1 on over-ask (and `check` also on blocking format errors); `verify presentation`, `verify trust`, `verify status`, and `verify status-list` exit 1 when not verified, untrusted, revoked, or on error; `x509-hash --client-id` exits 1 on mismatch; `doctor` exits 1 on findings; `register` refuses (exit 1) on over-ask without `--force` and bails on blocking format errors. Add `--json` for structured output an agent or CI step can parse.
