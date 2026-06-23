# Augenmaß Workbench: end-to-end use cases

Five complete walkthroughs. Every command here runs against the real binary as written, using committed fixtures under `fixtures/` and `examples/`. Paths are relative to the repo root. The examples use bare `augenmass` for readability; inside the Claude Code skill, prefer `${CLAUDE_PLUGIN_ROOT}/bin/augenmass`. In this repo a local debug build is `./target/debug/augenmass`.

Conventions used throughout:

- Artifact inputs accept a file path, an inline value, or `-` for stdin.
- Commands that render structured output take `--json` for machine output (CI and agents).
- Exit codes are CI-friendly: a command exits non-zero on its "bad" outcome (over-ask, rejection, mismatch, findings) and `0` when clean. Each walkthrough notes the relevant codes.
- Verification is offline. The clock is injectable with `--now` (Unix seconds), so fixture-based runs are reproducible. The fixtures use `--now 1780435200`.

Shared binding values (from the fixtures):

- nonce: `b4ba2623-76a2-486b-a1f6-f1656025d07b`
- aud (verifier client_id): `https://self-issued.me/v2`
- vct: `urn:eudi:pid:de:1`
- our relying party id: `2af138a8-59ea-4a84-aea3-666cafdb1369` ("Hackathon - Reza")

## 1. "What is this token?" Identify, then decode

You were handed an artifact and you do not know what it is. Start with `inspect`, which sniffs the type and dispatches to the right decoder. Once you know the type, `decode <type>` gives you the focused, type-specific view.

Sniff an SD-JWT VC presentation:

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

`inspect` recognizes every common artifact. A signed authorization request, for example, comes back as a JAR with its header and claims surfaced:

```
augenmass inspect fixtures/requests/eudiplo-request.jwt
```

```
Detected: OpenID4VP authorization request (JAR)
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

A registration certificate (typ `rc-wrp+jwt`) auto-detects too, and you can ask for the same payload-only view directly with `decode regcert`:

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

The full decoder set is `decode {jwt|sd-jwt|regcert|request|offer|status-list|mdoc}`. When in doubt, use `inspect` first, then reach for the specific decoder once you know the type. None of these verify a signature; they decode payloads only. Verification is walkthrough 4.

A note on offer fixtures: `fixtures/offers/eudiplo-offer.json` wraps an `openid4vp://` request URI, so `decode offer` renders it as an OpenID4VP request URI (scheme, client_id, request_uri, request_uri_method). The same holds for `fixtures/offers/eudiplo-offer-uri.txt`.

## 2. Auditor: lint a relying party's request for over-ask

You are auditing a relying party. You have its registration certificate and you want to know whether what it asks for is proportionate to a stated purpose, with the legal basis attached to every finding.

First, read the curated baselines and the legal basis the engine cites. These baselines are taste judgments, not Rulebook derivations, and the tool says so:

```
augenmass baselines
```

```
Curated purpose baselines:

  age_gate_18  (Age gate (over 18))
    minimal: age_equal_or_over.18
  event_checkin  (Event check-in)
    minimal: given_name, family_name, age_equal_or_over.18
  car_rental  (Car rental (over 21, named))
    minimal: given_name, family_name, age_equal_or_over.21
  bank_kyc  (Bank onboarding (KYC))
    minimal: given_name, family_name, birthdate, address.resident_street, address.resident_city, address.resident_postal_code, address.resident_country

Legal basis cited on every over-ask finding:
  eIDAS Regulation (EU) 2024/1183, Art. 5b(3)
    Relying parties shall not request users to provide data other than that indicated for their intended use.
  GDPR (EU) 2016/679, Art. 5(1)(c)
    Personal data shall be adequate, relevant and limited to what is necessary (data minimisation).
  EUDI ARF, registration certificate, RPRC_07
    The wallet verifies requested attributes are within the registration certificate and notifies the user otherwise.
```

Next, decode the certificate so you can see what it actually requests (this is the `decode regcert` output from walkthrough 1): given_name, family_name, age_equal_or_over.18, with the stated purpose "age-over-18 verification for an event check-in."

Now lint a request against a purpose, scoped to that certificate with `--cert`. The certificate's three claims match the `event_checkin` baseline exactly, so against that purpose the request is clean:

```
augenmass audit --request minimal --purpose event_checkin --cert fixtures/regcert/rc-by-id.json
```

```
OK: Minimal: all 3 requested claims are within purpose and registration.
Purpose: Demonstration: age-over-18 verification for an event check-in.   Baseline: Event check-in

Requested claims:
  [ok]  given_name                   Within the purpose-minimal baseline.
  [ok]  family_name                  Within the purpose-minimal baseline.
  [ok]  age_equal_or_over.18         Within the purpose-minimal baseline.
```

The auditor's point is the contrast. The same certificate, judged against a stricter purpose (a plain over-18 age gate), is over-asking: name attributes are registered but not needed to prove age.

```
augenmass audit --request minimal --purpose age_gate_18 --cert fixtures/regcert/rc-by-id.json
```

```
OVER-ASK: Over-ask vs purpose: 2 of 3 requested claims exceed the stated purpose.
Purpose: Demonstration: age-over-18 verification for an event check-in.   Baseline: Age gate (over 18)

Requested claims:
  [over]  given_name                   Registered, but beyond what the stated purpose needs.
  [over]  family_name                  Registered, but beyond what the stated purpose needs.
  [ok]  age_equal_or_over.18         Within the purpose-minimal baseline.

Over-asking 2 claim(s) beyond the stated purpose.

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

The `--request` argument also accepts a path to a DCQL JSON file, plus two built-ins: `minimal` (the default) and `overask`. Use `overask` for the worst-case shape, which over-asks against every baseline.

Exit codes for `audit`: `1` on over-ask, `0` otherwise. Each row is `[ok]` (within baseline) or `[over]` (beyond the stated purpose). The wording shifts with `--cert`: with a certificate, an over claim reads "Registered, but beyond what the stated purpose needs"; without one, it reads "Beyond what the stated purpose needs; registration not evaluated." For a CI gate, add `--json`.

## 3. Developer: build a proportionate registration, and watch the guard refuse an over-broad one

You are the relying party. You want to register exactly what you need and nothing more, and you want the tool to stop you before you write something that over-asks.

Start from a generated, proportionate body. The default `generate regbody` use case is the age check, and it already emits JSON to stdout:

```
augenmass generate regbody
```

```
{
  "rpId": "2af138a8-59ea-4a84-aea3-666cafdb1369",
  "support_uri": "support@example.com",
  "privacy_policy": "https://example.com/privacy",
  "purpose": [
    {
      "lang": "en",
      "content": "Age verification"
    }
  ],
  "credentials": [
    {
      "format": "dc+sd-jwt",
      "meta": {
        "vct_values": [
          "urn:eudi:pid:de:1"
        ]
      },
      "claims": [
        {
          "path": [
            "age_equal_or_over",
            "18"
          ]
        }
      ]
    }
  ]
}
```

Note the schema this body gets right, which `check` enforces: `claims[].path` is an array of segments (`["age_equal_or_over", "18"]`, not the string `"age_equal_or_over.18"`); the requested claims live under `credentials` (not `provided_attestations`); `purpose` is a list of `{lang, content}` objects (not a bare string); `privacy_policy` is a URL; `support_uri` is any non-empty contact string (do not over-validate it as a URL).

Gate the body before any write. Pipe `generate` straight into `check` with `-` for stdin:

```
augenmass generate regbody | augenmass check -
```

```
OK: no over-ask, no format errors. - is ready to register.
```

`check` exits `0` here. Now run a clone, which is a local, registrar-compatible store (axum + SQLite) with no signing, no auth, and no x5c. It is the safe default write target. Start it in one terminal:

```
augenmass clone serve --port 8080 --db /tmp/augenmass-clone-demo.sqlite
```

In another terminal, dry-run first. Writes are dry-run by default; nothing is written until you pass `--yes`:

```
augenmass register examples/min.json --target clone
```

```
OK: no over-ask, no format errors. examples/min.json is ready to register.
DRY RUN: nothing written. Re-run with --yes to write to clone.
```

Then write for real:

```
augenmass register examples/min.json --target clone --yes
```

```
OK: no over-ask, no format errors. examples/min.json is ready to register.
Writing to clone under RP 2af138a8-59ea-4a84-aea3-666cafdb1369...
Wrote registration 6e352d08-be3f-4e8c-89c7-4457730528ff to clone.
```

Read it back, decoded, for the one relying party:

```
augenmass list --target clone
```

```
1 registration(s) for RP 2af138a8-59ea-4a84-aea3-666cafdb1369 on clone:

- 6e352d08-be3f-4e8c-89c7-4457730528ff  purpose: "Age verification"
    claims: age_equal_or_over.18
```

The registration id is generated per write, so yours will differ. `list` defaults its `--rp` to `2af138a8-59ea-4a84-aea3-666cafdb1369`; pass `--rp <id>` for another.

Now the contrast: the over-broad refusal. `generate regbody --over-broad` adds name, birthdate, address, and nationalities to the same "Age verification" purpose. The guard catches it and refuses the write (exit `1`), citing the legal basis. `--yes` confirms intent to write but does not override an over-ask; only `--force` does that:

```
augenmass generate regbody --over-broad | augenmass register - --target clone --yes
```

```
OVER-ASK: Over-ask vs purpose: 6 of 6 requested claims exceed the stated purpose.
Purpose: Age verification   Baseline: Age gate (over 18)

Requested claims:
  [over]  given_name                   Registered, but beyond what the stated purpose needs.
  [over]  family_name                  Registered, but beyond what the stated purpose needs.
  [over]  birthdate                    Registered, but beyond what the stated purpose needs.
  [over]  address.resident_street      Registered, but beyond what the stated purpose needs.
  [over]  address.resident_city        Registered, but beyond what the stated purpose needs.
  [over]  nationalities                Registered, but beyond what the stated purpose needs.

Over-asking 6 claim(s) beyond the stated purpose.

Suggested minimal request:
  age_equal_or_over.18

Legal basis:
  eIDAS Regulation (EU) 2024/1183, Art. 5b(3)
    Relying parties shall not request users to provide data other than that indicated for their intended use.
  ...
```

The same `check` gate runs ahead of the write, so you can catch this before you ever call `register`:

```
augenmass generate regbody --over-broad | augenmass check -
```

That exits `1` with the same over-ask report.

`check` also blocks on format mistakes, independent of over-ask. The `examples/bad-path.json` fixture encodes a path as a string instead of an array:

```
augenmass check examples/bad-path.json
```

```
Format findings:
  CHECK-PATH-STRING [blocking]: claims[].path must be an array of segments, not a string.
    Fix: Change "path": "age_equal_or_over" to "path": ["age_equal_or_over", "18"].
```

This exits `1`. A blocking format error stops `register` outright; only the over-ask warning is bypassable, and only with `--force`.

For a real off-stage rehearsal, swap `--target clone` for `--target sandbox`, which talks to the actual registrar over OAuth. That path needs environment configuration (`AUGENMASS_API_BASE`, `AUGENMASS_OIDC_TOKEN_URL`, `AUGENMASS_USERNAME`, `AUGENMASS_PASSWORD`) and a working `client_id` of `swagger`. Use `--target cached-sandbox` only for read-only cached sandbox reads; confirmed writes to cached-sandbox are refused before any network call. Always write under the one relying party; never mint extra relying parties.

## 4. Verify a wallet presentation end to end

You received an SD-JWT VC presentation in response to your request. Verify it in layers: cryptographic validity and request binding, then trust anchoring, then revocation. Each layer is its own command, and the heavy one (`verify presentation`) folds the others in via flags.

Step one, cryptographic verification with request binding. `--nonce` and `--aud` are required: the KB-JWT must echo your request nonce and bind to your client_id. `--now` pins the clock so the fixture verifies deterministically:

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

This exits `0`. Tamper with any binding and it rejects with exit `1` and a typed reason. Wrong nonce:

```
augenmass verify presentation fixtures/presentations/erica-vp-WRONG_NONCE.sdjwt \
  --nonce b4ba2623-76a2-486b-a1f6-f1656025d07b \
  --aud https://self-issued.me/v2 --now 1780435200
```

```
REJECTED [NonceMismatch]: KB-JWT nonce does not match the request
```

An expired credential (here verified at `--now 1780435200`) likewise rejects:

```
REJECTED [CredentialExpired]: credential expired at 1780348665
```

Other failure fixtures exist in `fixtures/presentations/`: `WRONG_AUDIENCE`, `MISSING_HOLDER_BINDING`, `OVER_DISCLOSURE`, `EXPIRED`.

Step two, trust. By default the issuer signature is checked against the leaf key in the credential. To require that the issuer chains to a trust anchor, use `verify trust`. ERICA chains to `erica-trust-anchor.pem`:

```
augenmass verify trust fixtures/presentations/erica-vp-VALID.sdjwt \
  --anchor fixtures/certs/erica-trust-anchor.pem --now 1780435200
```

```
TRUSTED: the issuer chains to one of 1 anchor(s).
```

Point it at an unrelated anchor and it fails (exit `1`):

```
augenmass verify trust fixtures/presentations/erica-vp-VALID.sdjwt \
  --anchor fixtures/certs/registrar-ca.pem --now 1780435200
```

```
UNTRUSTED: the issuer does not chain to any of the 1 anchor(s) (or is out of its validity window).
```

This is leaf-chains-to-anchor plus a validity-window check, not full path validation.

Step three, revocation against a token status list. `verify status` reads the credential's status reference and checks it against a signed status-list token, fail-closed and offline. The `synthetic-pid-with-status.sdjwt` fixture carries a status entry; the status lists hold 256 entries with index 42 revoked in the REVOKED list. Against the clear list:

```
augenmass verify status fixtures/presentations/synthetic-pid-with-status.sdjwt \
  --token fixtures/status/status-list-CLEAR.jwt \
  --key fixtures/status/status-list-verify-key.pub.pem
```

```
VALID
```

Against the revoked list (exit `1`):

```
augenmass verify status fixtures/presentations/synthetic-pid-with-status.sdjwt \
  --token fixtures/status/status-list-REVOKED.jwt \
  --key fixtures/status/status-list-verify-key.pub.pem
```

```
REVOKED
```

To inspect a single index of a status list directly (verifying the token signature first), use `verify status-list --index`. Index 42 in the revoked list:

```
augenmass verify status-list \
  --token fixtures/status/status-list-REVOKED.jwt \
  --key fixtures/status/status-list-verify-key.pub.pem --index 42
```

```
REVOKED
```

A clear index (for example 7) on the same list reports `VALID` and exits `0`.

Step four, all in one pass. `verify presentation` can anchor trust and check status in the same invocation via `--trust-anchor`, `--status-token`, and `--status-key`. The summary then reports both flags as true. The synthetic PID with status, fully verified against the clear list:

```
augenmass verify presentation fixtures/presentations/synthetic-pid-with-status.sdjwt \
  --nonce b4ba2623-76a2-486b-a1f6-f1656025d07b \
  --aud https://self-issued.me/v2 --now 1780435200 \
  --status-token fixtures/status/status-list-CLEAR.jwt \
  --status-key fixtures/status/status-list-verify-key.pub.pem
```

```
VERIFIED
  vct: urn:eudi:pid:de:1
  holder binding: true
  trust anchored: false
  status checked: true
  disclosed claims:
    given_name = Erika
```

Swap in the REVOKED token and the whole verification rejects, which is the point of folding status into the verify step:

```
REJECTED [Revoked]: credential is revoked (status-list entry is INVALID)
```

`verify presentation` also takes `--vct` to override the expected credential type, `--max-age` for the KB-JWT freshness window (default 300 seconds), and `--trust-anchor` to anchor the issuer in the same call (as shown for the VALID fixture, which reports `trust anchored: true` when anchored). All four `verify` subcommands exit `1` on not-verified, untrusted, revoked, or error, and `0` only when the layer passes.

## 5. Diagnose a rejected JAR, then fix the client_id

Your signed authorization request (JAR) is being rejected by the wallet and you do not know why. `doctor` knows the common signed-request gotchas: x5c shape and the client_id binding.

Run it on a request. The `examples/bad-request.json` fixture has both classic mistakes: x5c as a bare string instead of a list, and a URL-style client_id instead of the x509_hash form:

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

`doctor` exits `1` when it finds anything. The fixes:

1. Wrap the certificate in an array, even for a single cert: `"x5c": ["MIIB..."]`.
2. Set the client_id to `x509_hash:<base64url(SHA-256(leaf-cert-DER))>`. The sandbox wallet only supports the `x509_hash` client_id scheme, not `x509_san_dns`.

Compute the correct client_id with `x509-hash`. Point it at the JAR and it pulls the leaf out of the x5c chain and hashes it:

```
augenmass x509-hash fixtures/requests/eudiplo-request.jwt
```

```
x509_hash:   7zvIjJaM1KQPpN7IZBuVLuh8anw1gcbZ0a6Wj3M9i4w
client_id:   x509_hash:7zvIjJaM1KQPpN7IZBuVLuh8anw1gcbZ0a6Wj3M9i4w
subject:     CN=Verifier Fixture Tenant,C=DE
issuer:      CN=Verifier Fixture Tenant,C=DE
serial:      00:DB:A3:5E:73:ED:1F:A1:D2:2B:7A:19:CD:FB:1E:6F:64
```

It also accepts a PEM certificate or base64 DER directly. The access leaf, for instance:

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

To assert that a claimed client_id matches the cert it ships, pass `--client-id`. On a match it exits `0`:

```
augenmass x509-hash fixtures/requests/eudiplo-request.jwt \
  --client-id x509_hash:7zvIjJaM1KQPpN7IZBuVLuh8anw1gcbZ0a6Wj3M9i4w
```

```
...
MATCH: x509_hash:7zvIjJaM1KQPpN7IZBuVLuh8anw1gcbZ0a6Wj3M9i4w matches the computed binding.
```

On a mismatch it prints both values and exits `1`, which makes it a usable CI assertion:

```
MISMATCH: claimed client_id
  x509_hash:WRONGWRONGWRONG
does not equal the computed
  x509_hash:7zvIjJaM1KQPpN7IZBuVLuh8anw1gcbZ0a6Wj3M9i4w
```

After applying the fixes, re-run `doctor` on the corrected request to confirm. A clean JAR (the eudiplo fixture is already correct) reports no findings and exits `0`:

```
augenmass doctor fixtures/requests/eudiplo-request.jwt
```

```
OK: no signed-request gotchas found.
Set Content-Type: application/json on every POST; the client does this for you.
```

The third trap `doctor` reminds you of is the transport one: set `Content-Type: application/json` on every POST. Watch out, too, for base64url-no-pad versus base64-standard when copying x5c entries and hashes by hand; the `x509_hash` value is base64url without padding.

## 6. Debug a live wallet interaction with a verifier-in-a-box

The first five walkthroughs read static artifacts. This one debugs the actual exchange. `augenmass serve` runs a local OpenID4VP verifier for the German PID profile (`vct urn:eudi:pid:de:1`, format `dc+sd-jwt`, response_mode `direct_post.jwt`, response encryption ECDH-ES, the registration certificate embedded as `verifier_info`), so a real EUDI wallet can present to it, and it records the whole exchange as a per-session trace. It runs until interrupted (Ctrl-C), so run it in its own terminal.

Start it zero-config. With no flags it mints a throwaway development certificate, so the verifier runs without a registrar-issued leaf:

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
  trace        : live on this console; also at <base>/trace/<session> and /api/trace/<session>

  Open the URL above, scan the QR with a wallet, and watch the trace below.
```

Open the printed URL in a browser. The landing page (`GET /`) mints a fresh session and shows a QR / deep-link to present, plus links to inspect and trace. Scan the QR with a wallet and watch the trace fill in. The events, in typical order, are `SESSION_CREATED`, `REQUEST_BUILT`, `REQUEST_OBJECT_FETCHED` (the wallet fetched the signed JAR from `GET /request/:id`), `RESPONSE_RECEIVED` (the wallet posted `direct_post.jwt` to `POST /response/:id`), `RESPONSE_DECRYPTED` (the JWE decrypted, ECDH-ES), then `VERIFIED` or `REJECTED`, then `OVER_ASK_ANALYZED`:

```
  23:20:51.551  29bbb9a0  SESSION_CREATED         new presentation session created
  23:20:51.551  29bbb9a0  REQUEST_BUILT           built the authorization request (minimal German PID query)
  23:20:51.608  29bbb9a0  REQUEST_OBJECT_FETCHED  wallet fetched the signed request object (JAR)
  ...           29bbb9a0  RESPONSE_RECEIVED       wallet posted its response (direct_post.jwt (encrypted))
  ...           29bbb9a0  RESPONSE_DECRYPTED      decrypted the JWE response (ECDH-ES)
  ...           29bbb9a0  VERIFIED                presentation verified: urn:eudi:pid:de:1
  ...           29bbb9a0  OVER_ASK_ANALYZED       ...
```

`POST /response/:id` returns JSON `{ status: "verified" | "rejected", reason?, inspect, trace }`: HTTP 200 with `status` "verified", or HTTP 422 with `status` "rejected" and a `reason`. The `inspect` and `trace` fields are absolute URLs to this session's over-ask inspector and timeline.

The same trace is available three ways: live on this console (color-coded; suppress it with `--quiet`), as a browser timeline at `/trace/<session>` (it auto-refreshes while the exchange is in flight and stays still once the session reaches a terminal outcome), and as JSON at `/api/trace/<session>` for programmatic debugging. `/api/sessions` lists every session this run. The default trace is redacted: it shows the decoded request shape, response field names, lengths, SHA-256 digests, disclosed claim keys, and reject reasons, but never raw POST bodies, decrypted payloads, or claim values. Use `--unsafe-debug-artifacts <DIR>` only when you explicitly need full-fidelity local capture; those raw artifacts are written to disk and never served over HTTP. The over-ask inspector is at `/inspect/<session>`, with a `?demo=overask` variant that inspects an over-asking request shape.

To make the `client_id` the registered identity, sign with the real registrar leaf by passing `--key` and `--leaf` together (or set `RP_KEY_PATH` and `RP_LEAF_PATH`). To enforce issuer trust and reject revoked credentials, add `--trust-anchor` and `--live-status`:

```
augenmass serve --key rp-key.pem --leaf rp-leaf.pem \
  --trust-anchor pid-issuer-anchor.pem --live-status
```

With `--live-status` plus an anchor, the trace gains a `STATUS_CHECKED` step before the over-ask analysis, and a revoked or suspended credential is rejected fail-closed.

For a phone wallet on another device, `127.0.0.1` will not work: the `--public-url` is baked into the `request_uri` and `response_uri`, so bind all interfaces and set a base URL the phone can reach (it must end in `/`):

```
augenmass serve --host 0.0.0.0 --public-url http://192.0.2.10:8080/
```

A note on replay: you cannot post a static or fixture wallet response to a running server. Each run generates a fresh ephemeral encryption key and nonce, so the wallet must encrypt to this run's key and echo this run's nonce; a captured response from an earlier run will not decrypt or will fail the nonce binding.

## Quick reference: commands and exit codes

| Goal | Command | Non-zero exit when |
| --- | --- | --- |
| Identify any artifact | `inspect <input>` | (read-only) |
| Decode a known type | `decode {jwt\|sd-jwt\|regcert\|request\|offer\|status-list\|mdoc} <input>` | (read-only) |
| List or show baselines | `baselines [<id>]` | (read-only) |
| Gate a registration body | `check <body>` | over-ask or blocking format error |
| Lint a request for over-ask | `audit --request <minimal\|overask\|FILE> --purpose <id> [--cert FILE]` | over-ask |
| Verify a presentation | `verify presentation <p> --nonce <n> --aud <a> [--now ...]` | not verified |
| Check issuer trust | `verify trust <p> --anchor <pem>` | untrusted |
| Check revocation | `verify status <p> --token <t> --key <k>` | revoked / error |
| Read a status-list index | `verify status-list --token <t> --key <k> --index <i>` | revoked / error |
| Compute or check x509_hash | `x509-hash <input> [--client-id ...]` | client_id mismatch |
| Produce a body or query | `generate {regbody\|dcql} ...` | (producer) |
| Diagnose a JAR | `doctor <request>` | findings |
| Debug a live wallet interaction | `serve [--port --host --public-url --key --leaf --purpose --trust-anchor --live-status --quiet]` | (server; runs until Ctrl-C) |
| Write a registration | `register <body> --target <clone\|cached-sandbox\|sandbox> [--yes --force]` | over-ask without `--force`, blocking format error, or confirmed cached-sandbox write |
| Read registrations back | `list --target <clone\|cached-sandbox\|sandbox> [--rp <id>]` | (read-only) |
| Run the local clone store | `clone serve [--db <path> --port <n>]` | (server) |
| Run the cached-sandbox mirror | `cache serve [--db <path> --host <host> --port <n> --upstream <url> --ttl-secs <n> --timeout-secs <n> --admin-token <token>]` | (server) |
| Prewarm the cached-sandbox mirror | `cache warm [--api-base <url> --admin-token <token> --rp <id>]` | refresh failure |

Add `--json` to any read-only command for machine output. Compose freely with `-` for stdin, as in `generate regbody | check -` and `generate regbody --over-broad | register - --target clone --yes`.
