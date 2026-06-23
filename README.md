# Augenmaß Workbench

A swiss-army CLI and Claude Code skill for the EUDI Wallet ecosystem.

Augenmaß Workbench gives developers and auditors one tool to inspect, decode, audit over-ask, verify, generate, repair, live-debug, and replay EUDI artifacts and flows: SD-JWT VC presentations, ISO 18013-5 mdoc credentials, registration certificates, OpenID4VP requests and JARs, credential offers, status lists, DCQL queries, the wallet-to-verifier presentation exchange itself, and local evidence bundles captured from that exchange. It is built on a single engine (`augenmass-core`, reused as-is from the verifier project). Static artifact commands run fully offline; live surfaces are explicit: registrar targets (`clone`, `cached-sandbox`, `sandbox`), the cache server, and the wallet-interaction debugger (`serve`). Every read-only command takes `--json` so it drops cleanly into agents and CI.

It supersedes the v1 workbench (which had six commands: `generate`, `check`, `doctor`, `register`, `list`, `clone`) by surfacing the entire engine (verification, status, trust, disclosure, crypto) and adding net-new offline decoders behind one cohesive CLI.

## Install

Build from source with Cargo. The output binary is `augenmass`.

```sh
cargo build --release
./target/release/augenmass --help
```

The same tool also ships as a Claude Code plugin. The skill auto-triggers on EUDI registration and verifier-debugging work, and underneath it is the same plain CLI you can call directly.

This repository is currently private, so the marketplace commands below resolve to it only for accounts that have access; building from source (above) is the path that always works. Once the repository is published publicly, the same commands work for everyone.

```
/plugin marketplace add augenmass/augenmass-workbench
/plugin install augenmass-workbench@augenmass
```

For plugin and skill specifics, see `docs/TOOLS.md` and the skill at `plugins/augenmass-workbench/skills/augenmass`.

## Quickstart

Every artifact argument accepts a file path, an inline value, or `-` for stdin. Read-only commands accept `--json`. The examples below use committed fixtures under `fixtures/` and run against the debug binary; swap in `./target/release/augenmass` for a release build.

Auto-detect any artifact and decode it:

```sh
augenmass inspect fixtures/presentations/erica-vp-VALID.sdjwt
# Detected: SD-JWT VC presentation
#   vct: urn:eudi:pid:de:1
#   disclosed claims: 2 (family_name = Mustermann, given_name = Erika)
```

Decode a specific type (SD-JWT VC: issuer claims, disclosures, KB-JWT, resolved view):

```sh
augenmass decode sd-jwt fixtures/presentations/erica-vp-VALID.sdjwt
```

Gate a registration body before a write (over-ask plus format). Exits 1 on over-ask:

```sh
augenmass check examples/over.json
# OVER-ASK: 6 of 6 requested claims exceed the stated purpose.
augenmass check examples/min.json
# OK: no over-ask, no format errors. examples/min.json is ready to register.
```

Audit an OpenID4VP request against a purpose baseline. Exits 1 on over-ask:

```sh
augenmass audit --request overask --purpose event_checkin
# OVER-ASK: 4 of 6 requested claims exceed the stated purpose.
```

Cryptographically verify a presentation against its binding values, with an injected clock:

```sh
augenmass verify presentation fixtures/presentations/erica-vp-VALID.sdjwt \
  --nonce b4ba2623-76a2-486b-a1f6-f1656025d07b \
  --aud https://self-issued.me/v2 \
  --now 1780435200
# VERIFIED  (vct: urn:eudi:pid:de:1, holder binding: true)
```

Compute the `x509_hash` client_id binding from a JAR's x5c leaf:

```sh
augenmass x509-hash fixtures/requests/eudiplo-request.jwt
# x509_hash:   7zvIjJaM1KQPpN7IZBuVLuh8anw1gcbZ0a6Wj3M9i4w
# client_id:   x509_hash:7zvIjJaM1KQPpN7IZBuVLuh8anw1gcbZ0a6Wj3M9i4w
```

Check a claimed client_id against a leaf certificate. Exits 1 on mismatch:

```sh
augenmass x509-hash fixtures/certs/access-leaf.pem \
  --client-id x509_hash:VE3qp3vLVkU8JyVmXkjL7CSDVxVoTFdTv5fAEwmjKOI
# MATCH: matches the computed binding.
```

Generate a proportionate registration body (the minimal age check by default):

```sh
augenmass generate regbody --json
```

Debug a live wallet interaction: run a local verifier, scan the QR with a real EUDI wallet, and watch every step of the exchange in the terminal and the browser:

```sh
augenmass serve
# augenmass serve: wallet-interaction debugger
#   open      : http://127.0.0.1:8080/
#   client_id : x509_hash:...
#   trace     : redacted by default; live on this console; also at <base>/trace/<session> and /api/trace/<session>
#   artifacts : off (set --unsafe-debug-artifacts <dir> to capture raw wallet material locally; UNSAFE)
#
#   23:20:51.551  29bbb9a0  SESSION_CREATED         new presentation session created
#   23:20:51.551  29bbb9a0  REQUEST_BUILT           built the authorization request (minimal German PID query)
#   23:20:51.608  29bbb9a0  REQUEST_OBJECT_FETCHED  wallet fetched the signed request object (JAR)
#   ...           ...       RESPONSE_RECEIVED       wallet posted its response (direct_post.jwt)
#   ...           ...       RESPONSE_DECRYPTED      decrypted the JWE response (ECDH-ES)
#   ...           ...       VERIFIED                presentation verified: urn:eudi:pid:de:1
#   ...           ...       OVER_ASK_ANALYZED       ...
```

## The toolbox

UNDERSTAND
- `inspect <input>`: sniff an artifact's type, then decode it ("what is this?").
- `decode {jwt | sd-jwt | regcert | request | offer | status-list | mdoc} <input>`: decode a known artifact type, no signature verification.
- `decode mdoc <input>`: decode an ISO 18013-5 mdoc (`mso_mdoc`): the document type, the disclosed namespaces and elements, the issuer authentication (COSE_Sign1 algorithm and its X.509 chain), and the Mobile Security Object (validity window, value-digest counts, device key). Accepts raw CBOR bytes, hex, or base64/base64url. Decode only; the COSE signature and value digests are not verified.

PROPORTIONALITY (the core IP)
- `check <body>`: pre-write gate on a registration body for over-ask and format errors.
- `audit --request {minimal | overask | FILE} --purpose <id> [--cert FILE]`: lint a DCQL request against a purpose baseline.
- `baselines [<id>]`: list the curated purpose baselines and the legal basis, or show one in detail.

CRYPTO
- `verify presentation <p> --nonce --aud [--vct --now --max-age --trust-anchor --status-token --status-key]`: full SD-JWT VC plus KB-JWT verification.
- `verify trust <p> --anchor`: check whether the issuer chains to a trust anchor.
- `verify status <p> --token --key`: check a presentation's revocation status against a status-list token.
- `verify status-list --token --key --index`: verify a status-list token and read one index.
- `x509-hash <input> [--client-id]`: compute (and optionally check) the `x509_hash` client_id binding.

PRODUCE
- `generate regbody [--use-case --over-broad --rp --support-uri --privacy-policy --purpose]`: produce a proportionate registration body.
- `generate dcql --claim <path> ...`: build a DCQL query from claim paths.

DIAGNOSE
- `doctor <request>`: diagnose verifier signed-request and JAR gotchas (x5c shape, client_id binding).
- `validate dcql <input>`: validate a DCQL query for unique credential ids, `credential_sets` options that reference known ids, and claim paths whose shape matches the credential format (mdoc `[namespace, element]` vs SD-JWT string/null/index segments). Exits non-zero on a blocking error, so it gates CI.

DEBUG (live wallet interaction)
- `serve [--port --host --public-url --key --leaf --purpose --trust-anchor --live-status --quiet --unsafe-debug-artifacts]`: run a local OpenID4VP verifier (a verifier-in-a-box) so a real EUDI wallet can present to it, and trace the whole exchange. The trace is redacted by default (no raw bodies, no claim values); it streams to the console, renders as a live browser timeline at `/trace/<session>`, and serializes at `/api/trace/<session>`.

EVIDENCE (local audit bundles)
- `evidence export <session-dir> --out <bundle.json> [--signing-key <pem>]`: export one `serve --unsafe-debug-artifacts` session directory into a sensitive portable bundle. The bundle contains raw local material and a deterministic redacted replay trace.
- `evidence verify <bundle.json> [--verify-key <pem>]`: verify bundle hashes, replay determinism, and the optional ES256 signature.
- `evidence replay <bundle.json> [--verify-key <pem>]`: render the projector-safe replay timeline. It is redacted like the live trace.

WRITE AND TARGETS (guard-railed)
- `register <body> --target {clone | cached-sandbox | sandbox} [--yes --force]`: gate a registration body under guardrails. Confirmed writes are allowed only for `clone` and `sandbox`; `cached-sandbox` is read-only and useful for dry-run output symmetry.
- `list --target {clone | cached-sandbox | sandbox} --rp`: read registrations back for one relying party, decoded.
- `clone serve [--db --port]`: run the registrar-compatible local clone store.
- `cache serve [--db --port --upstream --ttl-secs]`: run a read-through cached-sandbox mirror for public sandbox GET routes.

## Over-ask and the legal basis

Over-ask is the central concern: a relying party must not request more personal data than its stated purpose needs. The same engine that audits the EUDI registry for over-asking helps a developer avoid over-asking when they register. Every over-ask finding cites the basis it rests on:

1. eIDAS Regulation (EU) 2024/1183, Art. 5b(3): "Relying parties shall not request users to provide data other than that indicated for their intended use."
2. GDPR (EU) 2016/679, Art. 5(1)(c): data minimisation, personal data must be "adequate, relevant and limited to what is necessary".
3. EUDI ARF, registration certificate, RPRC_07: the wallet verifies requested attributes are within the registration certificate and notifies the user otherwise.

The curated purpose baselines (`age_gate_18`, `event_checkin`, `car_rental`, `bank_kyc`) are taste judgments, not Rulebook derivations. See `augenmass baselines`.

## Debug the wallet interaction

`augenmass serve` is a verifier-in-a-box for debugging the actual wallet exchange, not just static artifacts. It runs a local OpenID4VP verifier for the German PID profile (x509_hash client_id, signed request object by reference, `direct_post.jwt` encrypted response, the registration certificate embedded as `verifier_info`), and records the whole flow as a per-session trace:

1. `SESSION_CREATED` and `REQUEST_BUILT`: a fresh session and the minimal-disclosure authorization request (carrying the nonce, client_id, and DCQL).
2. `REQUEST_OBJECT_FETCHED`: the wallet pulls the signed request object (the JAR); the trace shows the decoded header and payload it received.
3. `RESPONSE_RECEIVED`: the wallet posts its response; the trace records its shape (mode, byte length, SHA-256, field names, state), never the raw body.
4. `RESPONSE_DECRYPTED`: the JWE is decrypted (ECDH-ES); the trace records the payload shape (length, SHA-256, field names, whether a `vp_token` is present and its shape), never a disclosed claim value.
5. `VERIFIED` or `REJECTED`: the SD-JWT VC issuer signature, the KB-JWT holder binding, the nonce/audience, and the vct are checked; on failure the exact reason is recorded.
6. `STATUS_CHECKED` (with `--live-status` and a trust anchor): the token-status-list is resolved and a revoked or suspended credential is rejected fail-closed.
7. `OVER_ASK_ANALYZED`: what the wallet actually disclosed is run through the over-ask inspector.

The trace is redacted by default: each step records its shape (lengths, SHA-256 digests, sorted field names) and the disclosed claim keys, never the raw POST body, the decrypted payload, or a claim value, so the unauthenticated `/api/trace/<session>` is safe to expose during a real PID demo. The same trace is available three ways: live on the console (color-coded), as a browser timeline at `/trace/<session>` (refreshes while the exchange is in flight), and as JSON at `/api/trace/<session>` for programmatic debugging. `/api/sessions` lists every session seen this run.

Zero-config, it runs on a throwaway development certificate (the client_id is then not the registered identity). To sign with the real registrar-issued leaf so the client_id matches the registration, pass `--key` and `--leaf` (or set `RP_KEY_PATH` and `RP_LEAF_PATH`). To enforce issuer trust, pass `--trust-anchor`; add `--live-status` to resolve revocation over the network.

Safe by default for a real PID demo. The trace is built for a phone-wallet presentation that carries real personal data, so it never exposes raw wallet material over the unauthenticated trace API. The received response and the decrypted payload are recorded as shape only: byte length, a SHA-256 digest, the sorted field names, and whether a `vp_token` is present, never the raw body and never a disclosed claim value. Each Authorization Request mints its own ephemeral response-encryption key, used once and dropped after the response is processed, so no key is shared across sessions. A plaintext `direct_post` is rejected with HTTP 422, because the verifier advertises the encrypted `direct_post.jwt` profile. The credential-controlled status-list fetch behind `--live-status` connects only to the addresses it already vetted (no re-resolution at connect time, which closes the DNS-rebinding window), stays https-only with redirects disabled and a timeout, caps the response body, normalizes IPv4-mapped IPv6 before vetting, and denies loopback, private, link-local, CGNAT, and unique-local targets.

Full-fidelity local debugging when you ask for it. When you need the raw bytes, `--unsafe-debug-artifacts <dir>` writes the raw `direct_post` body, the decrypted authorization response when an encrypted wallet response is decrypted, the per-session private key, the signed request object, the decoded request payload, and a verification context (`nonce`, `aud`, `vct`, clock, freshness window) to `<dir>/<session>/` with owner-only permissions (dirs `0700`, files `0600`) and a manifest marked sensitive. It is opt-in, local, and never served over HTTP; the trace records the file name, a label, the length, a SHA-256, and the redaction fields `unsafeDebugArtifacts`, `pathRedacted`, `redacted`, and `redaction`, never a path or a value. It is labeled UNSAFE in the startup banner. Leave it off for demos and shared machines.

Evidence replay turns that local capture into an audit artifact. Run `augenmass evidence export ./debug-out/<session> --out evidence.json` to create a sensitive bundle, optionally signed with `--signing-key`. Then run `augenmass evidence verify evidence.json` to check entry hashes, the canonical payload hash, replay determinism, and the optional signature. `augenmass evidence replay evidence.json` renders the same projector-safe timeline shape without exposing raw wallet material on stdout.

## Safety

Writes are dry-run by default. `register` makes no network call until you pass `--yes`; if the body over-asks, it refuses (exit 1) unless you also pass `--force`. Blocking format errors are never written past.

There are three target modes. `clone` (the default) is a local registrar-compatible store (axum plus SQLite) with no signing, no auth, and no x5c: it holds payload-only JWTs and exists so you can rehearse the read and write paths entirely offline. `cached-sandbox` is a read-only, server-side mirror for public sandbox reads, with provenance headers and stale fallback for demos. `sandbox` is the real registrar behind Keycloak; it is rehearsal-only and off-stage. Configure them through environment variables (see `docs/SANDBOX.md` and `.env.example`).

Secrets hygiene is enforced: the tool never logs, echoes, or commits tokens, certificates, or keys, and `.env*`, `secrets*.md`, `*.sqlite`, and `*signing-key*` are gitignored.

## How it works

One engine is the spine. `augenmass-core` is a vendored, HTTP-free, pure-Rust crate carried over as-is from the verifier project: inspector (over-ask analysis, baselines, legal basis), regcert, pid, disclosure, verify (clock-injectable), status (fail-closed, offline), trust, and crypto. v1 used only inspector, regcert, and pid; v2 surfaces all of it behind one CLI. Because the engine is HTTP-free and the verification clock is injectable, artifact decoding, proportionality, generation, and offline verification are deterministic, which is what makes the committed fixtures reproducible in CI. Network behavior stays in the shell (`clone`, `cache`, `sandbox`, and `serve`).

## Documentation

- `docs/ARCHITECTURE.md`: the one-engine spine and how the CLI wraps `augenmass-core`.
- `docs/COMMANDS.md`: every command, flag, exit code, and output shape.
- `docs/TOOLS.md`: the Claude Code plugin and skill.
- `docs/SANDBOX.md`: the clone store, the sandbox registrar, and their environment variables.
- The skill: `plugins/augenmass-workbench/skills/augenmass`.

## License

Apache-2.0.
