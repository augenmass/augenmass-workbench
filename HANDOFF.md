# HANDOFF: augenmass-workbench

This file is the cross-session memory for the build. Read it first in any new session.
It records what exists, what is verified, the (expanded) goal, and the prioritized next work.

## TL;DR of status

- Repo: `/Users/bioharz/git/eudi-wallet-hackathon/augenmass-workbench`, its own git repo on `main`.
- A working, fully-tested Rust CLI `augenmass` (v0.2.0) plus a Claude Code skill, cache backend, Docker image, and full docs.
- Build green, zero warnings, clippy clean, `cargo fmt --check` clean.
- Tests at last shipping pass: 41 unit + 43 CLI integration + 7 cache integration + 5 demo-proof integration + 1 serve integration, all passing against real committed offline fixtures.
- Every command verified by hand against the real fixtures (verification, revocation, x509_hash, over-ask, the guarded clone write/read loop, the live serve flow).
- HEADLINE capability built: `augenmass serve`, a live wallet-interaction debugger (P2 done), since hardened to be safe-by-default (the P0 security PR) with an `evidence` export/verify/replay group built on top.
- Commits on `main` (newest first): `1d1206a` evidence bundle caveats doc; `b22c73a` evidence
  export/verify/replay; `a19cea6` bundle serve hardening; `7555e0f` serve-hardening docs; `bc0eca8`
  harden live debugger + status fetch (the P0 security PR); `0b47ddf` prior HANDOFF update; `7d0f090`
  validate dcql (P4); `791b5c1` decode mdoc (P3); `657bf85` serve hardening from the adversarial
  review (P5, 12/13 fixed); `8930e77` serve (P2); `875a42c` foundation. Working tree clean;
  `just verify` exits 0.
- Done this session: P1 (harvest, 6 repos + `external/HARVEST-NOTES.md`), P2 (serve), P5 (review +
  fixes), P3-mdoc (decode mdoc + inspect detection), P4 (validate dcql). Surveyed codex (see below).
- Done since, as an Opus-plans / Codex-implements split across two merged PRs (frozen plan
  `plans/parallel-mixing-babbage.md`): (1) the P0 security PR, which made `serve` safe-by-default
  (redacted-by-default trace, per-session ephemeral response-encryption keys with single-use cleanup,
  plaintext `direct_post` rejection, SSRF resolver pin + status-body cap + mapped-IPv6/CGNAT deny,
  opt-in `--unsafe-debug-artifacts` local capture); (2) the `evidence` PR (export/verify/replay of
  sensitive audit bundles built from those captures: canonical hashing, optional ES256 signing, and a
  redacted projector-safe replay that can decrypt and offline-verify a captured response). Both were
  verified against the running binary and fast-forward merged to `main`.
- Added since: `cache serve`, `cache warm`, `cached-sandbox` read-through behavior, local
  `plugin-smoke`, `live-cache-smoke`, `docker-smoke`, explicit Linux Docker platform smokes,
  `shipping-smoke`, `platform-smoke`, and `local-release-proof` gates.
- NOT finished: the rest of P3 (mdoc cryptographic VERIFY, trust-list parse, PE->DCQL, OpenID4VCI
  metadata, full JAR signature verify) and fully proven native Windows/Linux release archives. See "Next work".
- The previously deferred review finding (LOW: serve reused one response-encryption key across
  requests) is now CLOSED by the P0 PR: per-session ephemeral keys, single-use, with cleanup on the
  success, plaintext-reject, and malformed-parse paths.

## The real goal (corrected and expanded by the user)

This is a LONG-RUNNING effort (hours, not minutes), not a one-shot. The user was emphatic:
it is no longer "just about over-ask". The goal is a genuinely comprehensive, complex,
production-grade Rust toolkit ("swiss army knife") for **debugging, interacting with, fixing,
and developing for and with the EUDI Wallet ecosystem** (the digital-identity infrastructure
Germany and the whole EU must support). Over-ask is now one tool among many.

Standing directions for the next session:
1. Keep building deep and broad. Do not stop early. Harvest knowledge, then build.
2. Stay in Rust. (Codex started in Python, the user told it to switch to Rust; we were right to be in Rust.)
3. Be independent (the user is often AFK). Use the Workflow tool for parallel harvest/build/review. Commit milestones.
4. Pull more external repos into `../external/` as needed: hackathon competitors' tools, other
   useful EUDI projects, standards docs, anything that teaches us the ecosystem or that we can reuse.
5. Headline new capability to build: **debug the actual wallet interaction.** A local
   verifier-in-a-box so a REAL EUDI wallet can present to our tool (QR / deep link -> request_uri
   JAR -> direct_post(.jwt) response -> JWE decrypt -> full SD-JWT VC + KB-JWT verification ->
   over-ask + trust + revocation trace). Other hackathon teams have such tooling; we should too.
   This is largely a port/adaptation of the existing `verifier/verifier-service` (axum) into a
   `serve` / `debug-flow` command here. Reuse it; do not rewrite from scratch.

## What is built (and verified) right now

CLI binary `augenmass` (src/main.rs -> src/cli.rs). Global `--json` on read-only commands.
Every artifact arg accepts a file path, an inline value, or `-` for stdin. Commands, grouped:

- UNDERSTAND: `inspect <input>` (universal auto-detect + decode), `decode {jwt|sd-jwt|regcert|request|offer|status-list|mdoc}` (mdoc = ISO 18013-5 mso_mdoc CBOR, src/mdoc.rs, decode-only; fixtures/mdoc/{issuer-signed,device-response}.hex)
- PROPORTIONALITY: `check <body>` (registration-body gate: over-ask + format), `audit --request {minimal|overask|FILE} --purpose <id> [--cert FILE]`, `baselines [<id>]`
- CRYPTO: `verify {presentation|trust|status|status-list}`, `x509-hash <input> [--client-id]`
- PRODUCE: `generate {regbody|dcql}`
- DIAGNOSE: `doctor <request>` (JAR x5c/client_id gotchas), `validate dcql <input>` (DCQL semantic validation: unique ids, credential_sets refs, per-format claim paths; CI-gateable, src/commands/validate.rs)
- DEBUG (live): `serve` (verifier-in-a-box; a real wallet presents and the whole OpenID4VP exchange is traced)
- EVIDENCE (offline audit): `evidence {export|verify|replay}` (turn a `serve --unsafe-debug-artifacts` capture into a sensitive, hash-verified, optionally ES256-signed bundle, then render a redacted projector-safe replay timeline)
- WRITE / CACHE (guard-railed): `register <body> --target {clone|cached-sandbox|sandbox} [--yes --force]`, `list`, `clone serve`, `cache serve`, `cache warm`

The `serve` command (src/serve/{mod,state,handlers,view,trace}.rs) is the headline
wallet-interaction debugger, ported and extended from `verifier/verifier-service`.
Endpoints: GET / (mints a session, QR + links), GET /request/:id (signed JAR,
content-type application/oauth-authz-req+jwt), POST /response/:id (wallet
direct_post.jwt -> decrypt -> verify -> trust -> status -> over-ask), GET
/inspect/:id, GET /trace/:id (live HTML timeline), GET /api/trace/:id (JSON), GET
/api/sessions, GET /health. The NEW part vs the old service is src/serve/trace.rs:
a per-session, timestamped TraceStore (event codes SESSION_CREATED, REQUEST_BUILT,
REQUEST_OBJECT_FETCHED, RESPONSE_RECEIVED, RESPONSE_DECRYPTED, VERIFIED/REJECTED,
STATUS_CHECKED, OVER_ASK_ANALYZED, ARTIFACT_SAVED, NOTE, ERROR). As of the P0 PR the trace is
redacted by default: it records shapes, lengths, SHA-256 digests, field names, and outcomes, never
raw bodies or claim values, and the unauthenticated `/api/trace/:id` serves only that redacted view.
Full-fidelity local capture is opt-in via `--unsafe-debug-artifacts <dir>` and is never served over
HTTP. The trace is mirrored live to the console (ANSI on a TTY), the browser, and JSON. Flags: --port
--host --public-url --key --leaf --purpose --trust-anchor --live-status --quiet.
Zero-config uses a throwaway dev cert (client_id is then NOT the registered one);
--key + --leaf use the real registrar leaf. A live wallet response cannot be
replayed from a fixture (fresh ephemeral enc key + nonce per session), which is why the
verify path is unit-tested via verify_vp_token against the oracle fixtures and the
request/trace path is integration-tested on an ephemeral port (tests/serve.rs).

Exit codes are CI-friendly: non-zero on the "bad" outcome (over-ask, blocking format error,
verification reject, untrusted, revoked, x509_hash mismatch, doctor findings).

## Architecture

- `crates/augenmass-core`: the engine, VENDORED as-is (renamed package from `verifier-core`).
  HTTP-free, pure. Modules: inspector (over-ask analyze + baselines + LEGAL_BASIS), regcert,
  pid, disclosure, verify (clock-injectable `_at`/`_full`), status (fail-closed revocation),
  trust (leaf-chains-to-anchor + validity window, NOT full path validation), crypto
  (JWE decrypt, x5c->JWK, leaf_cert_hash = x509_hash). Keep changes here minimal and pure.
- `src/`: the I/O shell. Shared modules: output, config, jose (JWT decode + PEM/x5c helpers),
  dcql, checkbody (the over-ask+format engine), render, artifact (the sniffer), x509util
  (cert parse + signer JWK from PEM), http_target, clone_server, generator.
  `src/commands/*`: one module per command group.
- Dep pins that MUST stay byte-identical (they make `DcqlQuery` unify): openid4vp git rev
  `d2847dfcd07d1ea70ffc0c713ad650519d424a82`; josekit fork `cobward/josekit-rs` rev `635c8a7`
  (pulled transitively); ssi 0.16. These mean the crate is NOT cargo-publishable to crates.io.

## How to build / test / verify

```
cd augenmass-workbench
cargo build
cargo test --workspace     # full workspace suite, including the reusable core crate
just verify                # fmt --check, clippy -D warnings, test, + real-fixture smoke battery
just shipping-smoke        # plugin bundle + live cached-sandbox + Docker cache backend
just platform-smoke        # host/cross-target cargo checks; skips missing cross toolchains unless strict
just local-release-proof   # strongest local gate; includes linux/arm64 and linux/amd64 Docker smokes
just bundle                # release build -> plugins/augenmass-workbench/bin/augenmass (arm64)
```

## Key facts you will need (verified)

- PID vct: `urn:eudi:pid:de:1`; PID format `dc+sd-jwt`.
- Shared fixture binding: nonce `b4ba2623-76a2-486b-a1f6-f1656025d07b`, aud
  `https://self-issued.me/v2`, deterministic clock `--now 1780435200`.
- ERICA VPs chain to `fixtures/certs/erica-trust-anchor.pem`. Synthetic PID (with a status
  pointer at index 42) chains to `fixtures/certs/synthetic-pid-anchor.pem`.
- Status lists: 256 entries, 1 bit; index 42 revoked in `status-list-REVOKED.jwt`; verify key
  `fixtures/status/status-list-verify-key.pub.pem` (SPKI PEM; private signing key intentionally absent).
- `access-leaf.pem` x509_hash = `VE3qp3vLVkU8JyVmXkjL7CSDVxVoTFdTv5fAEwmjKOI`.
  eudiplo JAR client_id = `x509_hash:7zvIjJaM1KQPpN7IZBuVLuh8anw1gcbZ0a6Wj3M9i4w`.
- Over-ask legal basis (verbatim from the engine): eIDAS (EU) 2024/1183 Art. 5b(3); GDPR
  (EU) 2016/679 Art. 5(1)(c); EUDI ARF registration certificate RPRC_07.
- Curated baselines: age_gate_18, event_checkin, car_rental, bank_kyc (taste judgments).
- Our relying party (write only under it): "Hackathon - Reza", id `2af138a8-59ea-4a84-aea3-666cafdb1369`.
- Sandbox: Keycloak resource-owner password grant, working client_id `swagger`. Env in `.env.example`.

## Pitfalls already discovered (do not relearn)

- `ssi`'s `SdJwt::new` and the engine verify/trust/status functions need the EXACT presentation
  string: TRIM file input (trailing newline) before passing in. (Done in decode + verify.)
- Building a signer JWK from an SPKI public PEM uses `p256::PublicKey::from_public_key_pem`
  (needs p256 features `pem`,`pkcs8`,`jwk`) then `to_jwk_string` -> serde into `ssi::jwk::JWK`.
  For a CERT pem, use `augenmass_core::crypto::public_key_from_cert_der`. See `src/x509util.rs::signer_jwk_from_pem`.
- The artifact sniffer must handle the registrar ENTITY ENVELOPE (`{jwt, intendedUse, ...}`,
  jwt nested) and the DCQL WRAPPER (`{dcql_query: {...}}`), not only bare forms. (Done.)
- Doc agents over-escaped `<`/`>`/`&` as HTML entities; persist step unescapes them.
- `verifier-core` src is byte-identical across the verifier/ and v1 workbench trees.
- The `serve` port needed p256 feature `ecdsa` (for `p256::ecdsa::SigningKey` /
  `P256Signer`) plus new deps rcgen, qrcode, rand, tower-http, tracing,
  tracing-subscriber. The bundled RC is `include_str!`'d from
  `fixtures/regcert/rc-by-id.json` (NOT `../fixtures/live/...` like the old service).
- Workflow `args` quirk: in the harvest Workflow run, `args.externalDir` arrived as
  `undefined` inside the script, so agents cloned into `augenmass-workbench/undefined/`
  instead of `../external/`. The 6 new repos were relocated to `../external/` by hand;
  the leftover `undefined/` (2 duplicate shallow clones) is gitignored and can be rm'd
  by the user. If you pass `args` to a Workflow, verify it actually reaches the script
  (log it early), or hardcode absolute paths in the script.

## Next work, prioritized (for the next session)

P1. DONE (this round). Harvested 6 new repos into `../external/` via a background
    Workflow: openeudi-openid4vp, sd-jwt-io, sphereon-oid4vc-demo, owf-sd-jwt-js,
    animo-openid4vc-playground, animo-openid4vc-playground-funke; index at
    `external/HARVEST-NOTES.md`. More can be harvested later (walt.id, Procivis One,
    COKIT, the eudi-lib-* SDKs, EWC). Read `external/HARVEST-NOTES.md` first.
P2. DONE. `augenmass serve` wallet-interaction debugger shipped (see "What is built"),
    then hardened via an adversarial review workflow (13 confirmed findings fixed:
    SSRF guard on the status fetch, infra-vs-revocation error distinction, REJECTED
    event on revoke so the timeline ends red, loud multi-credential warning, bind/
    public_url mismatch warning + always-shown bind address, public_url trailing-slash
    normalisation, seq ordering under the trace lock, camelCase trace JSON + eventCount,
    --quiet env, loopback note, landing reload note). The one deferred LOW finding (single reused
    response-encryption key) is now FIXED by the P0 security PR: per-session ephemeral keys minted in
    create_request, stored in a Mutex<HashMap<Uuid, JWK>> on AppState, single-use with cleanup on the
    success, plaintext-reject, and malformed-parse paths. The trace is also redacted by default now,
    with an opt-in --unsafe-debug-artifacts capture, and the "replay last response" follow-up is done
    via the evidence export/verify/replay group. Remaining serve follow-up: inline over-ask verdict on
    the trace page.
P3. IN PROGRESS. mdoc / mso_mdoc (ISO 18013-5) DECODING done: `decode mdoc` +
    inspect detection, src/mdoc.rs via `ciborium` (already transitive; no new deps),
    fixtures from isomdl (the real Jane Doe mDL issuer-signed + a synthetic
    device-response). Decode-only; COSE signature + value-digest verification is the
    next mdoc step. Still to do in P3: full mdoc cryptographic VERIFY (COSE_Sign1 +
    value-digest match + device binding); trust-list (ETSI) parse + validate against
    `../external/test-trust-lists`; presentation_definition (legacy PE) decode +
    PE->DCQL; OpenID4VCI issuer/wallet metadata; full JAR signature verification.
    Original P3 note follows for reference: broaden decoders/verifiers: mdoc via `isomdl` + CBOR/COSE;
    trust-list (ETSI TS 119 612 / 119 475) parse + validate against `../external/test-trust-lists`;
    presentation_definition (legacy PE) decode + PE->DCQL conversion; OpenID4VCI issuer metadata
    and wallet metadata; full JAR signature verification (not just decode).
P4. DONE. DCQL validation shipped: `validate dcql` (src/commands/validate.rs) checks unique
    credential ids, credential_sets options referencing known ids, and per-format claim paths
    (mdoc 2-element [namespace, element] vs SD-JWT string/null/index). Findings have stable ids
    + fixes; exits non-zero on blocking. Could extend with claim id uniqueness, claim_sets
    references, and JSON-schema validation against `../external/eudiplo/schemas`.
P5. DONE (this session). Adversarial multi-dimension review workflow run against the serve code;
    12 of 13 confirmed findings fixed (1 LOW deferred: per-request enc key). Re-run such a review
    over the whole repo (incl. mdoc + validate) when convenient.
P6. Cross-platform release binaries; consider a C-ABI / WASM build of the engine later.

## Awareness: the parallel Codex build (surveyed 2026-06-23)

`../augenmass-workbench-v2-codex` is a SEPARATE deliverable by Codex (the user's other agent),
its own git repo, STILL ACTIVELY being committed to (last seen: 34 commits, one 8 minutes before
this survey). Codex finished its Python -> Rust rewrite: it is now Rust-first (27 .rs, ~14,200
lines, edition 2024), two bins (`augenmass-workbench`, `agm-workbench`).

What codex now is (its old "no production crypto verification" boundary is GONE):
- It does REAL crypto, but via `verifier-core` as a PATH dependency to `../verifier/verifier-core`
  (NOT vendored). Consequence: codex's repo does NOT build standalone; it needs the sibling
  verifier/ checkout. OURS vendored the engine (crates/augenmass-core) and builds standalone.
- It ALSO built a `serve` verifier-in-a-box with a per-session trace, and converged on the exact
  same routes we did (/, /request/:id, /response/:id, /inspect/:id, /trace/:id, /api/trace/:id,
  /api/sessions, /health). Independent convergence; both ported verifier/verifier-service.
- Codex's serve WAS ahead of ours on two points (per-session response-encryption keys, which was
  exactly our deferred LOW finding #8, and a redacted /api/trace). The P0 PR closed both: ours is now
  redacted-by-default with per-session ephemeral keys, plus an opt-in --unsafe-debug-artifacts capture
  for full-fidelity local debugging.
- Codex went BROADER: SARIF output for check/lint, a machine-readable command catalog + 27 JSON
  schemas, `fix-plan` (JSON-Patch advice), `evidence capture`/`verify-manifest` + `wallet trace
  capture`/`replay` (SHA-256 manifests, tamper checks, offline replay), deep wallet/ERICA surface
  (wallet inspect-uri/flow/preflight/phone-check/fetch-request/direct-post/doctor; erica
  parse-url-payload/debug-payload/summarize; request profile de-sandbox/haip/dc-api), `ops doctor`,
  `jws decode/verify`, `trust diagnose-wrprc`.

OUR differentiators codex LACKS (keep these): self-contained build (vendored core); mdoc / ISO
18013-5 decoding (codex has no CBOR decoder, no ciborium); the guarded registrar WRITE path
(register/list/clone + local SQLite clone store); `validate dcql` semantic validation; the
adversarial-review-hardened serve.

Ideas worth borrowing from codex (the user said mine it, do not duplicate or depend on it):
1. DONE (P0). Per-session ephemeral enc keys + redacted-by-default trace in serve (closed our deferred #8).
2. DONE. Evidence export/verify/replay: turn a --unsafe-debug-artifacts capture into a sensitive,
   hash-verified, optionally ES256-signed bundle and replay a redacted timeline offline. This was the
   "replay last response" follow-up; ours is an independent implementation (no dependency on codex's
   evidence module).
3. STILL OPEN: SARIF output for check/audit so findings drop into CI security dashboards.
Two independent tools; ours is the self-contained, mdoc-aware, write-capable, review-hardened one.

## House style (enforced by the user; violations are defects)

No emojis. No dashes as clause separators (no en-dash, em-dash, double-hyphen, hyphen-between-clauses;
use commas/colons/semicolons/parentheses; compound hyphens like over-ask are fine). No markdown
blockquotes. No wall-clock time estimates (use small/medium/large/XL). "Augenmaß" (ß) only in
prose/titles; every identifier is the slug "augenmass" (ss). Swiss German ss never ß. `bunx` never
`npx`. Never run `rm` (print for the user). Never change git remotes.

## Where the generated docs came from

The doc suite (README, docs/*, the skill + 3 reference docs, AGENTS.md, CHANGELOG.md) was authored
by an 11-agent documentation Workflow grounded in a shared fact sheet (`/tmp/augenmass-facts.md`,
may be gone after reboot) and the live binary. They were verified clean (no entities, dashes, emojis)
and written to disk. If a printed CLI string changes, re-sync the docs (especially docs/COMMANDS.md
and the copy in the skill) and re-run `just verify`.
