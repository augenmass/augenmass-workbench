# HANDOFF: augenmass-workbench-v2

This file is the cross-session memory for the build. Read it first in any new session.
It records what exists, what is verified, the (expanded) goal, and the prioritized next work.

## TL;DR of status

- Repo: `/Users/bioharz/git/eudi-wallet-hackathon/augenmass-workbench-v2`, its own git repo on `main`.
- A working, fully-tested Rust CLI `augenmass` (v0.2.0) plus a Claude Code skill and full docs.
- Build green, zero warnings, clippy clean, `cargo fmt --check` clean.
- Tests: 16 unit + 30 CLI integration + 1 serve integration = 47, all passing, against real committed offline fixtures.
- Every command verified by hand against the real fixtures (verification, revocation, x509_hash, over-ask, the guarded clone write/read loop, the live serve flow).
- HEADLINE capability now built: `augenmass serve`, a live wallet-interaction debugger (P2 done). See below.
- P1 (harvest) done this round: 6 new repos in `../external/` + `external/HARVEST-NOTES.md`.
- The work is NOT finished: P3, P4, P5, P6 remain. See "Next work" below.

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

- UNDERSTAND: `inspect <input>` (universal auto-detect + decode), `decode {jwt|sd-jwt|regcert|request|offer|status-list}`
- PROPORTIONALITY: `check <body>` (registration-body gate: over-ask + format), `audit --request {minimal|overask|FILE} --purpose <id> [--cert FILE]`, `baselines [<id>]`
- CRYPTO: `verify {presentation|trust|status|status-list}`, `x509-hash <input> [--client-id]`
- PRODUCE: `generate {regbody|dcql}`
- DIAGNOSE: `doctor <request>` (JAR x5c/client_id gotchas)
- DEBUG (live): `serve` (verifier-in-a-box; a real wallet presents and the whole OpenID4VP exchange is traced)
- WRITE (guard-railed): `register <body> --target {clone|sandbox} [--yes --force]`, `list`, `clone serve`

The `serve` command (src/serve/{mod,state,handlers,view,trace}.rs) is the headline
wallet-interaction debugger, ported and extended from `verifier/verifier-service`.
Endpoints: GET / (mints a session, QR + links), GET /request/:id (signed JAR,
content-type application/oauth-authz-req+jwt), POST /response/:id (wallet
direct_post.jwt -> decrypt -> verify -> trust -> status -> over-ask), GET
/inspect/:id, GET /trace/:id (live HTML timeline), GET /api/trace/:id (JSON), GET
/api/sessions, GET /health. The NEW part vs the old service is src/serve/trace.rs:
a per-session, timestamped TraceStore (event codes SESSION_CREATED, REQUEST_BUILT,
REQUEST_OBJECT_FETCHED, RESPONSE_RECEIVED, RESPONSE_DECRYPTED, VERIFIED/REJECTED,
STATUS_CHECKED, OVER_ASK_ANALYZED, NOTE, ERROR), each carrying the raw artifact,
mirrored live to the console (ANSI on a TTY), the browser, and JSON. Flags: --port
--host --public-url --key --leaf --purpose --trust-anchor --live-status --quiet.
Zero-config uses a throwaway dev cert (client_id is then NOT the registered one);
--key + --leaf use the real registrar leaf. A live wallet response cannot be
replayed from a fixture (fresh ephemeral enc key + nonce per run), which is why the
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
cd augenmass-workbench-v2
cargo build
cargo test                 # 15 unit + 30 integration
just verify                # fmt --check, clippy -D warnings, test, + real-fixture smoke battery
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
  `undefined` inside the script, so agents cloned into `augenmass-workbench-v2/undefined/`
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
P2. DONE. `augenmass serve` wallet-interaction debugger shipped (see "What is built").
    Possible follow-ups: render the over-ask verdict inline on the trace page; add a
    "replay last response" capture-to-file so a captured wallet response can be
    re-verified offline; multi-credential vp_token handling beyond "last wins".
P3. Broaden decoders/verifiers: mdoc / mso_mdoc (ISO 18013-5) via `isomdl` + CBOR/COSE;
    trust-list (ETSI TS 119 612 / 119 475) parse + validate against `../external/test-trust-lists`;
    presentation_definition (legacy PE) decode + PE->DCQL conversion; OpenID4VCI issuer metadata
    and wallet metadata; full JAR signature verification (not just decode).
P4. DCQL validation (unique ids, credential_sets reference known ids, format-correct paths:
    mdoc 2-element [namespace, element] vs SD-JWT nested). Schemas available under `../external/eudiplo/schemas`.
P5. Adversarial multi-agent review (correctness/security/DX/doc-accuracy/completeness) of the
    whole repo; fix findings. (Was planned but not yet run.)
P6. Cross-platform release binaries; consider a C-ABI / WASM build of the engine later.

## Awareness: the parallel Codex build (you may read it now)

`../augenmass-workbench-v2-codex` is a SEPARATE deliverable by Codex (the user's other agent).
It is its own git repo. Codex first built a dependency-free PYTHON CLI (`agm-workbench`) with
commands lint/check, generate, inspect, doctor, diff, audit, fixtures, schema, commands, version,
a Codex skill, docs, examples, JSON schemas, and tests. The user has since told Codex to REWRITE
IN RUST. Codex's honesty boundary: it is inspect/lint/diff/audit/report only and explicitly does
NOT do production crypto verification or registrar writes (it reports `crypto_verification: not-performed`).

Our differentiators to keep: real cryptographic verification (SD-JWT VC + KB-JWT, trust,
revocation), the guarded registrar WRITE path, and (next) the live WALLET-INTERACTION debugger.
Read codex for good ideas (its `diff`/`audit` corpus framing, its JSON schemas, its skill shape)
but do not duplicate or depend on it. Two independent tools; ours is the deeper, verifying one.

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
