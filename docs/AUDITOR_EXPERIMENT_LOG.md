# Auditor proof experiment log

Branch: `codex/auditor-proof-experiment`
Worktree: `augenmass-workbench-auditor-experiment`
Started: 2026-06-25

This branch is isolated from `main` for the last auditor-grade proof pieces:
issuer trust anchoring, live revocation/status checks, and sharper accounting of
what a wallet actually discloses when a request asks for a narrow nested claim.

## Ground truth from main

Already proven on `main`:

- Real iOS and Android sandbox wallets can complete the encrypted
  `direct_post.jwt` flow through `https://wallet.augenmass.tech`.
- The workbench decrypts the wallet response and verifies the SD-JWT VC
  presentation plus KB-JWT holder binding.
- The hosted relay carries only wallet-facing request/response endpoints.
- Redacted traces and local evidence bundles work; exported bundles pass
  `evidence verify` and `evidence assert-live`.

Not yet claimed on `main`:

- PID issuer trust anchoring with `--trust-anchor`.
- Live credential status/revocation with `--live-status`.
- A fully precise report for nested age disclosures where the verifier asks for
  `age_equal_or_over.18` but wallets show or disclose the wider
  `age_equal_or_over` object.

## Work split

Can be developed without a phone:

- Inspect existing captured request/response artifacts in local ignored
  `debug-out/` and exported bundles in ignored `dist/`.
- Add fixture and unit coverage for disclosure accounting.
- Exercise trust/status code against existing fixtures.
- Research available sandbox trust/status metadata from checked-in docs and
  public metadata endpoints.
- Automate no-phone reachability checks for public trust/status material.
- Update docs and proof language.

Needs a phone before promotion:

- Final iOS and Android scans after any request-shape or verification-path
  change.
- Any stage claim that `--trust-anchor --status-signer --live-status` works
  against the current sandbox wallet credential.

## Checkpoints

- 2026-06-25: Created isolated experiment branch/worktree and log.
- 2026-06-25: Added nested disclosure accounting for object-valued SD-JWT
  disclosures. A disclosed `age_equal_or_over` object is now expanded into
  leaf fields such as `age_equal_or_over.18`, so the inspector can distinguish
  the requested age threshold from wider threshold disclosure. Verified with
  `cargo fmt --check` and `cargo test -p augenmass-core --locked`.
- 2026-06-25: Added `augenmass evidence profile`, a redacted bundle profiler
  for auditor readiness. It verifies bundle hashes/replay first, then reports
  only safe metadata: presentation hashes, issuer header shape, x5c presence,
  disclosed claim keys, status-list reference presence, HTTPS/host/URI hash,
  and whether trust-anchor/live-status claims are possible with external trust
  material. Verified with `cargo fmt --check`,
  `cargo test -p augenmass-workbench commands::evidence --locked`, and
  `cargo test -p augenmass-workbench evidence_profile_reports_redacted_readiness --locked`.
- 2026-06-25: Profiled the latest local phone evidence bundles. The two iOS
  bundles profile cleanly. The previous Android bundle fails strict replay
  determinism after the nested-disclosure change, but re-exporting from its
  local unsafe-debug source with this branch produces a valid bundle. All three
  latest phone credentials carry an issuer x5c leaf and an HTTPS status-list
  reference on the Bundesdruckerei preprod PID provider.
- 2026-06-25: Fixed status-list decoding for the live sandbox token shape. The
  sandbox status-list token uses unpadded base64 in `status_list.lst`; the core
  verifier now normalizes unpadded/base64url list encodings after JWS signature
  verification and before status-list bit decoding. A local redacted probe
  fetched the Android credential's referenced `application/statuslist+jwt` and
  `augenmass verify status` returned `VALID` using the issuer leaf carried in
  the credential. This proves live status mechanics and reachability, but not
  external PID issuer trust anchoring.
- 2026-06-25: Ran the local gates after the experiment changes:
  `just demo-proof` and `just verify` both pass. The full gate covers
  formatting, Clippy with `-D warnings`, workspace unit/integration tests,
  fixture crypto/trust/status checks, request/audit checks, mdoc/DCQL decoding,
  relay source guard, and the local relay smoke.
- 2026-06-25: Located the live sandbox trust/status material. The provider root
  publishes `certificates/root-ca.crt` (issuer trust anchor) and
  `certificates/signer.crt` (status-list signer), while the BMI usercontent
  endpoint publishes a `trustlist+jwt` whose issuance/revocation services match
  the same Bundesdruckerei preprod PID provider. Re-exporting the Android phone
  evidence and running `verify presentation` with `--trust-anchor root-ca.crt`,
  `--status-token <fetched credential status-list>`, and
  `--status-key signer.crt` succeeds. Using the root CA as the status key fails,
  proving the status signer is intentionally separate from the issuer trust
  root.
- 2026-06-25: Added `augenmass serve --status-signer <PEM>` so the live
  debugger can express that real provider shape: `--trust-anchor` anchors the
  PID issuer, while `--status-signer` verifies token-status-list signatures.
  Without `--status-signer`, `serve --live-status` still falls back to the trust
  anchor key for older single-key fixtures. Verified with focused live-status
  unit tests and Clippy before the next full gate.
- 2026-06-25: Re-ran the full local gate after wiring `--status-signer`.
  `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace --locked`, `just demo-proof`, and `just verify` all
  pass. The full gate includes the local relay smoke and proves the public relay
  still forwards only wallet-facing endpoints while local traces remain
  redacted.
- 2026-06-25: Added `just bundesdruckerei-preprod-material-smoke`, a no-phone
  live-material smoke for the current preprod PID provider. It fetches the
  provider root page, root CA, status signer certificate, and BMI trustlist JWT
  with byte caps and HTTPS guards, parses the certs/JWT through the CLI, and
  prints only safe hashes and aggregate counts. This proves reachability and
  parseability of public trust/status material, not a completed wallet
  presentation.
- 2026-06-25: Added `augenmass evidence prove-trust-status`, a redacted bundle
  proof that re-verifies a captured presentation with explicit
  `--trust-anchor`, `--status-token`, and `--status-key` inputs. This removes
  manual nonce/audience/timestamp retyping because it uses the captured
  verification context from the evidence bundle. It complements
  `evidence assert-live`: `assert-live` proves the encrypted phone-wallet spine,
  while `prove-trust-status` proves issuer trust and supplied status-list
  validity for the captured authorization response.
- 2026-06-25: Extended `evidence prove-trust-status` with
  `--fetch-status-token`, an opt-in mode that fetches the referenced
  token-status-list from the captured credential URI through the same hardened
  public-address fetch path used by `serve --live-status`. This removes the
  manual status-token copy/paste step for live evidence while keeping
  `--status-token` available for fully offline proof.
- 2026-06-25: Added `bundesdruckerei-wallet-trust-status-proof`, a
  provider-specific proof wrapper for Bundesdruckerei preprod PID captures. It
  fetches the current provider root CA and status-list signer over bounded
  HTTPS, then runs `evidence assert-live` plus
  `evidence prove-trust-status --fetch-status-token`. This removes the manual
  cert-fetch step from the demo while keeping the proof gates explicit.
- 2026-06-25: Re-exported five real phone-wallet captures into temporary local
  evidence bundles and ran the redacted proof chain without committing any
  sensitive material. Sessions `4095f1f4-cb16-4930-8773-16c793b78e73`,
  `341c1ffc-88da-4c75-a13d-981c05c7e263`,
  `5d3e0451-bdc2-4773-a5f1-1181034de5b3`,
  `9118a5a0-405e-49d8-9ce8-cf4a7a7bd9b6`, and
  `e1dffbc6-fabb-4a45-8ee5-9b42950cfa26` all passed
  `evidence verify`, `evidence assert-live`, and
  `bundesdruckerei-wallet-trust-status-proof` with
  `statusTokenSource: fetched`. This is the current strongest demo proof:
  completed phone-wallet exchange plus post-capture Bundesdruckerei preprod
  trust/status verification, with PID-bearing material kept local and redacted.
- 2026-06-25: Hardened `evidence assert-live` so a successful proof must decrypt
  the captured `direct-post.body` with the captured `session-enc-key.jwk` and,
  when `auth-response.json` exists, verify that both payloads match. Added a
  Rust-only ECDH-ES JWE helper for no-phone harnesses and replaced the positive
  CLI fixture with a real compact JWE. The regression test now rejects a
  verified-looking bundle that only carries a synthetic decrypted artifact.
  Re-exported sessions `4095f1f4-cb16-4930-8773-16c793b78e73`,
  `341c1ffc-88da-4c75-a13d-981c05c7e263`, and
  `5d3e0451-bdc2-4773-a5f1-1181034de5b3` after the hardening; all still pass
  strict `evidence assert-live` plus the Bundesdruckerei trust/status wrapper.
- 2026-06-25: Added fail-closed CLI coverage for `evidence prove-trust-status`:
  revoked status-list token, wrong issuer trust anchor, wrong status signer,
  conflicting status sources, and missing status source. Focused
  `cargo test --test cli evidence_` now covers both positive and hostile
  trust/status bundle proof paths.
- 2026-06-25: Added `just auditor-no-phone-proof`, a local gate for the
  strongest automated proof we can run without a handset: strict encrypted
  evidence CLI tests, evidence unit tests, request-side serve runtime test,
  `serve-smoke`, evidence proof command exposure, and wrapper shell syntax.
- 2026-06-25: Ran the full `just verify` gate on
  `codex/auditor-proof-experiment` at commit `2ef1059`. It passed the complete
  local suite: formatting, Clippy, workspace tests, build, over-ask/regbody
  smoke checks, DCQL validation, the Bundesdruckerei wrapper shell check, relay
  source guard, and `relay-smoke`. The relay smoke confirmed the local relay
  still forwards only wallet-facing paths, refuses public trace/inspect access,
  rejects plaintext `direct_post`, keeps the local trace redacted, and emits
  redacted relay logs.
- 2026-06-25: Added a Rust-only no-phone encrypted serve-runtime proof. The
  unit test mints a fresh `augenmass serve` request, builds a fresh synthetic
  SD-JWT+KB presentation bound to that session's nonce and `x509_hash`
  audience, encrypts it as `direct_post.jwt` to the session response key, posts
  it through the real response handler, exports the resulting unsafe-debug
  artifacts, and runs strict `evidence assert-live` on the exported bundle. This
  closes the automated proof gap between request-side serve tests and manually
  captured iOS/Android phone evidence. It does not claim provider issuer trust
  or live revocation; those remain covered by the explicit
  `evidence prove-trust-status` and Bundesdruckerei wrapper proofs.
- 2026-06-25: Wired the new runtime proof into `just auditor-no-phone-proof`.
  While re-running the full gate, `relay-smoke` exposed a Bash guard edge case:
  a randomly generated relay run ID can begin with `-`, and BSD `grep` treated
  the forbidden-value pattern as flags. The guard now uses `grep -F --` for
  variable patterns, preserving the leak check while making it robust to
  leading hyphens. Verified with direct `relay-smoke` and a full `just verify`
  pass after the fix.
- 2026-06-25: Extended the no-phone encrypted runtime proof to cover the
  trust/status path through the real response handler. The test generates a
  runtime PID issuer leaf signed by a generated trust anchor, carries the leaf
  in the SD-JWT `x5c`, embeds a token-status-list reference, configures
  `serve` with the generated trust anchor plus the existing dedicated status
  signer fixture, and uses the recording status fetcher to return the clear
  status-list token. The resulting encrypted `direct_post.jwt` run must verify,
  trust-anchor, fetch status exactly once, record `STATUS_CHECKED`, and keep the
  trace redacted. `just auditor-no-phone-proof` now runs both runtime tests via
  the `encrypted_direct_post_runtime_` pattern.
- 2026-06-25: Added hostile encrypted runtime coverage for live revocation. The
  same generated trust-anchor/issuer setup now runs against the revoked
  status-list fixture and must return 422, record `STATUS_CHECKED` as bad,
  record `REJECTED`, remove the session encryption key, and keep the trace
  redacted. The runtime happy-path test also now asserts nested age-object
  disclosure accounting at the trace layer: the request is not over-asking, but
  the wallet response over-discloses five unrequested age thresholds, so the
  `OVER_ASK_ANALYZED` event is a warning with `overDisclosedCount: 5`.
- 2026-06-25: Extended evidence replay with the same safe nested-disclosure
  accounting when the captured request contains explicit DCQL claim paths. The
  exported evidence bundle now includes a redacted `OVER_ASK_ANALYZED` replay
  event for the synthetic age-only wallet proof: `requestedCount: 1` and
  `overDisclosedCount: 5`. Skeletal or non-parseable historical DCQL fixtures
  are skipped instead of failing export, so this remains an opportunistic
  auditor breadcrumb, not a new legal trust/status claim. `evidence assert-live`
  reports `walletOverDisclosureAnalyzed` separately while keeping
  `overAskAnalyzed`, `trustChecked`, and `statusChecked` reserved for explicit
  gates.
- 2026-06-25: Rehearsed the experiment branch against real iOS and Android
  sandbox wallets through `wallet.augenmass.tech`. iOS session
  `913aab78-18ca-4342-b183-18ef305c8d2c` reached `VERIFIED`; the wallet logs
  showed `PresentationSuccess` before a later wallet-side `Key mapping not
  found` UI issue. Android session `b601db78-60fe-485d-8ccd-2e01bd490956`
  reached `VERIFIED`, exported cleanly, and passed `evidence verify` plus
  strict `evidence assert-live`. The rehearsal exposed one evidence-retention
  edge case: a duplicate POST after a successful response could overwrite the
  canonical `direct-post.body` artifact. Unsafe-debug artifact writes are now
  append-only on filename collision, preserving the first canonical capture and
  suffixing later duplicates such as `direct-post-2.body`.
- 2026-06-25: Refreshed the committed plugin bundle binaries for `v0.3.0`
  across macOS Apple Silicon, macOS Intel, Linux x64, and Windows x64 after
  confirming stale target binaries could hide the newest phone-proof and
  trust/status behavior. The source-built CLI and refreshed plugin binaries pass
  strict `evidence assert-live` on the Android proof bundle and report
  `walletOverDisclosureAnalyzed`.
- 2026-06-25: Closed the follow-up audit findings before treating `v0.3.0` as
  shippable: URL-safe status-list `lst` values now remain URL-safe while
  padding is restored, array disclosures such as `nationalities` map to the
  modeled parent claim, live status rejects credentials without a status-list
  reference, `prove-trust-status` rejects mixed valid/invalid presentation
  bundles, and status-signer PEM parsing rejects ambiguous multi-certificate
  input.
