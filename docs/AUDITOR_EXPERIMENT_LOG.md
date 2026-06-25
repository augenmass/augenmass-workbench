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
