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
- Any stage claim that `--trust-anchor --live-status` works against the current
  sandbox wallet credential.

## Checkpoints

- 2026-06-25: Created isolated experiment branch/worktree and log.
