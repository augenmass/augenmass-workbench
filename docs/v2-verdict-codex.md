# Codex Verdict on the Augenmass Workbench v2 Effort

Date: 2026-06-23

## Executive Verdict

Use `/Users/bioharz/git/eudi-wallet-hackathon/augenmass-workbench-v2` as the canonical trunk.
Treat `/Users/bioharz/git/eudi-wallet-hackathon/augenmass-workbench-v2-codex` as the donor branch.
Treat `/Users/bioharz/git/eudi-wallet-hackathon/augenmass-workbench` as legacy.

The right next move is consolidation, not another separate feature branch.

Opus v2 has the better product spine: standalone Rust repo, vendored core, guarded registrar writes, mdoc decode, DCQL validation, a cleaner CLI shape, docs, plugin packaging, and a coherent verification gate.

Codex v2 has the better operational and evidence layer: safer live wallet debugging, per-session response encryption keys, redacted trace APIs, direct-post decrypt and verify tooling, request JWS verification, request profile readiness checks, SARIF, schemas, evidence capture, trace replay, audit bundles, ERICA helpers, and deeper phone-demo diagnostics.

The initial workbench remains valuable as the seed: it proved the guarded over-ask and registrar-write idea. But it is now too narrow for the ecosystem workbench the project actually needs.

## What The Initial Workbench Is

The initial workbench is a focused registration repair tool. Its core commands are:

- `generate`
- `check`
- `doctor`
- `register`
- `list`
- `clone serve`

Its strength is clarity. It has a simple and coherent promise: generate a proportionate registration body, check it for over-ask and format mistakes, then write it only under guardrails.

Its weaknesses are now structural:

- no live wallet interaction debugger,
- no presentation verification command surface,
- no status or trust diagnostic surface,
- no evidence manifest or replay layer,
- no SARIF or schema contract layer,
- thin test coverage compared with the v2 repos.

Verdict: keep the concept and guardrail semantics, but do not continue from this repo as the main line.

## What Opus v2 Created

Opus v2 expanded the initial workbench into a real standalone Rust CLI while preserving the original write path.

The important strengths:

- standalone build through vendored `augenmass-core`,
- guarded registrar writes still exist,
- local registrar clone still exists,
- real SD-JWT VC presentation verification via the shared core,
- trust and status verification surfaces,
- `serve` as a live verifier-in-a-box for real wallet interactions,
- mdoc / ISO 18013-5 decode,
- semantic DCQL validation,
- strong docs and plugin packaging,
- a serious `just verify` recipe.

The main weakness is in the live wallet debugger safety model:

- trace data can expose raw wallet POST body material,
- decrypted authorization response detail is recorded directly,
- one response encryption key is reused rather than generated per authorization request.

That is not a minor concern. For a real phone-wallet demo with PID-bearing material, Opus v2 must inherit Codex's safer tracing model before becoming the final public demo tool.

Verdict: Opus v2 is the best trunk, but it needs Codex's operational hardening.

## What Codex v2 Created

Codex v2 built a broader operator, auditor, and agent workbench around the EUDI wallet flow.

The important strengths:

- `serve` uses per-session response encryption keys,
- `/api/trace/:id` is redacted by default,
- plaintext `direct_post` is rejected for the encrypted response profile,
- unsafe debug artifacts are opt-in and local,
- trace capture and replay exist,
- direct-post inspect, decrypt, verify, and summarize flows exist,
- request JWS verification exists,
- request profile checks exist for German sandbox, HAIP, and DC API lanes,
- wallet preflight and phone-check commands exist,
- SARIF output exists,
- command catalog and JSON schemas exist,
- evidence capture and manifest verification exist,
- ERICA helper commands exist,
- WRPRC trust diagnostics and status-list inspection exist.

The important weaknesses:

- it depends on sibling `../verifier/verifier-core`, so it is not standalone,
- it does not implement registrar writes,
- its over-ask logic is more local-rule oriented while heavier crypto delegates outward,
- its command surface is powerful but sprawling.

Verdict: Codex v2 is the best donor for safety, evidence, CI, agent contracts, and wallet-demo diagnostics.

## Comparison

The initial workbench is the prototype.

Opus v2 is the best product trunk.

Codex v2 is the best operational donor.

Both v2 repos are real expansions, not README-only work. But keeping both as separate final tools would split attention and confuse users. The ecosystem needs one serious tool: standalone like Opus, safe and evidence-oriented like Codex.

## Recommended Next Goal

Make `/Users/bioharz/git/eudi-wallet-hackathon/augenmass-workbench-v2` the unified standalone Rust workbench by porting the high-leverage Codex pieces into it.

Priority order:

1. Port Codex's `serve` safety model:
   - per-session response encryption keys,
   - redacted trace API,
   - plaintext `direct_post` rejection,
   - explicit unsafe local debug artifact mode.

2. Port Codex's evidence layer:
   - evidence capture,
   - manifest verification,
   - wallet trace capture,
   - wallet trace replay,
   - unsafe wallet trace audit bundle replay.

3. Port Codex's request and phone-demo preflight layer:
   - request JWS verification,
   - request profile checks,
   - wallet URI inspection,
   - wallet flow preflight,
   - wallet phone-check.

4. Port Codex's agent and CI contracts:
   - command catalog,
   - JSON schemas,
   - SARIF output,
   - stable machine-readable error envelopes.

5. Only then continue new frontier work:
   - ITB export,
   - OpenID4VCI metadata inspection,
   - trust-list parsing,
   - mdoc cryptographic verification,
   - PE-to-DCQL conversion.

## Bottom Line

Do not keep building two separate v2s.

Promote Opus v2.
Mine Codex v2.
Retire the initial workbench as the historical seed.

The winning workbench is:

- standalone,
- Rust-only,
- write-capable,
- live-wallet capable,
- privacy-safe by default,
- evidence-producing,
- schema-backed,
- CI-friendly,
- agent-friendly,
- honest about what it verifies and what it only decodes.

