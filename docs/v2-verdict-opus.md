# Verdict: augenmass-workbench V1 vs v2 (mine) vs v2-codex

Author: Claude Opus 4.8
Date: 2026-06-23
Mode: read-only critical evaluation

## How this verdict was produced

Six agents ran read-only. Three inventoried each build and separated authored
code from the vendored crypto engine and from any harvested third-party repos.
Two hostile auditors actually built and ran each binary against its committed
fixtures, to test whether the bold capability claims hold rather than trusting
the README. One comparator wrote the head-to-head. The auditors caught and
corrected two errors made during the inventory phase (codex's
`fixtures/regcert/rc-by-id.json` is 6,410 bytes of valid JSON, not empty; codex's
registrar path is fully absent, not a stub). Every number below is one I
verified directly: line counts, a byte-identical `diff -q` of the engine, test
runs, path dependencies, and fixture sizes.

The three builds live at:

- V1 baseline: `/Users/bioharz/git/eudi-wallet-hackathon/augenmass-workbench`
- Mine (v2): `/Users/bioharz/git/eudi-wallet-hackathon/augenmass-workbench-v2`
- Codex (v2): `/Users/bioharz/git/eudi-wallet-hackathon/augenmass-workbench-v2-codex`
- Shared crypto engine: `/Users/bioharz/git/eudi-wallet-hackathon/verifier/verifier-core/src`

## The three builds, verified

| | V1 `augenmass-workbench` | mine `-v2` | codex `-v2-codex` |
|---|---|---|---|
| authored src lines | ~1,142 | 6,203 | 14,192 |
| authored test lines | ~70 | 662 | 2,944 |
| subcommands | 6 | 18 | 24+ (many nested) |
| tests (all green) | 6 | 61 | 75 |
| crypto engine | vendored, never called | vendored in-tree, wired in | PATH dep to sibling repo |
| self-contained | yes | yes | no |
| grade | (baseline) | A- | A- |

The 1,629-line crypto engine is byte-identical across all three (confirmed by
`diff -q`). It is excluded from every "authored" number above, because none of
the three builds wrote it; it comes from the verifier project.

## What each build delivered beyond V1

V1 was small and honest, but its headline crypto was dead code. It vendored the
verifier engine and the binary never called it (zero grep hits for `verify_pid`,
`decrypt_jwe`, `check_status`). V1 verified nothing cryptographically, and its
local clone minted unsigned `alg:none` tokens with a literal `fixture` signature.
Its real value was the over-ask / data-minimisation engine plus a guard-railed
registrar write path and a local SQLite clone.

Mine (v2) turned the dead engine into a working tool. SD-JWT VC / KB-JWT
signature verification, status-list revocation, trust anchoring, x509_hash, and
JWE decrypt are now reachable from the CLI and empirically fail closed. A
one-character tamper of the issuer signature flips VALID to an `IssuerSignature`
rejection (the auditor reproduced this and matched x509_hash against an
independent Python SHA-256). Added: a real CBOR ISO 18013-5 mdoc decoder
(decode-only), a `serve` verifier-in-a-box with per-session tracing, and DCQL
semantic validation. Kept the engine vendored in-tree, so it builds standalone.
Grew from 6 to 18 subcommands and 6 to 61 tests.

Codex did the same crypto wiring, then went much wider: a full wallet-flow
debugging suite (phone-check, flow preflight, trace ingest/replay/audit-bundle,
direct-post decrypt/verify), evidence capture with SHA-256 tamper-check
manifests, 27 JSON Schemas with a test that asserts committed schemas equal live
CLI output, SARIF output, a formal agent contract (stdout=data,
stderr=diagnostics, exit codes 0/2/3), ERICA payload prep, ops diagnostics, and
request-object ES256+x5c verification. But it dropped the registrar write path
entirely, and left both the crypto engine and all crypto fixtures outside its own
tree.

## Head-to-head

| Dimension | Winner | Note |
|---|---|---|
| Authored capability (src + tests) | Codex | 2.3x src and 4.4x test code, and it buys more working surfaces, not just lines |
| Crypto verify depth | Tie | The same byte-identical engine; both fail closed under tamper |
| Live wallet debugging | Codex | Both have a real serve; codex adds the whole wallet-side suite |
| Decode breadth | Codex (narrow) | Both decode mdoc; codex covers more request/offer/URI kinds |
| DCQL / validation | Codex (narrow) | My dedicated `validate` is clean; codex's schema-conformance gate is a stronger guarantee |
| Registrar write path | Mine | Codex removed it entirely |
| Self-containment | Mine (decisive) | Codex cannot build or test crypto in isolation |
| Security posture | Codex (narrow) | Mine carries the one confirmed medium bug; see below |
| Docs honesty | Tie | Both honesty sections survived the hostile audit |

## The most important weakness of each

Mine (v2): a genuine medium-severity SSRF in the `--live-status` fetch. It vets
resolved IPs at `src/serve/state.rs:121`, then hands the hostname to reqwest,
which re-resolves independently at connect time (`:139`) with no IP pinning. That
is a classic DNS-rebinding / TOCTOU window. It is partially mitigated (https-only,
redirects disabled, fetched only after issuer verify and trust pass), but it is
the one confirmed exploitable bug across either v2 build. Everything else v2 is
dinged for (mdoc decode-only, partial trust, no JAR signature verify) is honestly
disclosed scope, not a defect.

Codex: non-self-containment. For a tool whose headline is real crypto
verification, shipping a tree where the engine (`Cargo.toml:45` PATH dep to
`../verifier/verifier-core`) and every crypto fixture
(`../verifier/fixtures/oracle`) live in a sibling repo is the most serious
structural flaw. Move that directory and the crypto vanishes.

## Bottom line

Both v2 builds unambiguously surpassed V1. They took an engine V1 left dead and
made it actually verify and fail closed, without overclaiming. That is real
progress, not relabeled vendoring.

Between the two, codex is the stronger build. On authored capability the gap is
not close, and the hostile audit confirmed codex's extra surfaces actually run.
The crypto both tools lead with is the same engine, so neither can claim crypto
superiority. My v2 wins on exactly two things, and they are not trivial: it
stands alone, and it kept the registrar write path codex discarded. But my v2 is
the smaller build, it did not out-engineer codex on authored scope, and its
differentiating crypto layer is inherited byte-identical, not authored here. It
also carries the only confirmed medium security bug between them.

If breadth of real authored capability and a clean agent-facing contract are the
priority, codex wins. If a repo that stands alone and writes registrations end to
end is the priority, my v2 wins. Both honestly earn an A-.

## Highest-value follow-up for our build

Fix the SSRF: pin reqwest to the vetted IP via a custom resolver instead of
letting it re-resolve the hostname, and normalize IPv4-mapped IPv6 addresses in
the deny list. This closes the one real bug standing between v2 and an
unqualified A. It is a small, well-scoped change.
