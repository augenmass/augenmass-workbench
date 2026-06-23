# AGENTS.md

Guidance for AI agents and human contributors working in the Augenmaß Workbench repository. Read this before you touch anything. The repo root is `augenmass-workbench`; all paths below are relative to it.

## What this repository is

Augenmaß Workbench is a developer and auditor toolkit for the EUDI (European Digital Identity) Wallet ecosystem, shipped as a single Rust binary named `augenmass` plus a Claude Code skill. It decodes and inspects every common artifact (SD-JWT VC presentations, ISO 18013-5 mdoc credentials, registration certificates, OpenID4VP authorization requests and signed JARs, credential offers, token status lists, DCQL queries, X.509 certificates), audits requests for over-asking against curated purpose baselines and the legal basis, verifies presentations cryptographically, and writes registrations under guardrails. Static artifact commands run fully offline. Network behavior is explicit and lives in the shell: registrar targets, the cache server, and `serve`.

The product name "Augenmaß" (sense of proportion) is the whole point: the tool helps relying parties ask for exactly the personal data they need, no more.

## One engine, two surfaces

There is one engine (the spine) and two surfaces over it. The same proportionality logic that audits a registry for over-asking also helps a developer avoid over-asking when they register. The engine is the vendored `augenmass-core` crate. The CLI shell (`src/`) surfaces the engine plus net-new offline decoders behind one cohesive command set, with `--json` output on read-only commands for agents and CI.

v1 was "audit, debug, repair" with six commands. v2 surfaces the entire `augenmass-core` engine (verification, status, trust, disclosure, crypto) and adds offline decoders for the rest of the ecosystem's artifacts. The website and audit-board are out of scope for this repository.

## House style (mandatory)

These rules are enforced. Violations are defects. They apply to code comments, commit messages, documentation, the skill, and any prose you generate.

- No emojis anywhere.
- No dashes as clause separators. Forbidden: en-dash, em-dash, double-hyphen, and a hyphen used between clauses. Use commas, periods, colons, parentheses, or semicolons instead. Hyphens inside compound words (over-ask, dc+sd-jwt, x509_hash, age-over-18) are fine.
- No markdown blockquotes (the `>` syntax).
- No wall-clock time estimates. If you must size effort, use small, medium, large, or XL; never hours, days, or weeks.
- The display name is "Augenmaß" (with ß) for prose and titles only. Every technical identifier uses the slug "augenmass" (ss), never ß: the repo, the crate, the binary, the command, every path.
- Swiss Standard German orthography in any German text: ss never ß, except the display name Augenmaß.
- Be direct, factual, and concise. Keep American or British English consistent within a single file.

## Build and test

The binary builds at `./target/debug/augenmass`. Run it to verify any claim.

```
cargo build
cargo test
```

`cargo test` runs unit tests plus integration suites that drive the real binary against the committed fixtures. At this writing, that includes 45 unit tests under `src/` and `crates/`, 43 CLI integration tests, 5 demo-proof integration tests, 8 cache integration tests, and 1 serve integration test. There is a `just verify` convenience target that wraps the build, the test run, and smoke checks; `cargo build` and `cargo test` are the canonical path and always work.

For presentation and skill wording changes, run the focused proof gate too:

```
just demo-proof
```

It pins the stable offline demo path described in `docs/DEMO_PROOF.md`.

For install or release wording changes, run:

```
just install-smoke
just release-archive-smoke
just docker-release-archive-smoke-linux
```

They prove a fresh source install into an isolated local root and an extracted
release archive that carries its own docs, examples, and fixtures. The Docker
gate proves the Linux arm64 and amd64 release archives inside matching Linux
containers without spending runner credits.

When in doubt about command behavior, do not guess. Run the binary:

```
./target/debug/augenmass --help
./target/debug/augenmass baselines
./target/debug/augenmass inspect fixtures/presentations/erica-vp-VALID.sdjwt
```

## Layout

- `Cargo.toml`: declares the binary `augenmass` and the library `augenmass_workbench`.
- `crates/augenmass-core/`: the vendored engine. See the rules below before editing.
- `src/main.rs`, `src/lib.rs`, `src/cli.rs`: entry point, library surface, and clap command tree.
- `src/commands/`: one module per command (`inspect`, `decode`, `check`, `audit`, `baselines`, `verify`, `x509hash`, `generate`, `doctor`, `register`, `clone`, `cache`, plus `mod.rs`). Add or change command behavior here.
- `src/` supporting modules: `output.rs` (text and `--json` rendering), `config.rs` (env and targets), `jose.rs`, `dcql.rs`, `checkbody.rs`, `render.rs`, `artifact.rs` (the `inspect` sniffer and dispatch), `x509util.rs`, `http_target.rs`, `clone_server.rs` (the local registrar clone), `cache_server.rs` (the read-through cached-sandbox mirror), `generator.rs`.
- `tests/`: integration tests for the CLI, cache server, and serve debugger.
- `scripts/`: local smoke gates wrapped by `just`, no Python and no remote CI.
- `fixtures/`: committed offline test artifacts (see below).
- `examples/`: sample registration bodies and requests (`min.json`, `over.json`, `bad-path.json`, `bad-request.json`).
- `docs/`: documentation.
  - `docs/DEPLOYMENT.md`: cache backend deployment notes for Railway, Docker, VPS, Cloudflare, and Vercel.
  - `docs/RELEASE.md`: CI, release archives, and platform support.
- `plugins/augenmass-workbench/skills/`: the Claude Code skill plus its bundled binary.
- `LICENSE` (Apache-2.0), `README.md`, `CHANGELOG.md`, `.env.example`, `.gitignore`.

### Command surface (for orientation)

UNDERSTAND: `inspect <input>`, `decode {jwt|sd-jwt|regcert|request|offer|status-list|mdoc} <input>`.
PROPORTIONALITY: `check <body>`, `audit --request {minimal|overask|FILE} --purpose <id> [--cert FILE]`, `baselines [<id>]`.
CRYPTO: `verify {presentation|trust|status|status-list}`, `x509-hash <input> [--client-id]`.
PRODUCE: `generate {regbody|dcql}`.
DIAGNOSE: `doctor <request>`, `validate dcql <input>`.
DEBUG: `serve`.
EVIDENCE: `evidence {export|verify|replay}`.
WRITE AND TARGETS (guard-railed): `register <body> --target {clone|cached-sandbox|sandbox} [--yes --force]`, `list --target --rp`, `clone serve`, `cache serve`, `cache warm`.

Input ergonomics: every artifact argument accepts a file path, an inline value, or `-` for stdin. Keep this contract when you add commands.

Exit codes: commands exit non-zero on the bad outcome so they work in CI. `check` and `audit` exit 1 on over-ask (or, for `check`, a blocking format error); the `verify` family exits 1 when not verified, untrusted, revoked, or on error; `x509-hash --client-id` exits 1 on mismatch; `doctor` exits 1 when it has findings; `register` exits 1 when it refuses an over-ask without `--force`. Preserve these semantics.

## Safety rules for the write path

`register` is the only command that mutates registrar data, and it is guard-railed by design:

- Writes are dry-run by default. `--yes` is required to actually write. `--force` is required to write past an over-ask warning, and `--force` requires `--yes`.
- Three target modes: `clone` (default) is a local registrar-compatible store (axum plus SQLite) with no signing, no auth, and no x5c; it stores payload-only JWTs. `cached-sandbox` is a read-only mirror for public sandbox GET routes, local by default and deployable with an explicit `--host`, persistent `--db`, and optional admin token. `sandbox` is the real registrar behind Keycloak OAuth, for off-stage rehearsal only.
- One relying party per entity, many certificates. Our relying party is "Hackathon - Reza", id `2af138a8-59ea-4a84-aea3-666cafdb1369`. Write only under it; never mint extra relying parties.
- The clone is sound because every read path decodes payload-only and there is no client-side crypto on either path. Do not add signing or token handling to the clone.

When you change `register`, `clone_server.rs`, `cache_server.rs`, or `http_target.rs`, keep the dry-run default and the over-ask gate intact. Loosening either is a defect.

## Secrets

- Never log, echo, print, or commit tokens, certificates, or private keys.
- The following are gitignored and must stay that way: `.env` and `.env.*` (except `.env.example`), `secrets*.md`, `*.sqlite`, and `*signing-key*`. Only the public verify key is a committed fixture; private signing keys never enter the repo.
- Sandbox credentials come from the environment (`AUGENMASS_API_BASE`, `AUGENMASS_OIDC_TOKEN_URL`, `AUGENMASS_USERNAME`, `AUGENMASS_PASSWORD`, optional `AUGENMASS_OIDC_CLIENT_SECRET`); the clone uses `AUGENMASS_CLONE_API_BASE`; cached-sandbox uses `AUGENMASS_CACHE_API_BASE`. Read `.env.example` for the shape. Never bake real values into code, tests, or docs.

## Documentation and the skill must match the shipped binary

The `--help` output, the README, the docs under `docs/`, and the Claude Code skill under `plugins/augenmass-workbench/skills/` describe the behavior the binary actually has. They are not allowed to drift.

When you change a command, a flag, an exit code, or an output shape:

1. Update `src/cli.rs` and the relevant command module.
2. Update the README, the affected docs, and the skill in the same change.
3. Verify against the real binary, not from memory: run `./target/debug/augenmass <command> --help` and run the command on a fixture. The text you put in docs must be producible by the binary as written.

Every command shown in any document must work exactly as written. If you cannot run it and see the output, do not document it.

## The engine (augenmass-core) is vendored, keep it minimal and pure

`crates/augenmass-core/` was reused as-is from the verifier project. Its modules are `inspector` (over-ask analysis, baselines, `LEGAL_BASIS`), `regcert`, `pid` (German PID model and DCQL builders; `PID_VCT = "urn:eudi:pid:de:1"`, `PID_FORMAT = "dc+sd-jwt"`), `disclosure`, `verify` (SD-JWT VC and KB-JWT verification with an injectable clock), `status` (token status list revocation, fail-closed, offline), `trust` (X.509 leaf chains-to-anchor plus validity window, not full path validation), and `crypto` (JWE decrypt, x5c to JWK, `leaf_cert_hash` = x509_hash).

Rules for the engine:

- The engine is HTTP-free and pure. It performs no I/O: no network, no filesystem, no environment reads, no printing. All I/O lives in the CLI shell under `src/`.
- Keep changes here minimal. Prefer adding logic in `src/` and calling the engine, rather than editing the engine. v1 used only `inspector`, `regcert`, and `pid`; v2 surfaces the rest. The shape is intentionally stable.
- If a change genuinely belongs in the engine, keep it pure: take inputs, return values or typed errors, leave clock and key material injectable (as `verify` already does with its clock-injectable entry points). Do not introduce side effects to make a feature easier.

## Proportionality: the legal basis (cite verbatim)

Over-ask findings cite three sources, sourced from the engine's `LEGAL_BASIS`. Cite them verbatim; do not paraphrase or invent legal text.

1. eIDAS Regulation (EU) 2024/1183, Art. 5b(3): "Relying parties shall not request users to provide data other than that indicated for their intended use."
2. GDPR (EU) 2016/679, Art. 5(1)(c): data minimisation ("adequate, relevant and limited to what is necessary").
3. EUDI ARF, registration certificate, RPRC_07: the wallet verifies requested attributes are within the registration certificate and notifies the user otherwise.

The curated purpose baselines (`age_gate_18`, `event_checkin`, `car_rental`, `bank_kyc`) are taste judgments, not Rulebook derivations. Run `augenmass baselines` for the current set; do not hard-code a stale copy elsewhere.

## Gotchas the tool catches (keep them caught)

The value of `check`, `doctor`, and `x509-hash` is catching the traps below. If you touch `checkbody.rs`, `doctor.rs`, or `x509util.rs`, do not regress these checks.

Registration body (caught by `check`):

- `claims[].path` must be an array of segments, not a string (`["age_equal_or_over","18"]`, not `"age_equal_or_over.18"`).
- Use `credentials`, not `provided_attestations`, for requested claims.
- `purpose` is a list of `{lang, content}`, not a bare string.
- `privacy_policy` must be a valid URL.
- `support_uri` is any non-empty contact string (email, phone, or URL); do not over-validate it as a URL.

Signed request / JAR (caught by `doctor`, a different document):

- `x5c` must be a list of strings, even for a single certificate.
- `client_id` must be `x509_hash:<base64url(SHA-256(leaf-cert-DER))>`. Compute it with `augenmass x509-hash`.
- Set `Content-Type: application/json` on every POST.

Ecosystem traps worth keeping in mind: VCT can be a URN (`urn:eudi:pid:de:1`), not a URL; the sandbox wallet supports only `client_id_scheme` `x509_hash` (not `x509_san_dns`); base64url-no-pad versus base64-standard matters for x5c and hashes; mdoc claim paths are 2-element `[namespace, element]` while SD-JWT paths are nested arrays.

## Fixtures

Fixtures under `fixtures/` are offline and committed, with stable binding values used across the tests and docs. The shared binding is nonce `b4ba2623-76a2-486b-a1f6-f1656025d07b`, aud `https://self-issued.me/v2`, verification clock `--now 1780435200`, vct `urn:eudi:pid:de:1`. ERICA's leaf chains to `fixtures/certs/erica-trust-anchor.pem`. The status list has 256 entries, 1 bit each, with index 42 revoked in the REVOKED token. `fixtures/certs/access-leaf.pem` has x509_hash `VE3qp3vLVkU8JyVmXkjL7CSDVxVoTFdTv5fAEwmjKOI`. When you add or change a fixture, keep these binding values consistent with the tests, or update the tests in the same change.

## License

Apache-2.0. Open source, developer-tools framing.
