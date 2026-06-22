# Augenmaß Workbench

A swiss-army CLI and Claude Code skill for the EUDI Wallet ecosystem.

Augenmaß Workbench gives developers and auditors one tool to inspect, decode, audit over-ask, verify, generate, and repair EUDI artifacts: SD-JWT VC presentations, registration certificates, OpenID4VP requests and JARs, credential offers, status lists, and DCQL queries. It is built on a single engine (`augenmass-core`, reused as-is from the verifier project) and runs fully offline, the only exception being the registrar write path. Every read-only command takes `--json` so it drops cleanly into agents and CI.

It supersedes the v1 workbench (which had six commands: `generate`, `check`, `doctor`, `register`, `list`, `clone`) by surfacing the entire engine (verification, status, trust, disclosure, crypto) and adding net-new offline decoders behind one cohesive CLI.

## Install

Build from source with Cargo. The output binary is `augenmass`.

```sh
cargo build --release
./target/release/augenmass --help
```

The same tool also ships as a Claude Code plugin. The skill auto-triggers on EUDI registration and verifier-debugging work, and underneath it is the same plain CLI you can call directly.

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

## The toolbox

UNDERSTAND
- `inspect <input>`: sniff an artifact's type, then decode it ("what is this?").
- `decode {jwt | sd-jwt | regcert | request | offer | status-list} <input>`: decode a known artifact type, no signature verification.

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

WRITE (guard-railed)
- `register <body> --target {clone | sandbox} [--yes --force]`: write a registration under guardrails.
- `list --target --rp`: read registrations back for one relying party, decoded.
- `clone serve [--db --port]`: run the registrar-compatible local clone store.

## Over-ask and the legal basis

Over-ask is the central concern: a relying party must not request more personal data than its stated purpose needs. The same engine that audits the EUDI registry for over-asking helps a developer avoid over-asking when they register. Every over-ask finding cites the basis it rests on:

1. eIDAS Regulation (EU) 2024/1183, Art. 5b(3): "Relying parties shall not request users to provide data other than that indicated for their intended use."
2. GDPR (EU) 2016/679, Art. 5(1)(c): data minimisation, personal data must be "adequate, relevant and limited to what is necessary".
3. EUDI ARF, registration certificate, RPRC_07: the wallet verifies requested attributes are within the registration certificate and notifies the user otherwise.

The curated purpose baselines (`age_gate_18`, `event_checkin`, `car_rental`, `bank_kyc`) are taste judgments, not Rulebook derivations. See `augenmass baselines`.

## Safety

Writes are dry-run by default. `register` makes no network call until you pass `--yes`; if the body over-asks, it refuses (exit 1) unless you also pass `--force`. Blocking format errors are never written past.

There are two write targets. `clone` (the default) is a local registrar-compatible store (axum plus SQLite) with no signing, no auth, and no x5c: it holds payload-only JWTs and exists so you can rehearse the read and write paths entirely offline. `sandbox` is the real registrar behind Keycloak; it is rehearsal-only and off-stage. Configure both through environment variables (see `docs/SANDBOX.md` and `.env.example`).

Secrets hygiene is enforced: the tool never logs, echoes, or commits tokens, certificates, or keys, and `.env*`, `secrets*.md`, `*.sqlite`, and `*signing-key*` are gitignored.

## How it works

One engine is the spine. `augenmass-core` is a vendored, HTTP-free, pure-Rust crate carried over as-is from the verifier project: inspector (over-ask analysis, baselines, legal basis), regcert, pid, disclosure, verify (clock-injectable), status (fail-closed, offline), trust, and crypto. v1 used only inspector, regcert, and pid; v2 surfaces all of it behind one CLI. Because the engine is HTTP-free and the verification clock is injectable, every command except the registrar write path is offline and deterministic, which is what makes the committed fixtures reproducible in CI.

## Documentation

- `docs/ARCHITECTURE.md`: the one-engine spine and how the CLI wraps `augenmass-core`.
- `docs/COMMANDS.md`: every command, flag, exit code, and output shape.
- `docs/TOOLS.md`: the Claude Code plugin and skill.
- `docs/SANDBOX.md`: the clone store, the sandbox registrar, and their environment variables.
- The skill: `plugins/augenmass-workbench/skills/augenmass`.

## License

Apache-2.0.
