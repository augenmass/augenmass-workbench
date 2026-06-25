# Augenmaß Workbench: Architecture

This document describes how the Augenmaß Workbench is put together: the
engine/shell split, the engine module set, the CLI source map, the universal
`inspect` dispatch, the offline-vs-networked boundary, the agent/CI contracts
(`--json` and exit codes), what is reused versus net-new, and an honest scope
note. Every command shown here works as written against the built binary
(`augenmass` version 0.3.0). Identifiers use the slug `augenmass`; the display
name "Augenmaß" appears only in prose.

## The design: pure engine, thin shell

The Workbench is two crates with a hard boundary between them.

1. `augenmass-core` (vendored under `crates/augenmass-core/`) is the engine: a
   pure, deterministic, HTTP-free library. It decodes artifacts, analyzes
   over-asking, verifies signatures, evaluates revocation, and checks trust
   chains. It owns no argument parsing, no file reads, no sockets, and no
   terminal rendering. It has zero HTTP dependencies (no `reqwest`, `hyper`,
   `tokio`, `axum`, or `ureq`), so every cryptographic and proportionality
   decision it makes is reproducible from its inputs alone.

2. The `augenmass` binary (everything under `src/`, plus the `augenmass_workbench`
   library target) is the I/O shell: it parses arguments, reads files and stdin,
   talks to the network when an explicit target or serve command needs to, and
   renders results as either human text or JSON.

The reason for the split is testability and trust. The hard parts (does this
KB-JWT echo the right nonce? is index 42 revoked? does this leaf chain to that
anchor?) live where there is no clock you cannot inject, no network you cannot
see, and no global state. The messy parts (clap, the filesystem, Keycloak token
grants, axum) live in the shell where they belong. A reviewer can reason about
the engine as a function of its inputs and treat the shell as plumbing.

This boundary is also why the verification engine accepts an injectable clock:
the shell passes `--now` straight through to the engine's `_at`/`_full` entry
points, so expiry and freshness checks are deterministic in tests and in CI.

## The engine modules (`augenmass-core`)

The engine re-exports its public surface from
`crates/augenmass-core/src/lib.rs`. The modules:

- `inspector`: over-ask analysis (`analyze` returning an `OverAskReport`), the
  curated purpose `baselines`, and the verbatim `LEGAL_BASIS` text cited on
  every finding (eIDAS Art. 5b(3), GDPR Art. 5(1)(c), EUDI ARF RPRC_07). This is
  the proportionality core: the same logic audits a verifier's request and gates
  a relying party's own registration body.
- `regcert`: decodes a WRPRC registration certificate (typ `rc-wrp+jwt`),
  payload-only, no signature.
- `pid`: the German PID model and DCQL builders. `PID_VCT = "urn:eudi:pid:de:1"`
  and `PID_FORMAT = "dc+sd-jwt"` live here, so the rest of the tool defaults to
  the German PID without hard-coding strings.
- `disclosure`: resolves SD-JWT disclosures into the revealed claim view
  (`DisclosedClaim`, `RevealedView`).
- `verify`: SD-JWT VC plus KB-JWT verification (issuer signature, holder
  binding, nonce, audience, vct, freshness), with the clock-injectable
  `_at`/`_full` variants.
- `status`: token-status-list revocation. Fail-closed and offline: an
  unreadable or unverifiable status token is treated as not-cleared, not as
  cleared.
- `trust`: X.509 trust evaluation (`issuer_trusted`, `issuer_trusted_at`,
  `TrustAnchors`): does the leaf chain to a supplied anchor, inside its validity
  window.
- `crypto`: JWE decryption, `x5c` to JWK conversion, and the leaf certificate
  hash that is the `x509_hash` client_id binding.

v1 of the Workbench used only `inspector`, `regcert`, and `pid` (it was a
generate/check/doctor/register/list/clone tool). v2 surfaces the entire engine:
`disclosure`, `verify`, `status`, `trust`, and `crypto` are all now reachable
from the CLI, plus net-new offline decoders for the artifact types the engine
did not previously expose at the command line.

## The CLI source map (`src/`)

The shell is split into shared modules plus one file per command group.

```
augenmass-workbench/
  Cargo.toml                  bin: augenmass, lib: augenmass_workbench
  Cargo.lock
  crates/
    augenmass-core/           vendored engine (pure, HTTP-free)
      src/
        lib.rs                public re-exports
        inspector.rs          over-ask analyze + baselines + LEGAL_BASIS
        regcert.rs            WRPRC payload decode
        pid.rs                German PID model + DCQL builders
        disclosure.rs         SD-JWT disclosed claims
        verify.rs             SD-JWT VC + KB-JWT verification
        status.rs             token status list (fail-closed, offline)
        trust.rs              X.509 leaf chains-to-anchor
        crypto.rs             JWE decrypt, x5c to JWK, x509_hash
        error.rs              RejectKind, RejectReason, VerifyResult
  src/
    main.rs                   entry point
    lib.rs                    library wiring
    cli.rs                    clap command tree
    output.rs                 text-vs-JSON rendering switch (--json)
    config.rs                 env + target configuration
    jose.rs                   JOSE helpers shared across commands
    dcql.rs                   DCQL parsing/building shared helpers
    checkbody.rs              registration-body shape checks
    render.rs                 human-readable renderers
    artifact.rs               artifact type sniffing (inspect)
    x509util.rs               PEM/DER and certificate helpers
    http_target.rs            clone + cached-sandbox + sandbox target clients
    clone_server.rs           the local registrar-compatible store
    cache_server.rs           read-through cached-sandbox mirror
    generator.rs              regbody + DCQL generation
    commands/
      mod.rs
      inspect.rs   decode.rs   check.rs    audit.rs
      baselines.rs verify.rs   x509hash.rs generate.rs
      doctor.rs    register.rs clone.rs    cache.rs
  fixtures/                   committed offline test artifacts
  examples/                   min/over/bad-path/bad-request bodies
  tests/cli.rs                integration tests
  docs/                       this document and friends
  plugins/augenmass-workbench/ Claude Code/Codex plugin: skill + launcher + target binaries
  justfile  README.md  AGENTS.md  CHANGELOG.md  LICENSE  .env.example
```

The shared modules carry everything more than one command needs. `output.rs` is
the single place that decides text versus JSON. `http_target.rs` is the only
module that opens a socket for a write or read against a target. `artifact.rs`
is the brain behind `inspect`.

## The universal `inspect`

`inspect <input>` answers "what is this artifact?" and then decodes it, so a
developer can paste anything they found in a log or a redirect and get a reading.
Detection lives in `src/artifact.rs::sniff`, which tries, in order:

1. URIs first, by scheme prefix: `openid-credential-offer://` (a credential
   offer), then `openid4vp://`, `eudi-openid4vp://`, and `haip://` (an OpenID4VP
   request URI).
2. The `~` separator for an SD-JWT VC: if the input contains `~` and the part
   before the first `~` is a JWT, it is treated as an SD-JWT VC presentation.
3. ISO 18013-5 mdoc CBOR given as hex or base64/base64url.
4. A single compact JWT/JWS, branched first on the header `typ`
   (`rc-wrp+jwt`, `statuslist+jwt`, `kb+jwt`, `oauth-authz-req+jwt`), then on
   payload shape (for example, a payload carrying `response_type` is an
   authorization request).
5. A PEM block (an X.509 certificate).
6. JSON shape last: a parsed JSON document is classified by its fields (a
   `dcql_query` wrapper, a registrar body with `rpId`, a bare DCQL query, a
   URI-bearing object, or a generic JSON document).

This is heuristic but deterministic: the same input always sniffs to the same
kind, with no network lookup and no randomness. When detection guesses wrong, or
when you simply know the type, the explicit `decode <type> <input>` subcommands
are the bypass:

```
augenmass inspect fixtures/presentations/erica-vp-VALID.sdjwt
augenmass decode sd-jwt fixtures/presentations/erica-vp-VALID.sdjwt
```

Both decode the same artifact; `inspect` prints a `Detected:` line (to stderr,
so JSON on stdout stays clean) and then the same rendering as the matching
`decode`. None of this verifies a signature: `inspect` and `decode` are pure
reads. Signature, trust, and revocation checks are the job of `verify`.

Artifact inputs accept file paths, inline values, or `-` for stdin where the
command consumes an artifact directly, so `inspect`, `decode`, `check`,
`verify`, `x509-hash`, `doctor`, and `register` all compose with pipes.
`audit --request` accepts `minimal`, `overask`, a DCQL file, inline DCQL JSON, or
`-`; `--cert` is a file path.

## Offline versus networked

Almost everything runs fully offline. Decoding (`inspect`, `decode`),
proportionality (`check`, `audit`, `baselines`), all of `verify`, `x509-hash`,
`generate`, and `doctor` touch no network: they operate on the bytes you give
them and on the engine. The committed fixtures under `fixtures/` make every one
of those paths reproducible without any external service.

Only explicit live surfaces touch sockets or external services:

- `register --target sandbox` and `list --target sandbox`: the real registrar,
  reached over HTTP with a Keycloak token grant.
- `register --target clone` and `list --target clone`: a local
  registrar-compatible store (the default target), reached over a loopback HTTP
  socket.
- `clone serve`: runs that local store (axum plus SQLite).
- `list --target cached-sandbox`: reads a loopback cached-sandbox server.
- `cache serve`: runs the read-through cached-sandbox mirror and fetches public
  sandbox GET routes from its configured upstream.
- `serve`: runs the wallet-interaction debugger; with `--live-status`, it may
  fetch a credential status-list token under the SSRF guard.

The engine itself never opens a socket. All networking lives in the shell's
`http_target.rs`, `clone_server.rs`, `cache_server.rs`, and `serve/`.

## The `--json` contract (agents and CI)

The global `--json` flag is available on read-only commands and switches the
output from a human text rendering to machine-readable JSON on stdout. Any
incidental human chatter (the `inspect` `Detected:` line) goes to stderr, so a
consumer can pipe stdout straight into a parser:

```
augenmass inspect --json fixtures/presentations/erica-vp-VALID.sdjwt 2>/dev/null
```

returns a stable object beginning with an `artifact` discriminator
(`"sd-jwt-vc"`, and so on) followed by the decoded fields. This is the surface
the agent skill and CI scripts consume.

## The exit-code contract (CI gates)

Read-only commands that make a judgment exit non-zero on the bad outcome, so they
work as gates in a pipeline without parsing output:

- `check`: exit 1 on over-ask or a blocking format error; exit 0 if clean.
- `audit`: exit 1 on over-ask; exit 0 otherwise.
- `verify presentation`, `verify trust`, `verify status`, `verify status-list`:
  exit 1 if not verified, untrusted, revoked, or on error; exit 0 on success.
- `x509-hash --client-id`: exit 1 on mismatch.
- `doctor`: exit 1 if it has findings.
- `register`: refuses with exit 1 on over-ask without `--force`, and bails on
  blocking format errors.

Verified examples:

```
augenmass check examples/bad-path.json   ; echo $?   # 1
augenmass check examples/min.json        ; echo $?   # 0
augenmass verify presentation fixtures/presentations/erica-vp-VALID.sdjwt \
  --nonce b4ba2623-76a2-486b-a1f6-f1656025d07b \
  --aud https://self-issued.me/v2 --now 1780435200 ; echo $?   # 0
```

Writes are conservative by default: `register` is a dry-run until `--yes`, and
will not write past an over-ask warning without `--force`.

## Reuse versus net-new

Being honest about provenance: the engine and the fixtures are reused, not
written fresh for this Workbench.

- Reused: `augenmass-core` was lifted as-is from the EUDI verifier project. The
  fixtures under `fixtures/` (the ERICA presentations and trust anchors, the
  status lists and verify key, the eudiplo request/offer/DCQL samples, the
  registration certificate samples) also came from that project, with their
  binding values intact (nonce `b4ba2623-76a2-486b-a1f6-f1656025d07b`, audience
  `https://self-issued.me/v2`, verification clock `1780435200`, vct
  `urn:eudi:pid:de:1`).
- Net-new in this Workbench: the entire CLI shell under `src/`, the universal `inspect`
  sniffer, the offline `decode` subcommands for artifact types the engine had
  not previously exposed at a command line, the `--json` rendering layer, the
  exit-code contract, the local clone store, and the guard-railed write path.
  v1's three engine modules grew to the full engine surface plus this shell
  around it.

## Honest scope and limitations

- Trust is leaf-chains-to-anchor, not full path validation. `verify trust` and
  the trust check inside `verify presentation` confirm that the issuer leaf
  chains to a supplied anchor inside its validity window. They do not perform
  complete X.509 path validation (no revocation of intermediates, no policy or
  name-constraint processing, no full chain-building against a store).
- mdoc support is decode-only. `decode mdoc` reads ISO 18013-5 / `mso_mdoc`
  CBOR structures (DeviceResponse, Document, IssuerSigned, or MSO) and surfaces
  namespaces, data elements, issuerAuth metadata, X.509 chain information, and
  MSO shape. It does not verify the COSE_Sign1 signature or recompute value
  digests.
- The model is PID-centric. The defaults, the curated baselines, and the DCQL
  builders assume the German PID (`urn:eudi:pid:de:1`, format `dc+sd-jwt`). Other
  credential types can be inspected and decoded, but the proportionality
  baselines and generation defaults are PID-shaped. `audit` accepts a `--vct`
  override for other credential types, but the curated baselines themselves are
  PID claims.
- The baselines are curated taste judgments, not Rulebook derivations. The tool
  says so itself in `baselines` output. They encode a reasonable minimum per
  purpose, not a normative entitlement set.
