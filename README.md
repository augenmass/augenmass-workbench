# Augenmaß Workbench

An agent skill for the EUDI Wallet ecosystem, with a Rust CLI underneath it.

Install the skill, then ask in plain language. Augenmaß Workbench understands EUDI Wallet work, so you can say "is this registration over-asking?", "generate a proportionate age check", or "why is my wallet rejecting this request?", and it does the work: it reads the artifact, screens it against protocol rules and curated purpose baselines grounded in the cited legal basis for data minimisation, and tells you what to fix. The skill drives a single Rust binary (`augenmass`), so every answer is something you can also run yourself, script, or drop into CI.

Augenmaß is German for a trained sense of proportion: judging the right amount by eye. That is the whole point. The tool helps a relying party ask for exactly the personal data its purpose needs, and no more.

One engine, two surfaces. The same proportionality engine that audits the public EUDI registry at augenmass.tech runs locally here, so you can catch an over-ask on your own machine before you ever register it.

The hackathon version was a light tool with six commands (`generate`, `check`, `doctor`, `register`, `list`, `clone`). This version surfaces the entire engine (verification, status, trust, disclosure, crypto), adds offline decoders for the rest of the ecosystem's artifacts, ships a live wallet debugger, and gives presenters a hosted relay/cache path for real-phone demos.

## Current release shape

The current branch is the `v0.3.0` EUDI On presentation release, not a README-only prototype. In the last proof pass, the workbench gained:

- A platform-aware Claude Code/Codex plugin bundle with native launcher targets for macOS Apple Silicon, macOS Intel, Linux x64, and Windows x64.
- Published `v0.2.0` release archives with checksums and provenance manifests for the main desktop targets.
- Current `v0.3.0` line for live wallet proof, hosted relay, evidence replay, and the presentation-ready plugin bundle across macOS, Linux, and Windows targets.
- A stapled Apple Silicon macOS `.pkg`, signed by Developer ID Installer and accepted by Gatekeeper as `source=Notarized Developer ID`.
- A deployed cached-sandbox backend at `https://cache.augenmass.tech/api` for stable public sandbox reads and demo prewarming.
- A deployed wallet-only relay at `https://wallet.augenmass.tech`, proven with `just hosted-relay-proof`, so a phone wallet can reach `augenmass serve` without exposing trace, inspect, evidence, or unsafe debug artifacts publicly. The hosted relay is protected; operators configure the token through `AUGENMASS_RELAY_TOKEN`.

The strongest demo path is still skill first, CLI underneath: ask the agent what an artifact is, have it run the Rust tool, show the over-ask finding with the legal basis, then switch to `serve --relay augenmass` for the real wallet exchange.

## Install the skill

This repository is public and Apache-2.0 licensed. There is no curated public
Claude Code marketplace listing yet, so install the skill/plugin from this
repository itself, in Claude Code or Codex. The first experience should be a
conversation with the skill, not a terminal manual.

```
/plugin marketplace add augenmass/augenmass-workbench
/plugin install augenmass-workbench@augenmass
```

For Codex, this repository now includes a local marketplace and Codex plugin
manifest:

```sh
codex plugin marketplace add .
codex plugin add augenmass-workbench@augenmass
```

Both commands install directly from this public repository: the Claude Code path
adds the marketplace by its public repo reference; the Codex commands install
from the checked-out local repository. The only piece not yet in place is a
curated public Claude Code marketplace listing.

## First run in an agent

Start with prompts that do not require a repository checkout:

| Audience | Prompt | Expected outcome |
| --- | --- | --- |
| Developer | `Use the augenmass skill: show the purpose baselines, generate a proportionate age-check body, and check it.` | The agent runs no-file commands, explains the generated minimal body, and confirms it passes the over-ask gate. |
| Auditor | `Use the augenmass skill: explain why a full birthdate is too much for an over-18 check, and cite the basis.` | The agent explains the proportionality concern, cites the data-minimisation basis, and proposes `age_equal_or_over.18`. |
| Non-technical reviewer | `Use the augenmass skill: in plain language, what should an age-check service ask for and what should it avoid?` | The agent avoids JSON detail, names the unnecessary data, explains the risk, and gives the safer replacement. |
| Live demo | `Use the augenmass skill: prepare a safe live wallet debug run with redacted traces.` | The agent explains `serve --relay augenmass`, the wallet-only public relay, trust/status caveats, and why raw debug artifacts are opt-in only. |

When the plugin was installed from a marketplace without the full repository checkout, use no-file prompts like these. Fixture prompts such as `inspect fixtures/requests/eudiplo-request.jwt` are for full checkouts or release archives that include `fixtures/` and `examples/`.

## CLI and bundled launcher

The plugin includes a small launcher plus native `v0.3.0` target binaries for macOS Apple Silicon, macOS Intel, Linux x64, and Windows x64. The skill resolves `AUGENMASS_BIN` first; otherwise it uses the bundled launcher and picks the matching target binary. Set `AUGENMASS_BIN` when you want to override the bundled binary, use an unsupported target, or point the skill at a source-built binary.

For the polished macOS Apple Silicon install path, use the stapled `.pkg`
produced by `just macos-pkg-notarize`; the current local proof validates the
package signature, stapling, and Gatekeeper install assessment. ZIP archives can
be accepted by Apple's notary service without being stapled, so treat the `.pkg`
as the offline-verifiable macOS installer. Windows binaries are not code-signed
yet; verify the release checksum first, then approve the binary manually through
the OS security UI, or build from source with `cargo build --release --locked`
and set `AUGENMASS_BIN`.

The skill is a thin layer over a plain CLI you can also build and run on its own, with or without an agent. On Unix-like shells:

```sh
cargo build --release --locked
./target/release/augenmass --help
```

On Windows PowerShell:

```powershell
cargo build --release --locked
.\target\release\augenmass.exe --help
```

For a local source install into your own bin directory:

```sh
cargo install --locked --path . --bin augenmass --root "$HOME/.local"
"$HOME/.local/bin/augenmass" --help
```

The binaries that ship inside the plugin come from the same release archives as the standalone CLI. Use a bare `augenmass` only when your session or shell has a compatible binary on PATH.

## Ask it like this

The skill is the front door. You talk to it the way you would talk to a colleague who knows the EUDI ecosystem cold; it picks the right command, runs it, and explains the result, citing the legal basis when a finding turns on it.

- "Is this registration over-asking?" It runs the over-ask engine and returns a per-claim diff: which requested claims exceed the stated purpose, and the basis (eIDAS Art. 5b(3), GDPR Art. 5(1)(c), EUDI ARF RPRC_07).
- "Generate a proportionate age-check body." You get only the over-18 attribute, never a raw birthdate.
- "Register it, but refuse if it over-asks." It dry-runs first and writes only on your explicit go-ahead, and it will not write past an over-ask unless you force it.
- "What is this token?" It sniffs the artifact and decodes it: an SD-JWT VC presentation, a JAR, a credential offer, an mdoc, a status list.
- "Why is the wallet rejecting my request?" It diagnoses the signed request (x5c shape, the x509_hash client_id binding, content type).
- "Run a verifier so I can test with a real wallet, and show me every step." It starts `augenmass serve`; for a phone that needs a public HTTPS callback, it can add `--relay augenmass` so only the wallet request/response endpoints are reachable through `wallet.augenmass.tech`, while trace and evidence stay local.
- "Explain this finding for someone non-technical." It restates the over-ask in plain language and ties it to the data-minimisation basis it rests on.

For example, a privacy reviewer should not have to read JSON first. The skill
can answer: "This age-check registration asks for the person's full birthdate,
name, address, and nationality. For an over-18 check, that is more information
than the stated purpose needs. Ask only for `age_equal_or_over.18`; it proves the
same thing without exposing a birthdate or identity details."

See `docs/ASK-IT-LIKE-THIS.md` for more, `docs/EXPLAINER.md` for the
plain-language version of what over-ask is and why it matters, and
`docs/SANDBOX.md` for the mode matrix that explains offline, clone,
cached-sandbox, live sandbox, deployed cache, and wallet-debugger workflows.

## Use it as a guardrail

Finding an over-ask once is good; never shipping one is better. Because the judgment commands exit non-zero on a bad outcome, the same engine works as a pre-commit hook or a CI gate, so an over-ask fails the build instead of reaching the registrar.

```sh
# pre-commit: refuse to commit a registration body that over-asks
augenmass check registration.json
```

```yaml
# CI: gate the pipeline on proportionality and a well-formed DCQL query
- run: augenmass check registration.json
- run: augenmass validate dcql request.json
```

See `docs/GUARDRAILS.md` for hook and pipeline recipes. The point of the skill is not only to fix an over-ask after the fact, but to give an agent enough context to prevent the next one.

## The CLI underneath

Everything the skill does, it does by running these commands, so you can run them yourself. Artifact inputs accept file paths, inline values, or `-` for stdin; `audit --request` accepts `minimal`, `overask`, a DCQL file, inline DCQL JSON, or `-`. Read-only commands accept `--json` where they render machine output. The examples below use committed fixtures under `fixtures/`; run them with the plugin launcher, a release archive, or a local build such as `./target/release/augenmass` (`.\target\release\augenmass.exe` on Windows).

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

Debug a live wallet interaction: run a local verifier, scan the QR with a real
EUDI wallet, and watch every step of the exchange in the terminal and the
browser. For a physical phone, use the hosted wallet-only relay so the phone can
reach the request and response endpoints over HTTPS while the debug UI remains
on localhost:

For the exact capture/export/proof checklist, use
`docs/PHONE_WALLET_PROOF.md`.

```sh
export AUGENMASS_RELAY_TOKEN=<relay-token>
augenmass serve --relay augenmass --age-only
# augenmass serve: wallet-interaction debugger
#   open      : http://127.0.0.1:8080/
#   public    : https://wallet.augenmass.tech/r/<run-id>/
#   client_id : x509_hash:...
#   trace     : redacted by default; live on this console; also at <base>/trace/<session> and /api/trace/<session>
#   artifacts : off (set --unsafe-debug-artifacts <dir> to capture raw wallet material locally; UNSAFE)
#
#   23:20:51.551  29bbb9a0  SESSION_CREATED         new presentation session created
#   23:20:51.551  29bbb9a0  REQUEST_BUILT           built the authorization request (age-only German PID query (age_equal_or_over.18))
#   23:20:51.608  29bbb9a0  REQUEST_OBJECT_FETCHED  wallet fetched the signed request object (JAR)
#   # The remaining events appear when a real encrypted wallet response completes:
#   ...           ...       RESPONSE_RECEIVED       wallet posted its response (direct_post.jwt)
#   ...           ...       RESPONSE_DECRYPTED      decrypted the JWE response (ECDH-ES)
#   ...           ...       VERIFIED                presentation verified: urn:eudi:pid:de:1
#   ...           ...       OVER_ASK_ANALYZED       ...
```

The hosted proof for `wallet.augenmass.tech` checks health, byte-for-byte
request-object forwarding, public trace/inspect refusal, plaintext
`direct_post` rejection, and local trace redaction. The committed smoke test also
proves the verifier runtime, request fetch, trace endpoints, plaintext
rejection, and redaction without a phone wallet; a full `RESPONSE_DECRYPTED` /
`VERIFIED` trace is the expected output of an actual phone-wallet run and should
be captured before claiming a specific wallet demo environment is proven.

## The toolbox

UNDERSTAND
- `inspect <input>`: sniff an artifact's type, then decode it ("what is this?").
- `decode {jwt | sd-jwt | regcert | request | offer | status-list | mdoc} <input>`: decode a known artifact type, no signature verification.
- `decode mdoc <input>`: decode an ISO 18013-5 mdoc (`mso_mdoc`): the document type, the disclosed namespaces and elements, the issuer authentication (COSE_Sign1 algorithm and its X.509 chain), and the Mobile Security Object (validity window, value-digest counts, device key). Accepts raw CBOR bytes, hex, or base64/base64url. Decode only; the COSE signature and value digests are not verified.

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
- `validate dcql <input>`: validate a DCQL query for unique credential ids, `credential_sets` options that reference known ids, and claim paths whose shape matches the credential format (mdoc `[namespace, element]` vs SD-JWT string/null/index segments). Exits non-zero on a blocking error, so it gates CI.

DEBUG (live wallet interaction)
- `serve [--port --host --public-url --relay --relay-token --key --leaf --purpose --trust-anchor --live-status --quiet --unsafe-debug-artifacts]`: run a local OpenID4VP verifier (a verifier-in-a-box) so a real EUDI wallet can present to it, and trace the whole exchange. `--relay augenmass` publishes only the phone-facing request/response endpoints through the hosted relay. The trace is redacted by default (no raw bodies, no claim values); it streams to the console, renders as a live browser timeline at `/trace/<session>`, and serializes at `/api/trace/<session>`.

EVIDENCE (local audit bundles)
- `evidence export <session-dir> --out <bundle.json> [--signing-key <pem>]`: export one `serve --unsafe-debug-artifacts` session directory into a sensitive portable bundle. The bundle contains raw local material and a deterministic redacted replay trace.
- `evidence verify <bundle.json> [--verify-key <pem>]`: verify bundle hashes, replay determinism, and the optional ES256 signature.
- `evidence replay <bundle.json> [--verify-key <pem>]`: render the projector-safe replay timeline. It is redacted like the live trace, and when the captured request contains explicit DCQL claim paths it also replays wallet over-disclosure as a redacted auditor signal.
- `evidence assert-live <bundle.json> [--verify-key <pem>]`: fail unless the bundle proves a completed encrypted phone-wallet exchange through request fetch, response receipt, decryption, and offline presentation verification. It reports `walletOverDisclosureAnalyzed` separately when replay could compare requested keys to disclosed keys; it does not claim issuer trust, live status, or legal over-ask proof.
- `evidence profile <bundle.json>`: summarize redacted proof readiness, including whether the bundle has the material needed for issuer trust and status checks.
- `evidence prove-trust-status <bundle.json> --trust-anchor <pem> (--status-token <jwt> | --fetch-status-token) --status-key <pem>`: re-verify the captured presentation with explicit issuer trust and status inputs without printing PID claim values.

WRITE AND TARGETS (guard-railed)
- `register <body> --target {clone | cached-sandbox | sandbox} [--yes --force]`: gate a registration body under guardrails. Confirmed writes are allowed only for `clone` and `sandbox`; `cached-sandbox` is read-only and useful for dry-run output symmetry.
- `list --target {clone | cached-sandbox | sandbox} [--rp <id>]`: read registrations back for one relying party, decoded.
- `clone serve [--db --port]`: run the registrar-compatible local clone store.
- `cache serve [--db --host --port --upstream --ttl-secs --timeout-secs --max-entries --admin-token --allowed-rp --allow-any-rp --unsafe-upstream]`: run a bounded read-through cached-sandbox mirror for public sandbox GET routes. Registration reads are RP-allowlisted; the default is the demo RP.
- `cache warm [--api-base --admin-token --rp --timeout-secs]`: prewarm schema and registration reads before a demo or outage-sensitive rehearsal.
- `cache status [--api-base --admin-token --timeout-secs]`: show the protected cache inventory, including upstream, TTL, max entries, allowlist, cached keys, fetch time, byte size, and SHA-256.

HOSTED PROOFS
- `just deployed-cache-smoke-required`: prove the hosted cache URL is HTTPS, non-local, protected, warmable, and serving expected public sandbox reads.
- `just hosted-relay-proof`: prove the hosted wallet relay can carry a local `serve` run without exposing trace/inspect routes.
- `just macos-pkg-notarization-status`: check the local stapled macOS `.pkg` notarization proof.

## Over-ask and the legal basis

Over-ask is the central concern: a relying party must not request more personal data than its stated purpose needs. The same engine that audits the EUDI registry for over-asking helps a developer avoid over-asking when they register. Every over-ask finding cites the basis it rests on:

1. eIDAS Regulation (EU) 2024/1183, Art. 5b(3): "Relying parties shall not request users to provide data other than that indicated for their intended use."
2. GDPR (EU) 2016/679, Art. 5(1)(c): data minimisation, personal data must be "adequate, relevant and limited to what is necessary".
3. EUDI ARF, registration certificate, RPRC_07: the wallet verifies requested attributes are within the registration certificate and notifies the user otherwise.

The curated purpose baselines (`age_gate_18`, `event_checkin`, `car_rental`, `bank_kyc`) are taste judgments, not Rulebook derivations. See `augenmass baselines`.

## Debug the wallet interaction

`augenmass serve` is a verifier-in-a-box for debugging the actual wallet exchange, not just static artifacts. It runs a local OpenID4VP verifier for the German PID profile (x509_hash client_id, signed request object by reference, `direct_post.jwt` encrypted response, the registration certificate embedded as array-shaped `verifier_info` plus `verifier_attestations`), and records the whole flow as a per-session trace:

1. `SESSION_CREATED` and `REQUEST_BUILT`: a fresh session and the minimal-disclosure authorization request (carrying the nonce, client_id, and DCQL).
2. `REQUEST_OBJECT_FETCHED`: the wallet pulls the signed request object (the JAR); the trace shows the decoded header and payload it received.
3. `RESPONSE_RECEIVED`: the wallet posts its response; the trace records its shape (mode, byte length, SHA-256, field names, state), never the raw body.
4. `RESPONSE_DECRYPTED`: the JWE is decrypted (ECDH-ES); the trace records the payload shape (length, SHA-256, field names, whether a `vp_token` is present and its shape), never a disclosed claim value.
5. `VERIFIED` or `REJECTED`: the SD-JWT VC issuer signature, the KB-JWT holder binding, the nonce/audience, and the vct are checked; on failure the exact reason is recorded.
6. `STATUS_CHECKED` (with `--live-status` and a trust anchor): the token-status-list is resolved and a revoked or suspended credential is rejected fail-closed.
7. `OVER_ASK_ANALYZED`: what the wallet actually disclosed is run through the over-ask inspector.

The trace is redacted by default: each step records its shape (lengths, SHA-256 digests, sorted field names) and the disclosed claim keys, never the raw POST body, the decrypted payload, or a claim value. That makes it suitable for controlled demos and debugging, but the unauthenticated `/api/trace/<session>` and `/api/sessions` endpoints are still debug surfaces: treat trace URLs and session metadata as sensitive, and do not publish them. The same trace is available three ways: live on the console (color-coded), as a browser timeline at `/trace/<session>` (refreshes while the exchange is in flight), and as JSON at `/api/trace/<session>` for programmatic debugging.

Zero-config, it runs on a throwaway development certificate (the client_id is then not the registered identity). To sign with the real registrar-issued leaf so the client_id matches the registration, pass `--key` and `--leaf` (or set `RP_KEY_PATH` and `RP_LEAF_PATH`). To enforce issuer trust, pass `--trust-anchor`; add `--live-status` to resolve revocation over the network.

Redacted by default for a real PID demo. The trace is built for a phone-wallet presentation that carries real personal data, so it never exposes raw wallet material over the unauthenticated trace API. The received response and the decrypted payload are recorded as shape only: byte length, a SHA-256 digest, the sorted field names, and whether a `vp_token` is present, never the raw body and never a disclosed claim value. Each Authorization Request mints its own ephemeral response-encryption key, used once and dropped after the response is processed, so no key is shared across sessions. A plaintext `direct_post` is rejected with HTTP 422, because the verifier advertises the encrypted `direct_post.jwt` profile. The credential-controlled status-list fetch behind `--live-status` connects only to the addresses it already vetted (no re-resolution at connect time, which closes the DNS-rebinding window), stays https-only with redirects disabled and a timeout, caps the response body, normalizes IPv4-mapped IPv6 before vetting, and denies loopback, private, link-local, CGNAT, and unique-local targets.

Full-fidelity local debugging when you ask for it. When you need the raw bytes, `--unsafe-debug-artifacts <dir>` writes the raw `direct_post` body, the decrypted authorization response when an encrypted wallet response is decrypted, the per-session private key, the signed request object, the decoded request payload, and a verification context (`nonce`, `aud`, `vct`, clock, freshness window) to `<dir>/<session>/` with owner-only permissions on Unix (dirs `0700`, files `0600`) and a manifest marked sensitive. Artifact writes are append-only on filename collision, so a duplicate wallet POST after a successful response keeps the first canonical capture and stores later duplicates as suffixed files such as `direct-post-2.body`. It is opt-in, local, and never served over HTTP; the trace records the file name, a label, the length, a SHA-256, and the redaction fields `unsafeDebugArtifacts`, `pathRedacted`, `redacted`, and `redaction`, never a path or a value. It is labeled UNSAFE in the startup banner. Leave it off for demos and shared machines; on Windows, use it only in a private profile or encrypted workspace until native ACL hardening is added.

Evidence replay turns that local capture into an audit artifact. Run `augenmass evidence export ./debug-out/<session> --out evidence.json` to create a sensitive bundle, optionally signed with `--signing-key`. Then run `augenmass evidence verify evidence.json` to check entry hashes, the canonical payload hash, replay determinism, and the optional signature. `augenmass evidence replay evidence.json` renders the same projector-safe timeline shape without exposing raw wallet material on stdout. When replay has explicit request claim keys, it also emits a redacted wallet over-disclosure event so an auditor can see whether the wallet disclosed keys beyond the request. Before presenting a phone-wallet run as proven, run `augenmass evidence assert-live evidence.json`; it fails unless the bundle shows the request object fetch, encrypted response receipt, response decryption, and successful offline presentation verification. Add `augenmass evidence prove-trust-status evidence.json --trust-anchor <pem> --fetch-status-token --status-key <pem>` when you also need issuer trust and live status proof for the captured presentation.

## Safety

Writes are dry-run by default. `register` makes no network call until you pass `--yes`; if the body over-asks, it refuses (exit 1) unless you also pass `--force`. Blocking format errors are never written past.

There are three target modes. `clone` (the default) is a local registrar-compatible store (axum plus SQLite) with no signing, no auth, and no x5c: it holds payload-only JWTs and exists so you can rehearse the read and write paths entirely offline. `cached-sandbox` is a read-only, server-side mirror for public sandbox reads, with bounded SQLite storage, provenance headers, stale fallback for demos, request coalescing on cache misses, and an RP allowlist for registration-certificate read-through. It can run locally or as a small backend on Railway or a VPS; the current presentation backend is proven at `https://cache.augenmass.tech/api`. Public binds require the admin token, a non-empty RP allowlist unless `--allow-any-rp` is explicitly set, and an https upstream without URL credentials, query, fragment, or private IP host unless `--unsafe-upstream` is explicitly set. Unlisted RP reads return `403` before the upstream is contacted. `sandbox` is the real registrar behind Keycloak; it is rehearsal-only and off-stage, and sandbox API/token URLs must be https unless `AUGENMASS_UNSAFE_SANDBOX_URLS=1` is used for loopback development. Configure targets through environment variables (see `docs/SANDBOX.md` and `.env.example`).

Secrets hygiene is enforced: the tool never logs, echoes, or commits tokens, certificates, or keys, and `.env*`, `secrets*.md`, `*.sqlite`, and `*signing-key*` are gitignored.

## How it works

One engine is the spine. `augenmass-core` is a vendored, HTTP-free, pure-Rust crate carried over as-is from the verifier project: inspector (over-ask analysis, baselines, legal basis), regcert, pid, disclosure, verify (clock-injectable), status (fail-closed, offline), trust, and crypto. v1 used only inspector, regcert, and pid; v2 surfaces all of it behind one CLI. Because the engine is HTTP-free and the verification clock is injectable, artifact decoding, proportionality, generation, and offline verification are deterministic, which is what makes the committed fixtures reproducible in CI. Network behavior stays in the shell (`clone`, `cache`, `sandbox`, and `serve`).

## Documentation

- `docs/EXPLAINER.md`: what over-ask is and why it matters, in plain language for developers, auditors, and non-technical readers.
- `docs/ASK-IT-LIKE-THIS.md`: natural-language recipes for driving the skill.
- `docs/GUARDRAILS.md`: using the tool as a pre-commit hook and a CI gate so an over-ask never ships.
- `docs/COMMANDS.md`: every command, flag, exit code, and output shape.
- `docs/TOOLS.md`: an artifact field guide, organized by artifact type.
- `docs/ARCHITECTURE.md`: the one-engine spine and how the CLI wraps `augenmass-core`.
- `docs/SANDBOX.md`: the clone store, the sandbox registrar, and their environment variables.
- `docs/DEPLOYMENT.md`: deploying the cached-sandbox backend and hosted wallet relay on Railway, Docker, or a VPS, with notes for Cloudflare and Vercel.
- `docs/RELAY.md`: the hosted wallet relay for phone demos, including the wallet-only public surface, Railway shape, and proof gates.
- `docs/INSTALL.md`: source install, plugin install, and platform caveats.
- `docs/RELEASE.md`: CI, release archives, notarization, and platform support.
- `docs/DEMO_PROOF.md`: offline demo gates plus local plugin, live-cache, deployed-cache, and Docker smoke checks.
- `docs/PHONE_WALLET_PROOF.md`: exact rehearsal checklist for capturing,
  exporting, replaying, and proving a real phone-wallet interaction.
- `docs/SHIPPING_STATUS.md`: the current demo-readiness verdict, proven gates, deployment status, and platform caveats.
- The skill: `plugins/augenmass-workbench/skills/augenmass`.

## License

Apache-2.0.
