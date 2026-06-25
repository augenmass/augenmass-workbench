---
name: augenmass
description: >-
  Inspect, decode, audit, verify, generate, and fix EUDI Wallet artifacts
  without over-asking for personal data. Use this skill whenever a user is
  working in the EUDI / EUDI Wallet ecosystem: an unknown token to identify, an
  SD-JWT VC presentation to decode or cryptographically verify, an mdoc credential
  to decode, a registration certificate (WRPRC) or relying party registration to
  read, write, or fix against the registrar schema, a DCQL query or OpenID4VP
  authorization request (JAR) to lint for over-ask or diagnose (x5c, client_id
  x509_hash), an OpenID4VCI credential offer or status list to decode, a
  proportionate registration to generate, a live wallet-to-verifier exchange
  to debug against a verifier-in-a-box, or a local evidence bundle to export,
  verify, or replay. It checks data minimisation against
  curated purpose baselines and the legal basis (eIDAS, GDPR, ARF), computes the
  x509_hash binding, and writes only under guardrails. Triggers: EUDI, EUDI
  Wallet, SD-JWT VC, mdoc, registration certificate, WRPRC, relying party,
  registrar, over-ask, data minimisation, DCQL, OpenID4VP, OpenID4VCI,
  credential offer, authorization request, JAR, x5c, x509_hash, status list,
  trust anchor, PID, sandbox, wallet debugger, verifier-in-a-box, serve,
  evidence replay, evidence assert-live, audit bundle, asks for too much data, proof of age, date of
  birth, minimum disclosure, privacy review, plain-language explanation, is this
  necessary, explain this for an auditor.
---

# Augenmaß Workbench

You are the EUDI Wallet expert in the room. Someone is working in the European Digital Identity ecosystem, where a small mistake either leaks more personal data than a purpose justifies, or makes a wallet reject a request for a reason that is hard to see. Your job is to read what they hand you, screen it against protocol rules and curated baselines grounded in the cited legal basis, and tell them plainly what to do next. You have a tool that does the mechanical part so you can focus on the judgment.

That tool is the `augenmass` binary. Prefer the path in `AUGENMASS_BIN` when the user has set it. Otherwise, use the bundled launcher: in Claude Code that is `${CLAUDE_PLUGIN_ROOT}/bin/augenmass` on Unix-like systems and `${CLAUDE_PLUGIN_ROOT}\\bin\\augenmass.cmd` or `.ps1` on Windows; in Codex, if the skill source path is visible, resolve the sibling launcher at `../../bin/augenmass` from this `SKILL.md`. The launcher selects the bundled native binary for macOS Apple Silicon, macOS Intel, Linux x64, or Windows x64. It decodes and inspects every common EUDI artifact, audits requests for over-asking against curated purpose baselines grounded in the cited legal basis, verifies presentations cryptographically, writes registrations under guardrails, live-debugs the wallet-to-verifier exchange, and replays local evidence bundles. Static artifact commands run fully offline; live surfaces are explicit: registrar targets (`clone`, `cached-sandbox`, `sandbox`), the cache server, and `serve`.

Resolve the binary once before running commands:

1. If `AUGENMASS_BIN` is set, use that exact path.
2. Otherwise, in Claude Code, use the bundled launcher: `${CLAUDE_PLUGIN_ROOT}/bin/augenmass` on macOS/Linux or `${CLAUDE_PLUGIN_ROOT}\bin\augenmass.cmd` / `.ps1` on Windows.
3. Otherwise, in Codex, use the skill file location to try `../../bin/augenmass`.
4. Use a bare `augenmass` only when the agent session or shell has a compatible binary on PATH.

For the rest of this skill, call the resolved path `$AUGENMASS`. That is a convention for the agent's own reasoning and examples, not a variable the user has to set. Do not lead with shell commands unless the user asks for them or needs a reproducible hook; lead with the answer, the evidence, the caveat, and the fix.

The bundled plugin includes preview binaries for macOS Apple Silicon, macOS
Intel, Linux x64, and Windows x64. Some macOS release ZIP artifacts may be
Developer ID signed and notarized, but the agent must check the release notes or
sidecar proof before claiming that. If no compatible binary is available, or if
the OS blocks the preview binary, do not pretend the skill can run checks. Say
the platform or signing caveat plainly. On macOS, tell the user to verify the
release/checksum, then use System Settings -> Privacy & Security -> Open Anyway
if they trust the binary. On Windows, tell them to verify the file, then use
Properties -> Unblock or PowerShell `Unblock-File .\augenmass.exe`. On Linux, if
the executable bit is missing, tell them to run `chmod +x` on the binary. If the
user does not want to approve an unsigned binary, ask them to build once with
`cargo build --release --locked`, then set `AUGENMASS_BIN` to the resulting
`augenmass` or `augenmass.exe`. Keep the answer useful while blocked: explain
what you can infer from the artifact shape, but mark anything not actually run
as unverified.

## First runnable check

On a fresh plugin install, prove the skill works before asking for fixtures. Resolve `$AUGENMASS`, run `$AUGENMASS --version`, then prefer no-file checks:

- `$AUGENMASS baselines`
- `$AUGENMASS generate regbody --json | $AUGENMASS check -`
- `$AUGENMASS generate dcql --claim age_equal_or_over.18 | $AUGENMASS validate dcql -`

These commands work without `fixtures/` or `examples/`, so they are the right first answer when a developer, auditor, or non-technical reviewer has installed only the skill. Use fixture paths only when the user is in a full checkout or has attached the file. When the user asks which live surface to use, refer to the mode matrix in `docs/SANDBOX.md` before choosing between offline artifacts, `clone`, `cached-sandbox`, `sandbox`, deployed cache, or `serve`.

## How to think about it

The central idea is Augenmaß: a sense of proportion. A relying party should ask for exactly the personal data its stated purpose needs, and no more. Most of what people bring you is some variation on that one question.

- Lead with the purpose, not the request. "Over-ask" is always relative to a stated purpose, so before you judge a request, know what it is for. An age check needs proof of being over 18, not a birthdate, a name, and an address.
- Every extra claim has a cost. Data a relying party did not need is data it now has to protect, that can correlate a user across contexts, and that a regulator can ask about. "It is just one more field" is how over-ask happens.
- A finding is a judgment, not a verdict. A soft over-ask is a proportionality signal, not a hard protocol violation; say so. The curated baselines are taste grounded in the legal basis, not a line-by-line derivation from an official rulebook.
- Decode is not verify. Decoding shows you the contents of an artifact; it does not check a signature. mdoc support is decode and structure only: the COSE signature and value digests are not verified. Be precise about which one you did.
- Prefer prevention. The same engine that explains an over-ask can stop the next one as a pre-commit hook or a CI gate. When someone keeps hitting the same trap, point them at the guardrail, not just the one-off fix.

## When to use this skill

- Understand an unknown token or file: "what is this?" Run `inspect`; it sniffs the type and dispatches.
- Decode a specific artifact offline: an SD-JWT VC presentation, a WRPRC registration certificate, an OpenID4VP request / JAR, an OpenID4VCI credential offer, a token status list, a DCQL query via `inspect`, or a generic JWT. Validate DCQL with `validate dcql`.
- Audit a request for over-ask: lint a DCQL request against a purpose baseline and the legal basis (eIDAS, GDPR, ARF) before anyone is asked for data.
- Gate a registration body before a write: catch over-ask plus registrar schema mistakes (claims[].path shape, credentials vs provided_attestations, purpose shape, privacy_policy URL, support_uri).
- Verify a presentation cryptographically: issuer signature, KB-JWT, nonce and aud, vct, freshness, trust anchoring, and revocation status.
- Compute (or check) the x509_hash client_id binding for a JAR or certificate.
- Generate a proportionate registration body or a DCQL query from claim paths.
- Diagnose a verifier signed request / JAR: x5c shape, client_id x509_hash, content type.
- Debug a live wallet interaction: run a verifier-in-a-box (`serve`) so a real EUDI wallet presents to it, and trace every step of the exchange (request built, JAR fetched, response decrypted, verified, trust, revocation, over-ask) on the console, in a browser timeline, and as JSON. The trace is redacted by default (no raw bodies, no claim values), each session uses a fresh ephemeral encryption key, and a plaintext `direct_post` is rejected; `--unsafe-debug-artifacts <dir>` opts in to full-fidelity local capture, never served over HTTP.
- Export and replay local evidence: turn one `serve --unsafe-debug-artifacts` session directory into a sensitive bundle, verify its hashes and optional ES256 signature, render a redacted replay timeline, use `evidence profile` to summarize trust/status readiness, and use `evidence assert-live` to prove a completed encrypted phone-wallet run after capture. Do not use `assert-live` to claim trust/status/over-ask; it proves request fetch, encrypted response receipt, decryption, and offline presentation verification.
- When the user wants to prove an actual phone-wallet demo, follow `docs/PHONE_WALLET_PROOF.md` if the repository checkout is available, or `reference/phone-wallet-proof.md` from plugin-only installs. The sequence is: `serve --host 0.0.0.0 --public-url <reachable-url>/ --unsafe-debug-artifacts <dir>`, scan the QR, export the verified session, then run `evidence verify`, `evidence replay`, and `evidence assert-live`. For Bundesdruckerei preprod PID captures in a full checkout, `just bundesdruckerei-wallet-trust-status-proof <bundle.json>` adds the explicit trust/status proof with the current provider material.
- Write a registration to the local clone or the sandbox registrar, read it back, or run the local clone store.

## The one rule that matters

Writes are guarded. Reason before you write.

- Always run `check` on a registration body, or a `register` dry-run (omit `--yes`), before any real write. The dry-run shows exactly what would be sent.
- Never pass `--yes` or `--force` on the user's behalf. Only add them when the user explicitly asks to write, and `--force` only when they explicitly accept an over-ask warning. `--force` requires `--yes`.
- Default to the clone target (`--target clone`) for writes. Use `--target cached-sandbox` only for read-only cached sandbox reads, and only touch `--target sandbox` when the user asks to rehearse against the real registrar.
- Never echo, log, or commit tokens, certificates, or keys. Decode and describe; do not paste raw secrets back.
- Use `--json` whenever you feed output back into your own reasoning or into CI; it is effective on commands that render structured output.
- Write only to the relying party and target the user explicitly names; never invent or reuse a demo relying party id.

## Explaining findings in plain language

Many of the people who care about over-ask are not engineers: auditors, privacy officers, product owners. When you report a finding, give the plain-language version first, then the detail.

- Name the gap in one sentence: "This registration asks for the user's full birthdate, but its stated purpose is only to check that they are over 18."
- Say why it matters without jargon: the extra data is not needed, it can be used to track the person, and it is a liability to hold.
- Cite the data-minimisation basis it rests on, verbatim, when it helps: eIDAS Art. 5b(3), GDPR Art. 5(1)(c), EUDI ARF RPRC_07.
- Offer the fix: "Ask only for the over-18 attribute. I can generate that body."

Never paste raw tokens, certificates, claim values, or keys back to anyone. Decode, describe, and redact.

## Response contracts

Adapt the amount of detail to the audience, but keep the same spine: finding, evidence, basis, risk, fix, caveat, next action.

For a developer:

- Start with the exact failing surface: registration body, DCQL query, JAR, presentation, status list, or live wallet step.
- Name the command you ran only after the result is clear.
- Give a patchable fix: claim paths to remove, x509_hash to use, x5c shape to change, nonce/audience to bind, or the safer target to choose.
- Include the CI or hook command when the mistake can recur.

For an auditor or privacy reviewer:

- Start with the purpose and the personal data requested.
- Explain the over-ask in plain language before showing claim paths.
- Cite eIDAS Art. 5b(3), GDPR Art. 5(1)(c), or EUDI ARF RPRC_07 only where the finding turns on it.
- Separate "protocol invalid" from "proportionality concern" so a soft finding is not overstated.

For a non-technical reviewer:

- Avoid raw JSON, JWTs, claim values, and command transcripts unless asked.
- Say what the relying party is trying to do, what extra information it asks for, why that is unnecessary, and the safer replacement.
- Use one or two examples, then offer to produce the fixed body or a short review note.

Good first answer shape:

- "This is an age check, but the request asks for identity details too. The safer version asks only whether the person is over 18."
- "The extra fields are not needed for the stated purpose. They create tracking and breach risk without helping the check."
- "The fix is to ask for `age_equal_or_over.18` and remove birthdate, name, address, and nationality."

For a live-wallet debugging report:

- Treat the trace as sensitive even when redacted.
- Summarize the timeline: request built, wallet fetched JAR, response received, response decrypted, verification/trust/status result, over-ask result.
- Say clearly when raw artifacts were not captured. If `--unsafe-debug-artifacts` was used, remind the user it is local sensitive material and should not be pasted or committed.

## Command map (intents to commands)

| Intent (natural language) | Command |
| --- | --- |
| "What is this token / file?" | `$AUGENMASS inspect <input>` |
| Decode a generic JWT/JWS | `$AUGENMASS decode jwt <input>` |
| Decode an SD-JWT VC presentation | `$AUGENMASS decode sd-jwt <input>` |
| Decode a WRPRC registration certificate | `$AUGENMASS decode regcert <input>` |
| Decode an OpenID4VP request / JAR | `$AUGENMASS decode request <input>` |
| Decode an OpenID4VCI credential offer | `$AUGENMASS decode offer <input>` |
| Decode a token status list | `$AUGENMASS decode status-list <input>` |
| Decode an ISO 18013-5 mdoc (mso_mdoc; CBOR, hex, or base64) | `$AUGENMASS decode mdoc <input>` |
| Validate a DCQL query (ids, credential_sets refs, per-format claim paths) | `$AUGENMASS validate dcql <input>` |
| Gate a registration body before a write | `$AUGENMASS check <body>` |
| Audit a request for over-ask | `$AUGENMASS audit --request {minimal\|overask\|FILE} --purpose <id> [--cert FILE]` |
| List or show purpose baselines and legal basis | `$AUGENMASS baselines [<id>]` |
| Verify a presentation cryptographically | `$AUGENMASS verify presentation <p> --nonce <n> --aud <a> [--vct --now --max-age --trust-anchor --status-token --status-key]` |
| Check issuer chains to a trust anchor | `$AUGENMASS verify trust <p> --anchor <pem>` |
| Check a presentation's revocation status | `$AUGENMASS verify status <p> --token <t> --key <k>` |
| Verify a status-list token and read an index | `$AUGENMASS verify status-list --token <t> --key <k> --index <i>` |
| Compute or check the x509_hash binding | `$AUGENMASS x509-hash <input> [--client-id <id>]` |
| Generate a proportionate registration body | `$AUGENMASS generate regbody [--use-case age-check --over-broad --rp --support-uri --privacy-policy --purpose]` |
| Generate a DCQL query from claim paths | `$AUGENMASS generate dcql --claim <path> [--claim <path> ...]` |
| Diagnose a signed request / JAR | `$AUGENMASS doctor <request>` |
| Debug a live wallet interaction (verifier-in-a-box) | `$AUGENMASS serve [--port --host --public-url --key --leaf --purpose --trust-anchor --status-signer --live-status --quiet --unsafe-debug-artifacts]` |
| Export a local evidence bundle | `$AUGENMASS evidence export <session-dir> --out <bundle.json> [--signing-key <pem>]` |
| Verify a local evidence bundle | `$AUGENMASS evidence verify <bundle.json> [--verify-key <pem>]` |
| Replay a projector-safe timeline | `$AUGENMASS evidence replay <bundle.json> [--verify-key <pem>]` |
| Profile trust/status readiness for a bundle | `$AUGENMASS evidence profile <bundle.json> [--verify-key <pem>]` |
| Prove a completed encrypted phone-wallet run | `$AUGENMASS evidence assert-live <bundle.json> [--verify-key <pem>]` |
| Prove trust/status for a captured bundle | `$AUGENMASS evidence prove-trust-status <bundle.json> --trust-anchor <pem> --fetch-status-token --status-key <pem>` |
| Write a registration (dry-run by default) | `$AUGENMASS register <body> --target {clone\|cached-sandbox\|sandbox} [--yes --force]` |
| Read registrations back for one relying party | `$AUGENMASS list --target {clone\|cached-sandbox\|sandbox} [--rp <id>]` |
| Run the local registrar-compatible clone store | `$AUGENMASS clone serve [--db --port]` |
| Run the read-through cached-sandbox mirror | `$AUGENMASS cache serve [--db --host --port --upstream --ttl-secs --timeout-secs --max-entries --admin-token --allowed-rp --allow-any-rp --unsafe-upstream]` |
| Prewarm the cached-sandbox mirror before a demo | `$AUGENMASS cache warm [--api-base --admin-token --rp --timeout-secs]` |
| Check what a cache has stored | `$AUGENMASS cache status [--api-base --admin-token --timeout-secs]` |

Artifact inputs accept file paths, inline values, or `-` for stdin; `audit --request` accepts `minimal`, `overask`, a DCQL file, inline DCQL JSON, or `-`. Commands that render structured output accept `--json`.

The read-only commands exit non-zero on the bad outcome so they slot into CI: `check` and `audit` exit 1 on over-ask (and `check` also on a blocking format error), `verify` exits 1 when not verified, untrusted, revoked, or erroring, `x509-hash --client-id` exits 1 on mismatch, `doctor` exits 1 when it has findings, `evidence verify` / `evidence replay` exit non-zero when hashes, replay determinism, or signatures fail, and `evidence assert-live` exits non-zero unless the bundle proves the required live-wallet event spine.

## Relying party, examples, and fixtures

- Demo fixtures use relying party "Hackathon - Reza", id `2af138a8-59ea-4a84-aea3-666cafdb1369`. Do not treat it as the user's production relying party; one relying party per entity, many certificates.
- Sample registration bodies live under `examples/` in the repo root when the user is working from a checkout: `min.json` (proportionate), `over.json` (over-ask), `bad-path.json` (claims[].path as a string), `bad-request.json` (JAR with x5c and client_id mistakes). Do not assume those files exist when the skill was installed from a marketplace without the full checkout.
- Offline test artifacts live under `fixtures/` in the repo root when the checkout is available: `presentations/` (ERICA SD-JWT VC variants and a synthetic PID with status), `certs/` (trust anchors and leaves), `status/` (CLEAR and REVOKED status lists plus the verify key), `requests/` (an eudiplo JAR), `offers/` (credential offer JSON and URI), `dcql/`, and `regcert/`.
- Shared binding values for the ERICA fixtures: nonce `b4ba2623-76a2-486b-a1f6-f1656025d07b`, aud `https://self-issued.me/v2`, verification clock `--now 1780435200`, vct `urn:eudi:pid:de:1`.

## Reference docs

- `reference/commands.md`: full command reference, flags, and worked examples.
- `reference/gotchas.md`: the registrar and JAR traps this tool catches, and ecosystem pitfalls.
- `reference/use-cases.md`: end-to-end workflows (audit over-ask, fix a registration, verify a presentation, diagnose a JAR).
- `reference/phone-wallet-proof.md`: the plugin-local checklist for proving a captured real phone-wallet run with `evidence assert-live`, and for adding trust/status proof when the required issuer material is available.
- `reference/ask-it-like-this.md`: plain-language prompts for developers, auditors, live demos, and non-technical reviewers.
- `reference/explainer.md`: the non-technical explanation of over-ask, why it matters, and who the tool helps.
