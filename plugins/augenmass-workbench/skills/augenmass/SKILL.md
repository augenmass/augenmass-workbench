---
name: augenmass
description: >-
  Inspect, decode, audit, verify, generate, and repair EUDI Wallet artifacts
  without over-asking for personal data. Use this skill whenever a user is
  working in the EUDI / EUDI Wallet ecosystem: an unknown token to identify, an
  SD-JWT VC or mdoc presentation to decode or cryptographically verify, a
  registration certificate (WRPRC) or relying party registration to read,
  write, or repair against the registrar schema, a DCQL query or OpenID4VP
  authorization request (JAR) to lint for over-ask or diagnose (x5c, client_id
  x509_hash), an OpenID4VCI credential offer or status list to decode, a
  proportionate registration to generate, or a live wallet-to-verifier exchange
  to debug against a verifier-in-a-box. It checks data minimisation against
  curated purpose baselines and the legal basis (eIDAS, GDPR, ARF), computes the
  x509_hash binding, and writes only under guardrails. Triggers: EUDI, EUDI
  Wallet, SD-JWT VC, mdoc, registration certificate, WRPRC, relying party,
  registrar, over-ask, data minimisation, DCQL, OpenID4VP, OpenID4VCI,
  credential offer, authorization request, JAR, x5c, x509_hash, status list,
  trust anchor, PID, sandbox, wallet debugger, verifier-in-a-box, serve.
---

# Augenmaß Workbench

This skill drives the bundled `augenmass` binary at `${CLAUDE_PLUGIN_ROOT}/bin/augenmass`, a developer and auditor toolkit for the EUDI Wallet ecosystem. It decodes and inspects every common artifact, audits requests for over-asking against curated purpose baselines and the legal basis, verifies presentations cryptographically, writes registrations under guardrails, and live-debugs the wallet-to-verifier exchange. Everything runs fully offline except two paths that are network by nature: the registrar write path, and the live wallet-interaction debugger (`serve`), where a real wallet connects to the tool.

Claude Code adds the plugin `bin/` directory to PATH, so a bare `augenmass` works too. The `${CLAUDE_PLUGIN_ROOT}/bin/augenmass` form is the safe explicit path; use whichever is convenient.

## When to use this skill

- Understand an unknown token or file: "what is this?" Run `inspect`; it sniffs the type and dispatches.
- Decode a specific artifact offline: an SD-JWT VC presentation, a WRPRC registration certificate, an OpenID4VP request / JAR, an OpenID4VCI credential offer, a token status list, a DCQL query, or a generic JWT.
- Audit a request for over-ask: lint a DCQL request against a purpose baseline and the legal basis (eIDAS, GDPR, ARF) before anyone is asked for data.
- Gate a registration body before a write: catch over-ask plus registrar schema mistakes (claims[].path shape, credentials vs provided_attestations, purpose shape, privacy_policy URL, support_uri).
- Verify a presentation cryptographically: issuer signature, KB-JWT, nonce and aud, vct, freshness, trust anchoring, and revocation status.
- Compute (or check) the x509_hash client_id binding for a JAR or certificate.
- Generate a proportionate registration body or a DCQL query from claim paths.
- Diagnose a verifier signed request / JAR: x5c shape, client_id x509_hash, content type.
- Debug a live wallet interaction: run a verifier-in-a-box (`serve`) so a real EUDI wallet presents to it, and trace every step of the exchange (request built, JAR fetched, response decrypted, verified, trust, revocation, over-ask) on the console, in a browser timeline, and as JSON. The trace is redacted by default (no raw bodies, no claim values), each session uses a fresh ephemeral encryption key, and a plaintext `direct_post` is rejected; `--unsafe-debug-artifacts <dir>` opts in to full-fidelity local capture, never served over HTTP.
- Write a registration to the local clone or the sandbox registrar, read it back, or run the local clone store.

## The one rule that matters

Writes are guarded. Reason before you write.

- Always run `check` on a registration body, or a `register` dry-run (omit `--yes`), before any real write. The dry-run shows exactly what would be sent.
- Never pass `--yes` or `--force` on the user's behalf. Only add them when the user explicitly asks to write, and `--force` only when they explicitly accept an over-ask warning. `--force` requires `--yes`.
- Default to the clone target (`--target clone`). Only touch `--target sandbox` when the user asks to rehearse against the real registrar.
- Never echo, log, or commit tokens, certificates, or keys. Decode and describe; do not paste raw secrets back.
- Use `--json` whenever you feed output back into your own reasoning or into CI; it is available on the read-only commands.
- Write only under the one relying party (see id below); never mint extra relying parties.

## Command map (intents to commands)

| Intent (natural language) | Command |
| --- | --- |
| "What is this token / file?" | `${CLAUDE_PLUGIN_ROOT}/bin/augenmass inspect <input>` |
| Decode a generic JWT/JWS | `${CLAUDE_PLUGIN_ROOT}/bin/augenmass decode jwt <input>` |
| Decode an SD-JWT VC presentation | `${CLAUDE_PLUGIN_ROOT}/bin/augenmass decode sd-jwt <input>` |
| Decode a WRPRC registration certificate | `${CLAUDE_PLUGIN_ROOT}/bin/augenmass decode regcert <input>` |
| Decode an OpenID4VP request / JAR | `${CLAUDE_PLUGIN_ROOT}/bin/augenmass decode request <input>` |
| Decode an OpenID4VCI credential offer | `${CLAUDE_PLUGIN_ROOT}/bin/augenmass decode offer <input>` |
| Decode a token status list | `${CLAUDE_PLUGIN_ROOT}/bin/augenmass decode status-list <input>` |
| Decode an ISO 18013-5 mdoc (mso_mdoc; CBOR, hex, or base64) | `${CLAUDE_PLUGIN_ROOT}/bin/augenmass decode mdoc <input>` |
| Validate a DCQL query (ids, credential_sets refs, per-format claim paths) | `${CLAUDE_PLUGIN_ROOT}/bin/augenmass validate dcql <input>` |
| Gate a registration body before a write | `${CLAUDE_PLUGIN_ROOT}/bin/augenmass check <body>` |
| Audit a request for over-ask | `${CLAUDE_PLUGIN_ROOT}/bin/augenmass audit --request {minimal\|overask\|FILE} --purpose <id> [--cert FILE]` |
| List or show purpose baselines and legal basis | `${CLAUDE_PLUGIN_ROOT}/bin/augenmass baselines [<id>]` |
| Verify a presentation cryptographically | `${CLAUDE_PLUGIN_ROOT}/bin/augenmass verify presentation <p> --nonce <n> --aud <a> [--vct --now --max-age --trust-anchor --status-token --status-key]` |
| Check issuer chains to a trust anchor | `${CLAUDE_PLUGIN_ROOT}/bin/augenmass verify trust <p> --anchor <pem>` |
| Check a presentation's revocation status | `${CLAUDE_PLUGIN_ROOT}/bin/augenmass verify status <p> --token <t> --key <k>` |
| Verify a status-list token and read an index | `${CLAUDE_PLUGIN_ROOT}/bin/augenmass verify status-list --token <t> --key <k> --index <i>` |
| Compute or check the x509_hash binding | `${CLAUDE_PLUGIN_ROOT}/bin/augenmass x509-hash <input> [--client-id <id>]` |
| Generate a proportionate registration body | `${CLAUDE_PLUGIN_ROOT}/bin/augenmass generate regbody [--use-case age-check --over-broad --rp --support-uri --privacy-policy --purpose]` |
| Generate a DCQL query from claim paths | `${CLAUDE_PLUGIN_ROOT}/bin/augenmass generate dcql --claim <path> [--claim <path> ...]` |
| Diagnose a signed request / JAR | `${CLAUDE_PLUGIN_ROOT}/bin/augenmass doctor <request>` |
| Debug a live wallet interaction (verifier-in-a-box) | `${CLAUDE_PLUGIN_ROOT}/bin/augenmass serve [--port --host --public-url --key --leaf --purpose --trust-anchor --live-status --quiet --unsafe-debug-artifacts]` |
| Write a registration (dry-run by default) | `${CLAUDE_PLUGIN_ROOT}/bin/augenmass register <body> --target {clone\|sandbox} [--yes --force]` |
| Read registrations back for one relying party | `${CLAUDE_PLUGIN_ROOT}/bin/augenmass list --target {clone\|sandbox} [--rp <id>]` |
| Run the local registrar-compatible clone store | `${CLAUDE_PLUGIN_ROOT}/bin/augenmass clone serve [--db --port]` |

Every artifact argument accepts a file path, an inline value, or `-` for stdin. Read-only commands accept `--json`.

The read-only commands exit non-zero on the bad outcome so they slot into CI: `check` and `audit` exit 1 on over-ask (and `check` also on a blocking format error), `verify` exits 1 when not verified, untrusted, revoked, or erroring, `x509-hash --client-id` exits 1 on mismatch, and `doctor` exits 1 when it has findings.

## Relying party, examples, and fixtures

- The relying party is "Hackathon - Reza", id `2af138a8-59ea-4a84-aea3-666cafdb1369`. It is the default for `generate regbody --rp` and `list --rp`. Write only under it; one relying party per entity, many certificates.
- Sample registration bodies live under `examples/` in the repo root: `min.json` (proportionate), `over.json` (over-ask), `bad-path.json` (claims[].path as a string), `bad-request.json` (JAR with x5c and client_id mistakes).
- Offline test artifacts live under `fixtures/`: `presentations/` (ERICA SD-JWT VC variants and a synthetic PID with status), `certs/` (trust anchors and leaves), `status/` (CLEAR and REVOKED status lists plus the verify key), `requests/` (an eudiplo JAR), `offers/` (credential offer JSON and URI), `dcql/`, and `regcert/`.
- Shared binding values for the ERICA fixtures: nonce `b4ba2623-76a2-486b-a1f6-f1656025d07b`, aud `https://self-issued.me/v2`, verification clock `--now 1780435200`, vct `urn:eudi:pid:de:1`.

## Reference docs

- `reference/commands.md`: full command reference, flags, and worked examples.
- `reference/gotchas.md`: the registrar and JAR traps this tool catches, and ecosystem pitfalls.
- `reference/use-cases.md`: end-to-end workflows (audit over-ask, repair a registration, verify a presentation, diagnose a JAR).
