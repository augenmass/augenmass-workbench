# Ask it like this

The Augenmaß skill is the front door. You describe what you have and what you want in plain language, and the skill picks the right command, runs the bundled `augenmass` launcher or your `AUGENMASS_BIN` override, and explains the result. You never have to remember a flag.

This page collects phrasings that work well, grouped by who is asking. Each one names the command the skill runs underneath, so you can also run it yourself; see `COMMANDS.md` for the full reference. The skill always reasons before it writes and never pastes raw secrets back (see "the one rule that matters" in the skill).

## If you are building a relying party

"Is this registration over-asking?"
The skill runs `check` on the registration body and returns a per-claim diff: which requested claims exceed the stated purpose, and the legal basis the finding rests on (eIDAS Art. 5b(3), GDPR Art. 5(1)(c), EUDI ARF RPRC_07). It exits non-zero on an over-ask, so the same question works in CI.

"Audit this request against an event check-in purpose."
The skill runs `audit` against the named purpose baseline and reports the over-ask, if any.

"Generate a proportionate age-check body."
The skill runs `generate regbody`. You get only the over-18 attribute, never a raw birthdate. Ask for the over-broad variant only if you specifically want to demonstrate what a bad request looks like.

"Build a DCQL query that asks for just the over-18 attribute."
The skill runs `generate dcql` from the claim paths you describe.

"Register it, but refuse if it over-asks."
The skill dry-runs `register` first (no network call), shows you exactly what would be sent, and writes only on your explicit go-ahead. It defaults to the local clone target, and it will not write past an over-ask unless you tell it to force the write.

"Why is the wallet rejecting my request?"
The skill runs `doctor` on the signed request and points at the usual causes: an `x5c` that is a bare string instead of a list, a `client_id` that is not the `x509_hash` binding of the leaf certificate, or a missing content type. Ask "what is the correct client_id for this certificate?" and it runs `x509-hash`.

## If you are auditing or reviewing

"What is this token?"
The skill runs `inspect`, which sniffs the artifact type and decodes it: an SD-JWT VC presentation, an OpenID4VP request or JAR, a credential offer, an mdoc, a status list, a registration certificate, or a plain JWT. Decoding shows contents; it does not verify a signature.

"Decode this credential and tell me what it actually discloses."
The skill runs the matching `decode` subcommand and lists the disclosed claims. For an mdoc this is structure only: the document type, namespaces, elements, and the security object, without verifying the COSE signature or value digests.

"Is this presentation cryptographically valid?"
The skill runs `verify presentation` with the nonce and audience you provide, checking the issuer signature, the holder binding, freshness, and the credential type. Add a trust anchor to also check the issuer chains to it, and a status token to check revocation. Revocation and trust are only asserted when you supply the inputs for them.

"Explain this finding for someone non-technical."
The skill restates the over-ask in one plain sentence, says why the extra data is a problem (not needed, correlatable, a liability to hold), and cites the rule only where it helps. See `EXPLAINER.md` for the tone.

## If you are running a live wallet test

"Run a verifier so I can test with a real wallet, and show me every step."
The skill starts `augenmass serve`, a local verifier-in-a-box for the German PID profile. You scan the QR with a real wallet, and the exchange is traced step by step on the console, in a browser timeline, and as JSON. The trace is redacted by default: it shows shapes, sizes, hashes, and disclosed claim keys, never raw bodies or claim values. Use it for controlled demos and debugging, but still treat trace URLs and session metadata as sensitive.

"I need the raw bytes to debug a failure."
Tell the skill to enable local debug artifacts. It adds `--unsafe-debug-artifacts <dir>`, which writes the raw material locally and never serves it over HTTP. On Unix the files are tightened to owner-only permissions; on Windows, keep them in a private profile or encrypted workspace. Use it only when you need it, and never on a shared screen.

"Turn that captured session into something I can replay in a review."
The skill runs `evidence export`, then `evidence verify` to check the hashes and any signature, `evidence replay` to render a redacted timeline you can show on a projector without leaking wallet contents, and `evidence assert-live` when you need proof that the captured run completed the encrypted phone-wallet exchange.

"Keep sandbox reads stable for a demo."
The skill starts `cache serve`, runs `cache warm` for the relying party you name, then reads through `list --target cached-sandbox`. The first call refreshes from the public sandbox, later calls can use the local cache, and stale fallback keeps the demo readable if the sandbox has a bad moment.

## If you want it to stop the next mistake

"Add a check that fails my build if a registration over-asks."
The skill shows you how to run `check` (and `validate dcql` for requests) as a pre-commit hook or a CI step. Both exit non-zero on a bad outcome, so the pipeline fails instead of the registrar accepting a bad body. See `GUARDRAILS.md`.

"Set this up so my whole team gets the same protection."
The same hook and CI recipes apply per repository. The skill can scaffold them and explain what each line does.

## Why this beats reading the docs

Debugging EUDI flows by hand is tedious, and tedious work gets skipped. The skill exists so the judgment (what does this purpose actually need?) stays with a person, and the mechanical part (decode, diff, verify, gate) is done for you, with enough context attached that the fix and the prevention are one short conversation away.
