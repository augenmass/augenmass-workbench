# Ask It Like This

Use the skill as the front door. The user describes the artifact, the purpose,
or the review question in plain language; the skill chooses the command, runs
the `augenmass` binary when available, and explains the result.

## Developer Prompts

"Is this registration over-asking?"

Answer shape: say whether the requested claims match the stated purpose, list
the extra claims, cite the legal basis when there is a finding, then give the
minimal replacement.

"Generate a proportionate age-check body."

Answer shape: produce a body that asks only for `age_equal_or_over.18`, then
explain why a raw birthdate is unnecessary.

"Why is the wallet rejecting my request?"

Answer shape: inspect or diagnose the request, call out concrete protocol
failures such as `x5c` shape, `x509_hash` client_id binding, content type, nonce,
audience, or response mode, then give the exact fix.

## Auditor And Privacy Reviewer Prompts

"Explain this over-ask for a privacy reviewer."

Answer shape: avoid raw JSON first. Say what the relying party is trying to do,
what extra data it asks for, why that is not necessary, and what should be
removed.

"What should an age-check service ask for?"

Answer shape: it should ask for an over-18 attribute, not full birthdate, name,
address, or nationality. Mention that the conclusion depends on the stated
purpose.

"Is this necessary for the stated purpose?"

Answer shape: compare every claim to the purpose. Separate protocol invalidity
from proportionality concerns.

## Live Demo Prompts

"Run a verifier so I can test with a real wallet, and show me every step."

Answer shape: start the live debugger only when the user is ready. Explain that
traces are redacted by default, raw material is captured only with
`--unsafe-debug-artifacts`, and trace URLs still deserve care.

"Keep sandbox reads stable for the demo."

Answer shape: start `cache serve`, warm the configured RP, read through
`cached-sandbox`, and explain whether the data came from a live refresh, a hit,
or stale fallback.

## Non-Technical Answer Example

"This age-check registration asks for the person's birthdate, name, address, and
nationality. For an over-18 check, the service only needs to know whether the
person is over 18. The safer request is `age_equal_or_over.18`; it proves the
same thing without exposing identity details."
