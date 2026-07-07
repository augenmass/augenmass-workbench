# Security Policy

Augenmaß Workbench is a developer and auditor toolkit for the EUDI (European
Digital Identity) Wallet ecosystem. It parses untrusted cryptographic artifacts
and can run a live OpenID4VP verifier that handles real personal data, so we
take security reports seriously and follow a coordinated-disclosure process
modelled on the European Digital Identity Wallet Vulnerability Disclosure Policy.

This policy is operated by the Augenmaß project (operating entity: Quellkern e.U.).

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Do not open a public issue,
pull request, or discussion for a security problem, and do not disclose it to
third parties before it is remediated.

Two private channels are available. The GitHub private advisory is preferred,
because it keeps the report, the fix, and the coordination in one place.

1. Primary: open a GitHub private security advisory at
   https://github.com/augenmass/augenmass-workbench/security/advisories/new
2. Alternative: email security@augenmass.tech. For sensitive details, encrypt
   the message with our PGP key (see [PGP key](#pgp-key)).

You may write in English or any official language of the European Union. English
is easiest for us to action quickly.

### What to include

A good report lets us reproduce the issue without guesswork. Where possible,
include:

- The affected component and version (for example the CLI command, `serve`, the
  cache backend, or the relay), plus the release or commit you tested.
- A clear description of the issue and its security impact.
- Step-by-step reproduction detail: the artifact, command, or request that
  triggers it. A minimal proof-of-concept is ideal.
- Any logs, stack traces, or crash output, with personal data removed.
- Whether you consent to being credited if the issue is fixed and disclosed (see
  [Recognition](#recognition)).

## Scope

In scope is this repository (`augenmass/augenmass-workbench`) and the EUDI
relying-party and verifier tooling it ships:

- The `augenmass` CLI and the vendored `augenmass-core` engine: the artifact
  decoders (SD-JWT VC, mdoc, JAR / OpenID4VP request, registration certificate,
  credential offer, status list, DCQL) and their handling of malformed or
  hostile input.
- The proportionality and over-ask analysis: the `check`, `audit`, and
  `baselines` paths and the registration-write guardrails (`register`, `clone`,
  `cache`), including any bypass of the over-ask or format gate.
- The cryptographic paths: SD-JWT VC and KB-JWT verification, the `x509_hash`
  client_id binding, trust-anchor checks, and token-status-list handling,
  including signature-verification or trust-chain bypasses.
- The `serve` verifier-in-a-box: the OpenID4VP verifier, signed request object
  (JAR) handling, the encrypted `direct_post.jwt` (JWE) response path, trace
  redaction, and the SSRF protections around status-list fetches.
- The evidence-bundle paths (`evidence export`, `verify`, `replay`,
  `assert-live`), including hash, replay-determinism, or signature-verification
  weaknesses.
- The hosted demo surfaces we operate: the cached-sandbox backend at
  `cache.augenmass.tech` and the wallet-only relay at `wallet.augenmass.tech`,
  tested within the rules below.

Examples of out-of-scope reports:

- Anything that requires access to systems we do not operate or that you are not
  authorized to test: live production EUDI wallets, third-party verifier
  deployments, the real registrar / sandbox behind Keycloak, or any relying
  party's own registration data. Test against the reference artifacts, the
  committed fixtures, and your own local `serve`, `clone`, or `cache` instances.
- Over-ask or proportionality judgements about a specific relying party's
  registry entry. Those are policy findings about registry data, not
  vulnerabilities in this code. The tool exists to surface them, and they are
  handled through the registry, not through this process.
- Missing hardening that is already documented as a known limitation (for
  example the unauthenticated local trace and debug endpoints, or Windows
  debug-artifact file permissions), unless you can show a concrete exploit
  beyond the documented behavior.
- Reports produced only by automated scanners with no demonstrated impact,
  best-practice or defense-in-depth suggestions without a security consequence,
  and already-public issues in third-party dependencies (report those upstream;
  tell us if we ship them).
- Social engineering, physical attacks, denial of service, and volumetric or
  stress testing against the hosted endpoints.

If you are unsure whether something is in scope, report it privately and ask.

## Supported versions

Augenmaß Workbench is in its `v0.x` release line and follows semantic
versioning. Pre-1.0 releases carry no guarantee of long-term support. Security
fixes land on the latest `v0.x` release.

| Version | Security fixes |
| --- | --- |
| Latest `v0.x` release | Yes |
| Older `v0.x` releases | No; please update to the latest release |

When a fix ships, we note the security-relevant change in `CHANGELOG.md`.

## Coordinated disclosure and confidentiality

We follow coordinated disclosure, modelled on the EU Digital Identity Wallet VDP:

- Keep the report confidential until the issue is remediated or we agree on a
  disclosure date together. Do not disclose it to third parties before then.
- We will work the issue with you, confirm whether we can reproduce it, assess
  severity, and prepare a fix.
- We coordinate the timing of public disclosure with you. Remediation timing
  depends on the severity and complexity of the issue; we keep you updated
  rather than commit to a fixed calendar date.
- Once a fix is available or a date is agreed, and if you wish, we credit you as
  the discoverer (see [Recognition](#recognition)).

### Our response targets

We are a small team and set commitments we can keep:

- Acknowledge your report within three business days.
- Provide an initial assessment (triage, reproduction status, and a severity
  view) within ten business days.
- Keep you informed of remediation progress and agree a disclosure timeline
  with you.

## Safe harbor for good-faith research

We support good-faith security research. If you make a good-faith effort to
follow this policy, we will treat your research as authorized, work with you to
understand and resolve the issue promptly, and not pursue or support legal
action against you.

Acting in good faith means you: avoid privacy violations and harm to data or to
service availability; access only the data and systems needed to demonstrate the
issue; give us reasonable time to remediate before any disclosure; and, if you
accidentally cross a line, stop and report it promptly. Under those conditions an
accidental, good-faith violation is not treated as a breach of this policy.

This authorization covers only the systems and artifacts in scope above. It does
not authorize testing systems operated by others (live wallets, third-party
verifiers, the real registrar). For those, follow their own disclosure policies
and the EUDI ecosystem VDPs.

## Rules for researchers

To stay within good-faith authorization, do not:

- Access, modify, delete, or exfiltrate data beyond the minimum needed to
  demonstrate the issue. A proof-of-concept must prove the bug, never exploit it.
- Handle real personal data (PID or other personal attributes) beyond what is
  strictly necessary to show the problem. Redact personal data from your report
  and use test or synthetic credentials wherever possible.
- Disrupt or degrade service: no denial of service, no volumetric or stress
  testing, and no automated scanning against the hosted `cache.augenmass.tech`
  or `wallet.augenmass.tech` endpoints.
- Pivot to out-of-scope systems, or use a finding to reach data or systems
  beyond the proof-of-concept.
- Use social engineering, phishing, or physical intrusion against the project,
  its operators, or its users.
- Publicly disclose the issue, or share it with third parties, before it is
  remediated or a disclosure date is agreed.

## PGP key

For encrypted reports, use our PGP key:

- Key: https://augenmass.tech/.well-known/pgp-key.txt
- Fingerprint: `CA79 A83F B7B2 B60B F65A CB0D 411C E654 00FE 8913` (Ed25519)
- UID: `Augenmass Security <security@augenmass.tech>`

Verify the fingerprint before you rely on the key.

## Recognition

With your consent, we credit you as the discoverer when the issue is disclosed.
If you prefer to stay anonymous, tell us and we will not name you. We do not run
a paid bug-bounty program.
