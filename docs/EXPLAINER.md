# What Augenmaß is, in plain language

This page is for anyone who wants to understand what Augenmaß does and why it matters, without reading code. Developers, auditors, privacy officers, product owners, and policy people should all be able to follow it. The technical reference lives in `COMMANDS.md` and `TOOLS.md`.

## The one-sentence version

Augenmaß checks whether a service is asking people for more personal data than it actually needs, and helps fix it before it ships.

## The words you need

EUDI Wallet. The European Digital Identity Wallet: an app on your phone that holds official credentials, like a digital version of your ID card or a proof of age. You decide what to share and with whom.

Relying party. Any service that asks you to prove something with your wallet: a bar checking you are over 18, a bank verifying your identity, a car rental confirming your licence. "Relying" because it relies on your credential instead of storing its own copy of your data.

Registration certificate. Before a relying party is allowed to ask for data, it registers what it intends to ask for and why. The registration certificate is that declared scope. It is meant to be a promise: "I will only ask for these things, for this purpose."

Over-ask. When a relying party asks for more than its stated purpose needs. The classic example: a service whose purpose is "check the customer is over 18" registers to collect the full date of birth, the given name, and the family name. None of the extra fields are needed to answer "over 18 or not." That gap, between what the purpose needs and what is requested, is the over-ask.

## Why over-ask matters

It is tempting to treat one extra field as harmless. It is not, for three reasons.

It is against the rules. European law is explicit that a relying party must not collect more than it needs. Augenmaß cites three sources for every finding:

1. eIDAS Regulation (EU) 2024/1183, Art. 5b(3): "Relying parties shall not request users to provide data other than that indicated for their intended use."
2. GDPR (EU) 2016/679, Art. 5(1)(c): personal data must be "adequate, relevant and limited to what is necessary" (data minimisation).
3. EUDI ARF, registration certificate, RPRC_07: the wallet checks that requested attributes are within the registration certificate and notifies the user otherwise.

It turns users into something trackable. A birthdate plus a name plus a place is enough to recognise the same person across unrelated services. Data that was never needed becomes a way to follow people around. Asking only for "over 18: yes" cannot do that.

It is a liability to hold. Every extra field is something that has to be stored, secured, explained to a regulator, and disclosed if there is a breach. Over-collected data is not an asset; it is risk you took on for no benefit. Over-ask and you get used, and it gets expensive.

## The two surfaces of Augenmaß

Augenmaß is one idea (a trained sense of proportion) with two ways to use it.

The board, at augenmass.tech. A public audit of the EUDI sandbox registry. It plots every relying party by how proportionate its requests are, so the over-asks stand out. This is the after-the-fact view: who has already registered a broader scope than their purpose needs.

The Workbench. The same proportionality engine, on your own machine, before you register anything. It is a Claude Code skill (you ask it questions in plain language) backed by a command-line tool (you can also run it directly, or in an automated pipeline). This is the preventive view: catch your own over-ask locally, fix it, and only then register.

Same engine, two surfaces: audit the registry on the board, catch it locally with the Workbench before you register.

## Who it helps, and how

A developer building a relying party. Ask "is this registration over-asking?" and get a per-claim answer before going live. Ask "generate a proportionate age-check body" and get a request that asks only for what the purpose needs. Wire the same check into the build so a regression cannot ship (see `GUARDRAILS.md`).

An auditor or privacy officer. Point it at a registration or a request and get a plain-language finding with the legal basis attached, suitable for a report. You do not need to read the raw certificate; the tool decodes and explains it.

A policy or product person. Use the board to see the shape of the problem across the ecosystem, and the Workbench's explanations to understand any single case without a technical briefing.

## Using it without being technical

If you have Claude Code, install the skill and talk to it:

```
/plugin marketplace add augenmass/augenmass-workbench
/plugin install augenmass-workbench@augenmass
```

Then ask in your own words. For example: "Here is a registration certificate. Is it asking for more than it needs? Explain it for a non-technical reader and tell me which rule it breaks." The skill reads the artifact, runs the check, and answers in plain language, citing the legal basis only where it helps.

For more example phrasings, see `ASK-IT-LIKE-THIS.md`.

A note on the name: Augenmaß is German for judging the right amount by eye, a trained sense of proportion. A relying party that asks for more than its purpose justifies is acting without it. The tool measures that proportion so you do not have to eyeball it.
