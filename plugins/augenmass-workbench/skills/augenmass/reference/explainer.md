# Explainer

Augenmaß checks whether a service is asking people for more personal data than
its stated purpose needs, then helps fix the request before it ships.

## Core Terms

EUDI Wallet: the European Digital Identity Wallet, an app that can hold official
credentials and let a person choose what to share.

Relying party: a service that asks the wallet for proof. Examples include an age
check, a bank onboarding flow, or a car rental service.

Registration certificate: the relying party's declared scope, meaning what it
intends to ask for and why.

Over-ask: asking for more data than the stated purpose needs. An age check that
requests birthdate, name, address, and nationality is the classic example.

## Why It Matters

Extra data is not harmless. It can identify people across contexts, it creates
storage and breach risk, and it can conflict with the data-minimisation basis.

The tool cites three sources when a finding rests on them:

1. eIDAS Regulation (EU) 2024/1183, Art. 5b(3): "Relying parties shall not request users to provide data other than that indicated for their intended use."
2. GDPR (EU) 2016/679, Art. 5(1)(c): personal data must be "adequate, relevant and limited to what is necessary".
3. EUDI ARF, registration certificate, RPRC_07: the wallet checks that requested attributes are within the registration certificate and notifies the user otherwise.

## Who It Helps

Developers use it before registering a relying party, so they can catch an
over-ask locally and ship a smaller request.

Auditors and privacy reviewers use it to turn a raw registration or request into
a clear finding, with the purpose, extra data, basis, risk, and fix separated.

Product and policy people use it to understand what a relying party is asking
for without reading JWTs, DCQL, or registrar JSON.

## Plain-Language Rule

Start with the purpose. Then ask what data is truly needed to satisfy that
purpose. Everything else should be removed or explicitly justified.
