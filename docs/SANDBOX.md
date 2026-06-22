# Targets and sandbox

Augenmaß has exactly two write targets for `register` and `list`: the local `clone` (the default, fully offline) and the real `sandbox` registrar (a rehearsal path that needs credentials). Everything else in the toolkit runs offline with no target at all. This guide covers what each target is, how to drive the clone end to end, the safety rules that apply to both, and one ecosystem caveat to confirm at sandbox time.

## The clone target

The clone is a registrar-compatible local store: an axum HTTP server backed by SQLite, started with `augenmass clone serve`. It speaks the same registration endpoints as the real registrar, so the same `register` and `list` code paths exercise it. It does no signing, no auth, and no x5c. It stores payload-only JWTs: each stored certificate is `header.payload.fixture`, where the header is `{"typ":"rc-wrp+jwt","alg":"none"}`.

An unsigned, payload-only store is sound here because nothing in the workbench verifies a registration-certificate signature on either side. Every read path (`decode regcert`, `list`, the over-ask engine) decodes the payload only; there is no client-side crypto on the write path or the read path. The clone therefore reproduces the data shape the tool cares about (the WRPRC payload) without pretending to be a certificate authority. It is a faithful target for rehearsing the proportionality gate and the read-back loop, not a security model.

### Endpoints

The clone serves the registrar-compatible routes under its API base, both bare and under an `/api` prefix:

- `POST /registration-certificates` and `POST /api/registration-certificates`: write a registration.
- `GET /registration-certificates` and `GET /api/registration-certificates`: read registrations back.

### Running `clone serve`

```
augenmass clone serve
```

Flags (verified):

- `--db <DB>`: SQLite file path. Default `./augenmass-clone.sqlite`.
- `--port <PORT>`: listen port. Default `8080`.

So the default server listens on `http://127.0.0.1:8080` and persists to `./augenmass-clone.sqlite` in the current directory.

### AUGENMASS_CLONE_API_BASE

`register --target clone` and `list --target clone` resolve the clone URL from the `AUGENMASS_CLONE_API_BASE` environment variable, defaulting to `http://127.0.0.1:8080/api`. That default matches `clone serve` on its default port, so with no configuration at all the two halves line up.

If you serve on a non-default port, point both halves at it. For port 9090:

```
augenmass clone serve --port 9090
AUGENMASS_CLONE_API_BASE=http://127.0.0.1:9090/api augenmass list --target clone
```

The variable is documented in `.env.example` at the repo root; copy that to `.env` only if you want to override the defaults.

## The sandbox target

The `sandbox` target talks to the real registrar over HTTP. It is the only path in the toolkit that is not offline, and it is a rehearsal path: you use it to confirm a body the clone already accepted will be taken by the live registrar, off-stage, before any demo. It is not a production deployment path.

### Authentication: Keycloak resource-owner password grant

The sandbox registrar sits behind Keycloak. The tool obtains a bearer token with the OAuth 2.0 resource-owner password grant (`grant_type=password`). The `client_id` it sends is hardcoded to `swagger`. This matters: `swagger` is the client that works against the sandbox; substituting a project-specific client_id fails with `invalid_client`. You do not configure the client_id, you only supply the user credentials and the token endpoint.

### Environment variables

The sandbox path reads these (see `.env.example`):

- `AUGENMASS_API_BASE`: the registrar API base. Default `https://sandbox.eudi-wallet.org/api`.
- `AUGENMASS_OIDC_TOKEN_URL`: the Keycloak token endpoint. Required for `--target sandbox`.
- `AUGENMASS_USERNAME`: the resource-owner username. Required for `--target sandbox`.
- `AUGENMASS_PASSWORD`: the resource-owner password. Required for `--target sandbox`.
- `AUGENMASS_OIDC_CLIENT_SECRET`: optional; sent only when set.

If `AUGENMASS_OIDC_TOKEN_URL`, `AUGENMASS_USERNAME`, or `AUGENMASS_PASSWORD` is missing, the command fails with a message naming the missing variable, so a misconfigured sandbox run never silently degrades into an anonymous one.

### Rehearsal-only posture

Because the sandbox is live and credential-bound, treat it as a dress rehearsal: prove the body locally against the clone first, then run sandbox once to confirm acceptance. Keep the credentials in `.env`, never on the command line or in shell history.

## Safety rules (both targets)

These guardrails apply to every `register` invocation, clone or sandbox:

- Dry-run by default. `register` without `--yes` decodes, runs the over-ask and format gate, and prints the verdict, but writes nothing. The output ends with `DRY RUN: nothing written. Re-run with --yes to write to <target>.`
- `--yes` is required to write. It confirms the write after the gate passes.
- `--force` writes past an over-ask warning, and requires `--yes`. Without `--force`, an over-asking body is refused (exit 1) on every target. A blocking format error is fatal regardless of `--force`.
- Write only under our relying party id `2af138a8-59ea-4a84-aea3-666cafdb1369` ("Hackathon - Reza"). That id is the default for `--rp` on `list` and for `--rp` on `generate regbody`, and it is the `rpId` in `examples/min.json` and `examples/over.json`.
- One relying party per entity, many certificates under it. Never mint additional relying parties; add certificates to the existing one.
- Secrets hygiene. Never log, echo, or commit tokens, certs, or keys. The repo gitignores `.env*`, `secrets*.md`, `*.sqlite`, and `*signing-key*`. Review staged changes before any git operation.

## Worked clone walkthrough

This sequence is verified against the real binary. Open two shells, both at the repo root.

Shell 1: start the clone and leave it running.

```
augenmass clone serve
```

It prints its listen address, for example `clone target listening on http://127.0.0.1:8080/api`.

Shell 2: dry-run first (default), then write the proportionate body.

```
augenmass register examples/min.json --target clone
```

```
OK: no over-ask, no format errors. examples/min.json is ready to register.
DRY RUN: nothing written. Re-run with --yes to write to clone.
```

Now write it:

```
augenmass register examples/min.json --target clone --yes
```

```
OK: no over-ask, no format errors. examples/min.json is ready to register.
Writing to clone under RP 2af138a8-59ea-4a84-aea3-666cafdb1369...
Wrote registration 6272cc79-fec7-4e10-804d-3a52e6a6d8c5 to clone.
```

Read it back:

```
augenmass list --target clone
```

```
1 registration(s) for RP 2af138a8-59ea-4a84-aea3-666cafdb1369 on clone:

- 6272cc79-fec7-4e10-804d-3a52e6a6d8c5  purpose: "Age verification"
    claims: age_equal_or_over.18
```

(The registration id is generated per write, so yours will differ.)

### The over-ask refusal

`examples/over.json` declares the same age-verification purpose but requests six attributes (`given_name`, `family_name`, `birthdate`, `address.resident_street`, `address.resident_city`, `nationalities`). Even with `--yes`, the write is refused:

```
augenmass register examples/over.json --target clone --yes
```

```
OVER-ASK: Over-ask vs purpose: 6 of 6 requested claims exceed the stated purpose.
Purpose: Age verification   Baseline: Age gate (over 18)

Requested claims:
  [over]  given_name                   Registered, but beyond what the stated purpose needs.
  [over]  family_name                  Registered, but beyond what the stated purpose needs.
  [over]  birthdate                    Registered, but beyond what the stated purpose needs.
  [over]  address.resident_street      Registered, but beyond what the stated purpose needs.
  [over]  address.resident_city        Registered, but beyond what the stated purpose needs.
  [over]  nationalities                Registered, but beyond what the stated purpose needs.

Over-asking 6 claim(s) beyond the stated purpose.

Suggested minimal request:
  age_equal_or_over.18

Legal basis:
  eIDAS Regulation (EU) 2024/1183, Art. 5b(3)
    Relying parties shall not request users to provide data other than that indicated for their intended use.
  GDPR (EU) 2016/679, Art. 5(1)(c)
    Personal data shall be adequate, relevant and limited to what is necessary (data minimisation).
  EUDI ARF, registration certificate, RPRC_07
    The wallet verifies requested attributes are within the registration certificate and notifies the user otherwise.

Refusing to write: this request over-asks (see above). Re-run with --yes --force to write it anyway.
```

The command exits 1, so CI catches it. To deliberately write the over-asking body anyway you must add `--force`:

```
augenmass register examples/over.json --target clone --yes --force
```

That reprints the same verdict, then writes with an explicit warning (`Warning: writing an over-asking registration because --force was given.`) and exits 0. Use `--force` only when over-asking is intentional and justified; the default refusal is the point of the gate.

The same gate runs before a write to either target, so a body that the clone refuses will be refused against the sandbox too. Prove proportionality locally, then rehearse against the sandbox.

## Caveat to verify at sandbox time: VCT URN vs @IsUrl

`examples/min.json` and `examples/over.json` set the credential vct to the German PID URN `urn:eudi:pid:de:1`, which is correct: a vct can be a URN, not only a URL. Some registrar DTO validators have been seen to annotate that field as a URL (an `@IsUrl`-style constraint), which would reject a valid URN. The local clone does not enforce this, so a body that passes the clone can still be refused by the live registrar on a vct-format technicality.

When you first rehearse against `--target sandbox`, confirm the registrar accepts the URN vct. If it rejects `urn:eudi:pid:de:1` as not a URL, that is a registrar-side validation bug, not a problem with the body; the URN is the spec-correct value. Note it as an ecosystem trap rather than relaxing the body, and raise it with the registrar.
