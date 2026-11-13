# Claim path test vectors

`fixtures/claim-paths/path-vectors.json` is a set of test vectors for one
question: is a requested claim within a registered claim? It pins the rules
`audit --cert`, `check` and `serve` use when they compare a request with a
registration (see `docs/COMMANDS.md`, "Registration comparison"). The file has
no dependency on the Workbench; any tool can read it.

Version 1.1 of the file holds 63 cases:

- 39 pointer cases (28 `dc+sd-jwt`, 11 `mso_mdoc`; 10 covered, 20 not_covered,
  9 invalid),
- 19 credential cases,
- 5 query cases (4 with a list of audited paths, 1 malformed).

## Format

The file is one JSON object. Its header keys:

- `title`, `version`, `licence`, `reuse`: what the file is, its version, and the
  reuse terms (see "Licence and reuse").
- `specification`: the specifications the cases cite (OpenID4VP 1.0 and EUDI
  TS5).
- `semantics`: the coverage rule in one paragraph (quoted below).
- `results`: the meaning of `covered`, `not_covered` and `invalid`.
- `pointer_defaults`: the credential metadata every pointer case uses.
- `credential_cases_description` and `query_cases_description`: the shape of
  the credential and query cases.

Then three case lists. Every case has an `id`, an `expected` result, a
`reason` in plain words, and the `section` of the specification it rests on.

`pointer_cases`: one registered credential and one requested path of the case
`format`. `registered` is a list of claim paths, `requested` is one claim path,
and `expected` is `covered`, `not_covered` or `invalid`. The credential type
comes from `pointer_defaults.meta`, so the credential always matches:

```json
{
  "id": "P05-index-under-null",
  "format": "dc+sd-jwt",
  "registered": [["memberships", null]],
  "requested": ["memberships", 2],
  "expected": "covered",
  "reason": "Null selects all elements of the array, so one element is within it.",
  "section": "OpenID4VP 1.0 section 7.1"
}
```

`credential_cases`: a list of `registered` credentials (format, meta, claim
paths) and one requested credential in `request`. A requested claim is either a
claim path or a DCQL claim object, and the request may carry `claim_sets`.
`expected` lists, in request order, every audited path with its result; a
`path` of `null` stands for the requested credential itself when it carries no
`claims` or its `claim_sets` select no claim:

```json
{
  "id": "C01-same-type",
  "registered": [
    { "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:example:membership:1"] }, "claims": [["member_name"]] }
  ],
  "request": { "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:example:membership:1"] }, "claims": [["member_name"]] },
  "expected": [{ "path": ["member_name"], "result": "covered" }],
  "reason": "Same format, same type, equal path.",
  "section": "OpenID4VP 1.0 section 6.1 and appendix B.3.5"
}
```

`query_cases` (added in version 1.1): a list of `registered` credentials and one
whole DCQL query in `query`, with `credentials` and `credential_sets`.
`expected` is the string `malformed` when the query must be rejected before any
audit, or a list, in request order, of every audited path with the `id` of the
credential query it belongs to and its result. A credential query that no
option of any credential set names has no entry:

```json
{
  "id": "Q01-credential-set-selects-named-credential-only",
  "registered": [
    { "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:example:membership:1"] }, "claims": [["member_name"]] }
  ],
  "query": {
    "credentials": [
      { "id": "club", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:example:membership:1"] }, "claims": [{ "path": ["member_name"] }] },
      { "id": "other", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:example:other:1"] }, "claims": [{ "path": ["member_since"] }] }
    ],
    "credential_sets": [{ "options": [["club"]] }]
  },
  "expected": [{ "credential": "club", "path": ["member_name"], "result": "covered" }],
  "reason": "Only credential queries that an option names are requested; the unregistered credential query that no option names is not audited.",
  "section": "OpenID4VP 1.0 sections 6.2 and 6.4.2"
}
```

All names in the file are invented (`urn:example:membership:1`,
`org.example.membership.1`, `member_name`); no case uses a real credential
type.

## What "covers" means

The file states the rule in its `semantics` field:

"A requested path is covered when one registered path of a matching credential selects, structurally, everything the requested path selects. Coverage is structural containment of claims path pointers: no concrete credential is evaluated, so array lengths and member existence play no role. JSON-based formats: a string selects an object member, a non-negative integer one array element, null every element of an array; a registered path covers an equal path, a path where the registered path has null and the requested path an integer at the same position, and every descendant of the paths it covers. mso_mdoc: a path is [namespace, data element identifier], exactly two strings, and is covered only by an equal registered path; a path of another shape is invalid on either side and covers nothing. Paths are compared segment by segment and never as joined strings; a string segment never equals an integer segment. Credentials are matched by format and type (vct_values for SD-JWT VC, doctype_value for mso_mdoc) before any path is compared, and a path is never covered by a credential of another format or type."

By kind of case:

- Pointer cases test the path rule alone. The registered and the requested
  credential always have the same format and type, so the result depends only
  on the two paths. `invalid` means the requested path is not a claims path
  pointer; the file's `results.invalid` says: "An invalid path is never
  covered, even by an equal registered path; a tool that does not reject it
  must report it as not_covered".
- Credential cases test the credential first: format and type are matched
  before any path is compared, a request that accepts several types must be
  within the registration for each, and a credential requested without claims
  is covered when its format and type are registered. With `claim_sets`, only
  claims named in some combination are audited.
- Query cases test which credential queries are requested at all. Every
  credential query named in any option of any credential set is audited,
  whether the set is required or not, and a credential query that no option
  names is not (OpenID4VP 1.0 section 6.4.2). A query with an empty option is
  `malformed`: section 6.2 requires every option to name at least one credential
  query.

That a registered null covers a requested index (case P05-index-under-null) is
the Workbench's stated reading of OpenID4VP 1.0 section 7.1, which says "If the
component is null, select all elements of the currently selected array(s).";
it is under discussion in
https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/issues/670
and is not a settled rule.

## How to run the cases

In this repository, `tests/claim_paths.rs` runs every case against the
Workbench engine; query cases go through the same DCQL parser that `audit
--request` uses:

```
cargo test --locked --test claim_paths
```

The same test file checks that the version 1 cases are unchanged, that every
case id is unique, that the file uses invented names only, and that a request
of exactly the registered claims of any registration fixture in the repository
is never flagged.

Another tool can read the JSON directly. For each case, build the registration
from `registered` (with `pointer_defaults.meta` for pointer cases), build the
request from `requested`, `request` or `query`, run its own comparison, and
compare the result with `expected`. A tool that does not reject an invalid path
reports it as `not_covered`. For example, with `jq`:

```
jq -r '.version' fixtures/claim-paths/path-vectors.json
jq '[.pointer_cases, .credential_cases, .query_cases] | map(length)' fixtures/claim-paths/path-vectors.json
jq -c '.pointer_cases[] | {id, format, registered, requested, expected}' fixtures/claim-paths/path-vectors.json
```

From version 1.1 on, each release attaches the file and its SHA-256 checksum
(`path-vectors.json` and `path-vectors.json.sha256`), so another project can
pin one version:

```
gh release download v0.4.1 --repo augenmass/augenmass-workbench --pattern 'path-vectors.json*' --dir vectors
(cd vectors && shasum -a 256 -c path-vectors.json.sha256)
```

## Licence and reuse

The file carries its own terms. `licence`: "Apache-2.0". `reuse`: "Licensed
Apache-2.0 like the Augenmass Workbench repository. Other tools may reuse,
copy and adapt this vector set; please keep the licence field."

## Version and change policy

`version` has the form MAJOR.MINOR; the version 1 file of release 0.4.0
(`"version": "1"`) reads as 1.0.

- A minor step adds cases or case lists. It never changes the id, the input or
  the expected result of an existing case, and it never changes the keys these
  depend on: `specification`, `semantics`, `results`, `pointer_defaults`, and
  the `*_description` key of every existing case list. `title` and the wording
  of `reuse` may change in a minor step.
- Any such change, a removed case, or a change of `licence` is a major step.
- A consumer should ignore top-level keys and case fields it does not know, so
  that a minor step does not break it.

Version 1.1 adds `query_cases_description` and `query_cases` (Q01 to Q05); the
39 pointer cases and 19 credential cases of version 1 are unchanged, which the
test `path_vectors_version_1_cases_are_unchanged` checks with a SHA-256 over
those cases and the keys they depend on.
