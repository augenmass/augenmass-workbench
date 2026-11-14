# Baseline files

A baseline file states, for one or more use cases, which claims a request needs (the minimal claims), which claims may be asked instead (acceptable alternatives), and which claims the author leaves open. `augenmass audit --baseline FILE` and `augenmass check BODY --baseline FILE` judge a request or a registration body against one entry of such a file, in place of the four built-in purpose baselines.

A baseline file is its author's assessment, not law and not legal advice. The tool reports what the file says; it does not check that the file is right. Every result under a baseline file names the file, the entry, its version and its status, and ends with the sentence "A baseline file is its author's assessment, not law and not legal advice."

This page describes format version `augenmass-baselines/0.1`. It is not part of the released 0.4.1 binaries; it is on the main branch and listed under `[Unreleased]` in `CHANGELOG.md`.

## Try it

The repository ships a synthetic example, `examples/baselines-example.json`. Its shop, its age rules and its legal source are invented for the example and marked as invented in the file. Run it from the repository root:

```
augenmass audit --request examples/age-minimal-request-sdjwt.json --baseline examples/baselines-example.json --purpose example.wine-shop.age-check.wine
```

```
OK: Within the purpose-minimal baseline; registration not evaluated.
Purpose: not stated   Baseline: Example Wine Shop: age check for an order of wine
Baseline file: baselines-example.json   entry: example.wine-shop.age-check.wine   version: 0.1   status: draft
draft baseline, no legal review
Applies when (stated by the baseline, not checked by this tool): the order holds wine and no spirits (invented rule: wine is sold from 18)

Requested claims:
  [ok]  age_equal_or_over.18         Minimal under this baseline entry.

A baseline file is its author's assessment, not law and not legal advice.
```

The same request against the entry for orders with spirits, whose minimal claim is the threshold 21, is an over-ask (exit 1):

```
augenmass audit --request examples/age-minimal-request-sdjwt.json --baseline examples/baselines-example.json --purpose example.wine-shop.age-check.spirits
```

## The format

A baseline file is one JSON object. JSON has no comments, so the annotated shape is given as a list below the example.

```json
{
  "schema": "augenmass-baselines/0.1",
  "info": { "note": "free form, never read" },
  "entries": [
    {
      "id": "example.wine-shop.age-check.wine",
      "version": "0.1",
      "status": "draft",
      "reviewer": null,
      "label": "Example Wine Shop: age check for an order of wine",
      "applies_when": "the order holds wine and no spirits (invented rule: wine is sold from 18)",
      "claims": [
        {
          "format": "dc+sd-jwt",
          "vct_values": ["urn:eudi:pid:de:1"],
          "minimal": [
            { "path": ["age_equal_or_over", "18"], "one_of": "age-claim" }
          ]
        },
        {
          "format": "mso_mdoc",
          "doctype_value": "eu.europa.ec.eudi.pid.1",
          "minimal": [
            { "path": ["eu.europa.ec.eudi.pid.de.1", "age_over_18"], "one_of": "age-claim" }
          ],
          "alternatives": [
            {
              "path": ["eu.europa.ec.eudi.pid.1", "age_over_18"],
              "one_of": "age-claim",
              "reason": "Invented for this example: the same yes-or-no answer, named in the other namespace of the PID."
            }
          ]
        }
      ],
      "one_of": [
        { "id": "age-claim", "reason": "invented rule: one age answer is enough for one order" }
      ],
      "legal_sources": [
        {
          "instrument": "Invented Example Ordinance (not a real law, written for this example file)",
          "locator": "section 1 (invented)",
          "quote": "Invented for this example: wine is sold only to buyers aged 18 or over, spirits only to buyers aged 21 or over."
        }
      ]
    }
  ]
}
```

The document:

- `schema` (required): exactly `"augenmass-baselines/0.1"`.
- `info` (optional): free form, never read.
- `entries` (required): a non-empty list of entries.

An entry:

- `id` (required): unique in the file; letters, digits, `.`, `_` and `-`, starting with a letter or a digit. It may not be the id of a built-in purpose (`age_gate_18`, `event_checkin`, `car_rental`, `bank_kyc`), so that no id means two things.
- `version` (required): a non-empty string, printed.
- `status` (required): `"draft"` or `"reviewed"`.
- `reviewer`: `null` or a non-empty string; required when the status is `"reviewed"`.
- `label` (optional): printed as the baseline label; the id is printed when it is absent.
- `applies_when` (optional): the case the entry is written for, as free text. It is printed on every result. An entry that has it is applied only when it is named with `--purpose` (see "Selecting an entry").
- `claims` (required): a non-empty list of credential blocks. At least one block has a `minimal` row.
- `one_of` (optional): the groups that rows refer to, each `{ "id": ..., "reason": ... }`. A group needs at least two rows.
- `legal_sources` (required, may be empty): each `{ "instrument", "locator", "quote" }` (required, non-empty) with the optional `url` (http or https), `retrieved` and `note`. They are carried in `--json`; the text output prints their number.
- `info` (optional): free form, never read.

A credential block:

- `format` (required): `dc+sd-jwt`, `vc+sd-jwt` or `mso_mdoc`. A `dc+sd-jwt` block does not judge a `vc+sd-jwt` request; the format must match exactly.
- the credential type, named as in the DCQL `meta` object of a request: `vct_values` (a non-empty list of distinct strings) for the SD-JWT VC formats, `doctype_value` (a string) for `mso_mdoc`. Two blocks of one entry may not model the same format and type. One entry may hold several blocks of one format with different types, for example the PID mdoc and the Proof of Age mdoc.
- `minimal`: rows `{ "path": [...], "one_of": "group id" }` (`one_of` optional). The claims the entry's case needs.
- `alternatives`: rows with a required `reason`. Claims that may be asked instead of a minimal claim; they are not an over-ask.
- `undecided`: rows with a required `reason`. Claims the author leaves open; a requested claim that matches one is not evaluated.

A block has at least one row in one of the three lists.

A path is an OpenID4VP claims path pointer with typed segments: a string, a non-negative integer, or `null`. `["age_equal_or_over", "18"]` and `["age_equal_or_over", 18]` are different paths. For `mso_mdoc` a path is exactly two strings, `[namespace, element]`.

A requested path matches a row by the coverage rule of the registration comparison (`docs/COMMANDS.md`, section "Registration comparison"): in the SD-JWT VC formats a row covers its own path and every path below it, and `null` covers every array index; in `mso_mdoc` only an equal path matches. Two rows of one block may not overlap, in the same list or across lists: no path may be covered by both. That excludes equal paths, a row that covers another, and two rows of which neither covers the other but both cover a common path, for example `["a", null, 0]` and `["a", 0, null]` (both cover `["a", 0, 0]`). So a requested path matches at most one row and no result depends on the order of rows.

Which members decide something:

| Kind | Members |
|---|---|
| Machine-read: they decide a verdict, a label or the selection | `schema`, `entries[].id`, `version`, `status`, `reviewer`, whether `applies_when` is present, `format`, `vct_values`, `doctype_value`, every `path`, every `one_of`, `one_of[].id` |
| Free text that is printed | `label`, the text of `applies_when`, every `reason`, the members of `legal_sources` |
| Never read | `info`, at file and at entry level |

## Strict parsing

A file that does not match the format is an error, never a partial pass. The error is printed on stderr as `Error: baseline file <file name>: <where>: <what>`, nothing is printed on stdout, and the exit code is 1. The tool rejects, among others:

- a document that is not JSON, not an object, or names one member twice in an object;
- a missing or different `schema`;
- any member that is not listed above, at any level except inside `info` (this catches a misspelt machine field such as `vct_value` or `minimial`, and a row member such as `when` or `condition`);
- an empty `entries` list, a duplicate entry id, an id with other characters, or the id of a built-in purpose;
- a missing or empty `version`, a `status` other than `draft` or `reviewed`, a `reviewed` entry without a reviewer;
- an entry without `claims`, a `claims` that is not a non-empty list, a block without rows, an entry without any `minimal` row;
- a block format other than the three above, a type member that does not fit the format, two blocks with the same format and type;
- a malformed path (not a non-empty list; a segment that is a negative or fractional number, a boolean, an object, or an empty string; an mdoc path that is not two strings);
- overlapping rows in one block (the error names both rows and a path that both cover);
- an alternative or undecided row without a `reason`;
- a row that names an undeclared group, a group with fewer than two rows, a duplicate group id, a group without a `reason`;
- a legal source without `instrument`, `locator` or `quote`, or with a `url` that is not http or https.

For example, a registration body passed as a baseline file:

```
augenmass audit --request examples/age-minimal-request-sdjwt.json --baseline examples/min.json
```

```
Error: baseline file min.json: the document: unknown member "rpId" (known members: schema, info, entries)
```

## Selecting an entry

One run judges against one entry.

- `--purpose <entry id>` selects it. With `--baseline`, `--purpose` names an entry of the file, never a built-in purpose.
- `--purpose` may be left out only when the file has exactly one entry and that entry has no `applies_when`. An entry that holds only in a stated case is never applied without being named.
- Without `--purpose` where one is needed, the run is a usage error (exit 2) that lists the entry ids with their `applies_when` text. An id that is not in the file is a usage error that lists the ids; when the id is a built-in purpose id the message adds that it is not used together with `--baseline`.
- `check --purpose` without `--baseline` is a usage error. `register` has no `--baseline`; it uses the built-in check.

```
augenmass audit --request examples/age-minimal-request-sdjwt.json --baseline examples/baselines-example.json
```

```
error: baseline file baselines-example.json has 3 entries; name the one to judge against with --purpose <entry id>:
  example.wine-shop.age-check.wine  applies when: the order holds wine and no spirits (invented rule: wine is sold from 18)
  example.wine-shop.age-check.spirits  applies when: the order holds spirits (invented rule: spirits are sold from 21)
  example.wine-shop.loyalty-card

Usage: augenmass audit [OPTIONS]

For more information, try '--help'.
```

Format 0.1 has no conditions inside an entry. A rule with cases (one threshold for one kind of order, another for another) is written as one entry per case, and each entry says in `applies_when` which case it is. The user states the case by naming the entry. The tool cannot see the case: a user who names the wrong entry gets the verdict for the wrong case, and the "Applies when" line on every result is the only guard.

## Results

Each requested claim gets one result:

| Result | Tag | `status` in `--json` | Line printed |
|---|---|---|---|
| minimal | `[ok]` | `MinimalForPurpose` | `Minimal under this baseline entry.` |
| acceptable alternative (not an over-ask) | `[alt]` | `AcceptableAlternative` | `Acceptable alternative, not an over-ask. Reason stated by the baseline: <reason>` |
| beyond the baseline (over-ask) | `[over]` | `BeyondPurpose` | `Beyond the baseline: not a minimal claim and not an acceptable alternative of entry <id> for <format>, <type>.` |
| not evaluated | `[n/a]` | `NotEvaluated` | the reason, see below |

A claim is not evaluated when:

- the entry has no block for the credential's format (`Not evaluated: entry <id> does not model the format <format>.`);
- the entry has no block for the credential's type (`Not evaluated: entry <id> does not model the credential type <type> in format <format>. It models ...`);
- the request names no credential type (`Not evaluated: the request names no credential type (meta.vct_values or meta.doctype_value), so the baseline cannot tell which credential is asked for.`);
- the claim matches an `undecided` row (`Not evaluated: the baseline leaves this claim open. Reason stated by the baseline: <reason>`);
- the credential accepts several types and one of them has no block, while the claim is within the entry under the others. A claim beyond the entry under any modelled type is an over-ask.

The request-level result and the exit code follow the same rule as for the built-in baselines (`docs/COMMANDS.md`, section "Exit codes"): OVER-ASK (exit 1) when any judged claim asks for too much; otherwise NOT EVALUATED (exit 3) when a claim could not be judged; otherwise OK (exit 0). An acceptable alternative counts as within the baseline.

An acceptable alternative, with its reason:

```
augenmass audit --request examples/age-minimal-request-mdoc.json --baseline examples/baselines-example.json --purpose example.wine-shop.age-check.wine
```

```
OK: Within the purpose-minimal baseline; registration not evaluated.
Purpose: not stated   Baseline: Example Wine Shop: age check for an order of wine
Baseline file: baselines-example.json   entry: example.wine-shop.age-check.wine   version: 0.1   status: draft
draft baseline, no legal review
Applies when (stated by the baseline, not checked by this tool): the order holds wine and no spirits (invented rule: wine is sold from 18)

Requested claims:
  [alt]  eu.europa.ec.eudi.pid.1.age_over_18 Acceptable alternative, not an over-ask. Reason stated by the baseline: Invented for this example: the same yes-or-no answer, named in the other namespace of the PID.

A baseline file is its author's assessment, not law and not legal advice.
```

A claim the entry leaves open (exit 3):

```
augenmass audit --request '{"credentials":[{"id":"card","format":"dc+sd-jwt","meta":{"vct_values":["urn:example:loyalty:1"]},"claims":[{"path":["member_id"]},{"path":["tier"]}]}]}' --baseline examples/baselines-example.json --purpose example.wine-shop.loyalty-card
```

```
NOT EVALUATED: 1 of 2 requested claims could not be judged.
Purpose: not stated   Baseline: Example Wine Shop: loyalty card at checkout
Baseline file: baselines-example.json   entry: example.wine-shop.loyalty-card   version: 0.1   status: draft
draft baseline, no legal review

Requested claims:
  [ok]  member_id                    Minimal under this baseline entry.
  [n/a]  tier                         Not evaluated: the baseline leaves this claim open. Reason stated by the baseline: Invented for this example: whether the discount tier is needed at checkout is left open.

Not evaluated: 1 claim(s). No judged claim asks for too much; exit code 3.

Minimal claims of this baseline entry (dc+sd-jwt, urn:example:loyalty:1):
  ["member_id"]

A baseline file is its author's assessment, not law and not legal advice.
```

Under OVER-ASK and NOT EVALUATED the output lists the entry's minimal claims and acceptable alternatives per block, and the reason of each `one_of` group, in place of the built-in "Suggested minimal request". The three built-in legal basis entries are still printed under OVER-ASK, followed by `Sources stated by the baseline: <n> (see --json).`

## The one-of rule

A `one_of` group says that a request may ask for one of its rows, not for two. The example's group `age-claim` holds every age claim of the wine entry: one age answer is enough.

- What is counted: matched rows, one per requested credential. Two requested paths of one credential that the same row covers count once. The same row matched in two credentials of the request counts twice. Rows of all three lists count, an `undecided` row included.
- When two rows count as asked together: unless the request proves that one response cannot hold both. Two claims of one credential are apart only when the credential has `claim_sets`, every id in it resolves, no option names both, and the credential does not set `multiple` to true. With `multiple`, one response can hold several credentials of that query, each answering another `claim_sets` option, so the claims count as asked together (the line then ends with `The credential query sets multiple, so one response can hold several credentials, each answering another claim_sets option.`). Two rows in different blocks that one credential matches (a credential that accepts several types) count as asked together only when it sets `multiple`: one returned credential has one type. Two credentials are apart only when the request has `credential_sets`, every id in it resolves, both credentials occur in options of one and the same set, and no option of that set names both. In every other case, including an id in `claim_sets` or `credential_sets` that the request does not carry, they count as asked together (OpenID4VP 1.0, sections 6.1, 6.4.1 and 6.4.2).
- What the line counts: `this request asks for <n> of them, and <m> of these can each be returned in one response together with another claim of the group.` `<n>` is the number of rows of the group the request matches, `<m>` the number of those with at least one partner in a response. The line does not say that one response holds all `<m>` at once.
- In `audit`, every claim of a broken group is beyond the baseline (an over-ask). In `check`, a registration body lists everything a party may ask for across its requests, so two rows of one group are not evaluated (exit 3), with the line `Not evaluated: entry <id> allows one claim of the group "<group>" per request. A registration may list more than one where the intended use needs each; this tool cannot check that.`

Both PID formats required together break the group (exit 1):

```
augenmass audit --request '{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:de:1"]},"claims":[{"path":["age_equal_or_over","18"]}]},{"id":"pid-mdoc","format":"mso_mdoc","meta":{"doctype_value":"eu.europa.ec.eudi.pid.1"},"claims":[{"path":["eu.europa.ec.eudi.pid.1","age_over_18"]}]}]}' --baseline examples/baselines-example.json --purpose example.wine-shop.age-check.wine
```

```
OVER-ASK: Over-ask vs purpose: 2 of 2 requested claims exceed the stated purpose.
...
Requested claims:
  [over]  age_equal_or_over.18         Beyond the baseline: entry example.wine-shop.age-check.wine allows one claim of the group "age-claim" per request (invented rule: one age answer is enough for one order); this request asks for 2 of them, and 2 of these can each be returned in one response together with another claim of the group.
  [over]  eu.europa.ec.eudi.pid.1.age_over_18 Beyond the baseline: entry example.wine-shop.age-check.wine allows one claim of the group "age-claim" per request (invented rule: one age answer is enough for one order); this request asks for 2 of them, and 2 of these can each be returned in one response together with another claim of the group.
```

The same two credentials offered as options of one credential set pass (exit 0), because the wallet returns one of them:

```
augenmass audit --request '{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:de:1"]},"claims":[{"path":["age_equal_or_over","18"]}]},{"id":"pid-mdoc","format":"mso_mdoc","meta":{"doctype_value":"eu.europa.ec.eudi.pid.1"},"claims":[{"path":["eu.europa.ec.eudi.pid.1","age_over_18"]}]}],"credential_sets":[{"options":[["pid"],["pid-mdoc"]]}]}' --baseline examples/baselines-example.json --purpose example.wine-shop.age-check.wine
```

## What every result names

The text output names, under the purpose line:

```
Baseline file: <file name>   entry: <id>   version: <version>   status: <status>
```

The file is named by its file name only, also when the argument was a path with directories. Text that comes from the baseline file or from the request (the label, the version, `applies_when`, every reason, credential types, claim paths) is printed on one line each: a line break, any other control character, and the Unicode characters that separate lines or change the reading direction are printed as an escape such as `\n` or `\u{1b}`. A path that is printed as a JSON array (the lines under `Minimal claims of this baseline entry` and `Acceptable alternatives of this baseline entry`) uses the JSON escape instead, for example `\u202e`, so the array stays valid JSON and can be pasted into a DCQL `path`. A file can therefore not print a second `Baseline file` line or remove the status line and the draft label on a terminal. `--json` carries the strings as the file has them. An entry whose status is not `reviewed` is labelled `draft baseline, no legal review`. A `reviewed` entry prints `reviewed by <reviewer> (as stated by the baseline file)`; the tool cannot check that statement. The `Applies when` line follows when the entry has `applies_when`, and every result ends with the assessment sentence.

`check --baseline` names the file, the entry, its version and its status also when it prints no report (a body that passes, a format error).

The same facts are in `--json`, in the member `baseline`:

```
augenmass audit --request examples/age-minimal-request-mdoc.json --baseline examples/baselines-example.json --purpose example.wine-shop.age-check.wine --json
```

An excerpt of its output (the full `claims` list holds every block of the entry):

```
"outcome": "ok",
"baseline": {
  "source": "file",
  "file": "baselines-example.json",
  "schema": "augenmass-baselines/0.1",
  "entry_id": "example.wine-shop.age-check.wine",
  "label": "Example Wine Shop: age check for an order of wine",
  "version": "0.1",
  "status": "draft",
  "reviewer": null,
  "legal_review": false,
  "notice": "draft baseline, no legal review",
  "applies_when": "the order holds wine and no spirits (invented rule: wine is sold from 18)",
  "assessment_notice": "A baseline file is its author's assessment, not law and not legal advice.",
  "credential_types": [ ... ],
  "claims": [ ... ],
  "one_of": [ ... ],
  "legal_sources": [ ... ]
},
"baseline_label": "Example Wine Shop: age check for an order of wine",
"baseline_note": "draft baseline, no legal review. A baseline file is its author's assessment, not law and not legal advice.",
```

Under a baseline file, `suggested_minimal` and `suggested_minimal_request` are `null`, `counts.acceptable_alternative` counts the acceptable alternatives, and `legal_basis` keeps the three built-in entries. `applies_when` and `reviewer` are `null` when the entry has none. In `check --json` the same member appears as `report.baseline`, and as a top-level `baseline` member.

## What format 0.1 does not express

- Conditions inside an entry. A row holds whenever its entry applies; a rule with cases is one entry per case (see "Selecting an entry").
- Patterns. A row is one path. "Any `age_over_NN`" cannot be a row; each threshold is its own row.
- A registration that serves several cases. `check --baseline` judges a body under one entry, so a registration that lists the thresholds of two cases is reported against one of them.
- Values. A baseline judges what a request asks for, not the values a wallet returns.
- A credential requested without `claims`. When the entry models its format and type, it gets no row and is not judged.
- Per-claim reasons for an over-ask. A claim beyond the baseline gets one general line; the file has no rows for claims that are beyond it.
- Other credential formats. A block is `dc+sd-jwt`, `vc+sd-jwt` or `mso_mdoc`.

## How to write a baseline file

1. Copy `examples/baselines-example.json` and replace the entries. Keep `"schema": "augenmass-baselines/0.1"`.
2. Give each entry an id of your own (not a built-in purpose id), a version, and the status `draft` until someone has reviewed it; then set `reviewed` and name the reviewer.
3. Write one entry per case. If the entry holds only in a stated case, say so in `applies_when`.
4. For each credential type the case accepts, add a block with its format and its type, copied from the `meta` of a request. Put the claims the case needs under `minimal`, claims that may be asked instead under `alternatives` with a reason, and claims you leave open under `undecided` with a reason. Copy each path from the request in its typed form.
5. If a request may ask for only one claim of a set (for example one age threshold), give those rows the same `one_of` group and declare the group with its reason.
6. List the legal sources the entry rests on, each with instrument, locator and a verbatim quote. Mark anything that is not a verbatim quote as such in the quote or in `note`.
7. Run your requests against the file with `augenmass audit --request <request> --baseline <file> --purpose <entry id>`. A file that does not load prints the place and the problem.
