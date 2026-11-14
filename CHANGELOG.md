# Changelog

All notable changes to the Augenmaß Workbench are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

House style note: this file does not carry release dates. The project does not
imply wall-clock timing for releases.

## [Unreleased]

The changes below, except the plugin bundle entry, are on the main branch and
not in the 0.4.1 binaries (the release archives and the binaries bundled in the
plugin). The version number stays 0.4.1 until the next release.

### Changed

- Exit codes of `check`, `audit` and `register`: a new result, NOT EVALUATED,
  with the new exit code 3. Exit code 0 now means that everything that was
  asked to be checked was checked and no requested claim asks for too much
  (one exception: a write forced with `register --yes --force` exits 0 when
  the write succeeded, see below).
  NOT EVALUATED is printed when no judged claim asks for too much and the
  purpose baseline or the registration comparison could not judge at least one
  requested claim, and by `audit` also for a query with a member name that
  resembles a defined one (the next entry). OVER-ASK keeps exit code 1 and
  wins over NOT EVALUATED. The
  headline, the per-claim lines (`[n/a]`), the new `outcome` member of `--json`
  and the exit code agree in every case but the forced write. Scripts that
  treat every non-zero code
  as a failure keep working; scripts that test for exit code 1 need a case for
  3. Several requests that exited 0 or 1 now exit 3 (the entries below). All
  exit codes are in one table in `docs/COMMANDS.md`.
- `audit` no longer prints OK for a DCQL query with a member that OpenID4VP 1.0
  does not define at its level and that resembles a defined one. Example: a
  credential query that says `claim` for `claims` and lists `given_name`,
  `birthdate` and `address` under it. A wallet ignores a member it does not
  know (OpenID4VP 1.0, section 6: "Implementations MUST ignore any unknown
  properties."), so 0.4.1 read such a query as a request for no claim and
  printed `OK: No claims requested.` with exit code 0, where the correctly
  spelled query is an OVER-ASK with exit code 1. The result is now NOT
  EVALUATED with exit code 3, with the reason line `Not evaluated: 1 member(s)
  of the query that a wallet ignores unless it knows them from an extension.`
  and the warning described under "Added". A request that over-asks stays
  OVER-ASK with exit code 1 and lists the warning. A request that was OK and
  has such a member (for example `value` for `values`, or `credential_set` for
  `credential_sets`) changes from exit code 0 to 3. A script that reads exit
  code 0 of `audit` as "nothing asks for too much" is not affected by a
  correctly spelled query. Limit: an extension may define a member whose name
  differs from a defined one only in the ways the warning covers (for example
  a plural ending, a separator or upper and lower case); `audit` reports it
  too, and this version has no option to accept it (`docs/COMMANDS.md`,
  `audit`).
- Text output of `audit`, `check` and `register`: the line under the headline
  reads `Registration purpose: <text>   Baseline: <label>` (before: `Purpose:
  <text>   Baseline: <label>`). Its first value is the purpose text of the
  registration, not the id given with `--purpose`, so it now says `no
  registration given` when no registration certificate was given (before: `not
  stated`, also when `--purpose` was given) and `not stated in the
  registration` when the registration has no purpose text, or a purpose text
  that shows nothing: empty, or only white space, code points that Unicode
  16.0.0 lists with the property Default_Ignorable_Code_Point (for example
  U+200B, U+034F and U+FE0F) and the blank Braille pattern U+2800. The
  bidirectional formatting characters among them are printed as their escape
  instead. A script that matches the old line needs the new label. No `--json`
  member changes.
- `audit --purpose <unknown id>` is a usage error with exit code 2 that names
  the id and lists the valid ids, with nothing on stdout. Before, it printed
  `OK` with exit code 0 and a note on stderr, without any purpose check.
  `serve --purpose <unknown id>` (also through the `PURPOSE` environment
  variable) fails at startup the same way; before, the server started without a
  purpose check.
- A claim of a credential format the baselines do not model (anything but
  `dc+sd-jwt`, `vc+sd-jwt` and `mso_mdoc`, for example `jwt_vc_json` or
  `ldp_vc`) is not evaluated, with the line `Not evaluated: the purpose
  baselines model only SD-JWT VC (dc+sd-jwt, vc+sd-jwt) and mso_mdoc claim
  paths, not the format <format>.` In 0.4.1 it was counted as beyond the
  purpose (`BeyondPurpose`, `Purpose not judged for this credential format`)
  and exited 1.
- The four built-in baselines state the credential types they model: SD-JWT VC
  (`dc+sd-jwt`, `vc+sd-jwt`) with vct `urn:eudi:pid:de:1` or `urn:eudi:pid:1`,
  and `mso_mdoc` with doctype `eu.europa.ec.eudi.pid.1`. A requested credential
  of another type (for example the mDL doctype `org.iso.18013.5.1.mDL`, the
  Proof of Age doctype `eu.europa.ec.av.1`, or a non-PID vct), or one whose
  `meta` names no type, is not evaluated. Before, its claims were judged against
  PID claim names, which gave OK or OVER-ASK depending on whether a claim name
  happened to match. A credential that accepts several types is judged per
  type: a claim beyond the baseline under a PID type is still an over-ask; a
  claim within it is not evaluated when another accepted type is not modelled.
  Verdicts for PID requests are unchanged, including the claims each baseline
  treats as minimal.
- A credential without `claims` of a format or type the baseline does not model
  gets one not evaluated row (`<id> (credential, no claims)`). Before, the
  request printed `OK: No claims requested.` and exited 0. A PID credential
  without claims is unchanged.
- The registration comparison (`audit --cert`, and the body itself in `check`)
  for a credential format whose type it does not read (anything but the SD-JWT
  VC formats and `mso_mdoc`): when a registered credential of the same format
  covers the requested path, the claim is not evaluated against the
  registration. Before, it was reported as outside the registered scope ("No
  registered credential of this format and type"), so `check` called such a
  body an over-ask against itself. When no registered credential of that format
  covers the path, the claim is still beyond the registration, exit 1, with the
  line `Not in the registered scope: no registered <format> credential covers
  this path, whatever its type.` when the registration holds credentials of
  that format.
- `register` refuses a body that was not evaluated unless `--yes --force` is
  given, with exit code 3, also in a dry-run: `Refusing to write: this request
  could not be evaluated (see above). Re-run with --yes --force to write it
  anyway.` With `--yes --force` it writes with a warning. The over-ask and
  format-error refusals are unchanged.
- `register --force` without `--yes` is a usage error with exit code 2,
  before the body is read. In 0.4.1 the flag was accepted alone: an
  over-asking body then skipped the refusal and ended as a dry-run with exit
  code 0 under the headline OVER-ASK. The help text of `--force` names both
  cases it writes past (an over-ask, a body that could not be evaluated).
- `register --yes --force`: the warning line printed before a forced write
  ends with `A forced write that succeeds exits 0.` (`Warning: writing an
  over-asking registration because --force was given. A forced write that
  succeeds exits 0.`, and the same for `a registration that could not be
  evaluated`). The exit code of a forced write is unchanged: 0 when the write
  succeeded, under the headline OVER-ASK or NOT EVALUATED. It is the one case
  in which exit code 0 does not mean that the body was judged and passed; the
  exit code table in `docs/COMMANDS.md` says so.
- "Suggested minimal request" for a PID requested as `vc+sd-jwt` (the earlier
  SD-JWT VC format identifier, vct `urn:eudi:pid:de:1` or `urn:eudi:pid:1`) is
  printed as claim paths, like for `dc+sd-jwt`. Before, the block said `No
  claim names are known for this credential type.` although the claims of
  that credential were judged as PID claims.
- Text output of `audit`, `check` and `register`: strings that come from a
  request, a registration or a baseline file (claim paths, credential types,
  the purpose text, format findings) are printed on one line each. A line
  break, any other control character, and the Unicode characters that
  separate lines or change the reading direction are printed as an escape
  such as `\n` or `\u{1b}`. A path of a baseline file that is
  printed as a JSON array (its minimal claims and acceptable alternatives)
  uses the JSON escape instead, for example `\u202e`, so the array stays
  valid JSON. `--json` is unchanged.
- `check --json`: `block` is true whenever `outcome` is not `ok`, so a body
  that was not evaluated blocks (`overAsk` stays false for it).
- `audit --help`: the `--purpose` text names the default `event_checkin` and
  says that an unknown id is a usage error.
- The note of the built-in baselines, the last line of `augenmass baselines`,
  and the footers of the `serve` pages say that the baselines are curated
  assessments, not law and not legal advice (before: "taste judgment, not a
  Rulebook derivation").
- The GDPR line of the printed legal basis (text output, `--json`
  `legal_basis`, `baselines`, the `serve` inspect page) quotes Article 5(1) of
  Regulation (EU) 2016/679 verbatim from its opening words and point (c), with
  the omitted points marked: `Personal data shall be: [...] (c) adequate,
  relevant and limited to what is necessary in relation to the purposes for
  which they are processed (‘data minimisation’);`. Before, it was a
  paraphrase. The locator `Art. 5(1)(c)` is unchanged.
- `docs/COMMANDS.md`: `check` states its scope. The format checks apply to any
  registration body in the shape of the German sandbox registrar; without
  `--baseline`, the over-ask verdict is measured against the built-in
  `age_gate_18` baseline only, and other built-in purposes go through
  `audit --purpose` on the request. `README.md` links the
  new section of `docs/SANDBOX.md`. Documentation only, no change in behavior.
- `doctor`: a request whose `dcql_query` has a member that resembles a defined
  one (for example `claim` for `claims`, the rule of the entry on member names
  above) no longer gets the line `OK: no signed-request gotchas found.`
  `doctor` lists the member as the finding `DCQL-MEMBER-NEAR-MISS` with the
  severity `warning`, with the message and fix of `validate dcql`, and closes
  with `No blocking finding (warnings only).` The exit code does not change:
  it is 1 for a blocking finding (`DOCTOR-X5C-STRING`,
  `DOCTOR-CLIENT-ID-X509HASH`, both unchanged) and 0 otherwise, because a
  wallet ignores a member it does not know and the member may belong to an
  extension. `doctor --json` has the new member `warnings` (the array of
  `audit --json`, empty when there is no such member); `ok` is true when there
  is no blocking finding.
- Plugin bundle: the four target binaries under `plugins/augenmass-workbench/bin`
  and `bin/manifest.json` are rebuilt from the `v0.4.1` release archives with
  `just bundle`, so the plugin carries the 0.4.0 and 0.4.1 changes. Both plugin
  manifests (`.claude-plugin/plugin.json`, `.codex-plugin/plugin.json`) say
  version 0.4.1. The skill reference files quote Article 5b(3) and RPRC_21 as
  the binary prints them, show the `bank_kyc` baseline, the registration
  certificate notice, the suggested minimal request in the spelling of the
  request, the mdoc age request under `age_gate_18`, the `serve` startup banner,
  and the stderr notice for the built-in sandbox address as the 0.4.1 binary
  prints them. `docs/RELEASE.md` gains the section "v0.4.1 release proof".

### Added

- `audit --baseline FILE` and `check BODY --baseline FILE`: judge against one
  entry of a baseline file with the schema id `augenmass-baselines/0.1`
  instead of a built-in purpose baseline. `--purpose <entry id>` selects the
  entry; it may be left out only when the file has one entry that states no
  `applies_when`, so an entry written for a stated case is never applied
  without being named. `check` gains `--purpose` only together with
  `--baseline`. A built-in purpose id together with `--baseline`, an entry id
  that is not in the file, or a missing `--purpose` where one is needed is a
  usage error with exit code 2. Results per claim: minimal, acceptable
  alternative (`[alt]`, not an over-ask, the reason is printed), beyond the
  baseline (over-ask), not evaluated (a format or type the entry does not
  model, or a claim the entry leaves open). A `one_of` group allows one of its
  rows per request; two rows that one response can hold together are an
  over-ask in `audit` and not evaluated in `check` (`claim_sets` and
  `credential_sets` can keep two rows apart; `multiple: true` on a credential
  lets one response hold several credentials, so its `claim_sets` options no
  longer keep rows apart). Two rows of one block may not overlap: no path may
  be covered by both, which also excludes crossed wildcards such as
  `["a", null, 0]` and `["a", 0, null]`. Free text of the file (label,
  version, `applies_when`, reasons) is printed on one line each with control
  characters escaped, so a file cannot print a second `Baseline file` line or
  remove the draft label on a terminal. Every result names the file
  by file name only, the entry id, its version and its status; an entry that
  is not `reviewed` is labelled `draft baseline, no legal review`; every result
  ends with `A baseline file is its author's assessment, not law and not legal
  advice.` The same facts are in `--json` under `baseline`. A file that does
  not match the format (an unknown schema id, an unknown or misspelt member, a
  duplicate entry id, an entry without claims, a malformed or overlapping path,
  and more) is an error with exit code 1 and nothing on stdout, never a pass.
  A file that starts with a UTF-8 byte order mark is rejected with an error
  that names the mark. The error for overlapping rows quotes its paths as JSON
  arrays with the JSON escape, like the minimal and alternative rows.
  See `docs/BASELINES.md`.
- `examples/baselines-example.json`: a synthetic baseline file with three
  entries for an invented shop; its legal source is marked as invented.
- `docs/BASELINES.md`: the baseline file format, the results, the one-of rule,
  what format 0.1 does not express, and how to write a file.
- `--json` of `audit` and `check`: `outcome` (`ok`, `over_ask`,
  `not_evaluated`; `check` also `format_error`), `baseline` (which baseline the
  request was judged against: built-in with its credential types, or the facts
  of the baseline file entry), `counts.could_not_judge` and
  `counts.acceptable_alternative` (0 under a built-in baseline). `requested[].status`
  gains the value `AcceptableAlternative` (only under a baseline file).
  Existing members keep their names and types.
- An authoring warning for a member name of a DCQL query that resembles a
  defined one, in `validate dcql`, `inspect` and `audit`. It is printed for a
  member of the query object, of a credential query, of a claims query or of
  a credential set query whose name OpenID4VP 1.0 does not define at that
  level and that differs from a name it does define there only by the plural
  ending of a word, by upper and lower case, by a letter written twice, or by
  characters that are not letters (the separator between its words, a space
  or a tab before or after the name, a digit, a dot):
  `claim` for `claims`, `claims_set` or `claim_set` for `claim_sets`,
  `credential_set` for `credential_sets`, `credential` for `credentials`,
  `option` for `options`, `paths` for `path`, `value` for `values`, and also
  `claimS`, `claims1`, `claimss` and `claims` with a space after it. In a
  credential query that has no `claims` member, a member that OpenID4VP 1.0
  does not define there and whose value has the form of a `claims` value (a
  non-empty array of objects that each have a `path` member) is reported in
  the same way, whatever its name, for example `klaims`. The comparison of
  names is not an edit distance. A character of the member name that is not
  ASCII, and a control character, is printed as its escape. The line
  names the place, the member and the defined name, and says that a wallet
  ignores a member it does not know unless it implements an extension that
  defines it. `validate dcql` lists it as the finding `DCQL-MEMBER-NEAR-MISS`
  with severity `warning`; the query stays valid and the exit code stays 0.
  `inspect` prints it under `authoring warnings` and exits 0. `audit` prints
  it under `Authoring warnings:` and gives NOT EVALUATED (see "Changed"). A
  query that the typed parse rejects stays an error with exit code 1, and the
  error names the member. An unknown member that resembles no defined one gets
  no warning. Registration bodies and registration certificates, where
  `claim` is a defined name, are not examined.
- `--json` of `audit`, `inspect` (for a DCQL query and for an authorization
  request), `decode request` and `validate dcql`: the member `warnings`, an
  array that is empty when the query has no such member. Each element has
  `id`, `place`, `level`, `member`, `resembles` and `message`.
- `inspect` and `decode request` print the same authoring warnings for the
  `dcql_query` of an authorization request, under the line `query: dcql_query
  present`.
- `examples/age-request-ignored-member.json`: a DCQL query that says `claim`
  for `claims`, to show the warning.
- `augenmass baselines` prints the credential types of each built-in baseline
  (`credential_types` in `--json`).
- The `serve` trace event `OVER_ASK_ANALYZED` carries `outcome` and uses the
  warning level for a result that was not evaluated.

Documentation and test data only, no change in behavior:

- `docs/SANDBOX.md`: section "After 19 November 2026". It gives what the EUDI
  Hub's page on sandbox migration says, by quote with the read date; what keeps
  working in the Workbench (the static artifact commands, the `clone` target,
  `audit --request ... --cert ...` on a registration certificate given as a
  compact JWT or as a JSON entry with `id` and `jwt`); what does not or may not
  (the `sandbox` target and the `cached-sandbox` reads; `serve` cannot carry
  another registration certificate than the bundled one); which Workbench
  commands to run, in which order, on a new registration certificate; and what
  was not tested: nothing was run on a certificate issued by the EUDI Hub.
- `docs/COMMANDS.md`: recipe "The wallet reports over-asking: reproduce it
  offline" under `audit`, with the synthetic example pair
  `examples/merged-path-registration.jwt` (readable payload
  `examples/merged-path-registration.payload.json`) and
  `examples/merged-path-request.json`: two requested claims, both beyond the
  registration, exit 1. The recipe says how to pass a signed request object
  (through `decode request --json`), which forms `--cert` reads, and how to
  tell a registration verdict from a purpose verdict. It states its limits: a
  registered parent path covers a requested child path in the Workbench, an OK
  does not mean that request and certificate are identical, and the recipe was
  not run against any wallet.
- `fixtures/hub-shape/registration-hub-shape.jwt` with its readable payload
  `fixtures/hub-shape/registration-hub-shape.payload.json`: a synthetic,
  unsigned registration certificate whose field names follow the EUDI Hub's
  public source snapshot "Public release 2026-09-09". Every value is invented.
  CLI tests cover `decode regcert` and `audit --cert` on it, and a test checks
  that every readable payload file matches its certificate.

The section and the recipe describe the behavior on main: the shown outputs
are from this build, and where the 0.4.1 binaries differ (the label
`Purpose:`, the note for an unknown purpose id with exit 0, no exit code 3)
the text names the 0.4.1 form.

### Fixed

- A reader that closes standard output or standard error early no longer ends
  a command with a panic and exit code 101. In 0.4.1, `augenmass audit
  --request overask --purpose age_gate_18 | head -c 0` ended `audit` with `failed printing to stdout: Broken pipe` and exit code 101
  instead of 1, and a result larger than the pipe buffer did the same with
  `| head -n 1`. The command now writes nothing more to the closed stream and
  exits with the code it computes with an open reader: 0, 1 or 3 for `check`,
  `audit` and a `register` dry run, and the codes of the other commands
  (`decode`, `inspect`, `validate dcql`, `baselines`, `verify`, `x509-hash`,
  `doctor`, `generate`, `evidence`, `list`, `cache warm`, `cache status`). The
  log lines of `serve` and of `augenmass-relay` no longer stop the server when
  both streams are closed, and `augenmass-relay --help` and `--version` no
  longer panic. A write to standard output that fails for another reason, for
  example a full disk, is the error `Error: write standard output` with exit
  code 1 (before: a panic). A confirmed write (`register --yes`) whose check
  report could not be read because standard output was closed stops before
  anything is sent, with exit code 1, as it did through the panic before.
- `inspect` and `decode request` read an authorization request given as a
  plain request object (a JSON object, for example the `payload` member of
  `decode request --json`). In 0.4.1 both tried to decode such a JSON object
  as a compact JWT and ended with `Error: decode authorization request JAR`
  and exit code 1, although `docs/COMMANDS.md` names the plain request object
  as an input of `decode request`. The first line of the text output is then
  `OpenID4VP authorization request object (plain JSON, not a signed JAR)`, the
  `typ`, `alg` and `x5c present` lines are left out, and `header` is `null` in
  `--json`. The `Detected:` line of `inspect` carries the same words for a
  plain request object, `Detected: OpenID4VP authorization request object
  (plain JSON, not a signed JAR)`; for a signed JAR it stays `Detected:
  OpenID4VP authorization request (JAR)`.
- `check` and `register` no longer pass a body whose `credentials` member is
  not an array (for example one credential object without the array). Such a
  body printed `OK: no over-ask, no format errors` with exit code 0, and
  `check --json` reported `block: false` with `report: null`, although no claim
  had been judged. It is now the blocking format error
  `CHECK-CREDENTIALS-SHAPE`, exit code 1. A body without `credentials`, or with
  an empty array, still passes, and the line says `OK: the body requests no
  credentials; no format errors. <path> is ready to register.`
- README: the `serve` banner sample says `<local>/trace/<session>`, as the
  binary prints it, and the `check` and `audit` samples show the headline as
  the binary prints it (`OVER-ASK: Over-ask vs purpose: ...`).
- AGENTS.md: the sentence on stdin input names the commands it applies to; the
  `evidence` commands take file paths only.

## [0.4.1]

This release fixes a false over-ask on the minimal mdoc age request, prints the
suggested minimal request in the spelling of the request, quotes ARF
requirement RPRC_21 verbatim, adds a sandbox notice, and extends the claim path
test vectors with `credential_sets` cases.

### Fixed

- Over-ask audit of mdoc age requests: an mdoc PID element `age_over_NN` in the
  namespace `eu.europa.ec.eudi.pid.1` or `eu.europa.ec.eudi.pid.de.1` is now
  judged for purpose under the claim-model key `age_equal_or_over.NN`, so it
  gets the verdict the SD-JWT VC claim `["age_equal_or_over", "NN"]` gets under
  the same baseline (`audit` and `check`).
  Before, `audit` printed `OVER-ASK` and exited 1 for the request of
  `["eu.europa.ec.eudi.pid.1", "age_over_18"]` under `age_gate_18`, while the
  SD-JWT VC request passed. Six verdicts change from beyond the purpose to
  within it: `age_over_18` under `age_gate_18` and `event_checkin`, and
  `age_over_21` under `car_rental`, each in both namespaces. Other age groups,
  and every age element under `bank_kyc`, stay beyond the purpose in both
  formats. Only `age_over_` followed by ASCII digits maps; every other element
  of the German namespace stays unmapped. The purpose verdict still does not
  depend on the credential type, as for the other mdoc elements in 0.4.0.
  Registration coverage and over-disclosure still compare raw paths, so the
  alias never authorizes a path in the other namespace or the other format.
  In `--json`, such a row now has `status` `MinimalForPurpose`, the label
  `Age over NN`, and the matching `counts`. The 0.4.0 entry below that lists
  `age_over_NN` among the mdoc paths without a claim-model key no longer holds
  for it.
- Purpose verdict of SD-JWT VC paths with an integer segment: an integer
  selects an array element, so `["age_equal_or_over", 18]` is no longer judged
  as the member `"18"` of the age object. Before, `check` and `audit` reported
  it as within the purpose under `age_gate_18`, `event_checkin` and (with 21)
  `car_rental` and exited 0; it is now beyond the purpose and exits 1. Integer
  and `null` element selectors of `nationalities` still count as the array.
- Purpose verdict of credential formats the baselines do not model: a claim of
  any format other than `dc+sd-jwt`, `vc+sd-jwt` and `mso_mdoc` (for example
  `jwt_vc_json`, `ldp_vc` or an unknown identifier) no longer borrows the
  SD-JWT VC spelling. Before, `["age_equal_or_over", "18"]` in such a format
  passed `age_gate_18` with exit 0; it now counts as beyond the purpose, with
  the rationale `Purpose not judged for this credential format`, and exits 1.

### Changed

- "Suggested minimal request" is printed in the spelling of the requested
  credential, one block per requested credential type, in the text output of
  `check`, `audit` and the `register` gate and on the `serve` inspect page.
  An SD-JWT VC request gets claim paths (`["age_equal_or_over", "18"]`), an
  mdoc PID request gets `[namespace, element]` pairs; the array part of each
  line can be pasted into a DCQL `path`. Because the EU PID and the German PID
  share the mdoc doctype `eu.europa.ec.eudi.pid.1`, an element that only one of
  them carries is marked `(German PID only)` or `(not in the German PID)`. A
  baseline claim that the credential type does not carry is named after
  `No known claim for this credential type:`, and a credential type without a
  known claim table gets the baseline claim names only. Before, the block
  listed internal baseline keys such as `age_equal_or_over.18` or
  `address.resident_street`, also for mdoc requests. `--json` adds
  `suggested_minimal_request` (per block: `credential_id`, `format`, `types`,
  `known_type`, `paths` with `path` and `profile_note`, `not_suggested`);
  `suggested_minimal` keeps the baseline keys.
- The legal basis entry `EUDI ARF, registration certificate, RPRC_21` now
  quotes the requirement verbatim from ARF Annex 2 (Topic 44), including that
  the wallet warns the user and that the wallet provider decides whether the
  presentation may go ahead. Before, it printed the paraphrase "The wallet
  verifies requested attributes are within the registration certificate and
  notifies the user otherwise." The change applies to the text and `--json`
  output (`legal_basis[2].text`) of `audit`, `check` and `baselines`; the
  source and locator are unchanged.
- Sandbox notice: when `--target sandbox` (`list`, and `register --yes`) uses
  the built-in registrar `https://sandbox.eudi-wallet.org/api` because neither
  `AUGENMASS_API_BASE` nor `API_BASE` is set, and when `cache serve` uses it as
  the upstream because neither `--upstream` nor `AUGENMASS_CACHE_UPSTREAM` is
  set, the tool prints one line on stderr with what the registrar's landing
  page said on 13 November 2026 (testing possible until 19 November 2026, the
  new wallet app version then no longer accepts its certificates, no new
  users). A variable set to the built-in address counts as configuration.
  `serve` prints a startup line `registration :` that names the source of its
  bundled registration certificate (`fixtures/regcert/rc-by-id.json`, issued by
  the German sandbox registrar) with the same notice. Standard output does not
  change, also with `--json`, and no network request is added. The default
  address is unchanged; `cache serve --help` now states it in the `--upstream`
  help text instead of a `[default: ...]` suffix.
- Claim path test vectors: `fixtures/claim-paths/path-vectors.json` is version
  1.1 and adds `query_cases`, five cases of whole DCQL queries with
  `credential_sets`: an option selects only the credential queries it names,
  an optional set is audited, every option of a set and every identifier of an
  option is audited, and an empty option is malformed. The 58 cases of version
  1 are unchanged. `tests/claim_paths.rs` runs the new cases through the same
  DCQL parser as `audit --request` and checks with a SHA-256 that the version 1
  cases did not change.

### Added

- `examples/`: demonstration inputs with invented relying-party names only.
  `age-broad-registration.jwt` (readable payload
  `age-broad-registration.payload.json`) with `age-broad-request.json` shows a
  request inside the registration and beyond the purpose: under `age_gate_18`
  all five requested claims are beyond the purpose and none beyond the
  registration, exit 1. `age-minimal-request-sdjwt.json` and
  `age-minimal-request-mdoc.json` are the minimal age requests (both exit 0
  under `age_gate_18`), and `kyc-request-plus-birthdate.json` is a German PID
  request of given name, nationalities, address locality and birth date.
- `docs/VECTORS.md`: the format of the vector file, what "covers" means for
  each kind of case, how to run the cases and consume the JSON, the licence and
  reuse terms, and the version and change policy.
- README: a table "What the Workbench does not do" (registration certificates
  are decoded, not verified; no test wallet; no mdoc presentation verification;
  no Digital Credentials API), each row with a free tool that covers it. The
  four built-in purpose baselines are described as curated assessments, not
  law and not legal advice.
- `docs/RELEASE.md`, "Cutting a release": the step that attaches
  `path-vectors.json` and its `.sha256` file to the published release.

The plugin binaries committed under `plugins/augenmass-workbench/` are
unchanged at this tag and do not carry these changes; the plugin bundle is
rebuilt from the 0.4.1 release archives in a follow-up change.

## [0.4.0]

This release adds request signature verification (`verify request`), compares
requested and registered claims as claims path pointers, segment by segment,
and states that a registration certificate is decoded and not verified.

### Added

- `verify request`: full JAR (JWT-Secured Authorization Request) signature
  verification, the request-side counterpart to `verify presentation` and the
  first v0.4.0 roadmap item. It proves the request was signed by the key in its
  `x5c` leaf (ES256 only; `none` and any alg-confusion attempt are rejected
  before any key handling), that an `x509_hash` `client_id` binds to that leaf,
  and, with `--anchor`, that the leaf chains directly to a trust anchor within
  its validity window. Missing `client_id` or any scheme other than `x509_hash`
  rejects with `JarClientIdUnbound`; a mismatched `x509_hash` value rejects with
  `JarClientIdMismatch`. `--now` pins the verification clock (anchor windows and
  the request `exp`/`nbf`); it exits 1 when not verified, unbound, untrusted, or
  expired, and emits `--json`. The check lives in the pure engine as
  `augenmass_core::jar` (a new module beside `verify` and `trust`), reusing the
  P-256 primitives and `trust::leaf_der_trusted_at` (a new leaf-DER anchoring
  helper shared with the SD-JWT issuer path). New fixture:
  `fixtures/certs/eudiplo-verifier-leaf.pem` (the captured request's self-signed
  leaf, used as a self-anchor). Deferred: non-ES256 algorithms, key resolution
  other than the `x5c` leaf, full RFC 5280 path validation, and support for any
  client identity scheme beyond `x509_hash`.
- Claim path test vectors: `fixtures/claim-paths/path-vectors.json`, one case
  per coverage rule (pointer cases for SD-JWT VC and mdoc paths, credential
  cases for format and type matching, requests without `claims`, and
  `claim_sets`), each with the format, the registered paths, the requested
  path, the expected result (`covered`, `not_covered`, or `invalid`), a reason
  and the OpenID4VP section. Invented names only; Apache-2.0, and the header
  states that other tools may reuse the set. `tests/claim_paths.rs` runs it and
  checks, for every registration fixture in the repository, that a request of
  exactly its registered claims is never flagged.
- Honest notice for registration certificates: `audit --cert`, `decode
  regcert`, `inspect` on a certificate, and a non-empty `list` print
  `Registration certificate: payload decoded; signature, issuer and revocation
  status not verified.` (for `audit` right under the verdict line, on the OK
  and the over-ask path). The JSON of `audit`, `decode regcert` and `inspect`
  carries `registration_certificate`: `{"decoded": true, "signature_verified":
  false, "issuer_verified": false, "revocation_checked": false}`, and `null` on
  an `audit` without `--cert`, whose verdict keeps saying `registration not
  evaluated`.
- `check` (and the `register` gate): new blocking findings `CHECK-CLAIM-PATH`
  (a credential without a non-empty `claims[]`, or a path that is not a claims
  path pointer: a boolean, a negative or fractional number, an empty array,
  or for mso_mdoc anything but two strings),
  `CHECK-CREDENTIAL-META` (no `format`, or no valid `vct_values` for SD-JWT VC
  or `doctype_value` for mso_mdoc), and `CHECK-UNREADABLE-REQUEST`. Before, a
  body such as `["birthdate", true]` skipped the over-ask guardrail and passed
  with exit 0.

### Fixed

- Registration comparison (`audit --cert`, `check`, `serve`): a request is now
  compared with the registration as OpenID4VP 1.0 claims path pointers,
  segment by segment and never as joined strings. Before, the decoder dropped
  `null` segments and registration matching compared dotted strings, so a
  request identical to its registration with `["nationalities", null]` was
  flagged as over-asking, a registered `["address"]` did not cover
  `["address", "locality"]`, one segment `"address.locality"` matched
  `["address", "locality"]`, and a request for another credential type passed
  because all registered credentials were merged. Now: an equal path is
  covered (`null` included); a registered `null` covers a requested index; a
  registered object covers its members; a requested `null` under a registered
  index, a parent of a registered member, `"0"` against `0`, and a dotted
  segment are not covered; mdoc paths are covered only by an equal
  `[namespace, element]` of two strings, and an mdoc path of another shape
  (`[namespace, null]`, an integer element, one or three components) is
  invalid and covers nothing, even an equal registered path (OpenID4VP 1.0
  section 7.2.1). The credential is matched by format and type first
  (`vct_values`, `doctype_value`); a request accepting several types must be
  within the registration for each; a request without a type, an empty or
  invalid registered path, and a registered credential with malformed type
  metadata authorize nothing. A credential requested without `claims` is
  within the registration when its type is registered and otherwise gets one
  row beyond it; so does a credential whose `claim_sets` select no claim
  (`[[]]`), since its mandatory claims are still presented. With `claim_sets`,
  only claims named in some combination are audited (every declared claim
  when a combination names an unknown id); with `credential_sets`, only
  credentials named in some option are audited (every credential when an
  option names an unknown id), so an unselected credential is no longer
  flagged. Engine: `regcert::PathSeg`, `parse_claim_path`,
  `valid_claim_path`, `path_covers`,
  `requested_types`, `RegisteredScope::covers`, and `RegisteredCredential`
  gains `doctype_value`; `claims` keeps typed segments and `fingerprint`
  includes the doctype and typed paths. Purpose: an SD-JWT segment that
  itself contains a dot no longer maps to a nested model key.
- `check` reads each body credential in its own format, type and raw paths
  (before, every body was read as a German PID SD-JWT VC with string
  segments), so `null` and integer segments and mso_mdoc bodies are judged.
- `baselines` text lists a baseline's mdoc elements (`mdoc elements:
  eu.europa.ec.eudi.pid.1/place_of_birth`) as the JSON `mdoc_elements` does.
- The PID claim model has rows and labels for `place_of_birth.region`,
  `place_of_birth.country`, `address.region`, `address.formatted` and
  `address.house_number`, so they appear in the disclosed-vs-withheld rows.
- `bank_kyc` baseline: adds `place_of_birth.locality` and `nationalities`, so a
  request with the German identification set for a natural person (GwG § 11
  Abs. 4 Nr. 1: name, place and date of birth, nationality, address) is no
  longer flagged as over-asking on 2 of 9 claims. The baseline note cites the
  statute and keeps the curated-judgment qualification; passing the check does
  not establish complete identification or AML compliance. Place of birth and
  nationality stay over-asking under `age_gate_18`, `event_checkin`, and
  `car_rental`.
- `bank_kyc` baseline, remaining false positives: every spelling of the GwG
  attributes in the EU PID SD-JWT VC and mdoc encodings is now within the
  baseline in its own format: SD-JWT `place_of_birth.region` and `.country`,
  `address.region`, `address.formatted`, `address.house_number`, the flat
  `birth_place` and `birth_country` of the ERICA fixture, and `nationalities`
  with an element selector (`null` or an index); mdoc `resident_state`,
  `resident_address`, and the structured `place_of_birth` element (new
  baseline field `mdoc_elements`, a list of `[namespace, element]` paths
  compared segment by segment, so a path such as
  `["eu.europa.ec.eudi.pid", "1.place_of_birth"]` does not match). Whole SD-JWT `address` and `place_of_birth`
  objects, spellings of the other format, other namespaces, and attributes
  outside the list stay over-asking.
- Over-ask audit of EU PID mdoc requests: a `mso_mdoc` path
  `["eu.europa.ec.eudi.pid.1", element]` is now judged for purpose under the
  matching claim-model key (`given_name`, `family_name`, `birth_date`,
  `nationality`, `resident_street`, `resident_city`, `resident_postal_code`,
  `resident_country`, and the legacy text element `birth_place`), so for example
  an mdoc `given_name` is no longer flagged under `bank_kyc`, `event_checkin`, or
  `car_rental`. New engine function `inspector::canonical_claim_key`. The
  mapping is format-aware: an mdoc path without a claim-model key (another
  namespace, `age_over_NN`, the structured `place_of_birth`) is judged only
  against the baseline's `mdoc_elements`, never against a model key, so an
  mdoc path such as `["address", "resident_city"]` cannot borrow an SD-JWT
  spelling. Registration and over-disclosure matching still compare raw
  paths, so an alias never authorizes a path in another format or another
  SD-JWT path (`address.locality` does not authorize a disclosed
  `address.resident_city`), and every requested path keeps its own verdict row
  (`counts.requested` is unchanged). The disclosed-vs-withheld rows map
  disclosed SD-JWT keys to model keys as well. A disclosed member of a
  requested object or array, or an element of an array requested with a
  wildcard, is no longer reported as over-disclosed.
- Article 5b(3) quotation: the over-ask legal basis now quotes Regulation (EU)
  No 910/2014, Article 5b(3) verbatim ("Relying parties shall not request
  users to provide any data other than that indicated pursuant to paragraph 2,
  point (c).") and names the amended act instead of the amending Regulation
  (EU) 2024/1183. The other two legal-basis entries are unchanged.
- A DCQL query whose `credential_sets` carry an empty option (`"options":
  [[]]`) is rejected as malformed by `audit --request` and `inspect`, the
  offline replay of an evidence bundle skips its over-disclosure analysis as
  for any query it cannot parse, and `validate dcql` reports it as
  the blocking finding `DCQL-SET-OPTION-EMPTY`. OpenID4VP 1.0 section 6.2
  requires every option to name at least one credential query. Before, such
  a query was accepted, no credential was selected, and the audit judged
  nothing and exited 0.

These fixes ship in the 0.4.0 CLI and its release archives. The plugin
binaries committed under `plugins/augenmass-workbench/` are unchanged at this
tag and keep the old `bank_kyc` baseline, the old mdoc behaviour, the old
Article 5b(3) wording (binary and skill reference files), and the old
dependency set until the plugin bundle is rebuilt from the 0.4.0 release
archives.

### Security

- `Cargo.lock` refreshed within the existing manifest requirements
  (`CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback cargo update`; 186 lock
  changes, among them rustls 0.23.46, rustls-webpki 0.103.17, webpki-roots
  1.0.12, h2 0.4.20, quinn-proto 0.11.19, tokio 1.54.1, and anyhow 1.0.104).
  No manifest, no `rust-toolchain.toml`, and no direct dependency major version
  changed, and no `--precise` downgrade was needed: every resolved package
  declares a `rust-version` of 1.92 or lower. `cargo audit` went from 20
  vulnerabilities and 14 warnings to 4 vulnerabilities and 10 warnings (8
  unmaintained, 2 unsound, 0 yanked). The remaining advisories need major
  upgrades and are deferred: RUSTSEC-2026-0459 (libsqlite3-sys 0.28 via rusqlite
  0.31), RUSTSEC-2026-0387 (crypto-bigint 0.3 and 0.5 via rsa 0.6 and
  elliptic-curve 0.13), RUSTSEC-2023-0071 (rsa 0.6 via ssi 0.16), and the
  unsound RUSTSEC-2023-0126 (im 15) and RUSTSEC-2026-0255 (sized-chunks 0.6),
  both via ssi 0.16. Each is listed with its removal condition in
  `docs/RELEASE.md`, "Dependency audit".

### Changed

- `decode regcert`, `inspect` and `audit --cert` refuse a registrar list with
  more than one entry and name the ids; before, the first entry was used
  silently. A list with one entry still works.
- New `.github/workflows/check.yml`: format, clippy, locked tests, and
  `cargo audit --deny unsound --deny yanked` (with one documented `--ignore` per
  accepted advisory) on pushes to `main`, on pull requests against `main`, and
  on demand, on GitHub-hosted `ubuntu-latest` only. `ci.yml` and
  `blacksmith-smoke.yml` stay manual, and `release.yml` stays tag-only.
- `scripts/ci-credit-guard.sh` allows branch-push and pull-request triggers only
  for a workflow that meets a strict profile (literal `ubuntu-latest` runners,
  one top-level read-only permissions block, no secret or token reference, only
  a SHA-pinned `actions/checkout` where each checkout step sets
  `persist-credentials: false` in its own `with:` block and passes no other
  input than `fetch-depth`, a job timeout, plain block YAML). The rule is
  fail-closed and checked line by line, without parsing expressions: in such
  a workflow `${{` may appear only on a line that equals an entry of a short
  allow-list in the guard, and `if:` keys, backslashes, quoted or spaced keys,
  and keys starting with `GITHUB_`, `RUNNER_`, `ACTIONS_`, or `INPUT_` are
  rejected. For every workflow, the top-level keys and the `on:` block must use
  a small plain block grammar (`push`, `pull_request`, `workflow_dispatch`,
  with `branches:` or `tags:` lists), so quoted, escaped, or spaced event keys,
  flow values, event lists, and an inline `on: push` cannot change the
  classification. Every workflow must also start its root mapping at column 0
  and hold only printable ASCII, tabs, and LF line breaks, so neither an
  indented root with a multi-line scalar nor a carriage return or Unicode line
  separator can hide structure from the line matcher.
  `scripts/ci-credit-guard-cases.sh` (`just
  ci-credit-guard-cases`) runs 71 committed regression cases under
  `tests/ci-credit-guard/`.
- Docs: `docs/RELEASE.md`, `docs/GUARDRAILS.md`, `docs/SHIPPING_STATUS.md`, and
  `AGENTS.md` describe the new automatic workflow. `docs/SHIPPING_STATUS.md` no
  longer lists third-party registration counts or another relying party's
  identifier, and `README.md` no longer advertises the macOS `.pkg`.

## [0.3.0]

This is the live-wallet proof release. It promotes Augenmaß from an offline
artifact and registrar guardrail toolkit into a demonstrable EUDI Wallet
workbench: a real phone wallet can scan a QR, fetch the signed OpenID4VP request,
post an encrypted response through the hosted relay, and leave behind a redacted
evidence bundle that can be verified later. The macOS plugin binaries are
refreshed from this branch, and the Linux/Windows plugin binaries are refreshed
from the same `v0.3.0` release workflow artifacts.

### Added

- Hosted wallet-only relay support (`serve --relay augenmass`) for real phone
  demos through `wallet.augenmass.tech`. The relay forwards only the OpenID4VP
  phone endpoints and keeps trace, inspect, evidence, session APIs, and unsafe
  debug artifacts on localhost.
- Real iOS and Android sandbox-wallet proof. Both wallets completed the
  OpenID4VP flow against `serve --relay augenmass --age-only` with the
  registrar-issued leaf; exported bundles passed `evidence verify` and
  `evidence assert-live`.
- Strict live evidence proof: `evidence assert-live` now proves the request
  object fetch, encrypted response receipt, JWE decryption, and offline
  presentation verification before a phone-wallet run can be claimed as proven.
- Wallet over-disclosure replay signal. When a captured request contains
  explicit DCQL claim paths, evidence replay can compare requested keys to
  disclosed keys and reports `walletOverDisclosureAnalyzed` separately from
  issuer trust, live status, and legal over-ask proof.
- Post-capture trust/status proof path with `evidence prove-trust-status` and
  the Bundesdruckerei preprod helper wrapper for the current sandbox PID
  material.
- Hosted and local sandbox cache proof: the cache backend can be warmed and used
  as a stable read-through mirror for public sandbox reads, with Railway
  deployment proof and a protected status surface.
- Plugin/skill documentation for the new phone-proof workflow, including
  plugin-only references so marketplace installs can guide an agent without the
  full repository checkout.

### Changed

- The plugin bundle binaries are refreshed from the current release branch for
  macOS Apple Silicon, macOS Intel, Linux x64, and Windows x64; each target now
  prints `augenmass 0.3.0`.
- Documentation now treats `0.3.0` as the presentation/demo release line.
- `serve --unsafe-debug-artifacts` keeps the first canonical artifact when a
  wallet retries the response after success, and writes later captures with a
  suffix such as `direct-post-2.body`.

### Fixed

- iOS wallet KB-JWT clock-skew tolerance for small future `iat` values.
- Evidence replay mismatch after duplicate wallet POSTs by preserving the first
  canonical unsafe artifact.
- Stale macOS plugin binary behavior: the committed macOS plugin launcher now
  accepts the newest phone proof bundle and reports `walletOverDisclosureAnalyzed`.
- Stale Linux and Windows plugin binary behavior: bundled non-macOS targets now
  come from the same `v0.3.0` workflow artifacts as the release line, not the
  older `v0.2.0` release.

### Security

- The hosted relay uses an operator token for run creation and is wallet-only by
  default, reducing the public attack surface.
- Trace and evidence docs now explicitly separate projector-safe redacted output
  from sensitive local bundles and raw unsafe artifacts.

### Known Caveats

- The hosted relay is suitable for controlled demos and operator use; a broader
  public service needs operational policy, monitoring, and abuse controls.
- The proof bundles are sensitive and intentionally not committed.
- The token-status-list signer is operator-supplied trust material. The status
  signer used by `serve --status-signer` and `evidence prove-trust-status
  --status-key` is not cryptographically bound to the issuer trust anchor
  (`--trust-anchor`): the verifier trusts whatever signer the operator passes, so
  a signer that matches a forged status list will verify it. This is intentional
  and real-world-consistent (the Bundesdruckerei preprod PID provider signs its
  status list with a key deliberately separate from the issuer root); anchoring
  the status signer to the issuer is a later step. See the code caveat in
  `crates/augenmass-core/src/status.rs:21-27`.

## [0.2.0]

Version 2 grows the workbench from an audit, debug, and repair helper into a
single cohesive command-line toolkit over the whole EUDI Wallet artifact surface,
for developers and auditors alike. The v1 workbench shipped six commands
(`generate`, `check`, `doctor`, `register`, `list`, `clone`) and used only part
of the engine. Version 2 surfaces the entire `augenmass-core` engine behind one
CLI and adds net-new offline decoders. It also adds `serve`, a live
wallet-interaction debugger so a real EUDI wallet can present to the tool over
OpenID4VP and the whole exchange is traced. Static artifact commands run fully
offline. Explicit live surfaces are network by nature: registrar targets, the
cached-sandbox mirror, and the live wallet-interaction debugger.

### Added

- `plugin-only-smoke`: copies only the plugin bundle to a temporary directory
  and runs no-file generated/stdin workflows from outside the checkout, proving
  marketplace-style first-run behavior without `fixtures/` or `examples/`.
- Universal `inspect <input>`: sniff any common EUDI artifact and decode it
  ("what is this?"). It detects the type, then dispatches to the right decoder.
  Recognised types include SD-JWT VC presentation, WRPRC registration certificate
  (typ `rc-wrp+jwt`), OpenID4VP authorization request and signed JAR
  (typ `oauth-authz-req+jwt`), OpenID4VCI credential offer
  (`openid-credential-offer://` URI or JSON), OpenID4VP request URI
  (`openid4vp://`), token status list (typ `statuslist+jwt`), DCQL query (bare or
  wrapped under `dcql_query`), registrar registration body, X.509 certificate
  (PEM), and generic JWT/JWS.
- Targeted `decode` subcommands for when you already know the type:
  `decode jwt`, `decode sd-jwt`, `decode regcert`, `decode request`,
  `decode offer`, `decode status-list`, and `decode mdoc`. These decode without
  verifying any signature.
- `validate dcql`: validate a DCQL query beyond what the typed parse enforces.
  It checks that credential ids are unique, that every `credential_sets` option
  references a known credential id, and that each claim path matches its
  credential format (an `mso_mdoc` path must be `[namespace, element]`, two
  strings; an SD-JWT path must be an array of string, null, or integer segments,
  not a dotted string). Each finding has a stable id, a severity, and a fix; the
  command exits non-zero on a blocking error so it gates CI. JSON via `--json`.
- `decode mdoc`: decode an ISO/IEC 18013-5 mdoc (`mso_mdoc`), the other major
  EUDI credential format alongside SD-JWT VC. It accepts a `DeviceResponse`, a
  single `Document`, an `IssuerSigned`, or a bare `MobileSecurityObject`, given as
  raw CBOR bytes, hex, or base64/base64url, and surfaces the document type, the
  disclosed namespaces and elements (with nested CBOR rendered as JSON and large
  byte values such as a portrait shown as a length-tagged hex preview), the issuer
  authentication (the COSE_Sign1 algorithm and the X.509 chain, whose leaf
  `x509_hash` the engine computes), and the Mobile Security Object (validity
  window, per-namespace value-digest counts, and device key). `inspect` detects an
  mdoc given as hex or base64. Decode only: the COSE signature is not verified and
  value digests are not recomputed (the output says so).
- `audit` command: lint an OpenID4VP request for over-asking against a curated
  purpose baseline. Takes `--request` (the value `minimal`, the value `overask`,
  or a path to a DCQL JSON file; defaults to `minimal`), `--purpose` (one of
  `age_gate_18`, `event_checkin`, `car_rental`, `bank_kyc`; defaults to
  `event_checkin`), an optional `--cert` (a registration certificate as compact
  JWT, entity JSON, or array), and an optional `--vct` override. Exits non-zero on
  over-ask so it works as a CI gate.
- `baselines [<id>]` command: list the curated purpose baselines and the legal
  basis cited on every over-ask finding, or show one baseline in detail. The four
  baselines are `age_gate_18` (age_equal_or_over.18), `event_checkin` (given_name,
  family_name, age_equal_or_over.18), `car_rental` (given_name, family_name,
  age_equal_or_over.21), and `bank_kyc` (given_name, family_name, birthdate, and
  the four address.resident_* fields).
- Cryptographic `verify` subcommands, surfacing the engine's verification, trust,
  and status modules:
  - `verify presentation <input> --nonce <NONCE> --aud <AUD>`: verify an SD-JWT VC
    presentation end to end (issuer signature, KB-JWT, nonce and audience binding,
    vct). Supports `--vct`, `--max-age` (KB-JWT freshness, default 300 seconds),
    `--now` (an injectable verification clock in Unix seconds), `--trust-anchor`
    (anchor the issuer to a PEM rather than the leaf key), and inline revocation
    via `--status-token` plus `--status-key`.
  - `verify trust <input> --anchor <ANCHOR>`: check whether the presentation's
    issuer chains to a trust anchor, with `--now` for the validity window.
  - `verify status <input> --token <TOKEN> --key <KEY>`: check a presentation's
    revocation status against a status-list token, fail-closed and offline.
  - `verify status-list --token <TOKEN> --key <KEY> --index <INDEX>`: verify a
    status-list token and read one index directly.
- `x509-hash <input>`: compute the `x509_hash:<base64url(SHA-256(leaf-cert-DER))>`
  client_id binding from a JAR's x5c leaf, a PEM certificate, or base64 DER. Pass
  `--client-id` to compare against a claimed value; mismatch exits non-zero.
- `generate dcql --claim <path> ...`: build a DCQL query from one or more claim
  paths (dotted or slashed, repeatable). Joins `generate regbody`, which now
  carries flags for `--use-case` (age-check), `--over-broad`, `--rp`,
  `--support-uri`, `--privacy-policy`, and `--purpose`.
- Global `--json` flag on the read-only commands: emit machine-readable JSON
  instead of the text rendering, for agents and CI.
- Input ergonomics across every artifact argument: each accepts a file path, an
  inline value, or `-` for stdin.
- The full `augenmass-core` engine is now surfaced. v1 used only the inspector,
  regcert, and pid modules; v2 also exposes disclosure (SD-JWT disclosed claims),
  verify (SD-JWT VC and KB-JWT verification with an injectable clock), status
  (token status list revocation), trust (X.509 leaf chains-to-anchor plus validity
  window), and crypto (JWE decrypt, x5c to JWK, leaf_cert_hash).
- `serve`: a live wallet-interaction debugger (a verifier-in-a-box). It runs a
  local OpenID4VP verifier for the German PID profile (x509_hash client_id, signed
  request object by reference, `direct_post.jwt` ECDH-ES encrypted response, the
  registration certificate embedded as `verifier_info`) so a real EUDI wallet can
  present to it, and records the whole exchange as a per-session trace:
  SESSION_CREATED, REQUEST_BUILT, REQUEST_OBJECT_FETCHED, RESPONSE_RECEIVED,
  RESPONSE_DECRYPTED, VERIFIED or REJECTED, STATUS_CHECKED (with `--live-status`
  and a trust anchor), and OVER_ASK_ANALYZED. The trace is redacted by default
  (shape and digests only; no raw bodies, no disclosed claim values). The trace is
  available three ways: live on the console
  (color-coded on a TTY), as a browser timeline at `/trace/<session>` that
  refreshes while the exchange is in flight, and as JSON at
  `/api/trace/<session>`; `/api/sessions` lists the sessions seen this run. Flags:
  `--port`, `--host`, `--public-url`, `--key` and `--leaf` (sign with the real
  registrar leaf so the client_id matches the registration; otherwise a throwaway
  development certificate is used), `--purpose`, `--trust-anchor` (enforce PID
  issuer trust), `--live-status` (resolve token-status-list revocation over the
  network), `--quiet`, and `--unsafe-debug-artifacts` (opt-in, off by default:
  write full-fidelity raw wallet material to local disk for private debugging,
  never served over HTTP). This is the headline new capability: the tool now
  debugs the actual wallet interaction, not just static artifacts. It is adapted
  from the verifier project's `verifier-service`, reusing the same engine.
- `evidence` command group: export, verify, and replay local audit bundles from
  `serve --unsafe-debug-artifacts` session directories. `evidence export
  <session-dir> --out <bundle.json>` writes a sensitive JSON bundle with raw local
  artifacts, canonical entry hashes, a deterministic redacted replay trace, and an
  optional ES256 signature via `--signing-key`. `evidence verify <bundle.json>`
  checks entry lengths, entry hashes, replay determinism, the canonical payload
  hash, and the optional signature (with `--verify-key` when supplied). `evidence
  replay <bundle.json>` renders the projector-safe timeline and never prints raw
  wallet material. When the capture contains `direct-post.body`,
  `session-enc-key.jwk`, `verification-context.json`, and an encrypted response,
  replay decrypts and verifies the SD-JWT VC offline against the captured nonce,
  audience, vct, clock, and freshness window.
- `cache serve`: a server-side read-through cached-sandbox mirror for public
  sandbox GET routes. It stores successful upstream responses in SQLite with a
  bounded entry cap, exposes public provenance headers (`x-augenmass-cache`, cache
  key, fetched-at, and SHA-256), serves fresh hits locally, and falls back to
  stale cached data when a refresh fails. Full upstream URLs stay in protected
  cache status instead of public response headers. `list --target cached-sandbox`
  reads through it, while confirmed writes to `--target cached-sandbox` are
  refused before any network call.
- Deployable cache backend hardening: `cache serve` now supports explicit bind
  host, `PORT`, persistent database path, upstream timeout, TTL, max entries,
  public health check, and optional admin-token protection for cache status and
  refresh endpoints. The repository includes a Dockerfile and Railway
  configuration for the current Axum plus SQLite backend.
- Native CI and release automation: GitHub Actions now offers a manual fmt,
  clippy, test, and release-build matrix on Linux, Windows, and macOS runners,
  with release archives for Linux x86_64, Windows x86_64, macOS Intel, and macOS
  Apple Silicon. The CI gate is manual-only to conserve private-repo runner
  minutes.
- `just ci-credit-guard`: a local workflow-trigger guard that fails if GitHub
  Actions can run on normal branch pushes or pull-request activity. The only
  allowed push trigger is the deliberate tag-only release path.
- Cache deployment proof is stricter: `deployed-cache-smoke-required` now
  requires an admin token, and Docker smoke restarts the cache container against
  the same volume to prove cached data survives a container restart.
- `just release-zip-layout-smoke`: a local no-runner-credit check for the
  Windows-style `.zip` archive layout. It proves packaging/extraction mechanics
  without claiming native Windows execution unless run on Windows.
- Local release proof is split into plugin-free CLI proof
  (`local-cli-release-proof`) and presenter plugin proof
  (`presenter-plugin-proof`), with `local-release-proof` composing both.
- `platform-smoke` now includes Linux arm64 in its default probe list and skips
  it when the target or cross C toolchain is not installed.
- `just demo-proof`, `just demo-run`, and `docs/DEMO_PROOF.md`: a focused,
  offline proof gate and rehearsal sequence for the agent-first presentation
  story. It pins the stable commands for artifact identification, over-ask
  guardrails, JAR fix guidance, offline crypto verification, safe demo
  targets, the request-side wallet debugger, and the cached-sandbox mirror.

### Changed

- The verification engine is renamed and vendored into this repository as the
  `augenmass-core` crate. It was reused as-is from the verifier project and is
  HTTP-free and pure.
- Commands are regrouped into clear families: UNDERSTAND (`inspect`, `decode`),
  PROPORTIONALITY (`check`, `audit`, `baselines`), CRYPTO (`verify`, `x509-hash`),
  PRODUCE (`generate`), DIAGNOSE (`doctor`, `validate`), DEBUG (`serve`),
  EVIDENCE (`evidence`), and WRITE (`register`, `list`, `clone`).
- `check` now gates a registrar registration body before a write on both over-ask
  and format. It catches the registrar DTO traps: `claims[].path` must be an array
  of segments (`["age_equal_or_over","18"]`, not the string `"age_equal_or_over.18"`);
  use `credentials`, not `provided_attestations`; `purpose` is a list of
  `{lang, content}`, not a bare string; `privacy_policy` must be a valid URL;
  `support_uri` is any non-empty contact string (email, phone, or URL) and is not
  over-validated as a URL. It exits non-zero on over-ask or a blocking format
  error, 0 when clean.
- `doctor` continues to diagnose verifier signed-request and JAR gotchas: x5c must
  be a list of strings even for a single cert; `client_id` must be the
  `x509_hash:` binding (compute it with `x509-hash`); set
  `Content-Type: application/json` on every POST. Exits non-zero when it finds
  issues.
- `register`, `list`, and `clone` are retained with the same guardrails. `register`
  is a dry-run by default, requires `--yes` to write, and requires `--force` to
  write past an over-ask warning; it refuses (non-zero) on over-ask without
  `--force` and bails on blocking format errors. Both `register` and `list` take a
  `--target` of `clone` (the local registrar-compatible store, the default),
  `cached-sandbox` (read-only cached sandbox reads), or `sandbox` (the real
  registrar, rehearsal only). Writes are scoped to one relying party; the tool
  never mints extra relying parties.

### Notes

- Offline and deterministic where it matters: artifact decoding,
  proportionality, generation, and offline verification run without network
  calls. Verification accepts an injectable clock (`--now`) so results are
  reproducible against the committed fixtures. Live surfaces are explicit:
  registrar targets, `cache serve`, and `serve`. `serve` is network by nature (a
  real wallet connects to it); its verification logic is the same offline engine,
  exercised by an integration test on an ephemeral port and a unit test against
  the committed oracle fixtures.
- `serve` hardening (after an adversarial review of the new code): the
  credential-controlled status-list URI fetch is guarded against SSRF (https
  only, redirects disabled, a request timeout, and a deny list for loopback,
  private, link-local, and other non-public addresses); a status-list transport
  or signature failure is reported and traced as an infrastructure error, never
  as a revocation; a revoked or suspended credential emits an explicit REJECTED
  trace event so the timeline ends red; a multi-credential `vp_token` is flagged
  loudly rather than silently reduced to the last presentation; the startup
  banner always prints the real bind address and warns when `--public-url` does
  not match it; and `--public-url` is normalised to end in '/'.
- `serve` live-status fetch hardening (second pass): the fetch is now pinned to
  the addresses vetted before connecting, so reqwest no longer re-resolves the
  hostname at connect time; this closes the DNS-rebinding / TOCTOU window between
  the IP check and the connection. The non-public deny list now normalises
  IPv4-mapped IPv6 (so `::ffff:127.0.0.1` and `::ffff:169.254.169.254` are denied)
  and adds the CGNAT range `100.64.0.0/10`. The response body is read under a size
  cap rather than unbounded.
- `serve` trace is redacted by default: the unauthenticated `/api/trace/<session>`
  and the browser timeline no longer carry the raw POST body or decrypted claim
  values. The received response and the decrypted payload are recorded as shape
  only (length, SHA-256, field names, `vp_token` presence and shape), and
  `VERIFIED` lists disclosed claim keys only.
- `serve` rejects a plaintext `direct_post`: the verifier advertises the encrypted
  `direct_post.jwt` profile, so an unencrypted response is refused (HTTP 422) and
  traced as `REJECTED` rather than verified.
- `serve --unsafe-debug-artifacts <dir>` (opt-in, off by default): writes
  full-fidelity local debug artifacts (raw `direct_post` body, decrypted response
  when an encrypted wallet response is decrypted, per-session private key, signed
  request object, decoded request payload, and verification replay context) to
  `<dir>/<session>/` with owner-only permissions on Unix (dirs `0700`, files
  `0600`) and a sensitive-marked `debug-manifest.json` carrying platform handling
  caveats, recorded in the trace as `ARTIFACT_SAVED` with file name, label,
  length, SHA-256, and the redaction fields `unsafeDebugArtifacts`,
  `pathRedacted`, `redacted`, and `redaction`. Never served over HTTP. This
  restores raw-material debugging for developers who explicitly opt in, after the
  default trace was made safe.
- `serve` now mints a fresh ephemeral response-encryption key per Authorization
  Request, advertised in that request's client metadata, used once, and dropped
  after the response is processed (and on the reject and malformed-parse paths).
  No response-encryption key is shared across sessions. This aligns with HAIP's
  preference for a per-request ephemeral key and does not affect the offline
  `verify` commands.
- Licensed under Apache-2.0. Open source, framed as a developer tool.
- Honest scope. `verify trust` checks that a leaf chains to a supplied anchor
  within its validity window; it is not full X.509 path validation. The decoders
  cover SD-JWT VC, ISO 18013-5 mdoc (structure only; the COSE signature and value
  digests are not verified), WRPRC, OpenID4VP request/JAR, credential offer,
  status list, DCQL, registration body, X.509 PEM, and generic JWT/JWS.
  Cryptographic mdoc verification (COSE_Sign1 plus value-digest matching plus
  device binding) is later work, mirrored on the SD-JWT side by `verify`. The
  curated baselines are deliberate taste judgments, not Rulebook derivations.

## [0.1.0]

Initial hackathon release. This was the seed workbench: a Claude Code oriented
skill and Rust CLI around the registrar workflow and over-ask guardrail.

### Added

- `generate`: create a proportionate registration body.
- `check`: catch over-asking and registrar body shape mistakes before writes.
- `doctor`: diagnose signed request and JAR gotchas.
- `register`: guarded registrar write path with dry-run by default.
- `list`: read registrations back for a relying party.
- `clone`: run a local registrar-compatible store for offline rehearsal.

### Notes

- Focused on the winning hackathon story: an agent can explain why a relying
  party is asking for too much data and produce the smaller, safer version.
- The deeper verifier engine, live wallet debugger, hosted relay, evidence
  replay, cache backend, and cross-platform plugin bundle arrived later.
