//! DCQL (Digital Credentials Query Language) helpers: parse a DCQL query from
//! JSON, build one from claim paths, and build the query a registrar
//! registration body stands for.

use std::sync::OnceLock;

use anyhow::{anyhow, Context, Result};
use augenmass_core::inspector::{Outcome, OverAskReport};
use augenmass_core::{pid, regcert};
use openid4vp::core::dcql_query::DcqlQuery;
use serde_json::{json, Value};

/// Parse a DCQL query from a JSON string. Accepts a bare query object or a
/// wrapper that carries the query under a `dcql_query` field. A query whose
/// `credential_sets` carry an empty option is rejected as malformed.
pub fn parse_dcql(input: &str) -> Result<DcqlQuery> {
    parse_dcql_with_warnings(input).map(|parsed| parsed.query)
}

/// A parsed query together with the authoring warnings of its JSON text.
pub struct ParsedDcql {
    pub query: DcqlQuery,
    pub warnings: Vec<IgnoredMember>,
}

/// Like [`parse_dcql`], and keeps the warnings of [`ignored_members`]. The
/// typed query no longer has the members it does not know, so the warnings
/// are taken from the JSON value before the typed parse. When the query is
/// rejected and there are warnings, the error names them: a member spelled
/// `paths` for `path` is then the likely cause of "missing field `path`".
pub fn parse_dcql_with_warnings(input: &str) -> Result<ParsedDcql> {
    let value: Value = serde_json::from_str(input.trim()).context("DCQL is not JSON")?;
    let inner = value.get("dcql_query").cloned().unwrap_or(value);
    let warnings = ignored_members(&inner);
    let typed = serde_json::from_value::<DcqlQuery>(inner)
        .context("parse DCQL query")
        .and_then(|query| reject_empty_credential_set_options(&query).map(|()| query));
    match typed {
        Ok(query) => Ok(ParsedDcql { query, warnings }),
        Err(error) if warnings.is_empty() => Err(error),
        Err(error) => {
            let lines: Vec<&str> = warnings.iter().map(|w| w.message.as_str()).collect();
            Err(error.context(format!(
                "the query has {} member(s) that a wallet ignores unless it knows them from an extension: {}",
                warnings.len(),
                lines.join(" ")
            )))
        }
    }
}

/// The id of the authoring warning for a member name that resembles a
/// defined one.
pub const NEAR_MISS_ID: &str = "DCQL-MEMBER-NEAR-MISS";

/// What to do about a [`NEAR_MISS_ID`] warning.
pub const NEAR_MISS_FIX: &str = "rename the member to the defined name if that was meant. If it belongs to an extension that the wallet implements, keep it; this warning then does not apply.";

/// The levels of a DCQL query whose members are examined, with the member
/// names OpenID4VP 1.0 defines at each. The names are copied from the
/// specification text (OpenID for Verifiable Presentations 1.0, 9 July
/// 2025): the top-level properties of a DCQL query (section 6), the
/// properties of a Credential Query (section 6.1), of a Credential Set Query
/// (section 6.2) and of a Claims Query (section 6.3, and `intent_to_retain`
/// from Appendix B.2.4, the ISO mdoc parameter of a Claims Query). The
/// Trusted Authorities Query (section 6.1.1) and the members of `meta`,
/// which each credential format defines for itself, are not examined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Level {
    /// The query object (section 6).
    Query,
    /// A Credential Query (section 6.1).
    Credential,
    /// A Claims Query (section 6.3).
    Claims,
    /// A Credential Set Query (section 6.2).
    CredentialSet,
}

impl Level {
    /// Every level, in the order of the enum.
    const ALL: [Level; 4] = [
        Self::Query,
        Self::Credential,
        Self::Claims,
        Self::CredentialSet,
    ];

    /// The serialized name of the level.
    fn id(self) -> &'static str {
        match self {
            Self::Query => "dcql_query",
            Self::Credential => "credential_query",
            Self::Claims => "claims_query",
            Self::CredentialSet => "credential_set_query",
        }
    }

    /// The name the specification gives the level.
    fn name(self) -> &'static str {
        match self {
            Self::Query => "DCQL query",
            Self::Credential => "Credential Query",
            Self::Claims => "Claims Query",
            Self::CredentialSet => "Credential Set Query",
        }
    }

    /// The member names OpenID4VP 1.0 defines at the level.
    fn defined(self) -> &'static [&'static str] {
        match self {
            Self::Query => &["credentials", "credential_sets"],
            Self::Credential => &[
                "id",
                "format",
                "multiple",
                "meta",
                "trusted_authorities",
                "require_cryptographic_holder_binding",
                "claims",
                "claim_sets",
            ],
            Self::Claims => &["id", "path", "values", "intent_to_retain"],
            Self::CredentialSet => &["options", "required"],
        }
    }
}

/// A member of a DCQL query that OpenID4VP 1.0 does not define at its level
/// and that resembles a member it does define there, by its name or (for
/// `claims` in a credential query without `claims`) by the form of its
/// value. A wallet that does not know the member ignores it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IgnoredMember {
    /// Always [`NEAR_MISS_ID`].
    pub id: &'static str,
    /// "query", "credentials[0]", "credentials[0].claims[1]",
    /// "credential_sets[0]".
    pub place: String,
    /// "dcql_query", "credential_query", "claims_query",
    /// "credential_set_query".
    pub level: &'static str,
    /// The member as written, for example "claim".
    pub member: String,
    /// The defined member it resembles, for example "claims".
    pub resembles: &'static str,
    /// The warning as one line of text.
    pub message: String,
}

/// The name a member name is compared by: its letters in lower case, with a
/// run of the same letter written once. Every character that is not a letter
/// is left out: a space or a tab, a separator (`_`, `-`, `.`), a digit, a
/// character without width. A letter outside ASCII stays as it is, so a name
/// with a look-alike letter compares as a different name.
fn skeleton(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars().filter(|c| c.is_alphabetic()) {
        let c = c.to_ascii_lowercase();
        if !out.ends_with(c) {
            out.push(c);
        }
    }
    out
}

/// A word of a defined member name in its singular and plural forms:
/// `claims` gives `claim` and `claims`, `path` gives `path` and `paths`,
/// `authorities` gives `authority`, `authoritys` and `authorities`.
fn word_forms(word: &str) -> Vec<String> {
    let stem_of_y = word
        .strip_suffix("ies")
        .or_else(|| word.strip_suffix('y'))
        .filter(|stem| !stem.is_empty());
    if let Some(stem) = stem_of_y {
        return vec![
            format!("{stem}y"),
            format!("{stem}ys"),
            format!("{stem}ies"),
        ];
    }
    let singular = match word.strip_suffix('s') {
        Some(stem) if !stem.is_empty() => stem,
        _ => word,
    };
    vec![singular.to_string(), format!("{singular}s")]
}

/// The spellings of a defined member name that a near miss is compared with:
/// its words (the name is split at `_`), each in every form of
/// [`word_forms`], joined without a separator.
fn spellings(defined: &str) -> Vec<String> {
    let mut joined = vec![String::new()];
    for word in defined.split('_') {
        let forms = word_forms(word);
        joined = joined
            .iter()
            .flat_map(|head| forms.iter().map(move |form| format!("{head}{form}")))
            .collect();
    }
    joined
}

/// The defined member of `level` that `name` resembles by its name: `name`
/// is not defined at the level, and differs from a defined member of the
/// level only by the plural ending of a word, by upper and lower case, by a
/// letter written twice, or by characters that are not letters (the
/// separator between its words, a space, a digit, a dot). The comparison
/// does not split `name` into words, so the place of an upper-case letter
/// makes no difference (`claimS` is `claims`). Not an edit distance: the
/// defined names are short, and a distance of one would relate `id` to `idx`
/// and `path` to `math`, names an extension could choose.
fn near_miss(level: Level, name: &str) -> Option<&'static str> {
    let defined = level.defined();
    if defined.contains(&name) {
        return None;
    }
    let written = skeleton(name);
    if written.is_empty() {
        return None;
    }
    compared(level)
        .iter()
        .find(|(_, spellings)| spellings.contains(&written))
        .map(|(defined, _)| *defined)
}

/// A defined member name and its [`spellings`] as [`skeleton`]s.
type Compared = (&'static str, Vec<String>);

/// The defined members of a level, each with its [`spellings`] as
/// [`skeleton`]s. Built once: a large query has many members to compare.
fn compared(level: Level) -> &'static [Compared] {
    static TABLE: OnceLock<Vec<Vec<Compared>>> = OnceLock::new();
    let table = TABLE.get_or_init(|| {
        Level::ALL
            .iter()
            .map(|level| {
                level
                    .defined()
                    .iter()
                    .map(|defined| {
                        let spelled = spellings(defined).iter().map(|s| skeleton(s)).collect();
                        (*defined, spelled)
                    })
                    .collect()
            })
            .collect()
    });
    &table[level as usize]
}

/// Whether a value has the form OpenID4VP 1.0 gives the value of `claims` in
/// a Credential Query (section 6.1: "A non-empty array of objects as defined
/// in Section 6.3"; section 6.3 requires `path` in each of them): a
/// non-empty array whose elements are all objects with a `path` member.
fn has_claims_form(value: &Value) -> bool {
    value.as_array().is_some_and(|entries| {
        !entries.is_empty()
            && entries
                .iter()
                .all(|entry| entry.as_object().is_some_and(|o| o.contains_key("path")))
    })
}

/// The sentence every warning ends with. The quoted sentence is verbatim
/// from OpenID4VP 1.0, section 6 ("Note: Future extensions may define
/// additional properties both at the top level and in the rest of the DCQL
/// data structure. Implementations MUST ignore any unknown properties.").
/// The words around it are this tool's own. The condition at the end is
/// there because the same note allows extensions: the tool knows only that
/// OpenID4VP 1.0 does not define the name at that level, not which
/// extensions a wallet implements.
fn ignored_by_a_wallet(member: &str) -> String {
    format!(
        "A wallet ignores a member it does not know (OpenID4VP 1.0, section 6: \"Implementations MUST ignore any unknown properties.\"), so \"{member}\" has no effect on the request unless the wallet implements an extension that defines it."
    )
}

/// A member name as a warning line prints it: every character outside
/// ASCII and every control character as its escape, for example `\u{200b}`
/// and `\t`. A name that differs from a defined one by a character without
/// width, or by a look-alike letter, would read like the defined name
/// otherwise. `--json` carries the name as written in `member`.
fn shown(member: &str) -> String {
    let mut out = String::with_capacity(member.len());
    for c in member.chars() {
        if c.is_ascii() && !c.is_ascii_control() {
            out.push(c);
        } else {
            out.extend(c.escape_default());
        }
    }
    out
}

/// The one line of a warning for a member whose name resembles a defined
/// one ([`near_miss`]).
fn near_miss_message(place: &str, level: Level, member: &str, resembles: &str) -> String {
    let member = shown(member);
    format!(
        "{place}: member \"{member}\" is not defined by OpenID4VP 1.0 for a {} and resembles \"{resembles}\". {}",
        level.name(),
        ignored_by_a_wallet(&member)
    )
}

/// The one line of a warning for a member of a Credential Query whose value
/// has the form of a `claims` value ([`has_claims_form`]) while the
/// Credential Query has no `claims` member. The words are this tool's own,
/// up to the sentence of [`ignored_by_a_wallet`].
fn claims_form_message(place: &str, member: &str) -> String {
    let member = shown(member);
    format!(
        "{place}: member \"{member}\" is not defined by OpenID4VP 1.0 for a {}, its value has the form of a \"claims\" value (an array of objects with a \"path\" member), and the {} has no \"claims\" member. {}",
        Level::Credential.name(),
        Level::Credential.name(),
        ignored_by_a_wallet(&member)
    )
}

/// The warnings of one object of a query: its members whose name resembles
/// a defined member of `level` ([`near_miss`]). In a Credential Query that
/// has no `claims` member, a member that is not defined there, whose name
/// resembles no defined one and whose value has the form of a `claims` value
/// ([`has_claims_form`]) is reported as well, with `claims` as the member it
/// resembles: the claims its author asked for are under a name the wallet
/// ignores, whatever the spelling (`klaims`, a look-alike letter).
fn examine(level: Level, place: &str, value: &Value, found: &mut Vec<IgnoredMember>) {
    let Some(object) = value.as_object() else {
        return;
    };
    let claims_absent = level == Level::Credential && !object.contains_key("claims");
    for (member, member_value) in object {
        let warning = match near_miss(level, member) {
            Some(resembles) => Some((
                resembles,
                near_miss_message(place, level, member, resembles),
            )),
            None if claims_absent
                && !level.defined().contains(&member.as_str())
                && has_claims_form(member_value) =>
            {
                Some(("claims", claims_form_message(place, member)))
            }
            None => None,
        };
        if let Some((resembles, message)) = warning {
            found.push(IgnoredMember {
                id: NEAR_MISS_ID,
                place: place.to_string(),
                level: level.id(),
                member: member.clone(),
                resembles,
                message,
            });
        }
    }
}

/// The authoring warnings of a DCQL query: every member of the query object,
/// of a credential query, of a claims query and of a credential set query
/// whose name OpenID4VP 1.0 does not define at that level and that resembles
/// a member it does define there, by its name ([`near_miss`]) or, for
/// `claims` in a credential query without `claims`, by the form of its value
/// ([`examine`]). `query` is the query object itself, not a wrapper around
/// it. An unknown member that resembles no defined one gets no warning:
/// extensions are allowed. A value of another JSON type at any place is
/// skipped; the function never fails.
///
/// This is for DCQL queries only. A registration body and a registration
/// certificate have their own member names (`claim` is a defined name
/// there) and are never given to it.
pub fn ignored_members(query: &Value) -> Vec<IgnoredMember> {
    let mut found = Vec::new();
    examine(Level::Query, "query", query, &mut found);
    if let Some(credentials) = query.get("credentials").and_then(Value::as_array) {
        for (i, credential) in credentials.iter().enumerate() {
            examine(
                Level::Credential,
                &format!("credentials[{i}]"),
                credential,
                &mut found,
            );
            if let Some(claims) = credential.get("claims").and_then(Value::as_array) {
                for (k, claim) in claims.iter().enumerate() {
                    examine(
                        Level::Claims,
                        &format!("credentials[{i}].claims[{k}]"),
                        claim,
                        &mut found,
                    );
                }
            }
        }
    }
    if let Some(sets) = query.get("credential_sets").and_then(Value::as_array) {
        for (i, set) in sets.iter().enumerate() {
            examine(
                Level::CredentialSet,
                &format!("credential_sets[{i}]"),
                set,
                &mut found,
            );
        }
    }
    found
}

/// The authoring warnings as `inspect` and `decode request` print them under
/// what they decoded: a count line and one line per warning. Empty when
/// there is no warning.
pub fn warning_block(warnings: &[IgnoredMember]) -> String {
    if warnings.is_empty() {
        return String::new();
    }
    let mut block = format!("  authoring warnings: {}\n", warnings.len());
    for warning in warnings {
        block.push_str(&format!("    {}\n", warning.message));
    }
    block
}

/// `audit` only: a result that would be OK becomes NOT EVALUATED when the
/// query has a member with an authoring warning, because the tool did not
/// evaluate a member that may change what the request asks for. OVER-ASK and
/// NOT EVALUATED stay as they are. The headline, the `outcome` member of
/// `--json` and the exit code follow the changed outcome.
pub fn apply_ignored_members(report: &mut OverAskReport, warnings: &[IgnoredMember]) {
    if warnings.is_empty() || report.outcome != Outcome::Ok {
        return;
    }
    report.outcome = Outcome::NotEvaluated;
    report.verdict_line = format!(
        "{} member(s) of the query resemble a defined member and are ignored by a wallet that does not know them.",
        warnings.len()
    );
}

/// OpenID4VP 1.0 section 6.2: each element of a credential set's `options` is
/// a non-empty array of credential query ids. The parser accepts an empty
/// option, which names no credential; the audit would then select none and
/// judge nothing, so the query is rejected instead.
fn reject_empty_credential_set_options(query: &DcqlQuery) -> Result<()> {
    let Some(sets) = query.credential_sets() else {
        return Ok(());
    };
    for (i, set) in sets.iter().enumerate() {
        for (k, option) in set.options().iter().enumerate() {
            if option.is_empty() {
                return Err(anyhow!(
                    "malformed DCQL query: credential_sets[{i}].options[{k}] is an empty list; \
                     each option must name at least one credential query id \
                     (OpenID4VP 1.0 section 6.2)"
                ));
            }
        }
    }
    Ok(())
}

/// Build a German-PID DCQL query from a list of claim paths.
/// Each path is a non-empty list of segments, e.g. `["age_equal_or_over","18"]`.
pub fn dcql_from_paths(paths: &[Vec<String>]) -> Result<DcqlQuery> {
    if paths.is_empty() {
        return Err(anyhow!("no claim paths given"));
    }
    if paths.iter().any(|p| p.is_empty()) {
        return Err(anyhow!("a claim path has no segments"));
    }
    let refs: Vec<Vec<&str>> = paths
        .iter()
        .map(|path| path.iter().map(String::as_str).collect())
        .collect();
    let slices: Vec<&[&str]> = refs.iter().map(Vec::as_slice).collect();
    Ok(pid::pid_query(&slices))
}

/// Parse a dotted or slash claim path string into segments.
/// Accepts `age_equal_or_over.18`, `address/resident_city`, or a single segment.
pub fn parse_claim_path(spec: &str) -> Vec<String> {
    spec.split(['.', '/'])
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Build the DCQL query a registrar registration body stands for: one
/// credential query per `credentials[]` entry, with that entry's format, its
/// `meta` (`vct_values` or `doctype_value`), and its claim paths exactly as
/// written (`claims[].path`, the registrar DTO, or the ETSI singular
/// `claim[].path`), null and integer segments included. `Ok(None)` when the
/// body has no `credentials` member or an empty `credentials` array. A
/// `credentials` value that is not an array is an error, so a body nobody
/// could read never counts as a body without credentials. An entry without a
/// format, without a non-empty claims array, or with a path that is not a
/// claims path pointer (OpenID4VP 1.0 section 7: a non-empty array of strings,
/// nulls and non-negative integers) is an error, never silently skipped.
pub fn dcql_from_registration_body(body: &Value) -> Result<Option<DcqlQuery>> {
    let credentials = match body.get("credentials") {
        None => return Ok(None),
        Some(Value::Array(credentials)) => credentials,
        Some(_) => return Err(anyhow!("credentials is not an array")),
    };
    if credentials.is_empty() {
        return Ok(None);
    }

    let mut out = Vec::new();
    for (i, credential) in credentials.iter().enumerate() {
        let format = credential
            .get("format")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("credential {i} has no format"))?;
        let meta = credential
            .get("meta")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let claims = credential
            .get("claims")
            .or_else(|| credential.get("claim"))
            .and_then(Value::as_array)
            .filter(|claims| !claims.is_empty())
            .ok_or_else(|| anyhow!("credential {i} has no claims[]"))?;
        let mut paths = Vec::new();
        for claim in claims {
            let path = claim
                .get("path")
                .filter(|p| regcert::parse_claim_path(p).is_some())
                .ok_or_else(|| {
                    anyhow!("credential {i} has a claim path that is not a claims path pointer")
                })?;
            paths.push(json!({ "path": path }));
        }
        out.push(json!({
            "id": format!("cred{i}"),
            "format": format,
            "meta": meta,
            "claims": paths,
        }));
    }

    let query = serde_json::from_value(json!({ "credentials": out }))
        .context("registration body as a DCQL query")?;
    Ok(Some(query))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_claim_path_splits_on_dot_and_slash() {
        assert_eq!(
            parse_claim_path("age_equal_or_over.18"),
            ["age_equal_or_over", "18"]
        );
        assert_eq!(
            parse_claim_path("address/resident_city"),
            ["address", "resident_city"]
        );
        assert_eq!(parse_claim_path("given_name"), ["given_name"]);
    }

    #[test]
    fn parse_dcql_rejects_an_empty_credential_set_option() {
        let credentials = json!([
            { "id": "a", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:example:a:1"] } },
            { "id": "b", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:example:b:1"] } },
        ]);
        for sets in [
            json!([{ "options": [[]] }]),
            json!([{ "options": [["a"], []] }]),
            json!([{ "options": [["a"]] }, { "options": [[]], "required": false }]),
        ] {
            let query = json!({ "credentials": credentials, "credential_sets": sets });
            let err = parse_dcql(&query.to_string()).expect_err("empty option is malformed");
            let message = format!("{err:#}");
            assert!(message.contains("is an empty list"), "{message}");
            assert!(message.contains("section 6.2"), "{message}");
            let wrapped = json!({ "dcql_query": query });
            assert!(parse_dcql(&wrapped.to_string()).is_err(), "{sets}");
        }
        let valid = json!({ "credentials": credentials,
            "credential_sets": [{ "options": [["a"], ["a", "b"]] }] });
        assert!(parse_dcql(&valid.to_string()).is_ok());
        assert!(parse_dcql(&json!({ "credentials": credentials }).to_string()).is_ok());
    }

    /// The member names per level, as OpenID4VP 1.0 (9 July 2025) lists
    /// them. Each comment names the section and the sentence that introduces
    /// the list.
    #[test]
    fn defined_members_match_openid4vp_1_0() {
        // Section 6: "A valid DCQL query is defined as a JSON-encoded object
        // with the following top-level properties:"
        assert_eq!(Level::Query.defined(), ["credentials", "credential_sets"]);
        // Section 6.1: "Each entry in credentials MUST be an object with the
        // following properties:"
        assert_eq!(
            Level::Credential.defined(),
            [
                "id",
                "format",
                "multiple",
                "meta",
                "trusted_authorities",
                "require_cryptographic_holder_binding",
                "claims",
                "claim_sets",
            ]
        );
        // Section 6.3: "Each entry in claims MUST be an object with the
        // following properties:", and Appendix B.2.4: "The following are ISO
        // mdoc specific parameters to be used in a Claims Query as defined
        // in Section 6.3."
        assert_eq!(
            Level::Claims.defined(),
            ["id", "path", "values", "intent_to_retain"]
        );
        // Section 6.2: "Each entry in credential_sets MUST be an object with
        // the following properties:"
        assert_eq!(Level::CredentialSet.defined(), ["options", "required"]);
        assert_eq!(Level::Query.name(), "DCQL query");
        assert_eq!(Level::Credential.name(), "Credential Query");
        assert_eq!(Level::Claims.name(), "Claims Query");
        assert_eq!(Level::CredentialSet.name(), "Credential Set Query");
    }

    /// The output of the rule as a literal list, so that a change of the
    /// rule is visible in review.
    #[test]
    fn near_miss_rule_classifies_as_listed() {
        let near = [
            (Level::Credential, "claim", "claims"),
            (Level::Credential, "claims_set", "claim_sets"),
            (Level::Credential, "claim_set", "claim_sets"),
            (Level::Credential, "claims_sets", "claim_sets"),
            (Level::Credential, "claimSets", "claim_sets"),
            (Level::Query, "credential_set", "credential_sets"),
            (Level::Query, "credentialSets", "credential_sets"),
            (Level::Query, "credential", "credentials"),
            (Level::CredentialSet, "option", "options"),
            (Level::Claims, "paths", "path"),
            (Level::Claims, "Path", "path"),
            (Level::Claims, "value", "values"),
            (Level::Claims, "intentToRetain", "intent_to_retain"),
            (Level::Claims, "intent-to-retain", "intent_to_retain"),
            (
                Level::Credential,
                "trusted_authority",
                "trusted_authorities",
            ),
            (
                Level::Credential,
                "trustedAuthorities",
                "trusted_authorities",
            ),
            (Level::Credential, "Claims", "claims"),
            (Level::Credential, "formats", "format"),
            (Level::Credential, "ID", "id"),
        ];
        for (level, name, defined) in near {
            assert_eq!(near_miss(level, name), Some(defined), "{level:?} {name}");
        }
        let not_near = [
            // Names an extension could choose.
            (Level::Credential, "x_example_profile"),
            (Level::Claims, "x_example_note"),
            (Level::Query, "x_example_extension"),
            (Level::Claims, "namespace"),
            (Level::Claims, "claim_name"),
            (Level::Credential, "vct"),
            (Level::Credential, "purpose"),
            (Level::Credential, "metadata"),
            (Level::Claims, "label"),
            (Level::Credential, "type"),
            // One letter away from a defined name, and not a near miss.
            (Level::Credential, "idx"),
            (Level::Claims, "pat"),
            (Level::Claims, "math"),
            (Level::CredentialSet, "require"),
            (Level::CredentialSet, "optional"),
            // A defined name at its own level.
            (Level::Credential, "claims"),
            (Level::Claims, "values"),
            // A defined name of another level.
            (Level::Query, "claims"),
            (Level::Credential, "options"),
            // Another letter, by one or two (not an edit distance), and a
            // letter outside ASCII.
            (Level::Credential, "claimz"),
            (Level::Credential, "klaims"),
            (Level::Credential, "cl\u{e4}ims"),
            (Level::Credential, "cla\u{456}ms"),
            // No letter at all.
            (Level::Credential, ""),
            (Level::Credential, "_"),
            (Level::Credential, " "),
            (Level::Credential, "1"),
        ];
        for (level, name) in not_near {
            assert_eq!(near_miss(level, name), None, "{level:?} {name:?}");
        }
    }

    /// `compared` reads its table by the position of the level in the enum.
    #[test]
    fn compared_spellings_belong_to_their_level() {
        for (position, level) in Level::ALL.into_iter().enumerate() {
            assert_eq!(level as usize, position);
            let names: Vec<&str> = compared(level).iter().map(|(name, _)| *name).collect();
            assert_eq!(names, level.defined(), "{level:?}");
        }
        let claim_sets = &compared(Level::Credential)[7];
        assert_eq!(claim_sets.0, "claim_sets");
        assert_eq!(
            claim_sets.1,
            ["claimset", "claimsets", "claimset", "claimsets"]
        );
    }

    /// A name that differs from a defined one only by upper and lower case
    /// is a near miss wherever the upper-case letters are: `claimS`,
    /// `cLaIm_sEtS`, `valueS`. The comparison does not split the written
    /// name into words at an upper-case letter.
    #[test]
    fn near_miss_covers_every_case_only_spelling() {
        let mut examined = 0;
        for level in Level::ALL {
            for defined in level.defined() {
                let letters: Vec<char> = defined.chars().collect();
                let mut spelled = vec![
                    defined.to_ascii_uppercase(),
                    // Every second letter in upper case, from the first and
                    // from the second letter.
                    alternate(&letters, 0),
                    alternate(&letters, 1),
                ];
                // One letter in upper case, at every place.
                for at in 0..letters.len() {
                    let mut name = letters.clone();
                    name[at] = name[at].to_ascii_uppercase();
                    spelled.push(name.into_iter().collect());
                }
                for name in spelled {
                    if name == *defined {
                        continue;
                    }
                    assert_eq!(near_miss(level, &name), Some(*defined), "{level:?} {name}");
                    examined += 1;
                }
            }
        }
        assert!(examined > 100, "{examined} spellings examined");
        // The spellings of the finding, by name.
        for (level, name, defined) in [
            (Level::Credential, "claimS", "claims"),
            (Level::Credential, "cLaImS", "claims"),
            (Level::Credential, "claim_setS", "claim_sets"),
            (Level::Credential, "cLaIm_sEtS", "claim_sets"),
            (Level::Query, "credentialS", "credentials"),
            (Level::Query, "credential_setS", "credential_sets"),
            (Level::CredentialSet, "optionS", "options"),
            (Level::Claims, "pathS", "path"),
            (Level::Claims, "valueS", "values"),
            (Level::Claims, "vAlUeS", "values"),
            // Case and plural ending together.
            (Level::Credential, "claimSetS", "claim_sets"),
            (Level::Credential, "ClaimsSet", "claim_sets"),
        ] {
            assert_eq!(near_miss(level, name), Some(defined), "{level:?} {name}");
        }
    }

    fn alternate(letters: &[char], upper_from: usize) -> String {
        letters
            .iter()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == upper_from {
                    c.to_ascii_uppercase()
                } else {
                    *c
                }
            })
            .collect()
    }

    /// A name that differs from a defined one only by characters that are
    /// not letters, or by a letter written twice, is a near miss: a space
    /// or a tab before or after it, a digit, a dot, a character without
    /// width, a doubled last letter.
    #[test]
    fn near_miss_covers_characters_that_are_not_letters_and_doubled_letters() {
        let mut examined = 0;
        for level in Level::ALL {
            for defined in level.defined() {
                let last = defined.chars().last().expect("a letter");
                for name in [
                    format!("{defined} "),
                    format!(" {defined}"),
                    format!("{defined}\t"),
                    format!("{defined}\n"),
                    format!("{defined}1"),
                    format!("{defined}."),
                    format!("{defined}_"),
                    format!("_{defined}"),
                    format!("{defined}-"),
                    format!("{defined}\u{200b}"),
                    format!("{defined}\u{202e}"),
                    format!("\u{feff}{defined}"),
                    format!("{defined}{last}"),
                ] {
                    assert_eq!(
                        near_miss(level, &name),
                        Some(*defined),
                        "{level:?} {name:?}"
                    );
                    examined += 1;
                }
            }
        }
        assert_eq!(examined, 16 * 13);
        for (level, name, defined) in [
            (Level::Credential, "claim ", "claims"),
            (Level::Credential, " claim", "claims"),
            (Level::Credential, "claim1", "claims"),
            (Level::Credential, "claimss", "claims"),
            (Level::Credential, "c_laims", "claims"),
            (Level::Credential, "claim_sets ", "claim_sets"),
            (Level::Query, "credential_sets ", "credential_sets"),
            (Level::CredentialSet, "optionss", "options"),
            (Level::Claims, "paths1", "path"),
            (Level::Claims, "value ", "values"),
            (Level::Claims, "valuess", "values"),
        ] {
            assert_eq!(near_miss(level, name), Some(defined), "{level:?} {name:?}");
        }
    }

    /// The claims of a credential query under a name the rule for names
    /// does not relate to `claims`: the member is reported by the form of
    /// its value, as long as the credential query has no `claims` member.
    #[test]
    fn claims_under_another_name_are_reported_by_the_form_of_the_value() {
        let credential = |member: &str, value: Value| {
            let mut credential = json!({
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
            });
            credential[member] = value;
            credential
        };
        let claims = json!([{ "path": ["given_name"] }, { "id": "b", "path": ["birthdate"] }]);
        for member in [
            "klaims",
            "claimz",
            "cla\u{456}ms",
            "requested",
            "x_example_claims",
        ] {
            let query = json!({ "credentials": [credential(member, claims.clone())] });
            let found = ignored_members(&query);
            assert_eq!(found.len(), 1, "{member}: {found:?}");
            assert_eq!(found[0].id, "DCQL-MEMBER-NEAR-MISS");
            assert_eq!(found[0].place, "credentials[0]");
            assert_eq!(found[0].level, "credential_query");
            assert_eq!(found[0].member, member);
            assert_eq!(found[0].resembles, "claims");
            // The line prints a letter outside ASCII as its escape.
            let member = member.replace('\u{456}', "\\u{456}");
            assert_eq!(
                found[0].message,
                format!(
                    "credentials[0]: member \"{member}\" is not defined by OpenID4VP 1.0 for a Credential Query, its value has the form of a \"claims\" value (an array of objects with a \"path\" member), and the Credential Query has no \"claims\" member. A wallet ignores a member it does not know (OpenID4VP 1.0, section 6: \"Implementations MUST ignore any unknown properties.\"), so \"{member}\" has no effect on the request unless the wallet implements an extension that defines it."
                )
            );
        }

        // A character without width and a tab are printed as their escape;
        // the member itself is kept as written.
        for (member, printed) in [
            ("claims\u{200b}", "claims\\u{200b}"),
            ("claims\t", "claims\\t"),
            ("\u{feff}claim", "\\u{feff}claim"),
        ] {
            let query = json!({ "credentials": [credential(member, claims.clone())] });
            let found = ignored_members(&query);
            assert_eq!(found.len(), 1, "{member:?}: {found:?}");
            assert_eq!(found[0].member, member);
            assert!(
                found[0].message.starts_with(&format!(
                    "credentials[0]: member \"{printed}\" is not defined by OpenID4VP 1.0 for a Credential Query and resembles \"claims\". "
                )),
                "{}",
                found[0].message
            );
            assert!(
                found[0]
                    .message
                    .ends_with(&format!("so \"{printed}\" has no effect on the request unless the wallet implements an extension that defines it.")),
                "{}",
                found[0].message
            );
        }

        // A name that is a near miss by its name gets the warning for the
        // name, once.
        let query = json!({ "credentials": [credential("claim", claims.clone())] });
        let found = ignored_members(&query);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].message.contains("and resembles \"claims\"."));

        // With `claims` in the credential query the member is an extension
        // member like any other: no warning.
        let mut with_claims = credential("klaims", claims.clone());
        with_claims["claims"] = json!([{ "path": ["age_equal_or_over", "18"] }]);
        assert_eq!(
            ignored_members(&json!({ "credentials": [with_claims] })),
            []
        );

        // A value of another form is no `claims` value: no warning.
        for value in [
            json!([]),
            json!("given_name"),
            json!({ "path": ["given_name"] }),
            json!([["given_name"]]),
            json!([{ "path": ["given_name"] }, "birthdate"]),
            json!([{ "name": "given_name" }]),
            json!([{ "path": ["given_name"] }, { "name": "birthdate" }]),
        ] {
            let query = json!({ "credentials": [credential("klaims", value.clone())] });
            assert_eq!(ignored_members(&query), [], "{value}");
        }

        // A defined member of the credential query is never reported, and
        // the rule is for a credential query only.
        let mut defined = credential("trusted_authorities", claims.clone());
        defined["meta"] = claims.clone();
        assert_eq!(ignored_members(&json!({ "credentials": [defined] })), []);
        let top =
            json!({ "credentials": [credential("claims", claims.clone())], "klaims": claims });
        assert_eq!(ignored_members(&top), []);
    }

    #[test]
    fn warning_names_place_member_level_and_defined_name() {
        let query = json!({
            "credential": [],
            "credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "claim": [],
                "claims": [{ "path": ["a"] }, { "path": ["b"], "value": [true] }],
            }],
            "credential_sets": [{ "options": [["pid"]] }, { "option": [["pid"]] }],
        });
        let found = ignored_members(&query);
        let line = |place: &str, member: &str, level: &str, defined: &str| {
            format!(
                "{place}: member \"{member}\" is not defined by OpenID4VP 1.0 for a {level} and resembles \"{defined}\". A wallet ignores a member it does not know (OpenID4VP 1.0, section 6: \"Implementations MUST ignore any unknown properties.\"), so \"{member}\" has no effect on the request unless the wallet implements an extension that defines it."
            )
        };
        let expected = [
            (
                "query",
                "dcql_query",
                "credential",
                "credentials",
                "DCQL query",
            ),
            (
                "credentials[0]",
                "credential_query",
                "claim",
                "claims",
                "Credential Query",
            ),
            (
                "credentials[0].claims[1]",
                "claims_query",
                "value",
                "values",
                "Claims Query",
            ),
            (
                "credential_sets[1]",
                "credential_set_query",
                "option",
                "options",
                "Credential Set Query",
            ),
        ];
        assert_eq!(found.len(), expected.len(), "{found:?}");
        for (warning, (place, level, member, resembles, level_name)) in found.iter().zip(expected) {
            assert_eq!(warning.id, "DCQL-MEMBER-NEAR-MISS");
            assert_eq!(warning.place, place);
            assert_eq!(warning.level, level);
            assert_eq!(warning.member, member);
            assert_eq!(warning.resembles, resembles);
            assert_eq!(warning.message, line(place, member, level_name, resembles));
        }
        let json = serde_json::to_value(&found[1]).expect("json");
        assert_eq!(
            json,
            json!({
                "id": "DCQL-MEMBER-NEAR-MISS",
                "place": "credentials[0]",
                "level": "credential_query",
                "member": "claim",
                "resembles": "claims",
                "message": line("credentials[0]", "claim", "Credential Query", "claims"),
            })
        );
    }

    /// The members of an authorization request object are not DCQL members.
    #[test]
    fn only_the_inner_query_of_a_wrapper_is_examined() {
        let request = json!({
            "client_id": "x509_hash:example",
            "nonce": "n-0S6_WzA2Mj",
            "claim": "not a DCQL member here",
            "option": 1,
            "dcql_query": { "credentials": [{
                "id": "pid", "format": "dc+sd-jwt",
                "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
                "claim": [{ "path": ["birthdate"] }],
            }] },
        });
        let parsed = parse_dcql_with_warnings(&request.to_string()).expect("parses");
        assert_eq!(parsed.warnings.len(), 1, "{:?}", parsed.warnings);
        assert_eq!(parsed.warnings[0].place, "credentials[0]");
        assert_eq!(parsed.warnings[0].member, "claim");
        // `parse_dcql` gives the same query and drops the warnings.
        let query = parse_dcql(&request.to_string()).expect("parses");
        assert_eq!(
            serde_json::to_value(&query).expect("json"),
            serde_json::to_value(&parsed.query).expect("json")
        );
    }

    #[test]
    fn values_of_another_type_are_skipped() {
        for query in [
            json!("credentials"),
            json!(null),
            json!([{ "claim": [] }]),
            json!({ "credentials": "claim" }),
            json!({ "credentials": [1, null, "claim", ["claim"]] }),
            json!({ "credentials": [{ "id": "a", "claims": { "paths": [] } }] }),
            json!({ "credentials": [{ "id": "a", "claims": [1, null, ["paths"]] }] }),
            json!({ "credentials": [], "credential_sets": [null, 1, "option"] }),
            json!({ "credentials": [], "credential_sets": { "option": [] } }),
        ] {
            assert_eq!(ignored_members(&query), [], "{query}");
        }
    }

    /// No DCQL query that is committed under `examples/` or `fixtures/dcql/`
    /// has a warning, except the example that is there to show one.
    #[test]
    fn committed_queries_have_no_warning() {
        let mut examined = 0;
        for dir in ["examples", "fixtures/dcql"] {
            for entry in std::fs::read_dir(dir).expect("directory") {
                let path = entry.expect("entry").path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).expect("read");
                let Ok(value) = serde_json::from_str::<Value>(&text) else {
                    continue;
                };
                // A DCQL query, bare or wrapped; a registration body has
                // `credentials` too, and `claim` is a defined name there.
                let query = match value.get("dcql_query") {
                    Some(inner) => inner,
                    None if value.get("credentials").is_some_and(Value::is_array)
                        && value.get("rpId").is_none()
                        && value.get("purpose").is_none() =>
                    {
                        &value
                    }
                    None => continue,
                };
                let found = ignored_members(query);
                if path.ends_with("age-request-ignored-member.json") {
                    assert_eq!(found.len(), 1, "{}", path.display());
                    assert_eq!(found[0].member, "claim");
                } else {
                    assert_eq!(found, [], "{}", path.display());
                }
                examined += 1;
            }
        }
        assert!(examined >= 6, "{examined} queries examined");
    }

    #[test]
    fn ok_becomes_not_evaluated_and_nothing_else_changes() {
        use augenmass_core::inspector;
        let warnings = ignored_members(&json!({ "credentials": [{ "claim": [] }] }));
        assert_eq!(warnings.len(), 1);
        let baseline = inspector::baseline("age_gate_18").expect("baseline");
        let report = |paths: &[&[&str]]| {
            inspector::analyze(
                augenmass_core::PID_VCT,
                &pid::pid_query(paths),
                None,
                Some(&baseline),
                &[],
            )
        };

        // OK becomes NOT EVALUATED, with a verdict line that says why.
        let mut ok = report(&[&["age_equal_or_over", "18"]]);
        assert_eq!(ok.outcome, Outcome::Ok);
        let counts = serde_json::to_value(ok.counts).expect("json");
        apply_ignored_members(&mut ok, &warnings);
        assert_eq!(ok.outcome, Outcome::NotEvaluated);
        assert_eq!(ok.outcome().exit_code(), 3);
        assert_eq!(
            ok.verdict_line,
            "1 member(s) of the query resemble a defined member and are ignored by a wallet that does not know them."
        );
        assert_eq!(serde_json::to_value(ok.counts).expect("json"), counts);

        // Without a warning nothing changes.
        let mut ok = report(&[&["age_equal_or_over", "18"]]);
        let line = ok.verdict_line.clone();
        apply_ignored_members(&mut ok, &[]);
        assert_eq!(ok.outcome, Outcome::Ok);
        assert_eq!(ok.verdict_line, line);

        // OVER-ASK stays OVER-ASK.
        let mut over = report(&[&["address"]]);
        assert_eq!(over.outcome, Outcome::OverAsk);
        let line = over.verdict_line.clone();
        apply_ignored_members(&mut over, &warnings);
        assert_eq!(over.outcome, Outcome::OverAsk);
        assert_eq!(over.verdict_line, line);

        // NOT EVALUATED stays, with its own verdict line.
        let unmodelled: DcqlQuery = serde_json::from_value(json!({ "credentials": [{
            "id": "card", "format": "dc+sd-jwt",
            "meta": { "vct_values": ["urn:example:member-card:1"] },
            "claims": [{ "path": ["member_number"] }],
        }] }))
        .expect("query");
        let mut unjudged = inspector::analyze(
            augenmass_core::PID_VCT,
            &unmodelled,
            None,
            Some(&baseline),
            &[],
        );
        assert_eq!(unjudged.outcome, Outcome::NotEvaluated);
        let line = unjudged.verdict_line.clone();
        apply_ignored_members(&mut unjudged, &warnings);
        assert_eq!(unjudged.outcome, Outcome::NotEvaluated);
        assert_eq!(unjudged.verdict_line, line);
    }

    /// A query the typed parse rejects stays an error, and the error names
    /// the member that is the likely cause.
    #[test]
    fn a_rejected_query_names_its_ignored_members() {
        let query = json!({ "credentials": [{
            "id": "pid", "format": "dc+sd-jwt",
            "claims": [{ "paths": ["birthdate"] }],
        }] });
        let error = parse_dcql_with_warnings(&query.to_string())
            .err()
            .expect("rejected");
        let chain: Vec<String> = error.chain().map(ToString::to_string).collect();
        assert_eq!(chain.len(), 3, "{chain:?}");
        assert!(
            chain[0].starts_with("the query has 1 member(s) that a wallet ignores unless it knows them from an extension: credentials[0].claims[0]: member \"paths\" is not defined by OpenID4VP 1.0 for a Claims Query and resembles \"path\"."),
            "{chain:?}"
        );
        assert_eq!(chain[1], "parse DCQL query");
        assert_eq!(chain[2], "missing field `path`");
        // Without such a member the error is the one of before.
        let plain = json!({ "credentials": [{ "id": "pid", "format": "dc+sd-jwt",
            "claims": [{ "id": "x" }] }] });
        let error = parse_dcql(&plain.to_string()).expect_err("rejected");
        assert_eq!(error.to_string(), "parse DCQL query");
    }

    #[test]
    fn dcql_from_paths_rejects_empty() {
        assert!(dcql_from_paths(&[]).is_err());
    }

    #[test]
    fn registration_body_keeps_typed_segments_per_credential() {
        let body = json!({ "credentials": [
            { "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:example:a:1"] },
              "claims": [{ "path": ["nationalities", null] }, { "path": ["badges", 0] }] },
            { "format": "mso_mdoc", "meta": { "doctype_value": "org.example.d.1" },
              "claim": [{ "path": ["org.example.ns1", "member_name"] }] },
        ]});
        let query = dcql_from_registration_body(&body)
            .expect("ok")
            .expect("query");
        let value = serde_json::to_value(&query).expect("json");
        assert_eq!(
            value["credentials"][0]["claims"][0]["path"],
            json!(["nationalities", null])
        );
        assert_eq!(
            value["credentials"][0]["claims"][1]["path"],
            json!(["badges", 0])
        );
        assert_eq!(value["credentials"][1]["format"], "mso_mdoc");
        assert_eq!(
            value["credentials"][1]["meta"]["doctype_value"],
            "org.example.d.1"
        );
    }

    #[test]
    fn registration_body_rejects_invalid_paths_and_claims() {
        for claims in [
            json!([{ "path": ["birthdate", true] }]),
            json!([{ "path": [] }]),
            json!([{ "path": ["a", -1] }]),
            json!([{ "path": ["a", 1.5] }]),
            json!([{ "path": "birthdate" }]),
            json!([{ "id": "x" }]),
            json!([]),
        ] {
            let body = json!({ "credentials": [{ "format": "dc+sd-jwt",
                "meta": { "vct_values": ["v"] }, "claims": claims }] });
            assert!(dcql_from_registration_body(&body).is_err(), "{claims}");
        }
        let no_claims = json!({ "credentials": [{ "format": "dc+sd-jwt", "meta": {} }] });
        assert!(dcql_from_registration_body(&no_claims).is_err());
        assert!(dcql_from_registration_body(&json!({}))
            .expect("ok")
            .is_none());
    }

    #[test]
    fn registration_body_without_credentials_is_none_and_a_non_array_is_an_error() {
        // No member, or an empty array: the body requests no credentials.
        for body in [json!({}), json!({ "credentials": [] })] {
            assert!(dcql_from_registration_body(&body).expect("ok").is_none());
        }
        // Anything else that is not an array was not read: an error, never
        // "no credentials".
        let object = json!({ "format": "dc+sd-jwt", "meta": { "vct_values": ["v"] },
            "claims": [{ "path": ["birthdate"] }] });
        for credentials in [object, json!("x"), json!(1), json!(true), Value::Null] {
            let body = json!({ "credentials": credentials });
            let err = dcql_from_registration_body(&body).expect_err("not an array");
            assert_eq!(
                format!("{err}"),
                "credentials is not an array",
                "{credentials}"
            );
        }
    }
}
