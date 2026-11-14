//! `doctor`: diagnose the verifier signed-request / JAR gotchas. A different
//! document than `check` (the registration body): here `x5c` must be a list of
//! strings, and `client_id` must be in the `x509_hash:...` form. When the
//! request carries a `dcql_query`, the authoring warnings of that query
//! (`dcql::ignored_members`) are reported as warning findings.

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::checkbody::Severity;
use crate::dcql::{ignored_members, IgnoredMember, NEAR_MISS_FIX, NEAR_MISS_ID};
use crate::jose::decode_compact;
use crate::output::{emit, OutputFormat};

/// One finding of `doctor`. The message is owned, because the message of an
/// authoring warning names the member it is about.
#[derive(Debug, Clone)]
pub struct Finding {
    pub id: &'static str,
    pub severity: Severity,
    pub message: String,
    pub fix: &'static str,
}

impl Finding {
    fn blocking(id: &'static str, message: &str, fix: &'static str) -> Self {
        Self {
            id,
            severity: Severity::Blocking,
            message: message.to_string(),
            fix,
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "severity": self.severity.as_str(),
            "message": self.message,
            "fix": self.fix,
        })
    }
}

/// What `doctor` found in one request: its findings, the blocking ones
/// first, and the authoring warnings of the `dcql_query` as `audit --json`
/// and `validate dcql --json` carry them.
pub struct Diagnosis {
    pub findings: Vec<Finding>,
    pub warnings: Vec<IgnoredMember>,
}

impl Diagnosis {
    /// True when a finding is blocking. A warning alone is not.
    pub fn blocking(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.severity == Severity::Blocking)
    }
}

/// Returns true if a blocking finding was reported (the CLI then exits 1).
/// A member of the `dcql_query` whose name resembles a defined one is a
/// warning finding: a wallet ignores a member it does not know, and the
/// member may belong to an extension, so it does not change the exit code.
/// It does change the headline: a request with such a member never gets the
/// line `OK: no signed-request gotchas found.`
pub fn run(input: &str, format: OutputFormat) -> Result<bool> {
    let diagnosis = diagnose(input)?;
    let blocking = diagnosis.blocking();
    let findings = &diagnosis.findings;
    let json = json!({
        "findings": findings.iter().map(Finding::to_json).collect::<Vec<_>>(),
        "ok": !blocking,
        "warnings": diagnosis.warnings,
    });

    let mut text = String::new();
    if findings.is_empty() {
        text.push_str("OK: no signed-request gotchas found.\n");
        text.push_str(
            "Set Content-Type: application/json on every POST; the client does this for you.\n",
        );
    } else {
        text.push_str("Signed-request findings:\n");
        for finding in findings {
            text.push_str(&format!(
                "  {} [{}]: {}\n    Fix: {}\n",
                finding.id,
                finding.severity.as_str(),
                finding.message,
                finding.fix
            ));
        }
        if !blocking {
            text.push_str("\nNo blocking finding (warnings only).\n");
        }
    }

    emit(format, &json, &text)?;
    Ok(blocking)
}

/// The findings of a request given as JSON or as a compact JWT.
pub fn doctor_input(input: &str) -> Result<Vec<Finding>> {
    diagnose(input).map(|diagnosis| diagnosis.findings)
}

fn diagnose(input: &str) -> Result<Diagnosis> {
    let value = parse_json_or_jwt(input)?;
    let mut findings = validate_signed_request(&value);
    // The query of the request is read from two places only: the direct
    // member `dcql_query` of the input, and the direct member `dcql_query`
    // of its `payload` when that is an object (a compact JWT is parsed into
    // a `{"header", "payload"}` pair). A member of the header is never read,
    // and no other depth is searched. A member whose value is not a JSON
    // object (`null`, for example) holds no query and is not counted. The
    // warnings of both are reported, each once per query; when both places
    // hold a query, the place of each warning names its query
    // (`dcql_query.credentials[0]`, `payload.dcql_query.credentials[0]`).
    let queries = request_queries(&value);
    let qualify = queries.len() > 1;
    let mut warnings = Vec::new();
    for (name, query) in queries {
        for mut warning in ignored_members(query) {
            if qualify {
                qualify_place(&mut warning, name);
            }
            warnings.push(warning);
        }
    }
    findings.extend(warnings.iter().map(|warning| Finding {
        id: NEAR_MISS_ID,
        severity: Severity::Warning,
        message: warning.message.clone(),
        fix: NEAR_MISS_FIX,
    }));
    Ok(Diagnosis { findings, warnings })
}

fn parse_json_or_jwt(input: &str) -> Result<Value> {
    let trimmed = input.trim();
    if let Ok(value) = serde_json::from_str(trimmed) {
        return Ok(value);
    }
    let decoded = decode_compact(trimmed).context("input is not JSON and not a compact JWT")?;
    Ok(json!({
        "header": decoded.header,
        "payload": decoded.payload,
    }))
}

/// The queries of the request, each with the name of the member it was read
/// from: the direct member `dcql_query` of the input, then the direct member
/// `dcql_query` of the input's `payload` when that is an object. A member
/// holds a query only when its value is a JSON object: a DCQL query is an
/// object, and `ignored_members` returns nothing for any other value, so a
/// `"dcql_query": null` next to a query must not count as a second query.
fn request_queries(value: &Value) -> Vec<(&'static str, &Value)> {
    let mut queries = Vec::new();
    if let Some(query) = value.get("dcql_query").filter(|query| query.is_object()) {
        queries.push(("dcql_query", query));
    }
    if let Some(query) = value
        .get("payload")
        .filter(|payload| payload.is_object())
        .and_then(|payload| payload.get("dcql_query"))
        .filter(|query| query.is_object())
    {
        queries.push(("payload.dcql_query", query));
    }
    queries
}

/// Prefixes the place of a warning, and the place its message starts with,
/// with the member its query was read from: `credentials[0]` becomes
/// `payload.dcql_query.credentials[0]`, `query` becomes `payload.dcql_query`.
fn qualify_place(warning: &mut IgnoredMember, query: &str) {
    let place = if warning.place == "query" {
        query.to_string()
    } else {
        format!("{query}.{}", warning.place)
    };
    if let Some(rest) = warning
        .message
        .strip_prefix(&format!("{}: ", warning.place))
    {
        warning.message = format!("{place}: {rest}");
    }
    warning.place = place;
}

fn validate_signed_request(value: &Value) -> Vec<Finding> {
    let mut findings = Vec::new();

    if find_key(value, "x5c").is_some_and(Value::is_string) {
        findings.push(Finding::blocking(
            "DOCTOR-X5C-STRING",
            "x5c must be a list of strings, even for a single certificate.",
            "Wrap the certificate in an array: \"x5c\": [\"MIIB...\"].",
        ));
    }

    if find_key(value, "client_id")
        .and_then(Value::as_str)
        .is_some_and(|client_id| !client_id.starts_with("x509_hash:"))
    {
        findings.push(Finding::blocking(
            "DOCTOR-CLIENT-ID-X509HASH",
            "client_id must be in the x509_hash form.",
            "Use \"client_id\": \"x509_hash:<base64url(SHA-256(leaf-cert-DER))>\". Compute it with `augenmass x509-hash`.",
        ));
    }

    findings
}

fn find_key<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) => map
            .get(key)
            .or_else(|| map.values().find_map(|child| find_key(child, key))),
        Value::Array(items) => items.iter().find_map(|child| find_key(child, key)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_x5c_string_and_client_id_shape() {
        let input = r#"{ "header": { "x5c": "MIIB" }, "payload": { "client_id": "wrong" } }"#;
        let findings = doctor_input(input).expect("doctor input");
        assert!(findings.iter().any(|f| f.id == "DOCTOR-X5C-STRING"));
        assert!(findings.iter().any(|f| f.id == "DOCTOR-CLIENT-ID-X509HASH"));
    }

    #[test]
    fn clean_request_has_no_findings() {
        let input =
            r#"{ "header": { "x5c": ["MIIB"] }, "payload": { "client_id": "x509_hash:abc" } }"#;
        let findings = doctor_input(input).expect("doctor input");
        assert!(findings.is_empty());
    }

    /// A request whose `dcql_query` says `claim` for `claims`: one warning
    /// finding with the message of `dcql::ignored_members`, not blocking.
    #[test]
    fn near_miss_member_of_the_query_is_a_warning_finding() {
        let input = r#"{ "header": { "x5c": ["MIIB"] }, "payload": { "client_id": "x509_hash:abc",
            "dcql_query": { "credentials": [ { "id": "pid", "format": "dc+sd-jwt",
              "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
              "claim": [ { "path": ["age_equal_or_over", "18"] } ] } ] } } }"#;
        let diagnosis = diagnose(input).expect("doctor input");
        assert_eq!(diagnosis.findings.len(), 1);
        let finding = &diagnosis.findings[0];
        assert_eq!(finding.id, "DCQL-MEMBER-NEAR-MISS");
        assert_eq!(finding.severity, Severity::Warning);
        assert_eq!(finding.fix, NEAR_MISS_FIX);
        assert_eq!(diagnosis.warnings.len(), 1);
        assert_eq!(finding.message, diagnosis.warnings[0].message);
        assert_eq!(diagnosis.warnings[0].member, "claim");
        assert_eq!(diagnosis.warnings[0].resembles, "claims");
        assert!(!diagnosis.blocking());
    }

    /// The blocking findings come first and stay blocking next to a warning;
    /// a query without such a member adds nothing.
    #[test]
    fn blocking_findings_stay_first_next_to_a_warning() {
        let input = r#"{ "header": { "x5c": "MIIB" }, "payload": { "client_id": "wrong",
            "dcql_query": { "credentials": [ { "id": "pid", "format": "dc+sd-jwt",
              "claims": [ { "paths": ["given_name"], "path": ["given_name"] } ] } ] } } }"#;
        let diagnosis = diagnose(input).expect("doctor input");
        let ids: Vec<&str> = diagnosis.findings.iter().map(|f| f.id).collect();
        assert_eq!(
            ids,
            [
                "DOCTOR-X5C-STRING",
                "DOCTOR-CLIENT-ID-X509HASH",
                "DCQL-MEMBER-NEAR-MISS"
            ]
        );
        assert!(diagnosis.blocking());

        let clean = r#"{ "client_id": "x509_hash:abc", "dcql_query": { "credentials": [
            { "id": "pid", "format": "dc+sd-jwt", "claims": [ { "path": ["given_name"] } ] } ] } }"#;
        let diagnosis = diagnose(clean).expect("doctor input");
        assert!(diagnosis.findings.is_empty());
        assert!(diagnosis.warnings.is_empty());
    }

    /// The query is the one of the request (the payload), not a member of
    /// the same name in the header: a header `dcql_query` neither hides the
    /// warning of the payload's query nor adds one of its own.
    #[test]
    fn the_query_of_the_payload_wins_over_a_header_member() {
        let competing = r#"{ "header": { "alg": "ES256", "dcql_query": {} },
            "payload": { "client_id": "x509_hash:abc", "dcql_query": { "credentials": [
              { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
                "claim": [ { "path": ["given_name"] } ] } ] } } }"#;
        let diagnosis = diagnose(competing).expect("doctor input");
        let ids: Vec<&str> = diagnosis.findings.iter().map(|f| f.id).collect();
        assert_eq!(ids, ["DCQL-MEMBER-NEAR-MISS"]);
        assert_eq!(diagnosis.warnings.len(), 1);
        assert_eq!(diagnosis.warnings[0].member, "claim");

        let header_only = r#"{ "header": { "alg": "ES256", "dcql_query": { "credentials": [
              { "id": "pid", "format": "dc+sd-jwt", "claim": [ { "path": ["given_name"] } ] } ] } },
            "payload": { "client_id": "x509_hash:abc", "dcql_query": { "credentials": [
              { "id": "pid", "format": "dc+sd-jwt", "claims": [ { "path": ["given_name"] } ] } ] } } }"#;
        let diagnosis = diagnose(header_only).expect("doctor input");
        assert!(diagnosis.findings.is_empty());
        assert!(diagnosis.warnings.is_empty());
    }

    /// A query that says `claim` for `claims`.
    const NEAR_MISS_QUERY: &str = r#"{ "credentials": [ { "id": "pid", "format": "dc+sd-jwt",
        "claim": [ { "path": ["given_name"] } ] } ] }"#;

    /// The same query with `claims`.
    const CLEAN_QUERY: &str = r#"{ "credentials": [ { "id": "pid", "format": "dc+sd-jwt",
        "claims": [ { "path": ["given_name"] } ] } ] }"#;

    fn places(diagnosis: &Diagnosis) -> Vec<&str> {
        diagnosis
            .warnings
            .iter()
            .map(|warning| warning.place.as_str())
            .collect()
    }

    /// A member `payload` that is an empty object does not hide the query
    /// at the top level of a plain request.
    #[test]
    fn the_top_level_query_is_read_next_to_an_empty_payload() {
        let input = format!(
            r#"{{ "client_id": "x509_hash:abc", "dcql_query": {NEAR_MISS_QUERY}, "payload": {{}} }}"#
        );
        let diagnosis = diagnose(&input).expect("doctor input");
        let ids: Vec<&str> = diagnosis.findings.iter().map(|f| f.id).collect();
        assert_eq!(ids, ["DCQL-MEMBER-NEAR-MISS"]);
        assert_eq!(places(&diagnosis), ["credentials[0]"]);
        assert!(diagnosis.findings[0]
            .message
            .starts_with("credentials[0]: member \"claim\""));
        assert!(!diagnosis.blocking());
    }

    /// Both places hold a query: the warning of the top-level query is
    /// reported, its place names that query, and the clean query of the
    /// payload adds nothing.
    #[test]
    fn the_top_level_query_is_read_next_to_a_payload_query() {
        let input = format!(
            r#"{{ "client_id": "x509_hash:abc", "dcql_query": {NEAR_MISS_QUERY},
                "payload": {{ "dcql_query": {CLEAN_QUERY} }} }}"#
        );
        let diagnosis = diagnose(&input).expect("doctor input");
        assert_eq!(diagnosis.findings.len(), 1);
        assert_eq!(places(&diagnosis), ["dcql_query.credentials[0]"]);
        assert!(diagnosis.findings[0]
            .message
            .starts_with("dcql_query.credentials[0]: member \"claim\""));
        assert_eq!(diagnosis.findings[0].message, diagnosis.warnings[0].message);
    }

    /// A pair whose payload holds the query and whose top level has none:
    /// the payload's warning is reported with the place `validate dcql`
    /// gives it.
    #[test]
    fn the_payload_query_is_read_when_the_top_level_has_none() {
        let input = format!(
            r#"{{ "header": {{ "alg": "ES256" }},
                "payload": {{ "client_id": "x509_hash:abc", "dcql_query": {NEAR_MISS_QUERY} }} }}"#
        );
        let diagnosis = diagnose(&input).expect("doctor input");
        assert_eq!(diagnosis.findings.len(), 1);
        assert_eq!(places(&diagnosis), ["credentials[0]"]);
    }

    /// A `dcql_query` in the header only is not the request's query.
    #[test]
    fn a_query_in_the_header_only_is_not_read() {
        let input = format!(
            r#"{{ "header": {{ "alg": "ES256", "dcql_query": {NEAR_MISS_QUERY} }},
                "payload": {{ "client_id": "x509_hash:abc" }} }}"#
        );
        let diagnosis = diagnose(&input).expect("doctor input");
        assert!(diagnosis.findings.is_empty());
        assert!(diagnosis.warnings.is_empty());
    }

    /// A `dcql_query` nested deeper than a direct member of the input or of
    /// its payload is not read.
    #[test]
    fn a_query_nested_deeper_is_not_read() {
        for input in [
            format!(
                r#"{{ "client_id": "x509_hash:abc",
                    "client_metadata": {{ "dcql_query": {NEAR_MISS_QUERY} }} }}"#
            ),
            format!(
                r#"{{ "header": {{ "alg": "ES256" }}, "payload": {{ "client_id": "x509_hash:abc",
                    "client_metadata": {{ "dcql_query": {NEAR_MISS_QUERY} }} }} }}"#
            ),
        ] {
            let diagnosis = diagnose(&input).expect("doctor input");
            assert!(diagnosis.findings.is_empty(), "{input}");
            assert!(diagnosis.warnings.is_empty(), "{input}");
        }
    }

    /// The same member in the query of the top level and in the query of
    /// the payload: one warning for each query, each naming its query.
    #[test]
    fn the_same_member_in_both_queries_is_reported_once_per_query() {
        let input = format!(
            r#"{{ "client_id": "x509_hash:abc", "dcql_query": {NEAR_MISS_QUERY},
                "payload": {{ "dcql_query": {NEAR_MISS_QUERY} }} }}"#
        );
        let diagnosis = diagnose(&input).expect("doctor input");
        assert_eq!(diagnosis.findings.len(), 2);
        assert_eq!(
            places(&diagnosis),
            [
                "dcql_query.credentials[0]",
                "payload.dcql_query.credentials[0]"
            ]
        );
        assert!(diagnosis.findings[0]
            .message
            .starts_with("dcql_query.credentials[0]: "));
        assert!(diagnosis.findings[1]
            .message
            .starts_with("payload.dcql_query.credentials[0]: "));

        // A warning about the query object itself names the query alone.
        let query_level = r#"{ "credentials": [ { "id": "pid", "format": "dc+sd-jwt",
            "claims": [ { "path": ["given_name"] } ] } ], "credential_set": [] }"#;
        let input = format!(
            r#"{{ "dcql_query": {query_level}, "payload": {{ "dcql_query": {query_level} }} }}"#
        );
        let diagnosis = diagnose(&input).expect("doctor input");
        assert_eq!(places(&diagnosis), ["dcql_query", "payload.dcql_query"]);
        assert!(diagnosis.warnings[1]
            .message
            .starts_with("payload.dcql_query: member \"credential_set\""));
    }

    /// A member `dcql_query` whose value is not a JSON object (`null`, a
    /// string, an array, a number) holds no query. It does not count as a
    /// second query, so the warning of the one query keeps the place
    /// `validate dcql` gives it. An empty object is a query.
    #[test]
    fn a_member_that_is_not_an_object_is_not_a_query() {
        for other in ["null", "\"x\"", "[]", "7", "true"] {
            let top = format!(
                r#"{{ "dcql_query": {other},
                    "payload": {{ "client_id": "x509_hash:abc", "dcql_query": {NEAR_MISS_QUERY} }} }}"#
            );
            let diagnosis = diagnose(&top).expect("doctor input");
            assert_eq!(places(&diagnosis), ["credentials[0]"], "{top}");
            assert!(
                diagnosis.findings[0]
                    .message
                    .starts_with("credentials[0]: member \"claim\""),
                "{top}"
            );

            let payload = format!(
                r#"{{ "client_id": "x509_hash:abc", "dcql_query": {NEAR_MISS_QUERY},
                    "payload": {{ "dcql_query": {other} }} }}"#
            );
            let diagnosis = diagnose(&payload).expect("doctor input");
            assert_eq!(places(&diagnosis), ["credentials[0]"], "{payload}");
        }

        let both = format!(
            r#"{{ "dcql_query": {{}},
                "payload": {{ "client_id": "x509_hash:abc", "dcql_query": {NEAR_MISS_QUERY} }} }}"#
        );
        let diagnosis = diagnose(&both).expect("doctor input");
        assert_eq!(places(&diagnosis), ["payload.dcql_query.credentials[0]"]);
    }
}
