//! DCQL validation: structural and cross-reference checks on a Digital
//! Credentials Query Language query, beyond what the typed parse enforces.
//!
//! It catches the mistakes a developer actually makes building a request:
//! duplicate credential ids, a `credential_sets` option referencing an unknown
//! id, and claim paths whose shape is wrong for the credential format (an mdoc
//! path must be `[namespace, element]`; an SD-JWT path must be an array of
//! string/null/index segments, not a dotted string). Exits non-zero on a
//! blocking error so it works as a CI gate.

use std::collections::HashSet;

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::checkbody::Severity;
use crate::dcql::{ignored_members, NEAR_MISS_FIX, NEAR_MISS_ID};
use crate::output::{emit, OutputFormat};

struct Finding {
    id: &'static str,
    severity: Severity,
    message: String,
    fix: &'static str,
}

impl Finding {
    fn blocking(id: &'static str, message: String, fix: &'static str) -> Self {
        Self {
            id,
            severity: Severity::Blocking,
            message,
            fix,
        }
    }
    fn warning(id: &'static str, message: String, fix: &'static str) -> Self {
        Self {
            id,
            severity: Severity::Warning,
            message,
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

const KNOWN_FORMATS: &[&str] = &[
    "dc+sd-jwt",
    "vc+sd-jwt",
    "mso_mdoc",
    "jwt_vc_json",
    "ldp_vc",
];

/// Validate a DCQL query (bare or wrapped under `dcql_query`). Emits the findings
/// and returns true if a blocking error was found (so the CLI exits non-zero).
/// A member name that resembles a defined one (`dcql::ignored_members`) is a
/// warning, listed before the other findings: a wallet ignores a member it
/// does not know, so such a query is valid, and a warning alone does not
/// change the result or the exit code.
pub fn dcql(input: &str, fmt: OutputFormat) -> Result<bool> {
    let value: Value = serde_json::from_str(input.trim()).context("DCQL is not JSON")?;
    let query = value.get("dcql_query").unwrap_or(&value);
    let warnings = ignored_members(query);
    let mut findings: Vec<Finding> = warnings
        .iter()
        .map(|w| Finding::warning(NEAR_MISS_ID, w.message.clone(), NEAR_MISS_FIX))
        .collect();
    findings.extend(validate(query));
    let blocking = findings.iter().any(|f| f.severity == Severity::Blocking);

    let json = json!({
        "valid": !blocking,
        "findingCount": findings.len(),
        "findings": findings.iter().map(Finding::to_json).collect::<Vec<_>>(),
        "warnings": warnings,
    });
    let text = render(&findings, blocking);
    emit(fmt, &json, &text)?;
    Ok(blocking)
}

fn validate(query: &Value) -> Vec<Finding> {
    let mut findings = Vec::new();

    let credentials = match query.get("credentials").and_then(Value::as_array) {
        Some(c) if !c.is_empty() => c,
        Some(_) => {
            findings.push(Finding::blocking(
                "DCQL-CREDENTIALS-EMPTY",
                "credentials[] is empty".into(),
                "a DCQL query must request at least one credential",
            ));
            return findings;
        }
        None => {
            findings.push(Finding::blocking(
                "DCQL-CREDENTIALS-MISSING",
                "no credentials[] array".into(),
                "a DCQL query must have a top-level credentials array",
            ));
            return findings;
        }
    };

    let mut ids: HashSet<String> = HashSet::new();
    for (i, cred) in credentials.iter().enumerate() {
        let label = format!("credentials[{i}]");

        match cred.get("id").and_then(Value::as_str) {
            None => findings.push(Finding::blocking(
                "DCQL-CRED-ID-MISSING",
                format!("{label} has no string id"),
                "every credential query needs a unique string id",
            )),
            Some(idv) => {
                if !ids.insert(idv.to_string()) {
                    findings.push(Finding::blocking(
                        "DCQL-CRED-ID-DUPLICATE",
                        format!("duplicate credential id '{idv}'"),
                        "credential ids must be unique within a DCQL query",
                    ));
                }
            }
        }

        let format = cred.get("format").and_then(Value::as_str);
        match format {
            None => findings.push(Finding::blocking(
                "DCQL-CRED-FORMAT-MISSING",
                format!("{label} has no string format"),
                "set format, e.g. dc+sd-jwt or mso_mdoc",
            )),
            Some(f) if !KNOWN_FORMATS.contains(&f) => findings.push(Finding::warning(
                "DCQL-CRED-FORMAT-UNKNOWN",
                format!("{label} has an unrecognized format '{f}'"),
                "expected one of: dc+sd-jwt, vc+sd-jwt, mso_mdoc, jwt_vc_json, ldp_vc",
            )),
            _ => {}
        }

        if let Some(claims) = cred.get("claims") {
            match claims.as_array() {
                None => findings.push(Finding::blocking(
                    "DCQL-CLAIMS-NOT-ARRAY",
                    format!("{label}.claims is not an array"),
                    "claims must be an array of claim queries",
                )),
                Some(claims) => {
                    for (j, claim) in claims.iter().enumerate() {
                        validate_claim_path(
                            &format!("{label}.claims[{j}]"),
                            claim,
                            format,
                            &mut findings,
                        );
                    }
                }
            }
        }
    }

    validate_credential_sets(query, &ids, &mut findings);
    findings
}

fn validate_claim_path(
    label: &str,
    claim: &Value,
    format: Option<&str>,
    findings: &mut Vec<Finding>,
) {
    // A claim may match by id instead of path, so a missing path is not an error.
    let path = match claim.get("path") {
        Some(p) => p,
        None => return,
    };
    let arr = match path.as_array() {
        Some(a) => a,
        None => {
            findings.push(Finding::blocking(
                "DCQL-PATH-NOT-ARRAY",
                format!("{label}.path is a {}, not an array", short_type(path)),
                "a DCQL claim path is a JSON array of segments, not a dotted string",
            ));
            return;
        }
    };

    if format == Some("mso_mdoc") {
        // ISO mdoc: exactly [namespace, dataElementIdentifier], both strings.
        if arr.len() != 2 || !arr.iter().all(Value::is_string) {
            findings.push(Finding::blocking(
                "DCQL-MDOC-PATH",
                format!(
                    "{label}.path for mso_mdoc must be [namespace, element] (two strings), got {} segment(s)",
                    arr.len()
                ),
                "use a two-string path, e.g. [\"org.iso.18013.5.1\", \"family_name\"]",
            ));
        }
        return;
    }

    // SD-JWT and other JSON-based formats: each segment is a string (object key),
    // null (all array elements), or a non-negative integer (array index).
    if !arr
        .iter()
        .all(|s| s.is_string() || s.is_null() || s.as_u64().is_some())
    {
        findings.push(Finding::blocking(
            "DCQL-SDJWT-PATH",
            format!("{label}.path segments must be strings, null, or array indices"),
            "use string keys, null for all array elements, or an integer index",
        ));
    }
    if arr.is_empty() {
        findings.push(Finding::warning(
            "DCQL-PATH-EMPTY",
            format!("{label}.path is an empty array"),
            "an empty path selects the whole credential; usually you want a specific claim",
        ));
    }
}

fn validate_credential_sets(query: &Value, ids: &HashSet<String>, findings: &mut Vec<Finding>) {
    let sets = match query.get("credential_sets") {
        Some(s) => s,
        None => return,
    };
    let sets = match sets.as_array() {
        Some(s) => s,
        None => {
            findings.push(Finding::blocking(
                "DCQL-SETS-NOT-ARRAY",
                "credential_sets is not an array".into(),
                "credential_sets must be an array of {options:[[id,...],...]}",
            ));
            return;
        }
    };
    for (i, set) in sets.iter().enumerate() {
        let options = match set.get("options").and_then(Value::as_array) {
            Some(o) => o,
            None => {
                findings.push(Finding::blocking(
                    "DCQL-SET-OPTIONS-MISSING",
                    format!("credential_sets[{i}] has no options[]"),
                    "each credential_set needs an options array of id lists",
                ));
                continue;
            }
        };
        for (k, opt) in options.iter().enumerate() {
            match opt.as_array() {
                None => findings.push(Finding::blocking(
                    "DCQL-SET-OPTION-NOT-ARRAY",
                    format!("credential_sets[{i}].options[{k}] is not an array of ids"),
                    "each option is an array of credential ids",
                )),
                Some(refs) if refs.is_empty() => findings.push(Finding::blocking(
                    "DCQL-SET-OPTION-EMPTY",
                    format!("credential_sets[{i}].options[{k}] is an empty list"),
                    "each option must name at least one credential id (OpenID4VP 1.0 section 6.2)",
                )),
                Some(refs) => {
                    for r in refs {
                        if let Some(rid) = r.as_str() {
                            if !ids.contains(rid) {
                                findings.push(Finding::blocking(
                                    "DCQL-SET-REF-DANGLING",
                                    format!(
                                        "credential_sets[{i}] references unknown credential id '{rid}'"
                                    ),
                                    "every id in a credential_set option must match a credentials[].id",
                                ));
                            }
                        }
                    }
                }
            }
        }
    }
}

fn short_type(v: &Value) -> &'static str {
    match v {
        Value::String(_) => "string",
        Value::Number(_) => "number",
        Value::Bool(_) => "bool",
        Value::Object(_) => "object",
        Value::Null => "null",
        Value::Array(_) => "array",
    }
}

fn render(findings: &[Finding], blocking: bool) -> String {
    let mut out = String::new();
    if findings.is_empty() {
        out.push_str("DCQL VALID: no structural or reference issues found.\n");
        return out;
    }
    out.push_str("DCQL findings:\n");
    for f in findings {
        out.push_str(&format!(
            "  {} [{}]: {}\n    Fix: {}\n",
            f.id,
            f.severity.as_str(),
            f.message,
            f.fix
        ));
    }
    if blocking {
        out.push_str("\nDCQL INVALID: at least one blocking error above.\n");
    } else {
        out.push_str("\nDCQL OK (warnings only).\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block_ids(input: &str) -> Vec<&'static str> {
        let value: Value = serde_json::from_str(input).unwrap();
        let q = value.get("dcql_query").unwrap_or(&value);
        validate(q)
            .into_iter()
            .filter(|f| f.severity == Severity::Blocking)
            .map(|f| f.id)
            .collect()
    }

    #[test]
    fn clean_sd_jwt_query_has_no_blocking() {
        let q = r#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","claims":[{"path":["family_name"]},{"path":["address","locality"]}]}]}"#;
        assert!(block_ids(q).is_empty());
    }

    #[test]
    fn duplicate_id_and_dangling_set_and_bad_mdoc_path() {
        let q = r#"{
            "credentials":[
                {"id":"a","format":"mso_mdoc","claims":[{"path":["org.iso.18013.5.1"]}]},
                {"id":"a","format":"dc+sd-jwt"}
            ],
            "credential_sets":[{"options":[["missing"]]}]
        }"#;
        let ids = block_ids(q);
        assert!(ids.contains(&"DCQL-CRED-ID-DUPLICATE"), "{ids:?}");
        assert!(ids.contains(&"DCQL-MDOC-PATH"), "{ids:?}");
        assert!(ids.contains(&"DCQL-SET-REF-DANGLING"), "{ids:?}");
    }

    #[test]
    fn empty_credential_set_option_blocks() {
        let q = r#"{"credentials":[{"id":"a","format":"dc+sd-jwt"}],"credential_sets":[{"options":[["a"],[]]}]}"#;
        assert!(block_ids(q).contains(&"DCQL-SET-OPTION-EMPTY"));
        let ok = r#"{"credentials":[{"id":"a","format":"dc+sd-jwt"}],"credential_sets":[{"options":[["a"]]}]}"#;
        assert!(block_ids(ok).is_empty());
    }

    #[test]
    fn dotted_string_path_is_rejected() {
        let q = r#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","claims":[{"path":"address.locality"}]}]}"#;
        assert!(block_ids(q).contains(&"DCQL-PATH-NOT-ARRAY"));
    }

    #[test]
    fn good_mdoc_path_is_accepted() {
        let q = r#"{"credentials":[{"id":"mdl","format":"mso_mdoc","claims":[{"path":["org.iso.18013.5.1","family_name"]}]}]}"#;
        assert!(block_ids(q).is_empty());
    }
}
