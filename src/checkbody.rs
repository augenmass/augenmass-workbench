//! The registration-body pre-write gate: the over-ask guardrail (the fix
//! pillar) plus the registration-body format validator (the debug pillar). One
//! body in, two kinds of finding out, each with a plain-language fix.

use anyhow::{Context, Result};
use augenmass_core::inspector::{self, OverAskReport};
use augenmass_core::{regcert, PID_VCT};
use serde_json::{json, Value};
use url::Url;

use crate::dcql;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Blocking,
    Warning,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Blocking => "blocking",
            Severity::Warning => "warning",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub id: &'static str,
    pub severity: Severity,
    pub message: &'static str,
    pub fix: &'static str,
}

impl Finding {
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "severity": self.severity.as_str(),
            "message": self.message,
            "fix": self.fix,
        })
    }
}

#[derive(Debug)]
pub struct CheckOutcome {
    pub report: Option<OverAskReport>,
    pub findings: Vec<Finding>,
}

impl CheckOutcome {
    pub fn has_blocking_format_error(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.severity == Severity::Blocking)
    }

    pub fn has_over_ask(&self) -> bool {
        self.report
            .as_ref()
            .is_some_and(OverAskReport::has_over_ask)
    }

    pub fn should_block(&self) -> bool {
        self.has_blocking_format_error() || self.has_over_ask()
    }

    pub fn to_json(&self, path: &str) -> Value {
        json!({
            "path": path,
            "overAsk": self.has_over_ask(),
            "blockingFormatError": self.has_blocking_format_error(),
            "block": self.should_block(),
            "report": self.report.as_ref().map(|r| serde_json::to_value(r).unwrap_or(Value::Null)),
            "findings": self.findings.iter().map(Finding::to_json).collect::<Vec<_>>(),
        })
    }
}

pub fn check_body(body: &Value) -> CheckOutcome {
    let mut findings = validate_body_shape(body);
    let has_blocking = findings
        .iter()
        .any(|finding| finding.severity == Severity::Blocking);

    // A body the guardrail cannot read blocks, never passes unexamined.
    let report = if has_blocking {
        None
    } else {
        match analyze_body(body) {
            Ok(report) => report,
            Err(_) => {
                findings.push(Finding {
                    id: "CHECK-UNREADABLE-REQUEST",
                    severity: Severity::Blocking,
                    message: "The requested credentials could not be read as a DCQL query, so the over-ask guardrail could not run.",
                    fix: "Give every credentials[] entry a format, a meta object, and claims[] with array paths.",
                });
                None
            }
        }
    };

    CheckOutcome { report, findings }
}

pub fn check_body_str(input: &str) -> Result<(Value, CheckOutcome)> {
    let body: Value = serde_json::from_str(input).context("registration body is not JSON")?;
    let outcome = check_body(&body);
    Ok((body, outcome))
}

/// The over-ask report for a body, judged against itself as the registration
/// (credential by credential, typed paths) and the age-gate baseline. `None`
/// when the body requests no credentials.
fn analyze_body(body: &Value) -> Result<Option<OverAskReport>> {
    let Some(query) = dcql::dcql_from_registration_body(body)? else {
        return Ok(None);
    };
    let registered = regcert::scope_from_payload(body).context("registration body shape")?;
    let baseline = inspector::baseline("age_gate_18");
    Ok(Some(inspector::analyze(
        PID_VCT,
        &query,
        Some(&registered),
        baseline.as_ref(),
        &[],
    )))
}

fn validate_body_shape(body: &Value) -> Vec<Finding> {
    let mut findings = Vec::new();

    if contains_claims_in_provided_attestations(body) {
        findings.push(Finding {
            id: "CHECK-PROVIDED-ATTESTATIONS",
            severity: Severity::Blocking,
            message: "Requested claims are under provided_attestations; the registrar reads requests from credentials.",
            fix: "Move the requested credential into credentials[], with format, meta, and claims[].path.",
        });
    }

    if contains_path_string(body.get("credentials"))
        || contains_path_string(body.get("provided_attestations"))
    {
        findings.push(Finding {
            id: "CHECK-PATH-STRING",
            severity: Severity::Blocking,
            message: "claims[].path must be an array of segments, not a string.",
            fix: "Change \"path\": \"age_equal_or_over\" to \"path\": [\"age_equal_or_over\", \"18\"].",
        });
    }

    if invalid_claim_paths(body.get("credentials")) {
        findings.push(Finding {
            id: "CHECK-CLAIM-PATH",
            severity: Severity::Blocking,
            message: "Every credentials[] entry needs a non-empty claims[], and every claims[].path must be a non-empty array of strings, nulls and non-negative integers (OpenID4VP claims path pointer); for mso_mdoc exactly two strings, namespace and data element.",
            fix: "Use paths such as [\"given_name\"], [\"address\", \"locality\"], or [\"nationalities\", null]; no booleans, negative or fractional numbers, or empty arrays. For mso_mdoc use [namespace, element], e.g. [\"eu.europa.ec.eudi.pid.1\", \"family_name\"].",
        });
    }

    if invalid_credential_meta(body.get("credentials")) {
        findings.push(Finding {
            id: "CHECK-CREDENTIAL-META",
            severity: Severity::Blocking,
            message: "Every credentials[] entry needs a format and its type in meta: vct_values (a non-empty array of strings) for SD-JWT VC, doctype_value (a string) for mso_mdoc.",
            fix: "Set \"meta\": { \"vct_values\": [\"urn:eudi:pid:de:1\"] } for dc+sd-jwt, or \"meta\": { \"doctype_value\": \"eu.europa.ec.eudi.pid.1\" } for mso_mdoc.",
        });
    }

    if body.get("purpose").is_some_and(Value::is_string) || malformed_purpose(body.get("purpose")) {
        findings.push(Finding {
            id: "CHECK-PURPOSE-SHAPE",
            severity: Severity::Blocking,
            message: "purpose must be a list of {lang, content} objects, not a string.",
            fix: "Use \"purpose\": [{ \"lang\": \"en\", \"content\": \"Age verification\" }].",
        });
    }

    if body
        .get("privacy_policy")
        .and_then(Value::as_str)
        .is_none_or(|url| Url::parse(url).is_err())
    {
        findings.push(Finding {
            id: "CHECK-PRIVACY-POLICY-URL",
            severity: Severity::Blocking,
            message: "privacy_policy must be a valid URL.",
            fix: "Set privacy_policy to a URL, for example https://example.com/privacy.",
        });
    }

    if body
        .get("support_uri")
        .and_then(Value::as_str)
        .is_none_or(|value| value.trim().is_empty())
    {
        findings.push(Finding {
            id: "CHECK-SUPPORT-URI-EMPTY",
            severity: Severity::Warning,
            message: "support_uri is empty. It must be a non-empty contact string (email, phone, or URL are all valid).",
            fix: "Set support_uri to any contact, for example support@example.com or https://example.com/support.",
        });
    }

    findings
}

fn contains_claims_in_provided_attestations(body: &Value) -> bool {
    body.get("provided_attestations")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items
                .iter()
                .any(|item| item.get("claims").is_some() || item.get("claim").is_some())
        })
}

fn contains_path_string(value: Option<&Value>) -> bool {
    let Some(value) = value else {
        return false;
    };
    match value {
        Value::Object(map) => {
            map.get("path").is_some_and(Value::is_string)
                || map.values().any(|child| contains_path_string(Some(child)))
        }
        Value::Array(items) => items.iter().any(|child| contains_path_string(Some(child))),
        _ => false,
    }
}

/// True when a `credentials[]` entry has no non-empty claims array, or a claim
/// whose path is neither a string (reported as CHECK-PATH-STRING) nor a valid
/// claims path pointer.
fn invalid_claim_paths(credentials: Option<&Value>) -> bool {
    let Some(credentials) = credentials.and_then(Value::as_array) else {
        return false;
    };
    credentials.iter().any(|credential| {
        let Some(claims) = credential
            .get("claims")
            .or_else(|| credential.get("claim"))
            .and_then(Value::as_array)
            .filter(|claims| !claims.is_empty())
        else {
            return true;
        };
        let format = credential
            .get("format")
            .and_then(Value::as_str)
            .unwrap_or_default();
        claims.iter().any(|claim| match claim.get("path") {
            Some(Value::String(_)) => false,
            Some(path) => regcert::parse_claim_path(path)
                .is_none_or(|segs| !regcert::valid_claim_path(format, &segs)),
            None => true,
        })
    })
}

/// True when a `credentials[]` entry has no string format, or its type is
/// missing or malformed for SD-JWT VC (`vct_values`) or mso_mdoc
/// (`doctype_value`). Other formats are not type-checked here.
fn invalid_credential_meta(credentials: Option<&Value>) -> bool {
    let Some(credentials) = credentials.and_then(Value::as_array) else {
        return false;
    };
    credentials.iter().any(|credential| {
        let Some(format) = credential.get("format").and_then(Value::as_str) else {
            return true;
        };
        let meta = credential.get("meta");
        match format {
            regcert::FORMAT_MSO_MDOC => meta
                .and_then(|m| m.get("doctype_value"))
                .and_then(Value::as_str)
                .is_none(),
            "dc+sd-jwt" | "vc+sd-jwt" => meta
                .and_then(|m| m.get("vct_values"))
                .and_then(Value::as_array)
                .is_none_or(|vcts| vcts.is_empty() || vcts.iter().any(|v| !v.is_string())),
            _ => false,
        }
    })
}

fn malformed_purpose(value: Option<&Value>) -> bool {
    let Some(value) = value else {
        return true;
    };
    let Some(items) = value.as_array() else {
        return true;
    };
    items.is_empty()
        || items.iter().any(|item| {
            item.get("lang").and_then(Value::as_str).is_none()
                || item.get("content").and_then(Value::as_str).is_none()
        })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn min_body() -> Value {
        json!({
            "rpId": "rp",
            "support_uri": "support@example.com",
            "privacy_policy": "https://example.com/privacy",
            "purpose": [{ "lang": "en", "content": "Age verification" }],
            "credentials": [{
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
                "claims": [{ "path": ["age_equal_or_over", "18"] }]
            }]
        })
    }

    #[test]
    fn minimal_age_gate_is_clean() {
        let outcome = check_body(&min_body());
        assert!(!outcome.should_block());
        assert!(!outcome.has_over_ask());
        assert!(!outcome.has_blocking_format_error());
    }

    #[test]
    fn path_string_is_blocking() {
        let mut body = min_body();
        body["credentials"][0]["claims"][0]["path"] = json!("age_equal_or_over.18");
        let outcome = check_body(&body);
        assert!(outcome.has_blocking_format_error());
        assert!(outcome.findings.iter().any(|f| f.id == "CHECK-PATH-STRING"));
    }

    #[test]
    fn over_broad_body_flags_over_ask() {
        let mut body = min_body();
        body["credentials"][0]["claims"] = json!([
            { "path": ["given_name"] },
            { "path": ["family_name"] },
            { "path": ["birthdate"] },
            { "path": ["nationalities"] }
        ]);
        let outcome = check_body(&body);
        assert!(outcome.has_over_ask());
        assert!(!outcome.has_blocking_format_error());
    }

    #[test]
    fn non_pointer_path_blocks_instead_of_skipping_the_guardrail() {
        for path in [
            json!(["birthdate", true]),
            json!([]),
            json!(["nationalities", -1]),
            json!(["nationalities", 0.5]),
            json!(["a", { "b": 1 }]),
        ] {
            let mut body = min_body();
            body["credentials"][0]["claims"][0]["path"] = path.clone();
            let outcome = check_body(&body);
            assert!(outcome.should_block(), "{path}");
            assert!(outcome.has_blocking_format_error(), "{path}");
            assert!(
                outcome.findings.iter().any(|f| f.id == "CHECK-CLAIM-PATH"),
                "{path}"
            );
        }
    }

    #[test]
    fn missing_or_empty_claims_block() {
        let mut body = min_body();
        body["credentials"][0]["claims"] = json!([]);
        assert!(check_body(&body)
            .findings
            .iter()
            .any(|f| f.id == "CHECK-CLAIM-PATH"));
        let mut body = min_body();
        body["credentials"][0]
            .as_object_mut()
            .unwrap()
            .remove("claims");
        assert!(check_body(&body)
            .findings
            .iter()
            .any(|f| f.id == "CHECK-CLAIM-PATH"));
    }

    #[test]
    fn invalid_credential_metadata_blocks() {
        for meta in [
            json!({}),
            json!({ "vct_values": [] }),
            json!({ "vct_values": ["a", 1] }),
        ] {
            let mut body = min_body();
            body["credentials"][0]["meta"] = meta.clone();
            let outcome = check_body(&body);
            assert!(
                outcome
                    .findings
                    .iter()
                    .any(|f| f.id == "CHECK-CREDENTIAL-META"),
                "{meta}"
            );
        }
        let mut body = min_body();
        body["credentials"][0]["format"] = json!("mso_mdoc");
        body["credentials"][0]["meta"] = json!({ "vct_values": ["urn:eudi:pid:de:1"] });
        assert!(check_body(&body)
            .findings
            .iter()
            .any(|f| f.id == "CHECK-CREDENTIAL-META"));
    }

    #[test]
    fn null_and_index_segments_are_within_their_own_registration() {
        let mut body = min_body();
        body["credentials"][0]["claims"] = json!([
            { "path": ["age_equal_or_over", "18"] },
            { "path": ["nationalities", null] },
            { "path": ["nationalities", 0] },
        ]);
        let outcome = check_body(&body);
        assert!(
            !outcome.has_blocking_format_error(),
            "{:?}",
            outcome.findings
        );
        let report = outcome.report.expect("report");
        assert_eq!(
            report.counts.beyond_registration, 0,
            "{:?}",
            report.requested
        );
        assert_eq!(report.counts.requested, 3);
    }

    #[test]
    fn mdoc_body_is_judged_as_mdoc() {
        let mut body = min_body();
        body["credentials"][0]["format"] = json!("mso_mdoc");
        body["credentials"][0]["meta"] = json!({ "doctype_value": "eu.europa.ec.eudi.pid.1" });
        body["credentials"][0]["claims"] =
            json!([{ "path": ["eu.europa.ec.eudi.pid.1", "given_name"] }]);
        let outcome = check_body(&body);
        let report = outcome.report.expect("report");
        assert_eq!(report.counts.beyond_registration, 0);
        assert_eq!(
            report.requested[0].key,
            "eu.europa.ec.eudi.pid.1.given_name"
        );
    }

    #[test]
    fn invalid_mdoc_path_blocks_even_against_itself() {
        for path in [
            json!(["eu.europa.ec.eudi.pid.1", null]),
            json!(["eu.europa.ec.eudi.pid.1", "address", "locality"]),
            json!(["eu.europa.ec.eudi.pid.1"]),
        ] {
            let mut body = min_body();
            body["credentials"][0]["format"] = json!("mso_mdoc");
            body["credentials"][0]["meta"] = json!({ "doctype_value": "eu.europa.ec.eudi.pid.1" });
            body["credentials"][0]["claims"] = json!([{ "path": path }]);
            let outcome = check_body(&body);
            assert!(
                outcome.findings.iter().any(|f| f.id == "CHECK-CLAIM-PATH"),
                "{path}: {:?}",
                outcome.findings
            );
            assert!(outcome.has_blocking_format_error(), "{path}");
            if let Some(report) = outcome.report {
                assert_eq!(report.counts.beyond_registration, 1, "{path}");
            }
        }
    }
}
