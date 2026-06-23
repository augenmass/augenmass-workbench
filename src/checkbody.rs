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
    let findings = validate_body_shape(body);
    let has_blocking = findings
        .iter()
        .any(|finding| finding.severity == Severity::Blocking);

    let report = if has_blocking {
        None
    } else {
        analyze_body(body).ok()
    };

    CheckOutcome { report, findings }
}

pub fn check_body_str(input: &str) -> Result<(Value, CheckOutcome)> {
    let body: Value = serde_json::from_str(input).context("registration body is not JSON")?;
    let outcome = check_body(&body);
    Ok((body, outcome))
}

fn analyze_body(body: &Value) -> Result<OverAskReport> {
    let paths = dcql::collect_claim_paths(body)?;
    let query = dcql::dcql_from_paths(&paths)?;
    let registered = regcert::scope_from_payload(body).context("registration body shape")?;
    let baseline = inspector::baseline("age_gate_18");
    Ok(inspector::analyze(
        PID_VCT,
        &query,
        Some(&registered),
        baseline.as_ref(),
        &[],
    ))
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
}
