//! The registration-body pre-write gate: the over-ask guardrail (the fix
//! pillar) plus the registration-body format validator (the debug pillar). One
//! body in, two kinds of finding out, each with a plain-language fix.

use anyhow::{Context, Result};
use augenmass_core::inspector::{self, BaselineInfo, Outcome, OverAskReport};
use augenmass_core::typed_baseline::{BaselineRef, Subject, TypedBaseline};
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

/// The result of checking one registration body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckResult {
    /// No over-ask, no blocking format error, and everything was judged.
    Ok,
    /// A judged claim asks for too much.
    OverAsk,
    /// No judged claim asks for too much, and the purpose baseline or the
    /// registration comparison could not judge at least one requested claim.
    NotEvaluated,
    /// A blocking format error: the over-ask guardrail did not run.
    FormatError,
}

impl CheckResult {
    /// The name in `check --json`: `ok`, `over_ask`, `not_evaluated`,
    /// `format_error`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::OverAsk => "over_ask",
            Self::NotEvaluated => "not_evaluated",
            Self::FormatError => "format_error",
        }
    }

    /// Process exit code: 0, 1, 3, 1.
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Ok => 0,
            Self::OverAsk | Self::FormatError => 1,
            Self::NotEvaluated => 3,
        }
    }
}

#[derive(Debug)]
pub struct CheckOutcome {
    pub report: Option<OverAskReport>,
    pub findings: Vec<Finding>,
    /// True only when the body has no `credentials` member or an empty
    /// `credentials` array: the one state in which no report is not an error.
    pub no_credentials: bool,
    /// The entry of a baseline file the body was checked against
    /// (`check --baseline`); `None` for the built-in baseline.
    pub baseline_file: Option<BaselineInfo>,
}

impl CheckOutcome {
    /// The result of the check. A blocking format error wins, because then
    /// no report exists. A body without a report is ok only when it requests
    /// no credentials; in any other state nothing was judged, which is never
    /// a pass.
    pub fn outcome(&self) -> CheckResult {
        if self.has_blocking_format_error() {
            return CheckResult::FormatError;
        }
        match &self.report {
            Some(report) => match report.outcome() {
                Outcome::Ok => CheckResult::Ok,
                Outcome::OverAsk => CheckResult::OverAsk,
                Outcome::NotEvaluated => CheckResult::NotEvaluated,
            },
            None if self.no_credentials => CheckResult::Ok,
            None => CheckResult::FormatError,
        }
    }

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

    /// True unless the result is ok: an over-ask, a blocking format error,
    /// or a body that could not be evaluated.
    pub fn should_block(&self) -> bool {
        self.outcome() != CheckResult::Ok
    }

    pub fn to_json(&self, path: &str) -> Value {
        let mut json = json!({
            "path": path,
            "outcome": self.outcome().as_str(),
            "overAsk": self.has_over_ask(),
            "blockingFormatError": self.has_blocking_format_error(),
            "block": self.should_block(),
            "report": self.report.as_ref().map(|r| serde_json::to_value(r).unwrap_or(Value::Null)),
            "findings": self.findings.iter().map(Finding::to_json).collect::<Vec<_>>(),
        });
        // Only a run with `--baseline` carries the member: the baseline file
        // is named also when no report exists (a format error, or a body
        // without credentials).
        if let (Some(info), Some(obj)) = (&self.baseline_file, json.as_object_mut()) {
            obj.insert(
                "baseline".to_string(),
                serde_json::to_value(info).unwrap_or(Value::Null),
            );
        }
        json
    }
}

/// Check a body against the built-in age-gate baseline.
pub fn check_body(body: &Value) -> CheckOutcome {
    check_body_against(body, None)
}

/// Check a body against one entry of a loaded baseline file, or, with
/// `None`, against the built-in age-gate baseline.
pub fn check_body_against(body: &Value, baseline: Option<&TypedBaseline>) -> CheckOutcome {
    let mut findings = validate_body_shape(body);
    let has_blocking = findings
        .iter()
        .any(|finding| finding.severity == Severity::Blocking);

    // A body the guardrail cannot read blocks, never passes unexamined.
    let report = if has_blocking {
        None
    } else {
        match analyze_body(body, baseline) {
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

    let no_credentials = match body.get("credentials") {
        None => true,
        Some(Value::Array(credentials)) => credentials.is_empty(),
        Some(_) => false,
    };
    CheckOutcome {
        report,
        findings,
        no_credentials,
        baseline_file: baseline.map(TypedBaseline::info),
    }
}

pub fn check_body_str(input: &str) -> Result<(Value, CheckOutcome)> {
    check_body_str_against(input, None)
}

pub fn check_body_str_against(
    input: &str,
    baseline: Option<&TypedBaseline>,
) -> Result<(Value, CheckOutcome)> {
    let body: Value = serde_json::from_str(input).context("registration body is not JSON")?;
    let outcome = check_body_against(&body, baseline);
    Ok((body, outcome))
}

/// The over-ask report for a body, judged against itself as the registration
/// (credential by credential, typed paths) and a baseline: the given entry
/// of a baseline file, or the built-in age-gate baseline. A body is not one
/// request: it lists everything a party may ask, which the one-of rule of a
/// baseline entry takes into account ([`Subject::RegistrationBody`]). `None`
/// when the body requests no credentials (no `credentials` member, or an
/// empty array); a `credentials` value that is not an array is an error.
fn analyze_body(body: &Value, typed: Option<&TypedBaseline>) -> Result<Option<OverAskReport>> {
    let Some(query) = dcql::dcql_from_registration_body(body)? else {
        return Ok(None);
    };
    let registered = regcert::scope_from_payload(body).context("registration body shape")?;
    let built_in = inspector::baseline("age_gate_18");
    let baseline = match typed {
        Some(entry) => Some(BaselineRef::Typed(entry)),
        None => built_in.as_ref().map(BaselineRef::BuiltIn),
    };
    Ok(Some(inspector::analyze_against(
        PID_VCT,
        &query,
        Some(&registered),
        baseline,
        Subject::RegistrationBody,
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

    // A `credentials` value that is not an array holds nothing the guardrail
    // can read as a list of credentials: block instead of judging nothing.
    if body.get("credentials").is_some_and(|c| !c.is_array()) {
        findings.push(Finding {
            id: "CHECK-CREDENTIALS-SHAPE",
            severity: Severity::Blocking,
            message: "credentials must be an array of credential objects.",
            fix: "Wrap the credential object in an array: \"credentials\": [ { ... } ].",
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

    // --- the result of a check: ok, over-ask, not evaluated, format error ---

    #[test]
    fn outcome_names_and_exit_codes() {
        for (result, name, code) in [
            (CheckResult::Ok, "ok", 0),
            (CheckResult::OverAsk, "over_ask", 1),
            (CheckResult::NotEvaluated, "not_evaluated", 3),
            (CheckResult::FormatError, "format_error", 1),
        ] {
            assert_eq!(result.as_str(), name);
            assert_eq!(result.exit_code(), code);
        }
        let outcome = check_body(&min_body());
        assert_eq!(outcome.outcome(), CheckResult::Ok);
        assert!(!outcome.no_credentials);
        assert_eq!(outcome.to_json("body.json")["outcome"], "ok");
    }

    #[test]
    fn credentials_that_is_not_an_array_is_a_blocking_format_error() {
        let object = json!({
            "format": "dc+sd-jwt",
            "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
            "claims": [{ "path": ["birthdate"] }]
        });
        for credentials in [object, json!("x"), json!(7), json!(true), Value::Null] {
            let mut body = min_body();
            body["credentials"] = credentials.clone();
            let outcome = check_body(&body);
            assert!(
                outcome
                    .findings
                    .iter()
                    .any(|f| f.id == "CHECK-CREDENTIALS-SHAPE" && f.severity == Severity::Blocking),
                "{credentials}: {:?}",
                outcome.findings
            );
            assert!(outcome.has_blocking_format_error(), "{credentials}");
            assert_eq!(outcome.outcome(), CheckResult::FormatError, "{credentials}");
            assert!(outcome.should_block(), "{credentials}");
            assert!(outcome.report.is_none(), "{credentials}");
            assert!(!outcome.no_credentials, "{credentials}");
            let json = outcome.to_json("body.json");
            assert_eq!(json["outcome"], "format_error", "{credentials}");
            assert_eq!(json["blockingFormatError"], true, "{credentials}");
            assert_eq!(json["block"], true, "{credentials}");
            assert!(json["report"].is_null(), "{credentials}");
        }
    }

    #[test]
    fn body_without_credentials_is_ok_and_says_so() {
        let mut missing = min_body();
        missing.as_object_mut().unwrap().remove("credentials");
        let mut empty = min_body();
        empty["credentials"] = json!([]);
        for body in [missing, empty] {
            let outcome = check_body(&body);
            assert!(outcome.no_credentials);
            assert!(outcome.report.is_none());
            assert!(outcome.findings.is_empty(), "{:?}", outcome.findings);
            assert_eq!(outcome.outcome(), CheckResult::Ok);
            assert!(!outcome.should_block());
            let json = outcome.to_json("body.json");
            assert_eq!(json["outcome"], "ok");
            assert_eq!(json["block"], false);
            assert!(json["report"].is_null());
            let text = crate::render::render_check("body.json", &outcome);
            assert_eq!(
                text,
                "OK: the body requests no credentials; no format errors. body.json is ready to register.\n"
            );
        }
    }

    #[test]
    fn no_report_without_a_blocking_finding_only_for_a_body_without_credentials() {
        // Every shape of `credentials`: when no report exists, either a
        // blocking finding says why, or the body requests no credentials.
        // No other state reaches "no report", so no unjudged body is ok.
        let entry = min_body()["credentials"][0].clone();
        let shapes = [
            None,
            Some(json!([])),
            Some(json!([entry.clone()])),
            Some(entry.clone()),
            Some(json!("x")),
            Some(json!(["x"])),
            Some(json!([[entry.clone()]])),
            Some(json!([{}])),
            Some(json!([{ "format": "dc+sd-jwt" }])),
            Some(json!([{ "format": "jwt_vc_json", "claims": [{ "path": ["a"] }] }])),
            Some(json!([{ "format": 7, "meta": {}, "claims": [{ "path": ["a"] }] }])),
            Some(json!({ "0": entry.clone() })),
            Some(Value::Null),
            Some(json!(0)),
            Some(json!(false)),
        ];
        for shape in shapes {
            let mut body = min_body();
            match &shape {
                Some(credentials) => body["credentials"] = credentials.clone(),
                None => {
                    body.as_object_mut().unwrap().remove("credentials");
                }
            }
            let outcome = check_body(&body);
            if outcome.report.is_none() {
                assert!(
                    outcome.has_blocking_format_error() || outcome.no_credentials,
                    "{shape:?}: no report, no blocking finding, and credentials present"
                );
            }
            if outcome.no_credentials {
                assert!(matches!(&shape, None | Some(Value::Array(_))), "{shape:?}");
            }
            assert_eq!(
                outcome.outcome() == CheckResult::Ok,
                !outcome.should_block(),
                "{shape:?}"
            );
        }
        // The state itself, if it were ever reached, is not a pass.
        let unreachable = CheckOutcome {
            report: None,
            findings: Vec::new(),
            no_credentials: false,
            baseline_file: None,
        };
        assert_eq!(unreachable.outcome(), CheckResult::FormatError);
        assert!(unreachable.should_block());
    }

    #[test]
    fn body_the_baseline_or_the_registration_cannot_judge_is_not_evaluated() {
        // A credential type the age-gate baseline does not model.
        let mut body = min_body();
        body["credentials"][0]["meta"] = json!({ "vct_values": ["urn:example:membership:1"] });
        let outcome = check_body(&body);
        assert_eq!(outcome.outcome(), CheckResult::NotEvaluated);
        assert!(outcome.should_block());
        assert!(!outcome.has_over_ask());
        assert!(!outcome.has_blocking_format_error());
        let json = outcome.to_json("body.json");
        assert_eq!(json["outcome"], "not_evaluated");
        assert_eq!(json["overAsk"], false);
        assert_eq!(json["block"], true);
        assert_eq!(json["report"]["outcome"], "not_evaluated");
        let text = crate::render::render_check("body.json", &outcome);
        assert!(text.starts_with("NOT EVALUATED: "), "{text}");
        assert!(!text.contains("OK:"), "{text}");
        assert!(!text.contains("ready to register"), "{text}");

        // A format whose credential type is not read: the body covers its own
        // path, the type cannot be matched.
        let mut body = min_body();
        body["credentials"] = json!([{
            "format": "jwt_vc_json",
            "meta": { "type_values": [["IdentityCredential"]] },
            "claims": [{ "path": ["credentialSubject", "family_name"] }]
        }]);
        let outcome = check_body(&body);
        assert_eq!(outcome.outcome(), CheckResult::NotEvaluated);
        let report = outcome.report.as_ref().expect("report");
        assert_eq!(report.counts.beyond_registration, 0);
        assert_eq!(report.counts.could_not_judge, 1);

        // An over-ask in the same body wins.
        body["credentials"].as_array_mut().unwrap().push(json!({
            "format": "dc+sd-jwt",
            "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
            "claims": [{ "path": ["birthdate"] }]
        }));
        let outcome = check_body(&body);
        assert_eq!(outcome.outcome(), CheckResult::OverAsk);
        assert!(outcome.has_over_ask());
    }
}
