//! `doctor`: diagnose the verifier signed-request / JAR gotchas. A different
//! document than `check` (the registration body): here `x5c` must be a list of
//! strings, and `client_id` must be in the `x509_hash:...` form.

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::checkbody::{Finding, Severity};
use crate::jose::decode_compact;
use crate::output::{emit, OutputFormat};

/// Returns true if findings were reported (a problem was found).
pub fn run(input: &str, format: OutputFormat) -> Result<bool> {
    let findings = doctor_input(input)?;
    let json = json!({
        "findings": findings.iter().map(Finding::to_json).collect::<Vec<_>>(),
        "ok": findings.is_empty(),
    });

    let mut text = String::new();
    if findings.is_empty() {
        text.push_str("OK: no signed-request gotchas found.\n");
        text.push_str(
            "Set Content-Type: application/json on every POST; the client does this for you.\n",
        );
    } else {
        text.push_str("Signed-request findings:\n");
        for finding in &findings {
            text.push_str(&format!(
                "  {} [{}]: {}\n    Fix: {}\n",
                finding.id,
                finding.severity.as_str(),
                finding.message,
                finding.fix
            ));
        }
    }

    emit(format, &json, &text)?;
    Ok(!findings.is_empty())
}

pub fn doctor_input(input: &str) -> Result<Vec<Finding>> {
    let value = parse_json_or_jwt(input)?;
    Ok(validate_signed_request(&value))
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

fn validate_signed_request(value: &Value) -> Vec<Finding> {
    let mut findings = Vec::new();

    if find_key(value, "x5c").is_some_and(Value::is_string) {
        findings.push(Finding {
            id: "DOCTOR-X5C-STRING",
            severity: Severity::Blocking,
            message: "x5c must be a list of strings, even for a single certificate.",
            fix: "Wrap the certificate in an array: \"x5c\": [\"MIIB...\"].",
        });
    }

    if find_key(value, "client_id")
        .and_then(Value::as_str)
        .is_some_and(|client_id| !client_id.starts_with("x509_hash:"))
    {
        findings.push(Finding {
            id: "DOCTOR-CLIENT-ID-X509HASH",
            severity: Severity::Blocking,
            message: "client_id must be in the x509_hash form.",
            fix: "Use \"client_id\": \"x509_hash:<base64url(SHA-256(leaf-cert-DER))>\". Compute it with `augenmass x509-hash`.",
        });
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
}
