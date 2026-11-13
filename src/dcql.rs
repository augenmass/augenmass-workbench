//! DCQL (Digital Credentials Query Language) helpers: parse a DCQL query from
//! JSON, build one from claim paths, and build the query a registrar
//! registration body stands for.

use anyhow::{anyhow, Context, Result};
use augenmass_core::{pid, regcert};
use openid4vp::core::dcql_query::DcqlQuery;
use serde_json::{json, Value};

/// Parse a DCQL query from a JSON string. Accepts a bare query object or a
/// wrapper that carries the query under a `dcql_query` field.
pub fn parse_dcql(input: &str) -> Result<DcqlQuery> {
    let value: Value = serde_json::from_str(input.trim()).context("DCQL is not JSON")?;
    let inner = value.get("dcql_query").cloned().unwrap_or(value);
    serde_json::from_value(inner).context("parse DCQL query")
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
/// body has no credentials. An entry without a format, without a non-empty
/// claims array, or with a path that is not a claims path pointer (OpenID4VP
/// 1.0 section 7: a non-empty array of strings, nulls and non-negative
/// integers) is an error, never silently skipped.
pub fn dcql_from_registration_body(body: &Value) -> Result<Option<DcqlQuery>> {
    let Some(credentials) = body.get("credentials").and_then(Value::as_array) else {
        return Ok(None);
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
}
