//! DCQL (Digital Credentials Query Language) helpers: parse a DCQL query from
//! JSON, build one from claim paths, and collect the claim paths a registrar
//! registration body requests.

use anyhow::{anyhow, Context, Result};
use augenmass_core::pid;
use openid4vp::core::dcql_query::DcqlQuery;
use serde_json::Value;

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

/// Collect the claim paths a registrar registration body requests, from
/// `credentials[].claims[].path` (the registrar DTO) or the ETSI singular
/// `credentials[].claim[].path`.
pub fn collect_claim_paths(body: &Value) -> Result<Vec<Vec<String>>> {
    let credentials = body
        .get("credentials")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("registration body has no credentials[]"))?;

    let mut out = Vec::new();
    for credential in credentials {
        let claims = credential
            .get("claims")
            .or_else(|| credential.get("claim"))
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("credential has no claims[]"))?;
        for claim in claims {
            let path = claim
                .get("path")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("claim path is not an array"))?;
            let segments: Vec<String> = path
                .iter()
                .map(|segment| {
                    segment
                        .as_str()
                        .map(ToOwned::to_owned)
                        .ok_or_else(|| anyhow!("claim path segment is not a string"))
                })
                .collect::<Result<_>>()?;
            out.push(segments);
        }
    }

    Ok(out)
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
}
