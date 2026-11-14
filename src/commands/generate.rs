//! `generate`: produce proportionate (and, for contrast, over-broad) artifacts.
//! A registrar registration body, or a raw DCQL query built from claim paths.

use anyhow::Result;
use serde_json::{json, Value};

use crate::dcql;
use crate::generator::{age_check_body, GenerateOptions};
use crate::output::outln;

pub fn regbody(options: &GenerateOptions) -> Result<()> {
    let body = age_check_body(options);
    outln(&serde_json::to_string_pretty(&body)?)
}

/// Build a German-PID DCQL query from claim path specs (dotted or slashed).
pub fn dcql_query(claim_specs: &[String]) -> Result<()> {
    let paths: Vec<Vec<String>> = claim_specs
        .iter()
        .map(|s| dcql::parse_claim_path(s))
        .collect();
    let query = dcql::dcql_from_paths(&paths)?;
    let value: Value = serde_json::to_value(&query).unwrap_or(json!({}));
    outln(&serde_json::to_string_pretty(&value)?)
}
