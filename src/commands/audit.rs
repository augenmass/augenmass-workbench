//! Over-ask audit: lint an OpenID4VP request (a DCQL query) against a registered
//! scope (a registration certificate) and a curated purpose baseline. This is
//! the engine's core IP surfaced as a standalone command, distinct from `check`
//! (which gates a registrar registration body before a write).

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use augenmass_core::inspector::{self, OverAskReport};
use augenmass_core::regcert::RegisteredScope;
use augenmass_core::{pid, PID_VCT};
use openid4vp::core::dcql_query::DcqlQuery;
use serde_json::Value;

use crate::commands::decode::extract_regcert_jwt;
use crate::dcql::parse_dcql;
use crate::output::{emit, OutputFormat};
use crate::render::render_audit;

pub struct AuditArgs {
    /// "minimal", "overask", or a path to a DCQL JSON file.
    pub request: String,
    /// Purpose baseline id (age_gate_18, event_checkin, car_rental, bank_kyc).
    pub purpose: String,
    /// Path to a registration certificate (compact JWT, entity JSON, or array).
    pub cert: Option<PathBuf>,
    /// Override the expected vct (defaults to the German PID).
    pub vct: Option<String>,
}

/// Returns true when the request is not over-asking.
pub fn run(args: AuditArgs, format: OutputFormat) -> Result<bool> {
    let scope = load_scope(args.cert.as_ref())?;
    let query = build_request(&args.request)?;
    let baseline = inspector::baseline(&args.purpose);
    if baseline.is_none() {
        eprintln!(
            "note: unknown purpose '{}'; the purpose axis is skipped (try: augenmass baselines)",
            args.purpose
        );
    }
    let vct = args.vct.as_deref().unwrap_or(PID_VCT);
    let report: OverAskReport =
        inspector::analyze(vct, &query, scope.as_ref(), baseline.as_ref(), &[]);

    let json = serde_json::to_value(&report).unwrap_or(Value::Null);
    let text = render_audit(&report);
    emit(format, &json, &text)?;
    Ok(!report.has_over_ask())
}

fn load_scope(cert: Option<&PathBuf>) -> Result<Option<RegisteredScope>> {
    let Some(path) = cert else {
        return Ok(None);
    };
    let content = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let jwt = extract_regcert_jwt(&content)?;
    let scope = augenmass_core::regcert::decode_registration_jwt(&jwt)
        .context("decode registration certificate")?;
    Ok(Some(scope))
}

fn build_request(request: &str) -> Result<DcqlQuery> {
    match request {
        "minimal" => Ok(pid::pid_dcql_minimal()),
        "overask" => Ok(pid::pid_dcql_overask_example()),
        input => {
            let content = read_request_input(input)?;
            parse_dcql(&content).with_context(|| {
                format!("--request must be 'minimal', 'overask', or a DCQL JSON value ({input})")
            })
        }
    }
}

fn read_request_input(input: &str) -> Result<String> {
    if input == "-" {
        let mut content = String::new();
        std::io::stdin()
            .read_to_string(&mut content)
            .context("read --request from stdin")?;
        return Ok(content);
    }
    let path = Path::new(input);
    if path.is_file() {
        return fs::read_to_string(path).with_context(|| format!("read {input}"));
    }
    if input.trim_start().starts_with('{') {
        return Ok(input.to_string());
    }
    Err(anyhow!(
        "--request must be 'minimal', 'overask', a DCQL file path, inline DCQL JSON, or '-'"
    ))
}
