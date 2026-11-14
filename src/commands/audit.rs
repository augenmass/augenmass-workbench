//! Over-ask audit: lint an OpenID4VP request (a DCQL query) against a registered
//! scope (a registration certificate) and a curated purpose baseline. This is
//! the engine's core IP surfaced as a standalone command, distinct from `check`
//! (which gates a registrar registration body before a write).

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use augenmass_core::inspector::{self, Outcome, OverAskReport, PurposeBaseline};
use augenmass_core::regcert::RegisteredScope;
use augenmass_core::typed_baseline::{BaselineRef, Subject, TypedBaseline};
use augenmass_core::{pid, PID_VCT};
use openid4vp::core::dcql_query::DcqlQuery;
use serde_json::Value;

use crate::commands::decode::extract_regcert_jwt;
use crate::dcql::parse_dcql;
use crate::output::{emit, OutputFormat};
use crate::render::{regcert_status_json, render_audit};

/// What `audit` judges the request against.
pub enum AuditBaseline {
    /// A built-in purpose baseline (`--purpose <id>`, or the default).
    BuiltIn(PurposeBaseline),
    /// One entry of a baseline file (`--baseline FILE [--purpose <entry id>]`).
    File(TypedBaseline),
}

impl AuditBaseline {
    fn as_ref(&self) -> BaselineRef<'_> {
        match self {
            Self::BuiltIn(baseline) => BaselineRef::BuiltIn(baseline),
            Self::File(entry) => BaselineRef::Typed(entry),
        }
    }
}

pub struct AuditArgs {
    /// "minimal", "overask", or a path to a DCQL JSON file.
    pub request: String,
    /// The baseline to judge against, already resolved (an unknown purpose
    /// or entry id is a usage error, and a baseline file that does not match
    /// the format an error, before this command runs).
    pub baseline: AuditBaseline,
    /// Path to a registration certificate (compact JWT, entity JSON, or array).
    pub cert: Option<PathBuf>,
    /// Override the expected vct (defaults to the German PID).
    pub vct: Option<String>,
}

/// Returns the request-level outcome: ok, over-ask, or not evaluated. The
/// caller turns it into the exit code (0, 1, 3).
pub fn run(args: AuditArgs, format: OutputFormat) -> Result<Outcome> {
    let scope = load_scope(args.cert.as_ref())?;
    let query = build_request(&args.request)?;
    let vct = args.vct.as_deref().unwrap_or(PID_VCT);
    let report: OverAskReport = inspector::analyze_against(
        vct,
        &query,
        scope.as_ref(),
        Some(args.baseline.as_ref()),
        Subject::Request,
        &[],
    );

    // The certificate is decoded, never verified: say so in both outputs.
    let mut json = serde_json::to_value(&report).unwrap_or(Value::Null);
    if let Some(obj) = json.as_object_mut() {
        obj.insert(
            "registration_certificate".to_string(),
            if scope.is_some() {
                regcert_status_json()
            } else {
                Value::Null
            },
        );
    }
    let text = render_audit(&report, scope.is_some());
    emit(format, &json, &text)?;
    Ok(report.outcome())
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
