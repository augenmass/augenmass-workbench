//! `check`: the pre-write gate for a registrar registration body. Runs the
//! over-ask guardrail (fix) and the format validator (debug) on one body.

use anyhow::Result;

use crate::checkbody::check_body_str;
use crate::output::{emit, OutputFormat};
use crate::render::render_check;

/// Returns true if the body should block (over-ask or a blocking format error).
pub fn run(label: &str, content: &str, format: OutputFormat) -> Result<bool> {
    let (_, outcome) = check_body_str(content)?;
    let json = outcome.to_json(label);
    let text = render_check(label, &outcome);
    emit(format, &json, &text)?;
    Ok(outcome.should_block())
}
