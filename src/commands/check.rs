//! `check`: the pre-write gate for a registrar registration body. Runs the
//! over-ask guardrail (fix) and the format validator (debug) on one body.

use anyhow::Result;

use augenmass_core::typed_baseline::TypedBaseline;

use crate::checkbody::{check_body_str_against, CheckResult};
use crate::output::{emit, OutputFormat};
use crate::render::render_check;

/// Returns the result of the check: ok, over-ask, not evaluated, or a
/// blocking format error. The caller turns it into the exit code (0, 1, 3, 1).
/// `baseline` is the selected entry of a baseline file (`--baseline`), or
/// `None` for the built-in age-gate baseline.
pub fn run(
    label: &str,
    content: &str,
    baseline: Option<&TypedBaseline>,
    format: OutputFormat,
) -> Result<CheckResult> {
    let (_, outcome) = check_body_str_against(content, baseline)?;
    let json = outcome.to_json(label);
    let text = render_check(label, &outcome);
    emit(format, &json, &text)?;
    Ok(outcome.outcome())
}
