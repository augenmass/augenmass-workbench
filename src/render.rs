//! Human-readable text rendering for the over-ask report, format findings, and
//! the registration-body check. JSON output is handled separately in `output`.

use augenmass_core::inspector::{BaselineInfo, ClaimStatus, Outcome, OverAskReport};
use augenmass_core::regcert::PathSeg;
use augenmass_core::typed_baseline::ASSESSMENT_NOTICE;
use serde_json::{json, Value};

use crate::baseline_file::path_text;
use crate::checkbody::{CheckOutcome, CheckResult, Finding};

/// The one line every output that read a registration certificate carries:
/// the payload was decoded, nothing about it was verified.
pub const REGCERT_NOTICE: &str =
    "Registration certificate: payload decoded; signature, issuer and revocation status not verified.";

/// The JSON form of [`REGCERT_NOTICE`], under `registration_certificate`.
pub fn regcert_status_json() -> Value {
    json!({
        "decoded": true,
        "signature_verified": false,
        "issuer_verified": false,
        "revocation_checked": false,
    })
}

/// A string that comes from a file (a baseline file, a request, a
/// registration) as the text output prints it: on one line, and without
/// characters that act on a terminal or reorder the line. Every control
/// character (a line break, the escape character of terminal sequences),
/// the Unicode line and paragraph separators and the bidirectional
/// formatting characters are replaced by their escape, for example `\n` and
/// `\u{1b}`. Without this, free text of a baseline file could print a second
/// "Baseline file: ... status: reviewed" line, or erase the real status line
/// and the draft label on a terminal. `--json` carries the strings unchanged;
/// JSON encoding escapes them itself. A path that is printed as a JSON array
/// goes through [`printable_json`] instead.
pub fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if not_printed_raw(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// The characters the text output never prints raw: every control character,
/// the Unicode line and paragraph separators and the bidirectional formatting
/// characters.
fn not_printed_raw(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{2028}'
                | '\u{2029}'
                | '\u{061C}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
        )
}

/// A serialized JSON value as the text output prints it. The characters that
/// [`printable`] replaces are written as the JSON escape `\uXXXX` (UTF-16
/// code units, four hexadecimal digits each), for example `\u202e`, so the
/// result is still valid JSON and parses to the same value. The escape of
/// [`printable`] (`\u{202e}`) is not JSON. The input must be the output of a
/// JSON serializer: there, such a character occurs only inside a string,
/// where the escape is allowed. [`printable`] leaves the result unchanged.
pub fn printable_json(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        if not_printed_raw(c) {
            let mut units = [0u16; 2];
            for unit in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub fn render_check(path: &str, outcome: &CheckOutcome) -> String {
    let mut out = String::new();

    // The report names a loaded baseline file itself. Where no report is
    // printed (the body passed, or a format error stopped the check), the
    // baseline file is named after the result.
    let mut baseline_named = false;
    if let Some(report) = &outcome.report {
        if report.outcome() != Outcome::Ok {
            out.push_str(&render_report(report, None));
            out.push('\n');
            baseline_named = true;
        }
    }

    if !outcome.findings.is_empty() {
        out.push_str(&render_findings(&outcome.findings));
        out.push('\n');
    }

    if outcome.outcome() == CheckResult::Ok {
        if outcome.no_credentials {
            out.push_str(&format!(
                "OK: the body requests no credentials; no format errors. {path} is ready to register.\n"
            ));
        } else {
            out.push_str(&format!(
                "OK: no over-ask, no format errors. {path} is ready to register.\n"
            ));
        }
    }

    if let (Some(info), false) = (&outcome.baseline_file, baseline_named) {
        out.push_str(&baseline_file_lines(info));
        out.push_str(&format!("{ASSESSMENT_NOTICE}\n"));
    }

    out
}

/// The lines that name a loaded baseline file on every result: the file name
/// (never a directory), the entry id, its version and its status; then
/// "draft baseline, no legal review" for every status other than `reviewed`,
/// or the reviewer the file names; then the case the entry states, if any.
/// Empty for a built-in baseline.
fn baseline_file_lines(info: &BaselineInfo) -> String {
    let Some(info) = info.file() else {
        return String::new();
    };
    let mut out = format!(
        "Baseline file: {}   entry: {}   version: {}   status: {}\n{}\n",
        printable(&info.file),
        printable(&info.entry_id),
        printable(&info.version),
        info.status.as_str(),
        printable(&info.notice)
    );
    if let Some(case) = &info.applies_when {
        out.push_str(&format!(
            "Applies when (stated by the baseline, not checked by this tool): {}\n",
            printable(case)
        ));
    }
    out
}

/// The blocks printed in place of the built-in "Suggested minimal request"
/// under a loaded baseline entry: its minimal rows and its acceptable
/// alternatives per credential block, as JSON path arrays that stay valid
/// JSON ([`printable_json`]), and one line per one-of group. Empty for a
/// built-in baseline.
fn baseline_file_blocks(info: &BaselineInfo) -> Vec<(String, Vec<String>)> {
    let Some(info) = info.file() else {
        return Vec::new();
    };
    let (claims, one_of) = (&info.claims, &info.one_of);
    let mut blocks = Vec::new();
    let grouped = |group: &Option<String>| {
        group
            .as_deref()
            .map(|g| format!(" (group \"{g}\")"))
            .unwrap_or_default()
    };
    let path_line = |path: &[PathSeg]| printable_json(&path_text(path));
    for block in claims {
        let of = format!("({}, {})", block.format, block.types().join(", "));
        if !block.minimal.is_empty() {
            blocks.push((
                format!("Minimal claims of this baseline entry {of}:"),
                block
                    .minimal
                    .iter()
                    .map(|row| format!("{}{}", path_line(&row.path), grouped(&row.one_of)))
                    .collect(),
            ));
        }
        if !block.alternatives.is_empty() {
            blocks.push((
                format!("Acceptable alternatives of this baseline entry {of}:"),
                block
                    .alternatives
                    .iter()
                    .map(|row| format!("{}{}", path_line(&row.path), grouped(&row.one_of)))
                    .collect(),
            ));
        }
    }
    if !one_of.is_empty() {
        blocks.push((
            "One claim per request from each group:".to_string(),
            one_of
                .iter()
                .map(|group| format!("\"{}\": {}", group.id, group.reason))
                .collect(),
        ));
    }
    blocks
}

pub fn render_over_ask(report: &OverAskReport) -> String {
    render_report(report, None)
}

/// The headline word of a report: `OK`, `OVER-ASK`, or `NOT EVALUATED`.
pub fn headline(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Ok => "OK",
        Outcome::OverAsk => "OVER-ASK",
        Outcome::NotEvaluated => "NOT EVALUATED",
    }
}

/// One renderer for the three headlines, with an optional notice line right
/// under the verdict. Every result prints the headline, the purpose line and
/// the claim list. OVER-ASK adds the over-ask summary, a count of the claims
/// that could not be judged (when there are any), the suggestion blocks and
/// the legal basis. NOT EVALUATED adds the count of claims that could not be
/// judged and the suggestion blocks.
fn render_report(report: &OverAskReport, notice: Option<&str>) -> String {
    let outcome = report.outcome();
    let mut out = String::new();
    out.push_str(&format!("{}: {}\n", headline(outcome), report.verdict_line));
    if let Some(notice) = notice {
        out.push_str(&format!("{notice}\n"));
    }
    // The purpose text comes from a registration, the label of a loaded
    // baseline from its file, the claim keys and parts of the rationales
    // from the request and the baseline file: all are printed on one line
    // each ([`printable`]).
    let purpose = printable(report.purpose.as_deref().unwrap_or("not stated"));
    let baseline = printable(report.baseline_label.as_deref().unwrap_or("not evaluated"));
    out.push_str(&format!("Purpose: {purpose}   Baseline: {baseline}\n"));
    let file_baseline = report
        .baseline
        .as_ref()
        .filter(|info| info.file().is_some());
    if let Some(info) = file_baseline {
        out.push_str(&baseline_file_lines(info));
    }
    out.push('\n');

    out.push_str("Requested claims:\n");
    for claim in &report.requested {
        let tag = match claim.status {
            ClaimStatus::MinimalForPurpose => "ok",
            ClaimStatus::AcceptableAlternative => "alt",
            ClaimStatus::BeyondPurpose | ClaimStatus::BeyondRegistration => "over",
            ClaimStatus::NotEvaluated => "n/a",
        };
        out.push_str(&format!(
            "  [{tag}]  {:<28} {}\n",
            printable(&claim.key),
            printable(&claim.rationale)
        ));
    }

    // Every result under a loaded baseline file ends with the sentence that
    // says what such a file is.
    let closing = |mut out: String| {
        if file_baseline.is_some() {
            out.push_str(&format!("\n{ASSESSMENT_NOTICE}\n"));
        }
        out
    };

    let unjudged = report.counts.could_not_judge;
    match outcome {
        Outcome::Ok => return closing(out),
        Outcome::OverAsk => {
            if report.counts.beyond_registration > 0 {
                out.push_str(&format!(
                    "\nOver-asking {} claim(s) beyond the stated purpose, and {} beyond the registration.\n",
                    report.counts.beyond_purpose, report.counts.beyond_registration
                ));
            } else {
                out.push_str(&format!(
                    "\nOver-asking {} claim(s) beyond the stated purpose.\n",
                    report.counts.beyond_purpose
                ));
            }
            if unjudged > 0 {
                out.push_str(&format!("Not evaluated: {unjudged} claim(s).\n"));
            }
        }
        Outcome::NotEvaluated => {
            out.push_str(&format!(
                "\nNot evaluated: {unjudged} claim(s). No judged claim asks for too much; exit code {}.\n",
                outcome.exit_code()
            ));
        }
    }

    // A path array in these lines is already escaped as JSON
    // ([`printable_json`]), so [`printable`] below changes only the text
    // around it and the array can still be pasted into a DCQL `path`.
    let blocks = match file_baseline {
        Some(info) => baseline_file_blocks(info),
        None => suggestion_blocks_with(report, |path| printable_json(&path_json(path))),
    };
    if !blocks.is_empty() {
        out.push('\n');
        for (heading, lines) in blocks {
            out.push_str(&format!("{}\n", printable(&heading)));
            for line in lines {
                out.push_str(&format!("  {}\n", printable(&line)));
            }
        }
    }

    if outcome == Outcome::OverAsk {
        out.push_str(&render_legal_basis(report));
        if let Some(info) = file_baseline.and_then(BaselineInfo::file) {
            out.push_str(&format!(
                "Sources stated by the baseline: {} (see --json).\n",
                info.legal_sources.len()
            ));
        }
    }
    closing(out)
}

/// The line printed once under a PID mdoc suggestion that carries a profile
/// mark.
pub const SHARED_DOCTYPE_NOTE: &str = "The EU PID and the German PID share the doctype eu.europa.ec.eudi.pid.1; a marked element exists in only one of them.";

/// A suggested path as a JSON string array with ", " between segments, so
/// it can be pasted into a DCQL `path`.
fn path_json(path: &[String]) -> String {
    let segs: Vec<String> = path
        .iter()
        .map(|s| serde_json::to_string(s).unwrap_or_else(|_| format!("\"{s}\"")))
        .collect();
    format!("[{}]", segs.join(", "))
}

/// The "Suggested minimal request" blocks of a report: one heading and its
/// lines (without indentation) per requested credential type, in the format
/// and spelling of that request. Empty when no baseline was evaluated. The
/// strings are not escaped for a terminal; the caller escapes them for its
/// output.
pub fn suggestion_blocks(report: &OverAskReport) -> Vec<(String, Vec<String>)> {
    suggestion_blocks_with(report, path_json)
}

/// [`suggestion_blocks`] with the function that writes one suggested path.
fn suggestion_blocks_with(
    report: &OverAskReport,
    path_line: impl Fn(&[String]) -> String,
) -> Vec<(String, Vec<String>)> {
    let Some(blocks) = &report.suggested_minimal_request else {
        return Vec::new();
    };
    let several = blocks.len() > 1;
    blocks
        .iter()
        .map(|block| {
            let types = if block.types.is_empty() {
                "no type".to_string()
            } else {
                block.types.join(", ")
            };
            let named = if several {
                format!(" for \"{}\"", block.credential_id)
            } else {
                String::new()
            };
            let spelling = match (block.known_type, block.format == "mso_mdoc") {
                (false, _) => "",
                (true, true) => ", as [namespace, element]",
                (true, false) => ", as claim paths",
            };
            let heading = format!(
                "Suggested minimal request{named} ({}, {types}){spelling}:",
                block.format
            );
            let mut lines = Vec::new();
            if block.known_type {
                for p in &block.paths {
                    let mark = p
                        .profile_note
                        .as_deref()
                        .map(|n| format!(" ({n})"))
                        .unwrap_or_default();
                    lines.push(format!("{}{mark}", path_line(&p.path)));
                }
                if block.paths.iter().any(|p| p.profile_note.is_some()) {
                    lines.push(SHARED_DOCTYPE_NOTE.to_string());
                }
                if !block.not_suggested.is_empty() {
                    lines.push(format!(
                        "No known claim for this credential type: {}.",
                        block.not_suggested.join(", ")
                    ));
                }
            } else {
                lines.push(format!(
                    "No claim names are known for this credential type. The purpose baseline asks only for: {}.",
                    block.not_suggested.join(", ")
                ));
            }
            (heading, lines)
        })
        .collect()
}

/// Render a report for the `audit` command: OK, OVER-ASK, or NOT EVALUATED.
/// With `cert_decoded`, the registration-certificate notice follows the
/// verdict line on every path.
pub fn render_audit(report: &OverAskReport, cert_decoded: bool) -> String {
    render_report(report, cert_decoded.then_some(REGCERT_NOTICE))
}

pub fn render_legal_basis(report: &OverAskReport) -> String {
    let mut out = String::new();
    out.push_str("\nLegal basis:\n");
    for legal in &report.legal_basis {
        out.push_str(&format!("  {}, {}\n", legal.source, legal.locator));
        out.push_str(&format!("    {}\n", legal.text));
    }
    out
}

pub fn render_findings(findings: &[Finding]) -> String {
    let mut out = String::new();
    out.push_str("Format findings:\n");
    for finding in findings {
        out.push_str(&format!(
            "  {} [{}]: {}\n    Fix: {}\n",
            finding.id,
            finding.severity.as_str(),
            printable(finding.message),
            printable(finding.fix)
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A serialized path with characters the text output may not print raw
    /// stays valid JSON with the same value, on one line, and `printable`
    /// has nothing left to replace in it.
    #[test]
    fn printable_json_keeps_a_serialized_path_valid_json() {
        let path = vec![
            "a\u{202e}b".to_string(),
            "line\nbreak\u{1b}[2K".to_string(),
            "sep\u{2028}\u{2029}\u{85}\u{7f}".to_string(),
            "quote\" backslash\\ \\u{202e} \u{e4}\u{10348}".to_string(),
        ];
        let printed = printable_json(&path_json(&path));
        assert_eq!(
            printed,
            "[\"a\\u202eb\", \"line\\nbreak\\u001b[2K\", \"sep\\u2028\\u2029\\u0085\\u007f\", \"quote\\\" backslash\\\\ \\\\u{202e} \u{e4}\u{10348}\"]"
        );
        assert!(!printed.chars().any(not_printed_raw), "{printed:?}");
        assert_eq!(printable(&printed), printed);
        let parsed: Vec<String> = serde_json::from_str(&printed).expect("valid JSON");
        assert_eq!(parsed, path);
    }

    /// Text that is not JSON keeps the escape of `printable`.
    #[test]
    fn printable_escapes_text_outside_json() {
        assert_eq!(printable("a\u{202e}\n\u{1b}"), "a\\u{202e}\\n\\u{1b}");
    }
}
