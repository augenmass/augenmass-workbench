//! Human-readable text rendering for the over-ask report, format findings, and
//! the registration-body check. JSON output is handled separately in `output`.

use augenmass_core::inspector::{ClaimStatus, OverAskReport};
use serde_json::{json, Value};

use crate::checkbody::{CheckOutcome, Finding};

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

pub fn render_check(path: &str, outcome: &CheckOutcome) -> String {
    let mut out = String::new();

    if let Some(report) = &outcome.report {
        if report.has_over_ask() {
            out.push_str(&render_over_ask(report));
            out.push('\n');
        }
    }

    if !outcome.findings.is_empty() {
        out.push_str(&render_findings(&outcome.findings));
        out.push('\n');
    }

    if !outcome.should_block() {
        out.push_str(&format!(
            "OK: no over-ask, no format errors. {path} is ready to register.\n"
        ));
    }

    out
}

pub fn render_over_ask(report: &OverAskReport) -> String {
    render_over_ask_with(report, None)
}

/// The over-ask report with an optional notice line right under the verdict.
fn render_over_ask_with(report: &OverAskReport, notice: Option<&str>) -> String {
    let mut out = String::new();
    out.push_str(&format!("OVER-ASK: {}\n", report.verdict_line));
    if let Some(notice) = notice {
        out.push_str(&format!("{notice}\n"));
    }
    let purpose = report.purpose.as_deref().unwrap_or("not stated");
    let baseline = report.baseline_label.as_deref().unwrap_or("not evaluated");
    out.push_str(&format!("Purpose: {purpose}   Baseline: {baseline}\n\n"));

    out.push_str("Requested claims:\n");
    for claim in &report.requested {
        let tag = match claim.status {
            ClaimStatus::MinimalForPurpose => "ok",
            ClaimStatus::BeyondPurpose | ClaimStatus::BeyondRegistration => "over",
            ClaimStatus::NotEvaluated => "n/a",
        };
        out.push_str(&format!(
            "  [{tag}]  {:<28} {}\n",
            claim.key, claim.rationale
        ));
    }

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

    let blocks = suggestion_blocks(report);
    if !blocks.is_empty() {
        out.push('\n');
        for (heading, lines) in blocks {
            out.push_str(&format!("{heading}\n"));
            for line in lines {
                out.push_str(&format!("  {line}\n"));
            }
        }
    }

    out.push_str(&render_legal_basis(report));
    out
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
/// and spelling of that request. Empty when no baseline was evaluated.
pub fn suggestion_blocks(report: &OverAskReport) -> Vec<(String, Vec<String>)> {
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
                    lines.push(format!("{}{mark}", path_json(&p.path)));
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

/// Render an over-ask report for the `audit` command, including the OK case.
/// With `cert_decoded`, the registration-certificate notice follows the
/// verdict line on either path.
pub fn render_audit(report: &OverAskReport, cert_decoded: bool) -> String {
    let notice = cert_decoded.then_some(REGCERT_NOTICE);
    if report.has_over_ask() {
        return render_over_ask_with(report, notice);
    }

    let mut out = String::new();
    out.push_str(&format!("OK: {}\n", report.verdict_line));
    if let Some(notice) = notice {
        out.push_str(&format!("{notice}\n"));
    }
    let purpose = report.purpose.as_deref().unwrap_or("not stated");
    let baseline = report.baseline_label.as_deref().unwrap_or("not evaluated");
    out.push_str(&format!("Purpose: {purpose}   Baseline: {baseline}\n\n"));
    out.push_str("Requested claims:\n");
    for claim in &report.requested {
        let tag = match claim.status {
            ClaimStatus::MinimalForPurpose => "ok",
            ClaimStatus::BeyondPurpose | ClaimStatus::BeyondRegistration => "over",
            ClaimStatus::NotEvaluated => "n/a",
        };
        out.push_str(&format!(
            "  [{tag}]  {:<28} {}\n",
            claim.key, claim.rationale
        ));
    }
    out
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
            finding.message,
            finding.fix
        ));
    }
    out
}
