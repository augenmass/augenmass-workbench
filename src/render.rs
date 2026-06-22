//! Human-readable text rendering for the over-ask report, format findings, and
//! the registration-body check. JSON output is handled separately in `output`.

use augenmass_core::inspector::{ClaimStatus, OverAskReport};

use crate::checkbody::{CheckOutcome, Finding};

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
    let mut out = String::new();
    out.push_str(&format!("OVER-ASK: {}\n", report.verdict_line));
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

    if let Some(keys) = &report.suggested_minimal {
        out.push_str("\nSuggested minimal request:\n");
        for key in keys {
            out.push_str(&format!("  {key}\n"));
        }
    }

    out.push_str(&render_legal_basis(report));
    out
}

/// Render an over-ask report for the `audit` command, including the OK case.
pub fn render_audit(report: &OverAskReport) -> String {
    if report.has_over_ask() {
        return render_over_ask(report);
    }

    let mut out = String::new();
    out.push_str(&format!("OK: {}\n", report.verdict_line));
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
