//! The inspector: a pure, deterministic data-minimization rules engine.
//!
//! This is the differentiating layer. Detection of over-ask against the
//! registered scope is already done elsewhere (EUDIPLO enforces it server-side;
//! the wallet enforces it per ARF RPRC_07). The contribution here is a
//! human-legible, purpose-aware, legally-grounded verdict, shifted left to the
//! relying-party developer before they ship. It judges a request on two axes:
//!
//! 1. requested vs registered scope (does the request ask for a claim the RP did
//!    not register), the coarse, machine-checkable axis; and
//! 2. requested vs a purpose-minimal baseline (does the request ask for more than
//!    its stated purpose needs), the curated, opinionated axis.
//!
//! Axis 2 uses a small curated baseline. That baseline is a taste judgment, not
//! a derivation from the Rulebook, and is labelled as such so the tool stays
//! honest with standards-minded reviewers.

use std::collections::HashMap;

use openid4vp::core::dcql_query::{DcqlCredentialClaimsQueryPath as Seg, DcqlQuery};

use crate::pid::{pid_claim_model, PidClaim};
use crate::regcert::RegisteredScope;

/// How a single requested claim scores against purpose and registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ClaimStatus {
    /// Within the purpose-minimal baseline.
    MinimalForPurpose,
    /// Beyond what the stated purpose needs: over-ask vs purpose.
    BeyondPurpose,
    /// Not in the registered scope at all: over-ask vs registration.
    BeyondRegistration,
    /// Purpose could not be evaluated because no baseline was supplied.
    NotEvaluated,
}

/// The verdict for one requested claim.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ClaimVerdict {
    pub key: String,
    pub label: String,
    pub status: ClaimStatus,
    pub correlatable: bool,
    pub rationale: String,
}

/// One row of the disclosed-vs-withheld view over the full PID claim model.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ClaimRow {
    pub key: String,
    pub label: String,
    pub requested: bool,
    pub disclosed: bool,
    pub mandatory: bool,
    pub correlatable: bool,
}

/// A curated, named purpose with the minimal claim set it justifies.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PurposeBaseline {
    pub id: String,
    pub label: String,
    /// Dotted claim keys the purpose minimally justifies.
    pub minimal_keys: Vec<String>,
    /// Honest note that this baseline is a curated judgment.
    pub note: String,
}

/// A reference to the legal or normative basis for minimization.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct LegalRef {
    pub source: &'static str,
    pub locator: &'static str,
    pub text: &'static str,
}

/// The legal and normative basis the watchdog stands on.
pub const LEGAL_BASIS: &[LegalRef] = &[
    LegalRef {
        source: "eIDAS Regulation (EU) 2024/1183",
        locator: "Art. 5b(3)",
        text: "Relying parties shall not request users to provide data other than that indicated for their intended use.",
    },
    LegalRef {
        source: "GDPR (EU) 2016/679",
        locator: "Art. 5(1)(c)",
        text: "Personal data shall be adequate, relevant and limited to what is necessary (data minimisation).",
    },
    LegalRef {
        source: "EUDI ARF, registration certificate",
        locator: "RPRC_07",
        text: "The wallet verifies requested attributes are within the registration certificate and notifies the user otherwise.",
    },
];

/// Counts summarizing a report.
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct Counts {
    pub requested: usize,
    pub minimal: usize,
    pub beyond_purpose: usize,
    pub beyond_registration: usize,
    pub not_evaluated: usize,
    pub correlatable_requested: usize,
    pub registration_evaluated: bool,
    pub purpose_evaluated: bool,
}

/// The full over-ask report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OverAskReport {
    pub vct: String,
    pub purpose: Option<String>,
    pub baseline_label: Option<String>,
    pub baseline_note: Option<String>,
    pub requested: Vec<ClaimVerdict>,
    /// Claims disclosed by the wallet that were not requested (over-disclosure).
    pub over_disclosed: Vec<String>,
    /// Curated minimal request for the selected purpose, when known.
    pub suggested_minimal: Option<Vec<String>>,
    /// The full PID model annotated disclosed-vs-withheld (when a presentation
    /// is available; otherwise `disclosed` is false throughout).
    pub claim_rows: Vec<ClaimRow>,
    pub counts: Counts,
    pub legal_basis: Vec<LegalRef>,
    pub verdict_line: String,
}

impl OverAskReport {
    /// True if the request asks beyond either purpose or registration.
    pub fn has_over_ask(&self) -> bool {
        self.counts.beyond_purpose > 0 || self.counts.beyond_registration > 0
    }

    /// CSS class for the verdict pill.
    pub fn verdict_class(&self) -> &'static str {
        if self.has_over_ask() {
            "over"
        } else if !self.counts.registration_evaluated || !self.counts.purpose_evaluated {
            ""
        } else {
            "ok"
        }
    }
}

/// A curated baseline for a named purpose, or `None` if unknown.
///
/// These are taste judgments about the minimal claim set each purpose needs.
/// They are intentionally small and conservative, and are presented as opinion.
pub fn baseline(id: &str) -> Option<PurposeBaseline> {
    let note =
        "Curated minimal baseline (a taste judgment, not a Rulebook derivation).".to_string();
    let b = |label: &str, keys: &[&str]| PurposeBaseline {
        id: id.to_string(),
        label: label.to_string(),
        minimal_keys: keys.iter().map(|s| s.to_string()).collect(),
        note: note.clone(),
    };
    match id {
        "age_gate_18" => Some(b("Age gate (over 18)", &["age_equal_or_over.18"])),
        "event_checkin" => Some(b(
            "Event check-in",
            &["given_name", "family_name", "age_equal_or_over.18"],
        )),
        "car_rental" => Some(b(
            "Car rental (over 21, named)",
            &["given_name", "family_name", "age_equal_or_over.21"],
        )),
        "bank_kyc" => Some(b(
            "Bank onboarding (KYC)",
            &[
                "given_name",
                "family_name",
                "birthdate",
                "address.resident_street",
                "address.resident_city",
                "address.resident_postal_code",
                "address.resident_country",
            ],
        )),
        _ => None,
    }
}

/// The dotted claim keys requested by a DCQL query (across all credentials).
pub fn requested_keys(query: &DcqlQuery) -> Vec<String> {
    let mut keys = Vec::new();
    for cred in query.credentials() {
        if let Some(claims) = cred.claims() {
            for claim in claims {
                let parts: Vec<String> = claim.path().iter().map(seg_key).collect();
                keys.push(parts.join("."));
            }
        }
    }
    keys
}

fn seg_key(s: &Seg) -> String {
    match s {
        Seg::String(s) => s.clone(),
        Seg::Integer(i) => i.to_string(),
        Seg::Null => "*".to_string(),
    }
}

/// Analyze a request against an optional registered scope, an optional curated
/// purpose baseline, and the claims actually disclosed by a presentation.
pub fn analyze(
    vct: &str,
    query: &DcqlQuery,
    registered: Option<&RegisteredScope>,
    baseline: Option<&PurposeBaseline>,
    disclosed_keys: &[String],
) -> OverAskReport {
    let model = pid_claim_model();
    let lookup: HashMap<String, &PidClaim> = model.iter().map(|c| (c.key(), c)).collect();

    let requested = requested_keys(query);
    let registered_keys: Option<Vec<String>> = registered.map(|r| r.all_claim_keys());
    let minimal: Option<&[String]> = baseline.map(|b| b.minimal_keys.as_slice());

    let mut verdicts = Vec::new();
    let mut counts = Counts {
        requested: requested.len(),
        registration_evaluated: registered.is_some(),
        purpose_evaluated: baseline.is_some(),
        ..Default::default()
    };

    for key in &requested {
        let claim = lookup.get(key);
        let label = claim
            .map(|c| c.label.clone())
            .unwrap_or_else(|| key.clone());
        let correlatable = claim.map(|c| c.correlatable).unwrap_or(false);
        if correlatable {
            counts.correlatable_requested += 1;
        }

        let in_registered = registered_keys
            .as_ref()
            .map(|rk| rk.iter().any(|k| k == key));
        let in_minimal = minimal.map(|m| m.iter().any(|k| k == key));

        let (status, rationale) = match (in_registered, in_minimal) {
            (Some(false), _) => (
                ClaimStatus::BeyondRegistration,
                "Not in the relying party's registered scope.".to_string(),
            ),
            (_, Some(false)) => {
                let rationale = match in_registered {
                    Some(true) => "Registered, but beyond what the stated purpose needs.",
                    None => "Beyond what the stated purpose needs; registration not evaluated.",
                    Some(false) => unreachable!("beyond-registration matched first"),
                };
                (ClaimStatus::BeyondPurpose, rationale.to_string())
            }
            (_, Some(true)) => (
                ClaimStatus::MinimalForPurpose,
                "Within the purpose-minimal baseline.".to_string(),
            ),
            (_, None) => (
                ClaimStatus::NotEvaluated,
                "Purpose not evaluated: no baseline supplied.".to_string(),
            ),
        };
        match status {
            ClaimStatus::MinimalForPurpose => counts.minimal += 1,
            ClaimStatus::BeyondPurpose => counts.beyond_purpose += 1,
            ClaimStatus::BeyondRegistration => counts.beyond_registration += 1,
            ClaimStatus::NotEvaluated => counts.not_evaluated += 1,
        }
        verdicts.push(ClaimVerdict {
            key: key.clone(),
            label,
            status,
            correlatable,
            rationale,
        });
    }

    // Disclosed-vs-withheld over the full model.
    let claim_rows: Vec<ClaimRow> = model
        .iter()
        .map(|c| {
            let key = c.key();
            ClaimRow {
                requested: requested.contains(&key),
                disclosed: disclosed_keys.contains(&key),
                key,
                label: c.label.clone(),
                mandatory: c.mandatory,
                correlatable: c.correlatable,
            }
        })
        .collect();

    // Over-disclosure: disclosed but not requested.
    let over_disclosed: Vec<String> = disclosed_keys
        .iter()
        .filter(|k| !requested.contains(*k))
        .cloned()
        .collect();

    let verdict_line = verdict_line(&counts);

    OverAskReport {
        vct: vct.to_string(),
        purpose: registered.and_then(|r| r.purpose_text().map(String::from)),
        baseline_label: baseline.map(|b| b.label.clone()),
        baseline_note: baseline.map(|b| b.note.clone()),
        requested: verdicts,
        over_disclosed,
        suggested_minimal: baseline.map(|b| b.minimal_keys.clone()),
        claim_rows,
        counts,
        legal_basis: LEGAL_BASIS.to_vec(),
        verdict_line,
    }
}

fn verdict_line(c: &Counts) -> String {
    if c.beyond_registration > 0 {
        format!(
            "Over-ask: {} of {} requested claims are outside the registered scope.",
            c.beyond_registration, c.requested
        )
    } else if c.beyond_purpose > 0 {
        format!(
            "Over-ask vs purpose: {} of {} requested claims exceed the stated purpose.",
            c.beyond_purpose, c.requested
        )
    } else if c.requested == 0 {
        "No claims requested.".to_string()
    } else {
        match (c.registration_evaluated, c.purpose_evaluated) {
            (true, true) => format!(
                "Minimal: all {} requested claims are within purpose and registration.",
                c.requested
            ),
            (true, false) => {
                "Within registered scope; purpose not evaluated (no baseline supplied).".to_string()
            }
            (false, true) => {
                "Within the purpose-minimal baseline; registration not evaluated.".to_string()
            }
            (false, false) => "Neither registration nor purpose evaluated.".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{pid, PID_VCT};

    #[test]
    fn nested_age_leaf_disclosure_marks_requested_threshold() {
        let query = pid::pid_query(&[&["age_equal_or_over", "18"]]);
        let disclosed = vec!["age_equal_or_over.18".to_string()];

        let report = analyze(
            PID_VCT,
            &query,
            None,
            baseline("age_gate_18").as_ref(),
            &disclosed,
        );

        assert!(report.over_disclosed.is_empty());
        let age_18 = report
            .claim_rows
            .iter()
            .find(|row| row.key == "age_equal_or_over.18")
            .expect("age 18 row");
        assert!(age_18.requested);
        assert!(age_18.disclosed);
    }

    #[test]
    fn wider_age_object_disclosure_reports_unrequested_thresholds() {
        let query = pid::pid_query(&[&["age_equal_or_over", "18"]]);
        let disclosed = ["12", "14", "16", "18", "21", "65"]
            .into_iter()
            .map(|threshold| format!("age_equal_or_over.{threshold}"))
            .collect::<Vec<_>>();

        let report = analyze(
            PID_VCT,
            &query,
            None,
            baseline("age_gate_18").as_ref(),
            &disclosed,
        );

        assert_eq!(
            report.over_disclosed,
            vec![
                "age_equal_or_over.12",
                "age_equal_or_over.14",
                "age_equal_or_over.16",
                "age_equal_or_over.21",
                "age_equal_or_over.65",
            ]
        );
        let age_18 = report
            .claim_rows
            .iter()
            .find(|row| row.key == "age_equal_or_over.18")
            .expect("age 18 row");
        assert!(age_18.requested);
        assert!(age_18.disclosed);
    }
}
