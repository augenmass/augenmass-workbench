//! The German PID profile: the credential type, the documented claim model, and
//! the minimal-disclosure DCQL query.
//!
//! Age-path note (grounded conflict, kept on purpose): the live German wallet
//! uses the nested two-segment path `["age_equal_or_over","18"]`; ERICA's claim
//! allowlist only WARNS on it; EUDIPLO joins it to the dot-key
//! `age_equal_or_over.18`; the ARF Rulebook v1.1 removed age attributes. We use
//! the nested path because it matches the live wallet and the registration
//! certificate we created, and we document the conflict rather than hide it.

use openid4vp::core::credential_format::ClaimFormatDesignation;
use openid4vp::core::dcql_query::{
    DcqlCredentialClaimsQuery, DcqlCredentialClaimsQueryPath as Seg, DcqlCredentialQuery, DcqlQuery,
};
use openid4vp::utils::NonEmptyVec;

use crate::PID_VCT;

/// The SD-JWT VC format identifier used by the German PID.
pub const PID_FORMAT: &str = "dc+sd-jwt";

/// The German PID `age_equal_or_over` thresholds (BMI extension).
pub const AGE_THRESHOLDS: [u8; 6] = [12, 14, 16, 18, 21, 65];

/// One claim in the German PID claim model, used to render disclosed-vs-withheld.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PidClaim {
    /// Claims-path-pointer segments (DCQL / JSON pointer style).
    pub path: Vec<String>,
    /// Human label for the inspector.
    pub label: String,
    /// Mandatory in the German PID (vs optional or extension).
    pub mandatory: bool,
    /// Strongly identifying or correlatable; sharpens the over-ask note.
    pub correlatable: bool,
}

impl PidClaim {
    /// The dotted path key, e.g. `address.resident_city` or `age_equal_or_over.18`.
    pub fn key(&self) -> String {
        self.path.join(".")
    }
}

fn claim(path: &[&str], label: &str, mandatory: bool, correlatable: bool) -> PidClaim {
    PidClaim {
        path: path.iter().map(|s| (*s).to_string()).collect(),
        label: label.to_string(),
        mandatory,
        correlatable,
    }
}

/// The documented German PID claim model.
///
/// Source: the PID claim reference in the workspace wiki (`architecture.md`),
/// grounded in the BMI developer guide and the German PID Rulebook. This is the
/// documented subset used for the disclosed-vs-withheld view, not asserted as
/// the exhaustive normative set (the Rulebook is authoritative).
pub fn pid_claim_model() -> Vec<PidClaim> {
    let mut v = vec![
        claim(&["family_name"], "Family name", true, true),
        claim(&["given_name"], "Given name", true, true),
        claim(&["birthdate"], "Date of birth", true, true),
        claim(
            &["place_of_birth", "locality"],
            "Place of birth",
            true,
            true,
        ),
        claim(&["nationalities"], "Nationalities", true, true),
        claim(
            &["address", "resident_country"],
            "Resident country",
            false,
            true,
        ),
        claim(&["address", "resident_city"], "Resident city", false, true),
        claim(
            &["address", "resident_postal_code"],
            "Resident postal code",
            false,
            true,
        ),
        claim(
            &["address", "resident_street"],
            "Resident street",
            false,
            true,
        ),
        claim(&["family_name_birth"], "Birth family name", false, true),
        claim(&["given_name_birth"], "Birth given name", false, true),
        claim(&["date_of_expiry"], "Expiry date", true, false),
        claim(&["issuing_authority"], "Issuing authority", true, false),
        claim(&["issuing_country"], "Issuing country", true, false),
        claim(&["age_in_years"], "Age in years", false, false),
        claim(&["age_birth_year"], "Birth year", false, true),
    ];
    for t in AGE_THRESHOLDS {
        v.push(PidClaim {
            path: vec!["age_equal_or_over".to_string(), t.to_string()],
            label: format!("Age over {t}"),
            mandatory: false,
            correlatable: false,
        });
    }
    v
}

/// Build a DCQL claims query from string path segments.
fn claim_query(path: &[&str]) -> DcqlCredentialClaimsQuery {
    let segs: Vec<Seg> = path.iter().map(|s| Seg::String((*s).to_string())).collect();
    DcqlCredentialClaimsQuery::new(NonEmptyVec::try_from(segs).expect("non-empty claim path"))
}

/// Assemble a PID DCQL query for the given claim paths.
///
/// The deployed wallets error on some multi-`vct` orderings, so we send exactly
/// the one `vct` we need (singular `vct_values`).
pub fn pid_query(claim_paths: &[&[&str]]) -> DcqlQuery {
    let claims: Vec<DcqlCredentialClaimsQuery> =
        claim_paths.iter().map(|p| claim_query(p)).collect();

    let mut cq = DcqlCredentialQuery::new(
        "pid".to_string(),
        ClaimFormatDesignation::Other(PID_FORMAT.to_string()),
    );
    let mut meta = serde_json::Map::new();
    meta.insert("vct_values".to_string(), serde_json::json!([PID_VCT]));
    cq.set_meta(meta);
    cq.set_claims(Some(
        NonEmptyVec::try_from(claims).expect("non-empty claims"),
    ));

    DcqlQuery::new(NonEmptyVec::new(cq))
}

/// The canonical minimal-disclosure ask for the event-check-in demo:
/// `given_name`, `family_name`, and the derived `age_equal_or_over.18`.
pub fn pid_dcql_minimal() -> DcqlQuery {
    pid_query(&[
        &["given_name"],
        &["family_name"],
        &["age_equal_or_over", "18"],
    ])
}

/// A deliberately over-asking request for the inspector and the gallery: it
/// pulls `birthdate`, parts of the address, and `nationalities` when an age-gate
/// purpose needs only `age_equal_or_over.18`.
pub fn pid_dcql_overask_example() -> DcqlQuery {
    pid_query(&[
        &["given_name"],
        &["family_name"],
        &["birthdate"],
        &["address", "resident_street"],
        &["address", "resident_city"],
        &["nationalities"],
    ])
}
