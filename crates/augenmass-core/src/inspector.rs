//! The inspector: a pure, deterministic data-minimization rules engine.
//!
//! This is the differentiating layer. Detection of over-ask against the
//! registered scope is already done elsewhere (EUDIPLO enforces it server-side;
//! the wallet enforces it per ARF RPRC_21). The contribution here is a
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

use openid4vp::core::credential_format::ClaimFormatDesignation;
use openid4vp::core::dcql_query::{
    DcqlCredentialClaimsQuery, DcqlCredentialClaimsQueryPath as Seg, DcqlCredentialQuery, DcqlQuery,
};

use crate::pid::{pid_claim_model, PidClaim};
use crate::regcert::{self, PathSeg, RegisteredScope};

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
    /// Claim-model keys (dotted, in the SD-JWT model spelling) the purpose
    /// minimally justifies. A requested path counts here only when
    /// [`canonical_claim_key`] maps it, in its own format, to one of these keys.
    pub minimal_keys: Vec<String>,
    /// `mso_mdoc` element paths (`[namespace, element]`) the purpose justifies
    /// that have no claim-model key, such as the structured mdoc
    /// `place_of_birth`. Only an `mso_mdoc` path of exactly these two segments
    /// matches; segments are compared separately, never as a dotted string.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mdoc_elements: Vec<[String; 2]>,
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
        source: "Regulation (EU) No 910/2014",
        locator: "Article 5b(3)",
        text: "Relying parties shall not request users to provide any data other than that indicated pursuant to paragraph 2, point (c).",
    },
    LegalRef {
        source: "GDPR (EU) 2016/679",
        locator: "Art. 5(1)(c)",
        text: "Personal data shall be adequate, relevant and limited to what is necessary (data minimisation).",
    },
    LegalRef {
        source: "EUDI ARF, registration certificate",
        locator: "RPRC_21",
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
        mdoc_elements: Vec::new(),
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
        "bank_kyc" => Some(PurposeBaseline {
            note: BANK_KYC_NOTE.to_string(),
            mdoc_elements: vec![[PID_MDOC_NAMESPACE.to_string(), "place_of_birth".to_string()]],
            ..b(
                "Bank onboarding (KYC)",
                &[
                    "given_name",
                    "family_name",
                    "birthdate",
                    "place_of_birth.locality",
                    "place_of_birth.region",
                    "place_of_birth.country",
                    "nationalities",
                    "address.resident_street",
                    "address.house_number",
                    "address.resident_city",
                    "address.resident_postal_code",
                    "address.region",
                    "address.resident_country",
                    "address.formatted",
                ],
            )
        }),
        _ => None,
    }
}

/// The note on the `bank_kyc` baseline. It names the German statute the claim
/// set follows and keeps the curated-judgment qualification.
const BANK_KYC_NOTE: &str =
    "Curated minimal baseline (a taste judgment, not a Rulebook derivation). \
It follows the German identification set for a natural person in GwG § 11 Abs. 4 Nr. 1: \
name, place of birth, date of birth, nationality, and address. \
A request within this baseline is not over-asking; that alone does not establish \
complete identification, identity verification, or AML compliance.";

/// The ISO/IEC 18013-5 namespace (equal to the doctype) of the EU PID mdoc.
pub const PID_MDOC_NAMESPACE: &str = "eu.europa.ec.eudi.pid.1";

/// The claim-model key a requested claim path is judged under for purpose, or
/// `None` when an `mso_mdoc` path has no claim-model key.
///
/// The mapping is format-aware: a spelling is mapped only in the credential
/// format it belongs to (EU PID Rulebook, Annex 3.01, sections 3.1.2 and 4.1.1;
/// the German PID Rulebook agrees).
///
/// Every format other than `mso_mdoc` (the SD-JWT VC form) returns the dotted
/// path unchanged (or `None` when a segment itself contains a dot, so a joined
/// spelling never borrows a nested key), except these SD-JWT spellings:
///
/// - the OIDC address members `address.street_address`, `address.locality`,
///   `address.postal_code`, `address.country` to the model keys
///   `address.resident_street`, `address.resident_city`,
///   `address.resident_postal_code`, `address.resident_country`
///   (`address.region`, `address.formatted` and `address.house_number` are
///   their own model keys);
/// - the flat `birth_place` and `birth_country` that
///   `fixtures/presentations/erica-pid-template-normal.json` carries to
///   `place_of_birth.locality` and `place_of_birth.country`.
///
/// An `mso_mdoc` path maps only when it is exactly `[PID_MDOC_NAMESPACE,
/// element]` and the element is one of:
///
/// - `given_name`, `family_name` (same name);
/// - `birth_date` to `birthdate`, `nationality` to `nationalities`;
/// - `resident_street`, `resident_city`, `resident_postal_code`,
///   `resident_country` to `address.resident_*`; `resident_state` to
///   `address.region`; `resident_address` to `address.formatted`;
/// - the legacy text element `birth_place` (one string, as the EUDIPLO PID mdoc
///   issues it) to `place_of_birth.locality`.
///
/// Every other mdoc path (for example the Rulebook structured `place_of_birth`,
/// which discloses the whole place structure, an element of another namespace,
/// or a three-segment path) returns `None`: it is judged only against
/// [`PurposeBaseline::mdoc_elements`], never against a model key, so an mdoc
/// path cannot borrow an SD-JWT spelling. This mapping is for purpose
/// evaluation and the model lookup only; registration compares the typed
/// requested path ([`crate::regcert::path_covers`]) and over-disclosure the
/// raw path, so an alias never authorizes another path.
pub fn canonical_claim_key(format: &ClaimFormatDesignation, path: &[String]) -> Option<String> {
    let raw = path.join(".");
    if *format != ClaimFormatDesignation::MsoMDoc {
        // A segment holding a dot (`["address.locality"]`) names a top-level
        // member with a dot in its name, not a nested claim; it has no model key.
        if path.iter().any(|seg| seg.contains('.')) {
            return None;
        }
        let mapped = match raw.as_str() {
            "address.street_address" => "address.resident_street",
            "address.locality" => "address.resident_city",
            "address.postal_code" => "address.resident_postal_code",
            "address.country" => "address.resident_country",
            "birth_place" => "place_of_birth.locality",
            "birth_country" => "place_of_birth.country",
            _ => return Some(raw),
        };
        return Some(mapped.to_string());
    }
    let [namespace, element] = path else {
        return None;
    };
    if namespace != PID_MDOC_NAMESPACE {
        return None;
    }
    let mapped = match element.as_str() {
        "given_name" => "given_name",
        "family_name" => "family_name",
        "birth_date" => "birthdate",
        "birth_place" => "place_of_birth.locality",
        "nationality" => "nationalities",
        "resident_street" => "address.resident_street",
        "resident_city" => "address.resident_city",
        "resident_postal_code" => "address.resident_postal_code",
        "resident_country" => "address.resident_country",
        "resident_state" => "address.region",
        "resident_address" => "address.formatted",
        _ => return None,
    };
    Some(mapped.to_string())
}

/// SD-JWT array claims whose element selectors (`null` for every element, an
/// integer index for one) select within the array the model key names.
const SD_JWT_ARRAY_CLAIMS: &[&str] = &["nationalities"];

/// The path purpose is judged under: an SD-JWT element selector of a known
/// array claim (`["nationalities", null]`, `["nationalities", 0]`) is judged as
/// the array itself; every other path is its dotted segments.
fn purpose_path(format: &ClaimFormatDesignation, segs: &[Seg]) -> Vec<String> {
    if *format != ClaimFormatDesignation::MsoMDoc {
        if let [Seg::String(parent), Seg::Null | Seg::Integer(_)] = segs {
            if SD_JWT_ARRAY_CLAIMS.contains(&parent.as_str()) {
                return vec![parent.clone()];
            }
        }
    }
    segs.iter().map(seg_key).collect()
}

/// Label and correlation flag for an `mso_mdoc` element path without a
/// claim-model key, matched by namespace and element separately.
fn mdoc_element_meta(path: &[String; 2]) -> Option<(&'static str, bool)> {
    let [namespace, element] = path;
    match (namespace.as_str(), element.as_str()) {
        (PID_MDOC_NAMESPACE, "place_of_birth") => Some(("Place of birth", true)),
        _ => None,
    }
}

/// One requested credential: its format and the types it accepts.
struct RequestedCredential {
    format: String,
    /// `meta.vct_values` (SD-JWT VC) or `[meta.doctype_value]` (mdoc); empty
    /// when missing or malformed, which matches no registered credential.
    types: Vec<String>,
}

/// One requested claim (or, with `segs` of `None`, a credential requested
/// without claims): the raw dotted key and how purpose judges it.
struct RequestedClaim {
    key: String,
    /// The typed claims path pointer that registration coverage compares,
    /// segment by segment; `None` for a credential without `claims`.
    segs: Option<Vec<PathSeg>>,
    /// Index of the requested credential in [`requested_credentials`].
    cred: usize,
    /// The claim-model key (label, correlation, model rows, `minimal_keys`);
    /// `None` for an `mso_mdoc` path without one (judged by `mdoc_elements`).
    model_key: Option<String>,
    /// For an `mso_mdoc` path of exactly two string segments, the
    /// `[namespace, element]` pair, kept apart so that no dotted spelling of
    /// another split can match it.
    mdoc_element: Option<[String; 2]>,
    /// For a path ending in an array wildcard (`null`), the dotted parent: a
    /// disclosure of that array or of its elements was requested.
    wildcard_parent: Option<String>,
}

fn requested_credentials(query: &DcqlQuery) -> Vec<RequestedCredential> {
    query
        .credentials()
        .iter()
        .map(|cred| {
            let format = cred.format().to_string();
            RequestedCredential {
                types: regcert::requested_types(&format, cred.meta()),
                format,
            }
        })
        .collect()
}

/// The claims of a credential query that the verifier may request (OpenID4VP
/// 1.0 section 6.4.1): every claim when `claim_sets` is absent; otherwise every
/// claim named in any combination, since the wallet may return any of them,
/// and no declared claim that no combination names. When a combination names
/// an id that no claim carries, the combinations cannot be resolved and every
/// declared claim is kept (fail closed). `None` when `claims` is absent; empty
/// when the only combinations are empty (`claim_sets: [[]]`).
fn selected_claims(cred: &DcqlCredentialQuery) -> Option<Vec<&DcqlCredentialClaimsQuery>> {
    let claims = cred.claims()?;
    let Some(sets) = cred.claim_sets() else {
        return Some(claims.iter().collect());
    };
    let referenced: Vec<&String> = sets.iter().flatten().collect();
    let resolves = referenced
        .iter()
        .all(|id| claims.iter().any(|c| c.id() == Some(*id)));
    if !resolves {
        return Some(claims.iter().collect());
    }
    Some(
        claims
            .iter()
            .filter(|c| c.id().is_some_and(|id| referenced.contains(&id)))
            .collect(),
    )
}

fn path_seg(s: &Seg) -> PathSeg {
    match s {
        Seg::String(k) => PathSeg::Key(k.clone()),
        Seg::Integer(i) => PathSeg::Index(*i as u64),
        Seg::Null => PathSeg::All,
    }
}

/// Which credential queries the verifier requests (OpenID4VP 1.0 section
/// 6.4.2): every one when `credential_sets` is absent; otherwise every one that
/// an option of any credential set names, required or not, since the wallet
/// may return it, and none that no option names. When an option names an id
/// that no credential query carries, the sets cannot be resolved and every
/// credential query is kept (fail closed).
fn selected_credentials(query: &DcqlQuery) -> Vec<bool> {
    let creds = query.credentials();
    let Some(sets) = query.credential_sets() else {
        return vec![true; creds.len()];
    };
    let referenced: Vec<&String> = sets
        .iter()
        .flat_map(|set| set.options().iter().flatten())
        .collect();
    let resolves = referenced
        .iter()
        .all(|id| creds.iter().any(|c| c.id() == id.as_str()));
    if !resolves {
        return vec![true; creds.len()];
    }
    creds
        .iter()
        .map(|c| referenced.iter().any(|id| id.as_str() == c.id()))
        .collect()
}

/// Every requested claim path of every selected credential, in request order,
/// with its purpose key. A selected credential that requests no claim (no
/// `claims`, or only empty `claim_sets` combinations) yields one entry for the
/// credential itself, so that its type is still judged.
fn requested_claims(query: &DcqlQuery) -> Vec<RequestedClaim> {
    let mut out = Vec::new();
    let selected = selected_credentials(query);
    for (index, cred) in query.credentials().iter().enumerate() {
        if !selected[index] {
            continue;
        }
        let claims = selected_claims(cred).unwrap_or_default();
        if claims.is_empty() {
            out.push(RequestedClaim {
                key: format!("{} (credential, no claims)", cred.id()),
                segs: None,
                cred: index,
                model_key: None,
                mdoc_element: None,
                wildcard_parent: None,
            });
            continue;
        }
        for claim in claims {
            let segs = claim.path();
            let path: Vec<String> = segs.iter().map(seg_key).collect();
            let wildcard_parent = match segs.split_last() {
                Some((Seg::Null, parent)) if !parent.is_empty() => {
                    Some(parent.iter().map(seg_key).collect::<Vec<_>>().join("."))
                }
                _ => None,
            };
            let mdoc_element = match segs {
                [Seg::String(namespace), Seg::String(element)]
                    if *cred.format() == ClaimFormatDesignation::MsoMDoc =>
                {
                    Some([namespace.clone(), element.clone()])
                }
                _ => None,
            };
            out.push(RequestedClaim {
                key: path.join("."),
                segs: Some(segs.iter().map(path_seg).collect()),
                cred: index,
                model_key: canonical_claim_key(cred.format(), &purpose_path(cred.format(), segs)),
                mdoc_element,
                wildcard_parent,
            });
        }
    }
    out
}

/// True when a disclosed dotted key lies within a requested path: the path
/// itself, a descendant of it (a requested object or array discloses its
/// members), or, for an array wildcard, the array or one of its elements.
fn disclosure_requested(disclosed: &str, claim: &RequestedClaim) -> bool {
    let within = |parent: &str| {
        disclosed == parent
            || disclosed
                .strip_prefix(parent)
                .is_some_and(|rest| rest.starts_with('.'))
    };
    claim.segs.is_some()
        && (within(&claim.key) || claim.wildcard_parent.as_deref().is_some_and(within))
}

/// The claim-model key a disclosed SD-JWT key marks in the model rows.
/// Disclosed keys come from SD-JWT VC presentations, so they map as SD-JWT; an
/// element of a known array claim (`nationalities.0`) marks the array.
fn disclosed_model_key(disclosed: &str) -> Option<String> {
    let path: Vec<String> = disclosed.split('.').map(str::to_string).collect();
    if let [parent, index] = path.as_slice() {
        if SD_JWT_ARRAY_CLAIMS.contains(&parent.as_str())
            && !index.is_empty()
            && index.bytes().all(|b| b.is_ascii_digit())
        {
            return Some(parent.clone());
        }
    }
    canonical_claim_key(&ClaimFormatDesignation::DcSdJwt, &path)
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

/// Rationale for a request whose credential format and type are not registered.
const UNREGISTERED_CREDENTIAL: &str =
    "No registered credential of this format and type in the relying party's registered scope.";

/// Rationale for an `mso_mdoc` path that is not exactly two strings: a wallet
/// aborts on it, and no registered path covers it.
const INVALID_MDOC_PATH: &str = "Not a valid mso_mdoc claims path pointer (exactly two strings, namespace and data element; OpenID4VP 1.0 section 7.2.1), so the registered scope does not cover it.";

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

    let creds = requested_credentials(query);
    let claims = requested_claims(query);

    let mut verdicts = Vec::new();
    let mut counts = Counts {
        registration_evaluated: registered.is_some(),
        purpose_evaluated: baseline.is_some(),
        ..Default::default()
    };

    // One verdict per requested path, aliases included. Registration matches
    // the requested credential by format and type, then compares typed path
    // segments (`RegisteredScope::covers`); a request that accepts several
    // types is within the registration only when it is for every type, since
    // the wallet may return any of them (OpenID4VP 1.0 appendix B.3.5).
    // Purpose and the model lookup use the model key, and an mdoc path
    // without one is judged only against the baseline's mdoc elements,
    // segment by segment.
    for RequestedClaim {
        key,
        segs,
        cred,
        model_key,
        mdoc_element,
        ..
    } in &claims
    {
        let cred = &creds[*cred];
        let type_registered = registered.map(|r| {
            !cred.types.is_empty() && cred.types.iter().all(|t| r.authorizes_vct(&cred.format, t))
        });

        // A credential without `claims` requests no selectively disclosable
        // claim (OpenID4VP 1.0 section 6.4.1): there is nothing to judge for
        // purpose, and it is within the registration when its format and type
        // are registered. Only an unregistered credential gets a row.
        let Some(segs) = segs else {
            if type_registered == Some(false) {
                counts.beyond_registration += 1;
                verdicts.push(ClaimVerdict {
                    key: key.clone(),
                    label: "Credential without claims".to_string(),
                    status: ClaimStatus::BeyondRegistration,
                    correlatable: false,
                    rationale: UNREGISTERED_CREDENTIAL.to_string(),
                });
            }
            continue;
        };

        let meta = match model_key {
            Some(m) => lookup
                .get(m.as_str())
                .map(|c| (c.label.clone(), c.correlatable)),
            None => mdoc_element
                .as_ref()
                .and_then(mdoc_element_meta)
                .map(|(l, c)| (l.to_string(), c)),
        };
        let (label, correlatable) = meta.unwrap_or_else(|| (key.clone(), false));
        if correlatable {
            counts.correlatable_requested += 1;
        }

        let in_registered = registered.map(|r| {
            type_registered == Some(true)
                && cred.types.iter().all(|t| r.covers(&cred.format, t, segs))
        });
        let in_minimal = baseline.map(|b| match model_key {
            Some(m) => b.minimal_keys.iter().any(|k| k == m),
            None => mdoc_element
                .as_ref()
                .is_some_and(|p| b.mdoc_elements.contains(p)),
        });

        let (status, rationale) = match (in_registered, in_minimal) {
            (Some(false), _) => (
                ClaimStatus::BeyondRegistration,
                if type_registered == Some(false) {
                    UNREGISTERED_CREDENTIAL
                } else if !regcert::valid_claim_path(&cred.format, segs) {
                    INVALID_MDOC_PATH
                } else {
                    "Not in the relying party's registered scope."
                }
                .to_string(),
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

    // Disclosed-vs-withheld over the full model. Requested and disclosed keys
    // both map to model keys here, so a row is marked under either spelling.
    let disclosed_model: Vec<String> = disclosed_keys
        .iter()
        .filter_map(|k| disclosed_model_key(k))
        .collect();
    let claim_rows: Vec<ClaimRow> = model
        .iter()
        .map(|c| {
            let key = c.key();
            ClaimRow {
                requested: claims.iter().any(|r| r.model_key.as_ref() == Some(&key)),
                disclosed: disclosed_model.contains(&key),
                key,
                label: c.label.clone(),
                mandatory: c.mandatory,
                correlatable: c.correlatable,
            }
        })
        .collect();

    // Over-disclosure: disclosed but not requested. This compares raw paths,
    // not model keys: `address.locality` and `address.resident_city` are
    // different SD-JWT claims, so disclosing one when only the other was
    // requested is over-disclosure even though both name the same attribute.
    let over_disclosed: Vec<String> = disclosed_keys
        .iter()
        .filter(|k| !claims.iter().any(|c| disclosure_requested(k, c)))
        .cloned()
        .collect();

    counts.requested = verdicts.len();
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

    #[test]
    fn array_claim_disclosure_matches_parent_model_key() {
        let query = pid::pid_query(&[&["nationalities"]]);
        let disclosed = vec!["nationalities".to_string()];

        let report = analyze(PID_VCT, &query, None, None, &disclosed);

        assert!(report.over_disclosed.is_empty());
        let nationalities = report
            .claim_rows
            .iter()
            .find(|row| row.key == "nationalities")
            .expect("nationalities row");
        assert!(nationalities.requested);
        assert!(nationalities.disclosed);
    }

    // --- bank_kyc baseline and mdoc purpose keys ----------------------------

    const GWG_SD_JWT_PATHS: &[&[&str]] = &[
        &["given_name"],
        &["family_name"],
        &["birthdate"],
        &["place_of_birth", "locality"],
        &["nationalities"],
        &["address", "resident_street"],
        &["address", "resident_city"],
        &["address", "resident_postal_code"],
        &["address", "resident_country"],
    ];

    const GWG_MDOC_ELEMENTS: &[&str] = &[
        "given_name",
        "family_name",
        "birth_date",
        "birth_place",
        "nationality",
        "resident_street",
        "resident_city",
        "resident_postal_code",
        "resident_country",
    ];

    /// A DCQL query with one `mso_mdoc` PID credential asking for each path.
    fn mdoc_query(paths: &[&[&str]]) -> DcqlQuery {
        credentials_query(&[("mso_mdoc", paths)])
    }

    fn mdoc_pid_query(elements: &[&str]) -> DcqlQuery {
        let paths: Vec<[&str; 2]> = elements.iter().map(|e| [PID_MDOC_NAMESPACE, e]).collect();
        let refs: Vec<&[&str]> = paths.iter().map(|p| p.as_slice()).collect();
        mdoc_query(&refs)
    }

    /// A DCQL query with one credential per `(format, paths)` entry, in order.
    fn credentials_query(creds: &[(&str, &[&[&str]])]) -> DcqlQuery {
        let credentials: Vec<serde_json::Value> = creds
            .iter()
            .enumerate()
            .map(|(i, (format, paths))| {
                let claims: Vec<serde_json::Value> = paths
                    .iter()
                    .map(|p| serde_json::json!({ "path": p }))
                    .collect();
                let meta = if *format == "mso_mdoc" {
                    serde_json::json!({ "doctype_value": PID_MDOC_NAMESPACE })
                } else {
                    serde_json::json!({ "vct_values": [PID_VCT] })
                };
                serde_json::json!({
                    "id": format!("cred{i}"),
                    "format": format,
                    "meta": meta,
                    "claims": claims,
                })
            })
            .collect();
        serde_json::from_value(serde_json::json!({ "credentials": credentials }))
            .expect("valid DCQL")
    }

    /// A registered scope for the invented relying party "Example Savings Bank",
    /// for the PID of `format` (the mdoc PID is registered by its doctype).
    fn scope(format: &str, paths: &[&[&str]]) -> RegisteredScope {
        let meta = if format == "mso_mdoc" {
            serde_json::json!({ "doctype_value": PID_MDOC_NAMESPACE })
        } else {
            serde_json::json!({ "vct_values": [PID_VCT] })
        };
        crate::regcert::scope_from_payload(&serde_json::json!({
            "purpose": [{ "lang": "en", "content": "Example Savings Bank account opening" }],
            "credentials": [{
                "format": format,
                "meta": meta,
                "claim": paths.iter().map(|p| serde_json::json!({ "path": p })).collect::<Vec<_>>(),
            }],
        }))
        .expect("scope")
    }

    fn status_of(report: &OverAskReport, key: &str) -> ClaimStatus {
        report
            .requested
            .iter()
            .find(|v| v.key == key)
            .unwrap_or_else(|| panic!("no verdict for {key}"))
            .status
    }

    #[test]
    fn bank_kyc_gwg_complete_sd_jwt_request_is_minimal() {
        let query = pid::pid_query(GWG_SD_JWT_PATHS);
        let registered = scope("dc+sd-jwt", GWG_SD_JWT_PATHS);
        let report = analyze(
            PID_VCT,
            &query,
            Some(&registered),
            baseline("bank_kyc").as_ref(),
            &[],
        );

        assert!(!report.has_over_ask(), "{:?}", report.requested);
        assert_eq!(report.counts.requested, 9);
        assert_eq!(report.counts.minimal, 9);
        assert_eq!(report.counts.correlatable_requested, 9);
        assert_eq!(report.verdict_class(), "ok");
    }

    #[test]
    fn bank_kyc_gwg_complete_mdoc_request_is_minimal() {
        let query = mdoc_pid_query(GWG_MDOC_ELEMENTS);
        let report = analyze(PID_VCT, &query, None, baseline("bank_kyc").as_ref(), &[]);

        assert!(!report.has_over_ask(), "{:?}", report.requested);
        assert_eq!(report.counts.requested, 9);
        assert_eq!(report.counts.minimal, 9);
        // Verdict keys stay raw; the model lookup uses the purpose key.
        let birth = report
            .requested
            .iter()
            .find(|v| v.key == "eu.europa.ec.eudi.pid.1.birth_date")
            .expect("raw mdoc key kept");
        assert_eq!(birth.label, "Date of birth");
        assert!(birth.correlatable);
        let row = report
            .claim_rows
            .iter()
            .find(|r| r.key == "nationalities")
            .expect("nationalities row");
        assert!(row.requested);
    }

    #[test]
    fn bank_kyc_still_flags_non_gwg_claims() {
        let query = pid::pid_query(&[&["given_name"], &["family_name_birth"], &["age_in_years"]]);
        let report = analyze(PID_VCT, &query, None, baseline("bank_kyc").as_ref(), &[]);

        assert_eq!(report.counts.beyond_purpose, 2);
        assert_eq!(
            status_of(&report, "family_name_birth"),
            ClaimStatus::BeyondPurpose
        );
        assert_eq!(
            status_of(&report, "age_in_years"),
            ClaimStatus::BeyondPurpose
        );
        assert_eq!(
            status_of(&report, "given_name"),
            ClaimStatus::MinimalForPurpose
        );
    }

    #[test]
    fn bank_kyc_still_flags_whole_sd_jwt_parent_objects() {
        // The SD-JWT parent objects disclose every member, including ones the
        // credential may carry beyond the baseline; request the members.
        for parent in ["place_of_birth", "address"] {
            let sd_jwt = pid::pid_query(&[&[parent]]);
            let report = analyze(PID_VCT, &sd_jwt, None, baseline("bank_kyc").as_ref(), &[]);
            assert_eq!(status_of(&report, parent), ClaimStatus::BeyondPurpose);
        }
    }

    #[test]
    fn bank_kyc_accepts_structured_mdoc_place_of_birth() {
        // The Rulebook mdoc `place_of_birth` is one element (a CBOR map of
        // country, region, locality, all GwG place-of-birth data); mdoc cannot
        // select inside it, so this element is the only way to ask for it.
        let mdoc = mdoc_pid_query(&["place_of_birth"]);
        let report = analyze(PID_VCT, &mdoc, None, baseline("bank_kyc").as_ref(), &[]);
        let v = &report.requested[0];
        assert_eq!(v.key, "eu.europa.ec.eudi.pid.1.place_of_birth");
        assert_eq!(v.status, ClaimStatus::MinimalForPurpose);
        assert_eq!(v.label, "Place of birth");
        assert!(v.correlatable);

        // Only in the mdoc form and only for bank_kyc.
        let sd_jwt = pid::pid_query(&[&[PID_MDOC_NAMESPACE, "place_of_birth"]]);
        let report = analyze(PID_VCT, &sd_jwt, None, baseline("bank_kyc").as_ref(), &[]);
        assert_eq!(report.requested[0].status, ClaimStatus::BeyondPurpose);
        for purpose in ["age_gate_18", "event_checkin", "car_rental"] {
            let report = analyze(PID_VCT, &mdoc, None, baseline(purpose).as_ref(), &[]);
            assert_eq!(report.counts.beyond_purpose, 1, "{purpose}");
        }
    }

    #[test]
    fn birthplace_and_nationality_still_beyond_non_bank_purposes() {
        let sd_jwt = pid::pid_query(&[&["place_of_birth", "locality"], &["nationalities"]]);
        let mdoc = mdoc_pid_query(&["birth_place", "nationality"]);
        for purpose in ["age_gate_18", "event_checkin", "car_rental"] {
            for query in [&sd_jwt, &mdoc] {
                let report = analyze(PID_VCT, query, None, baseline(purpose).as_ref(), &[]);
                assert_eq!(report.counts.beyond_purpose, 2, "{purpose}");
                assert!(report.has_over_ask(), "{purpose}");
            }
        }
    }

    #[test]
    fn nationalities_still_beyond_age_gate() {
        let query = pid::pid_query(&[&["age_equal_or_over", "18"], &["nationalities"]]);
        let report = analyze(PID_VCT, &query, None, baseline("age_gate_18").as_ref(), &[]);
        assert_eq!(
            status_of(&report, "nationalities"),
            ClaimStatus::BeyondPurpose
        );
        assert_eq!(
            status_of(&report, "age_equal_or_over.18"),
            ClaimStatus::MinimalForPurpose
        );
    }

    #[test]
    fn mdoc_names_count_as_baseline_names_for_checkin_and_rental() {
        let query = mdoc_pid_query(&["given_name", "family_name"]);
        for purpose in ["event_checkin", "car_rental"] {
            let report = analyze(PID_VCT, &query, None, baseline(purpose).as_ref(), &[]);
            assert_eq!(report.counts.minimal, 2, "{purpose}");
            assert!(!report.has_over_ask(), "{purpose}");
        }
    }

    #[test]
    fn canonical_claim_key_maps_only_pid_mdoc_two_segment_paths() {
        let mdoc = ClaimFormatDesignation::MsoMDoc;
        let sd_jwt = ClaimFormatDesignation::DcSdJwt;
        let p = |segs: &[&str]| segs.iter().map(|s| s.to_string()).collect::<Vec<_>>();

        for (element, expected) in [
            ("given_name", "given_name"),
            ("family_name", "family_name"),
            ("birth_date", "birthdate"),
            ("birth_place", "place_of_birth.locality"),
            ("nationality", "nationalities"),
            ("resident_street", "address.resident_street"),
            ("resident_city", "address.resident_city"),
            ("resident_postal_code", "address.resident_postal_code"),
            ("resident_country", "address.resident_country"),
            ("resident_state", "address.region"),
            ("resident_address", "address.formatted"),
        ] {
            assert_eq!(
                canonical_claim_key(&mdoc, &p(&[PID_MDOC_NAMESPACE, element])).as_deref(),
                Some(expected)
            );
        }
        // No model key for any other mdoc path: unknown elements, the
        // structured place_of_birth, SD-JWT spellings, other namespaces (even
        // when the dotted key equals a model key), other shapes.
        for segs in [
            p(&[PID_MDOC_NAMESPACE, "age_over_18"]),
            p(&[PID_MDOC_NAMESPACE, "place_of_birth"]),
            p(&[PID_MDOC_NAMESPACE, "street_address"]),
            p(&[PID_MDOC_NAMESPACE, "resident_house_number"]),
            p(&["org.iso.18013.5.1", "given_name"]),
            p(&["address", "resident_city"]),
            p(&["place_of_birth", "country"]),
            p(&["given_name"]),
            p(&[PID_MDOC_NAMESPACE, "birth_place", "locality"]),
        ] {
            assert_eq!(canonical_claim_key(&mdoc, &segs), None, "{segs:?}");
        }
        // SD-JWT keeps every unmapped path raw.
        for (segs, expected) in [
            (p(&["nationality"]), "nationality"),
            (p(&["resident_street"]), "resident_street"),
            (p(&["street_address"]), "street_address"),
            (p(&["address"]), "address"),
        ] {
            assert_eq!(
                canonical_claim_key(&sd_jwt, &segs).as_deref(),
                Some(expected)
            );
        }
        // An SD-JWT segment holding a dot has no model key, so no joined
        // spelling reaches a nested model key or an alias.
        for segs in [
            p(&[PID_MDOC_NAMESPACE, "given_name"]),
            p(&["address.locality"]),
            p(&["address.resident_city"]),
            p(&["age_equal_or_over.18"]),
        ] {
            assert_eq!(canonical_claim_key(&sd_jwt, &segs), None, "{segs:?}");
        }
    }

    #[test]
    fn canonical_claim_key_maps_standard_sd_jwt_address_components() {
        let p = |segs: &[&str]| segs.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for format in [
            ClaimFormatDesignation::DcSdJwt,
            ClaimFormatDesignation::Other(pid::PID_FORMAT.to_string()),
        ] {
            for (component, expected) in [
                ("street_address", "address.resident_street"),
                ("locality", "address.resident_city"),
                ("postal_code", "address.resident_postal_code"),
                ("country", "address.resident_country"),
            ] {
                assert_eq!(
                    canonical_claim_key(&format, &p(&["address", component])).as_deref(),
                    Some(expected)
                );
            }
        }
    }

    const GWG_SD_JWT_STANDARD_ADDRESS_PATHS: &[&[&str]] = &[
        &["given_name"],
        &["family_name"],
        &["birthdate"],
        &["place_of_birth", "locality"],
        &["nationalities"],
        &["address", "street_address"],
        &["address", "locality"],
        &["address", "postal_code"],
        &["address", "country"],
    ];

    #[test]
    fn bank_kyc_gwg_request_with_standard_sd_jwt_address_is_minimal() {
        let query = pid::pid_query(GWG_SD_JWT_STANDARD_ADDRESS_PATHS);
        let registered = scope("dc+sd-jwt", GWG_SD_JWT_STANDARD_ADDRESS_PATHS);
        let report = analyze(
            PID_VCT,
            &query,
            Some(&registered),
            baseline("bank_kyc").as_ref(),
            &[],
        );

        assert!(!report.has_over_ask(), "{:?}", report.requested);
        assert_eq!(report.counts.requested, 9);
        assert_eq!(report.counts.minimal, 9);
        assert_eq!(report.counts.correlatable_requested, 9);
        // Verdict keys stay raw; the model lookup uses the purpose key.
        let locality = report
            .requested
            .iter()
            .find(|v| v.key == "address.locality")
            .expect("raw SD-JWT key kept");
        assert_eq!(locality.label, "Resident city");
        let row = report
            .claim_rows
            .iter()
            .find(|r| r.key == "address.resident_street")
            .expect("resident street row");
        assert!(row.requested);
    }

    #[test]
    fn standard_sd_jwt_address_still_beyond_non_bank_purposes() {
        let query = pid::pid_query(&[&["address", "street_address"], &["address", "locality"]]);
        for purpose in ["age_gate_18", "event_checkin", "car_rental"] {
            let report = analyze(PID_VCT, &query, None, baseline(purpose).as_ref(), &[]);
            assert_eq!(report.counts.beyond_purpose, 2, "{purpose}");
        }
    }

    #[test]
    fn registration_matching_stays_exact_for_sd_jwt_address_aliases() {
        // Registered under the resident_* names: the standard component paths
        // are different paths and stay outside the registered scope, and the
        // other way round.
        let registered = scope("dc+sd-jwt", &[&["address", "resident_city"]]);
        let query = pid::pid_query(&[&["address", "locality"]]);
        let report = analyze(
            PID_VCT,
            &query,
            Some(&registered),
            baseline("bank_kyc").as_ref(),
            &[],
        );
        assert_eq!(
            status_of(&report, "address.locality"),
            ClaimStatus::BeyondRegistration
        );

        let registered = scope("dc+sd-jwt", &[&["address", "locality"]]);
        let query = pid::pid_query(&[&["address", "resident_city"]]);
        let report = analyze(PID_VCT, &query, Some(&registered), None, &[]);
        assert_eq!(
            status_of(&report, "address.resident_city"),
            ClaimStatus::BeyondRegistration
        );
    }

    #[test]
    fn unknown_mdoc_namespace_stays_beyond_purpose() {
        let query = mdoc_query(&[&["org.iso.18013.5.1", "given_name"]]);
        let report = analyze(PID_VCT, &query, None, baseline("bank_kyc").as_ref(), &[]);
        assert_eq!(
            status_of(&report, "org.iso.18013.5.1.given_name"),
            ClaimStatus::BeyondPurpose
        );
    }

    #[test]
    fn mdoc_element_match_keeps_the_namespace_boundary() {
        // `["eu.europa.ec.eudi.pid", "1.place_of_birth"]` joins to the same
        // dotted key as the PID `place_of_birth` element but names another
        // namespace and element; it is neither accepted nor labelled as it.
        let query = mdoc_query(&[&["eu.europa.ec.eudi.pid", "1.place_of_birth"]]);
        let report = analyze(PID_VCT, &query, None, baseline("bank_kyc").as_ref(), &[]);
        let v = &report.requested[0];
        assert_eq!(v.key, "eu.europa.ec.eudi.pid.1.place_of_birth");
        assert_eq!(v.status, ClaimStatus::BeyondPurpose);
        assert_eq!(v.label, v.key);
        assert!(!v.correlatable);

        // The same holds for any other split of a known element, and for an
        // mdoc path whose dotted form equals an SD-JWT model key.
        for path in [
            &["eu", "europa.ec.eudi.pid.1.place_of_birth"][..],
            &["eu.europa.ec.eudi.pid.1.place_of", "birth"][..],
            &["address", "resident_city"][..],
        ] {
            let query = mdoc_query(&[path]);
            let report = analyze(PID_VCT, &query, None, baseline("bank_kyc").as_ref(), &[]);
            let v = &report.requested[0];
            assert_eq!(v.status, ClaimStatus::BeyondPurpose, "{path:?}");
            assert_eq!(v.label, v.key, "{path:?}");
            assert!(!v.correlatable, "{path:?}");
        }
    }

    #[test]
    fn sd_jwt_nationality_is_not_an_alias_of_nationalities() {
        let query = pid::pid_query(&[&["nationality"]]);
        let report = analyze(PID_VCT, &query, None, baseline("bank_kyc").as_ref(), &[]);
        assert_eq!(
            status_of(&report, "nationality"),
            ClaimStatus::BeyondPurpose
        );

        let registered = scope("dc+sd-jwt", &[&["nationalities"]]);
        let report = analyze(PID_VCT, &query, Some(&registered), None, &[]);
        assert_eq!(
            status_of(&report, "nationality"),
            ClaimStatus::BeyondRegistration
        );
    }

    #[test]
    fn registration_matching_stays_exact_across_formats() {
        // Registered for SD-JWT given_name only: the mdoc given_name is a
        // different path and stays outside the registered scope.
        let registered = scope("dc+sd-jwt", &[&["given_name"]]);
        let query = mdoc_pid_query(&["given_name"]);
        let report = analyze(
            PID_VCT,
            &query,
            Some(&registered),
            baseline("bank_kyc").as_ref(),
            &[],
        );
        assert_eq!(
            status_of(&report, "eu.europa.ec.eudi.pid.1.given_name"),
            ClaimStatus::BeyondRegistration
        );

        // A flat registered `resident_street` does not authorize the nested path.
        let registered = scope("dc+sd-jwt", &[&["resident_street"]]);
        let query = pid::pid_query(&[&["address", "resident_street"]]);
        let report = analyze(PID_VCT, &query, Some(&registered), None, &[]);
        assert_eq!(
            status_of(&report, "address.resident_street"),
            ClaimStatus::BeyondRegistration
        );

        // The exact mdoc path registered under mso_mdoc is accepted.
        let registered = scope("mso_mdoc", &[&[PID_MDOC_NAMESPACE, "nationality"]]);
        let query = mdoc_pid_query(&["nationality"]);
        let report = analyze(
            PID_VCT,
            &query,
            Some(&registered),
            baseline("bank_kyc").as_ref(),
            &[],
        );
        assert!(!report.has_over_ask(), "{:?}", report.requested);
    }

    #[test]
    fn aliased_paths_keep_one_verdict_per_path_in_either_order() {
        const SD: &[&[&str]] = &[&["nationalities"]];
        const MD: &[&[&str]] = &[&[PID_MDOC_NAMESPACE, "nationality"]];
        let sd = ("dc+sd-jwt", SD);
        let md = ("mso_mdoc", MD);
        for order in [[sd, md], [md, sd]] {
            let query = credentials_query(&order);
            let report = analyze(PID_VCT, &query, None, baseline("bank_kyc").as_ref(), &[]);
            assert_eq!(report.counts.requested, 2);
            assert_eq!(report.requested.len(), 2);
            assert_eq!(report.counts.minimal, 2);
            assert_eq!(report.counts.correlatable_requested, 2);
            let keys: Vec<&str> = report.requested.iter().map(|v| v.key.as_str()).collect();
            assert!(keys.contains(&"nationalities"));
            assert!(keys.contains(&"eu.europa.ec.eudi.pid.1.nationality"));
        }
    }

    #[test]
    fn aliased_disclosure_still_counts_as_over_disclosure() {
        let query = pid::pid_query(&[&["nationalities"]]);
        let disclosed = vec!["eu.europa.ec.eudi.pid.1.nationality".to_string()];
        let report = analyze(PID_VCT, &query, None, None, &disclosed);
        assert_eq!(report.over_disclosed, disclosed);
    }

    // --- bank_kyc: every PID spelling of the GwG attributes -----------------

    /// A DCQL query with one credential of `format` and raw JSON claim paths,
    /// so element selectors (`null`, integers) can be expressed.
    fn json_paths_query(format: &str, paths: &[serde_json::Value]) -> DcqlQuery {
        let meta = if format == "mso_mdoc" {
            serde_json::json!({ "doctype_value": PID_MDOC_NAMESPACE })
        } else {
            serde_json::json!({ "vct_values": [PID_VCT] })
        };
        let claims: Vec<serde_json::Value> = paths
            .iter()
            .map(|p| serde_json::json!({ "path": p }))
            .collect();
        serde_json::from_value(serde_json::json!({ "credentials": [{
            "id": "pid", "format": format, "meta": meta, "claims": claims,
        }]}))
        .expect("valid DCQL")
    }

    fn single_status(format: &str, path: serde_json::Value, purpose: &str) -> ClaimStatus {
        let query = json_paths_query(format, &[path]);
        let report = analyze(PID_VCT, &query, None, baseline(purpose).as_ref(), &[]);
        assert_eq!(report.requested.len(), 1);
        report.requested[0].status
    }

    /// SD-JWT VC spellings: EU PID Rulebook section 4.1.1 (place_of_birth
    /// members per section 3.1.4, address.house_number per the private-name
    /// table), the German model spelling `address.resident_*`, and the flat
    /// `birth_place` and `birth_country` of
    /// fixtures/presentations/erica-pid-template-normal.json.
    const SD_JWT_GWG_SPELLINGS: &[&[&str]] = &[
        &["given_name"],
        &["family_name"],
        &["birthdate"],
        &["place_of_birth", "locality"],
        &["place_of_birth", "region"],
        &["place_of_birth", "country"],
        &["birth_place"],
        &["birth_country"],
        &["nationalities"],
        &["address", "street_address"],
        &["address", "house_number"],
        &["address", "locality"],
        &["address", "postal_code"],
        &["address", "region"],
        &["address", "country"],
        &["address", "formatted"],
        &["address", "resident_street"],
        &["address", "resident_city"],
        &["address", "resident_postal_code"],
        &["address", "resident_country"],
    ];

    /// mso_mdoc elements of the PID namespace: EU PID Rulebook section 3.1.2
    /// (structured `place_of_birth`) plus the EUDIPLO text `birth_place`.
    const MDOC_GWG_SPELLINGS: &[&str] = &[
        "given_name",
        "family_name",
        "birth_date",
        "place_of_birth",
        "birth_place",
        "nationality",
        "resident_street",
        "resident_city",
        "resident_postal_code",
        "resident_state",
        "resident_country",
        "resident_address",
    ];

    #[test]
    fn bank_kyc_accepts_each_sd_jwt_spelling() {
        for format in ["dc+sd-jwt", "vc+sd-jwt"] {
            for path in SD_JWT_GWG_SPELLINGS {
                assert_eq!(
                    single_status(format, serde_json::json!(path), "bank_kyc"),
                    ClaimStatus::MinimalForPurpose,
                    "{format} {path:?}"
                );
            }
        }
    }

    #[test]
    fn bank_kyc_accepts_each_mdoc_spelling() {
        for element in MDOC_GWG_SPELLINGS {
            assert_eq!(
                single_status(
                    "mso_mdoc",
                    serde_json::json!([PID_MDOC_NAMESPACE, element]),
                    "bank_kyc"
                ),
                ClaimStatus::MinimalForPurpose,
                "{element}"
            );
        }
    }

    #[test]
    fn bank_kyc_accepts_nationalities_element_selectors() {
        // OpenID4VP DCQL: `null` selects every array element, an integer one.
        for path in [
            serde_json::json!(["nationalities"]),
            serde_json::json!(["nationalities", null]),
            serde_json::json!(["nationalities", 0]),
            serde_json::json!(["nationalities", 3]),
        ] {
            assert_eq!(
                single_status("dc+sd-jwt", path.clone(), "bank_kyc"),
                ClaimStatus::MinimalForPurpose,
                "{path}"
            );
            // Still beyond a purpose that does not need nationality.
            assert_eq!(
                single_status("dc+sd-jwt", path.clone(), "age_gate_18"),
                ClaimStatus::BeyondPurpose,
                "{path}"
            );
        }
        let query = json_paths_query("dc+sd-jwt", &[serde_json::json!(["nationalities", null])]);
        let report = analyze(PID_VCT, &query, None, baseline("bank_kyc").as_ref(), &[]);
        assert_eq!(report.requested[0].key, "nationalities.*");
        assert_eq!(report.requested[0].label, "Nationalities");
        assert!(report.requested[0].correlatable);
    }

    #[test]
    fn bank_kyc_flags_invalid_nationalities_descendants() {
        for path in [
            serde_json::json!(["nationalities", "0"]),
            serde_json::json!(["nationalities", "code"]),
            serde_json::json!(["nationalities", null, "code"]),
            serde_json::json!(["nationalities", 0, 1]),
        ] {
            assert_eq!(
                single_status("dc+sd-jwt", path.clone(), "bank_kyc"),
                ClaimStatus::BeyondPurpose,
                "{path}"
            );
        }
        // No element selectors in the mdoc form.
        for path in [
            serde_json::json!([PID_MDOC_NAMESPACE, "nationality", 0]),
            serde_json::json!([PID_MDOC_NAMESPACE, "nationality", null]),
        ] {
            assert_eq!(
                single_status("mso_mdoc", path.clone(), "bank_kyc"),
                ClaimStatus::BeyondPurpose,
                "{path}"
            );
        }
    }

    #[test]
    fn bank_kyc_flags_mdoc_spellings_in_sd_jwt_form() {
        for path in [
            serde_json::json!(["nationality"]),
            serde_json::json!(["birth_date"]),
            serde_json::json!(["resident_street"]),
            serde_json::json!(["resident_city"]),
            serde_json::json!(["resident_state"]),
            serde_json::json!(["resident_address"]),
            serde_json::json!([PID_MDOC_NAMESPACE, "given_name"]),
            serde_json::json!([PID_MDOC_NAMESPACE, "place_of_birth"]),
            // Model-only spellings of the new keys are not SD-JWT claim names.
            serde_json::json!(["address", "resident_state"]),
            serde_json::json!(["address", "resident_address"]),
            serde_json::json!(["address", "resident_house_number"]),
            serde_json::json!(["place_of_birth", "resident_city"]),
        ] {
            assert_eq!(
                single_status("dc+sd-jwt", path.clone(), "bank_kyc"),
                ClaimStatus::BeyondPurpose,
                "{path}"
            );
        }
    }

    #[test]
    fn bank_kyc_flags_sd_jwt_spellings_in_mdoc_form() {
        let ns = PID_MDOC_NAMESPACE;
        for path in [
            serde_json::json!([ns, "birthdate"]),
            serde_json::json!([ns, "nationalities"]),
            serde_json::json!([ns, "street_address"]),
            serde_json::json!([ns, "locality"]),
            serde_json::json!([ns, "region"]),
            serde_json::json!([ns, "formatted"]),
            serde_json::json!([ns, "house_number"]),
            serde_json::json!([ns, "birth_country"]),
            // Not an element of the EU PID mdoc (SD-JWT only).
            serde_json::json!([ns, "resident_house_number"]),
            // mdoc cannot select inside an element.
            serde_json::json!([ns, "place_of_birth", "locality"]),
            // Another namespace, even when the dotted key equals a model key.
            serde_json::json!(["address", "resident_city"]),
            serde_json::json!(["place_of_birth", "country"]),
            serde_json::json!(["place_of_birth", "locality"]),
            serde_json::json!(["org.iso.18013.5.1", "birth_place"]),
            serde_json::json!(["eu.europa.ec.eudi.pid.de.1", "given_name"]),
            // A one-segment path.
            serde_json::json!(["given_name"]),
        ] {
            assert_eq!(
                single_status("mso_mdoc", path.clone(), "bank_kyc"),
                ClaimStatus::BeyondPurpose,
                "{path}"
            );
        }
    }

    #[test]
    fn bank_kyc_flags_attributes_outside_gwg_list() {
        for path in [
            "family_name_birth",
            "birth_family_name",
            "given_name_birth",
            "birth_given_name",
            "age_in_years",
            "age_birth_year",
            "sex",
            "email",
            "phone_number",
            "picture",
            "personal_administrative_number",
            "document_number",
        ] {
            assert_eq!(
                single_status("dc+sd-jwt", serde_json::json!([path]), "bank_kyc"),
                ClaimStatus::BeyondPurpose,
                "{path}"
            );
        }
        for element in [
            "family_name_birth",
            "sex",
            "email_address",
            "mobile_phone_number",
            "portrait",
            "age_over_18",
            "personal_administrative_number",
        ] {
            assert_eq!(
                single_status(
                    "mso_mdoc",
                    serde_json::json!([PID_MDOC_NAMESPACE, element]),
                    "bank_kyc"
                ),
                ClaimStatus::BeyondPurpose,
                "{element}"
            );
        }
    }

    #[test]
    fn bank_kyc_complete_rulebook_requests_are_minimal_with_labels() {
        let sd_jwt: Vec<serde_json::Value> = SD_JWT_GWG_SPELLINGS
            .iter()
            .map(|p| serde_json::json!(p))
            .collect();
        let mdoc: Vec<serde_json::Value> = MDOC_GWG_SPELLINGS
            .iter()
            .map(|e| serde_json::json!([PID_MDOC_NAMESPACE, e]))
            .collect();
        for (format, paths) in [("dc+sd-jwt", &sd_jwt), ("mso_mdoc", &mdoc)] {
            let query = json_paths_query(format, paths);
            let report = analyze(PID_VCT, &query, None, baseline("bank_kyc").as_ref(), &[]);
            assert!(!report.has_over_ask(), "{format}: {:?}", report.requested);
            assert_eq!(report.counts.minimal, paths.len(), "{format}");
            // Every GwG attribute is correlatable, new model keys included.
            assert_eq!(
                report.counts.correlatable_requested,
                paths.len(),
                "{format}"
            );
            for v in &report.requested {
                assert_ne!(v.label, v.key, "{format}: label for {}", v.key);
            }
        }
        let query = json_paths_query("dc+sd-jwt", &sd_jwt);
        let report = analyze(PID_VCT, &query, None, baseline("bank_kyc").as_ref(), &[]);
        let label = |key: &str| {
            report
                .requested
                .iter()
                .find(|v| v.key == key)
                .map(|v| v.label.clone())
                .unwrap_or_else(|| panic!("no verdict for {key}"))
        };
        assert_eq!(label("birth_place"), "Place of birth");
        assert_eq!(label("birth_country"), "Place of birth (country)");
        assert_eq!(label("address.region"), "Resident state");
        assert_eq!(label("address.formatted"), "Resident address");
        assert_eq!(label("address.house_number"), "Resident house number");
    }

    #[test]
    fn bank_kyc_fixture_shaped_request_is_minimal() {
        // The selectively disclosable GwG claims of
        // fixtures/presentations/erica-pid-template-normal.json.
        let paths: &[&[&str]] = &[
            &["given_name"],
            &["family_name"],
            &["birthdate"],
            &["address", "street_address"],
            &["address", "postal_code"],
            &["address", "locality"],
            &["address", "country"],
            &["nationalities"],
            &["birth_place"],
            &["birth_country"],
        ];
        let query = pid::pid_query(paths);
        let registered = scope("dc+sd-jwt", paths);
        let report = analyze(
            PID_VCT,
            &query,
            Some(&registered),
            baseline("bank_kyc").as_ref(),
            &[],
        );
        assert!(!report.has_over_ask(), "{:?}", report.requested);
        assert_eq!(report.counts.minimal, 10);
        let row = report
            .claim_rows
            .iter()
            .find(|r| r.key == "place_of_birth.locality")
            .expect("place of birth row");
        assert!(row.requested);
    }

    #[test]
    fn bank_kyc_new_spellings_still_beyond_non_bank_purposes() {
        for purpose in ["age_gate_18", "event_checkin", "car_rental"] {
            for path in [
                serde_json::json!(["place_of_birth", "region"]),
                serde_json::json!(["place_of_birth", "country"]),
                serde_json::json!(["birth_place"]),
                serde_json::json!(["birth_country"]),
                serde_json::json!(["address", "region"]),
                serde_json::json!(["address", "formatted"]),
                serde_json::json!(["address", "house_number"]),
            ] {
                assert_eq!(
                    single_status("dc+sd-jwt", path.clone(), purpose),
                    ClaimStatus::BeyondPurpose,
                    "{purpose} {path}"
                );
            }
            for element in ["resident_state", "resident_address", "place_of_birth"] {
                assert_eq!(
                    single_status(
                        "mso_mdoc",
                        serde_json::json!([PID_MDOC_NAMESPACE, element]),
                        purpose
                    ),
                    ClaimStatus::BeyondPurpose,
                    "{purpose} {element}"
                );
            }
        }
    }

    #[test]
    fn bank_kyc_baseline_lists_model_keys_and_mdoc_elements() {
        let b = baseline("bank_kyc").expect("bank_kyc");
        assert_eq!(b.minimal_keys.len(), 14);
        assert_eq!(
            b.mdoc_elements,
            [["eu.europa.ec.eudi.pid.1", "place_of_birth"].map(String::from)]
        );
        let json = serde_json::to_value(&b).expect("json");
        assert_eq!(
            json["mdoc_elements"],
            serde_json::json!([["eu.europa.ec.eudi.pid.1", "place_of_birth"]])
        );
        // The other baselines serialize without the field.
        let age = serde_json::to_value(baseline("age_gate_18").expect("age")).expect("json");
        assert!(age.get("mdoc_elements").is_none());
    }

    // --- disclosed claims: model rows by model key, over-disclosure by path --

    #[test]
    fn disclosed_alias_marks_model_row_but_is_not_authorized_by_it() {
        // Rows use model keys for requested and disclosed alike, so the
        // standard SD-JWT spelling marks the German model row.
        let query = pid::pid_query(&[&["address", "locality"]]);
        let disclosed = vec!["address.locality".to_string()];
        let report = analyze(PID_VCT, &query, None, None, &disclosed);
        assert!(report.over_disclosed.is_empty());
        let row = report
            .claim_rows
            .iter()
            .find(|r| r.key == "address.resident_city")
            .expect("resident city row");
        assert!(row.requested && row.disclosed);

        // Over-disclosure compares SD-JWT paths, not model keys: the other
        // spelling is a different claim, in either direction.
        let cases: [(&[&str], &str); 3] = [
            (&["address", "locality"], "address.resident_city"),
            (&["address", "resident_city"], "address.locality"),
            (&["birth_place"], "place_of_birth.locality"),
        ];
        for (path, other) in cases {
            let requested = path;
            let query = pid::pid_query(&[path]);
            let disclosed = vec![path.join("."), other.to_string()];
            let report = analyze(
                PID_VCT,
                &query,
                None,
                baseline("bank_kyc").as_ref(),
                &disclosed,
            );
            assert_eq!(report.over_disclosed, [other], "{requested:?}");
        }
    }

    #[test]
    fn disclosure_within_requested_path_is_not_over_disclosure() {
        // A wildcard over nationalities covers the array and its elements.
        let query = json_paths_query("dc+sd-jwt", &[serde_json::json!(["nationalities", null])]);
        let disclosed = vec!["nationalities".to_string(), "nationalities.0".to_string()];
        let report = analyze(PID_VCT, &query, None, None, &disclosed);
        assert!(
            report.over_disclosed.is_empty(),
            "{:?}",
            report.over_disclosed
        );
        let row = report
            .claim_rows
            .iter()
            .find(|r| r.key == "nationalities")
            .expect("nationalities row");
        assert!(row.requested && row.disclosed);

        // One index does not cover another element or the whole array.
        let query = json_paths_query("dc+sd-jwt", &[serde_json::json!(["nationalities", 0])]);
        let disclosed = vec![
            "nationalities.0".to_string(),
            "nationalities.1".to_string(),
            "nationalities".to_string(),
        ];
        let report = analyze(PID_VCT, &query, None, None, &disclosed);
        assert_eq!(report.over_disclosed, ["nationalities.1", "nationalities"]);

        // A requested object covers its members, not its siblings.
        let query = pid::pid_query(&[&["address"]]);
        let disclosed = vec!["address.locality".to_string(), "addressee".to_string()];
        let report = analyze(PID_VCT, &query, None, None, &disclosed);
        assert_eq!(report.over_disclosed, ["addressee"]);
    }

    #[test]
    fn bank_kyc_note_cites_gwg_and_keeps_qualification() {
        let b = baseline("bank_kyc").expect("bank_kyc");
        assert!(b.note.contains("GwG § 11 Abs. 4 Nr. 1"));
        assert!(b.note.contains("taste judgment"));
        assert!(b.note.contains("AML compliance"));
        assert_eq!(LEGAL_BASIS.len(), 3);
    }

    // --- registration coverage: typed paths, credential matching -----------

    fn query_json(v: serde_json::Value) -> DcqlQuery {
        serde_json::from_value(v).expect("valid DCQL")
    }

    fn scope_json(credentials: serde_json::Value) -> RegisteredScope {
        crate::regcert::scope_from_payload(&serde_json::json!({ "credentials": credentials }))
            .expect("scope")
    }

    #[test]
    fn request_identical_to_registration_with_null_segment_is_within_it() {
        let paths = serde_json::json!([
            ["given_name"],
            ["nationalities", null],
            ["address", "locality"]
        ]);
        let registered = scope_json(serde_json::json!([{
            "format": "dc+sd-jwt", "meta": { "vct_values": [PID_VCT] },
            "claim": paths.as_array().unwrap().iter().map(|p| serde_json::json!({ "path": p })).collect::<Vec<_>>(),
        }]));
        let query = json_paths_query("dc+sd-jwt", paths.as_array().unwrap());
        let report = analyze(
            PID_VCT,
            &query,
            Some(&registered),
            baseline("bank_kyc").as_ref(),
            &[],
        );
        assert_eq!(
            report.counts.beyond_registration, 0,
            "{:?}",
            report.requested
        );
        assert!(!report.has_over_ask(), "{:?}", report.requested);
        assert_eq!(report.counts.requested, 3);
    }

    #[test]
    fn dotted_single_segment_is_neither_registered_nor_minimal() {
        let registered = scope("dc+sd-jwt", &[&["address", "locality"]]);
        let query = pid::pid_query(&[&["address.locality"]]);
        let report = analyze(PID_VCT, &query, Some(&registered), None, &[]);
        assert_eq!(
            status_of(&report, "address.locality"),
            ClaimStatus::BeyondRegistration
        );

        let query = pid::pid_query(&[&["address.resident_city"]]);
        let report = analyze(PID_VCT, &query, None, baseline("bank_kyc").as_ref(), &[]);
        let v = &report.requested[0];
        assert_eq!(v.status, ClaimStatus::BeyondPurpose);
        assert_eq!(v.label, v.key);
    }

    #[test]
    fn claim_sets_audit_every_alternative_and_skip_unused_declarations() {
        let claims = serde_json::json!([
            { "id": "age", "path": ["age_equal_or_over", "18"] },
            { "id": "dob", "path": ["birthdate"] },
            { "id": "unused", "path": ["nationalities"] },
        ]);
        let q = |sets: serde_json::Value| {
            query_json(serde_json::json!({ "credentials": [{
                "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": [PID_VCT] },
                "claims": claims, "claim_sets": sets,
            }]}))
        };
        let keys = |r: &OverAskReport| {
            r.requested
                .iter()
                .map(|v| v.key.clone())
                .collect::<Vec<_>>()
        };

        // Only age selected: birthdate and nationalities are never requested.
        let report = analyze(
            PID_VCT,
            &q(serde_json::json!([["age"]])),
            None,
            baseline("age_gate_18").as_ref(),
            &[],
        );
        assert_eq!(keys(&report), ["age_equal_or_over.18"]);
        assert!(!report.has_over_ask());

        // Either combination may be returned: both are audited.
        let report = analyze(
            PID_VCT,
            &q(serde_json::json!([["age"], ["dob"]])),
            None,
            baseline("age_gate_18").as_ref(),
            &[],
        );
        assert_eq!(keys(&report), ["age_equal_or_over.18", "birthdate"]);
        assert_eq!(report.counts.beyond_purpose, 1);

        // An unresolvable reference keeps every declared claim (fail closed).
        let report = analyze(
            PID_VCT,
            &q(serde_json::json!([["age", "nope"]])),
            None,
            baseline("age_gate_18").as_ref(),
            &[],
        );
        assert_eq!(report.counts.requested, 3);
    }

    #[test]
    fn credential_without_claims_is_judged_by_type_only() {
        let q = |vct: &str| {
            query_json(serde_json::json!({ "credentials": [{
                "id": "card", "format": "dc+sd-jwt", "meta": { "vct_values": [vct] },
            }]}))
        };
        let registered = scope("dc+sd-jwt", &[&["given_name"]]);
        for b in [None, baseline("age_gate_18")] {
            // Registered type: nothing requested, nothing flagged.
            let report = analyze(PID_VCT, &q(PID_VCT), Some(&registered), b.as_ref(), &[]);
            assert!(report.requested.is_empty(), "{:?}", report.requested);
            assert!(!report.has_over_ask());
            assert_eq!(report.verdict_line, "No claims requested.");

            // Unregistered type: one credential row beyond the registration.
            let report = analyze(
                PID_VCT,
                &q("urn:example:other:1"),
                Some(&registered),
                b.as_ref(),
                &[],
            );
            assert_eq!(report.requested.len(), 1);
            let v = &report.requested[0];
            assert_eq!(v.status, ClaimStatus::BeyondRegistration);
            assert_eq!(v.key, "card (credential, no claims)");
            assert_eq!(report.counts.beyond_purpose, 0);
            assert!(report.has_over_ask());

            // Without a registration there is nothing to judge.
            let report = analyze(PID_VCT, &q("urn:example:other:1"), None, b.as_ref(), &[]);
            assert!(report.requested.is_empty());
        }
    }

    #[test]
    fn empty_claim_combination_is_judged_by_type_like_no_claims() {
        // `claim_sets: [[]]` selects no claim, but the credential (and its
        // mandatory claims) is still presented: its type must be registered.
        let q = |vct: &str| {
            query_json(serde_json::json!({ "credentials": [{
                "id": "card", "format": "dc+sd-jwt", "meta": { "vct_values": [vct] },
                "claims": [{ "id": "n", "path": ["given_name"] }],
                "claim_sets": [[]],
            }]}))
        };
        let registered = scope("dc+sd-jwt", &[&["given_name"]]);
        let report = analyze(
            PID_VCT,
            &q("urn:example:other:1"),
            Some(&registered),
            None,
            &[],
        );
        assert_eq!(
            report.counts.beyond_registration, 1,
            "{:?}",
            report.requested
        );
        assert_eq!(report.requested[0].key, "card (credential, no claims)");
        assert!(report.has_over_ask());

        let report = analyze(PID_VCT, &q(PID_VCT), Some(&registered), None, &[]);
        assert!(report.requested.is_empty(), "{:?}", report.requested);
        assert!(!report.has_over_ask());
    }

    #[test]
    fn credential_sets_skip_credentials_no_option_names() {
        let q = |sets: serde_json::Value| {
            query_json(serde_json::json!({
                "credentials": [
                    { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": [PID_VCT] },
                      "claims": [{ "path": ["given_name"] }] },
                    { "id": "unused", "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:example:other:1"] } },
                    { "id": "extra", "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:example:other:1"] },
                      "claims": [{ "path": ["member_name"] }] },
                ],
                "credential_sets": sets,
            }))
        };
        let registered = scope("dc+sd-jwt", &[&["given_name"]]);
        let keys = |r: &OverAskReport| {
            r.requested
                .iter()
                .map(|v| v.key.clone())
                .collect::<Vec<_>>()
        };

        // Neither unused nor extra is in any option: never requested.
        let report = analyze(
            PID_VCT,
            &q(serde_json::json!([{ "options": [["pid"]] }])),
            Some(&registered),
            None,
            &[],
        );
        assert_eq!(keys(&report), ["given_name"]);
        assert!(!report.has_over_ask(), "{:?}", report.requested);

        // An optional set may still be satisfied, so its credentials count.
        let report = analyze(
            PID_VCT,
            &q(serde_json::json!([
                { "options": [["pid"]] },
                { "options": [["unused"], ["extra"]], "required": false },
            ])),
            Some(&registered),
            None,
            &[],
        );
        assert_eq!(
            keys(&report),
            [
                "given_name",
                "unused (credential, no claims)",
                "member_name"
            ]
        );
        assert_eq!(report.counts.beyond_registration, 2);

        // An option naming an unknown id: every credential is audited.
        let report = analyze(
            PID_VCT,
            &q(serde_json::json!([{ "options": [["pid", "zzz"]] }])),
            Some(&registered),
            None,
            &[],
        );
        assert_eq!(report.counts.beyond_registration, 2);
    }

    #[test]
    fn equal_invalid_mdoc_paths_are_beyond_registration() {
        let path = serde_json::json!(["org.example.ns1", null]);
        let registered = scope_json(serde_json::json!([{
            "format": "mso_mdoc", "meta": { "doctype_value": "org.example.d.1" },
            "claim": [{ "path": path }],
        }]));
        let query = query_json(serde_json::json!({ "credentials": [{
            "id": "m", "format": "mso_mdoc", "meta": { "doctype_value": "org.example.d.1" },
            "claims": [{ "path": path }],
        }]}));
        let report = analyze(PID_VCT, &query, Some(&registered), None, &[]);
        assert_eq!(
            report.counts.beyond_registration, 1,
            "{:?}",
            report.requested
        );
        assert_eq!(report.requested[0].rationale, INVALID_MDOC_PATH);
        assert!(report.has_over_ask());
    }

    #[test]
    fn unregistered_credential_type_names_the_type_in_the_rationale() {
        let registered = scope("dc+sd-jwt", &[&["given_name"]]);
        let query = query_json(serde_json::json!({ "credentials": [{
            "id": "x", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:example:other:1"] },
            "claims": [{ "path": ["given_name"] }],
        }]}));
        let report = analyze(PID_VCT, &query, Some(&registered), None, &[]);
        assert_eq!(
            status_of(&report, "given_name"),
            ClaimStatus::BeyondRegistration
        );
        assert!(report.requested[0].rationale.contains("format and type"));

        // Same type, unregistered path: the path rationale.
        let report = analyze(
            PID_VCT,
            &pid::pid_query(&[&["birthdate"]]),
            Some(&registered),
            None,
            &[],
        );
        assert_eq!(
            report.requested[0].rationale,
            "Not in the relying party's registered scope."
        );
    }

    #[test]
    fn registered_parent_covers_requested_child_only() {
        let registered = scope("dc+sd-jwt", &[&["address"]]);
        let report = analyze(
            PID_VCT,
            &pid::pid_query(&[&["address", "locality"]]),
            Some(&registered),
            None,
            &[],
        );
        assert_eq!(report.counts.beyond_registration, 0);

        let registered = scope("dc+sd-jwt", &[&["address", "locality"]]);
        let report = analyze(
            PID_VCT,
            &pid::pid_query(&[&["address"]]),
            Some(&registered),
            None,
            &[],
        );
        assert_eq!(report.counts.beyond_registration, 1);
    }

    #[test]
    fn rulebook_members_have_model_rows_and_labels() {
        let paths: &[&[&str]] = &[
            &["place_of_birth", "region"],
            &["place_of_birth", "country"],
            &["address", "region"],
            &["address", "formatted"],
            &["address", "house_number"],
        ];
        let report = analyze(
            PID_VCT,
            &pid::pid_query(paths),
            None,
            baseline("bank_kyc").as_ref(),
            &[],
        );
        for (path, label) in paths.iter().zip([
            "Place of birth (region)",
            "Place of birth (country)",
            "Resident state",
            "Resident address",
            "Resident house number",
        ]) {
            let key = path.join(".");
            let row = report
                .claim_rows
                .iter()
                .find(|r| r.key == key)
                .unwrap_or_else(|| panic!("no model row for {key}"));
            assert!(row.requested, "{key}");
            assert_eq!(row.label, label);
            assert!(row.correlatable);
            let v = report
                .requested
                .iter()
                .find(|v| v.key == key)
                .expect("verdict");
            assert_eq!(v.label, label);
            assert_eq!(v.status, ClaimStatus::MinimalForPurpose);
        }
        assert_eq!(report.counts.correlatable_requested, 5);
    }
}
