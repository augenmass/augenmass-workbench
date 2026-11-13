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
        // Verbatim from ARF Annex 2.02, Topic 44, requirement RPRC_21.
        text: "After receiving a presentation request from a Relying Party, a Wallet Unit SHALL verify that all attributes requested in the request are included in the list of attributes in the registration certificate included in the same request. If the outcome of the verification is negative, the Wallet Unit SHALL, when asking for User approval according to RPA_07, warn the User that the Relying Party is requesting more information than it has registered. In addition, the Wallet Provider SHALL determine, based on its risk analysis and security policy, whether the Wallet Unit must a) enable the User to approve (or reject) the presentation of all requested attributes, including the non-registered ones, b) enable the User to approve (or reject) the presentation of the registered attributes only, or c) reject the presentation of all requested attributes.",
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
    /// The selected purpose's baseline model keys, when known. These are
    /// baseline model keys, not request paths; see `suggested_minimal_request`.
    pub suggested_minimal: Option<Vec<String>>,
    /// The curated minimal request in the spelling of each requested
    /// credential type, when a baseline is known ([`suggested_request`]).
    pub suggested_minimal_request: Option<Vec<SuggestedCredential>>,
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

/// The national namespace of the German PID mdoc (German PID Rulebook,
/// section "Additional national attributes of German PID"), which carries the
/// German specific elements such as `age_over_NN`. The German mdoc PID uses
/// the doctype [`PID_MDOC_NAMESPACE`] with this second namespace.
pub const PID_DE_MDOC_NAMESPACE: &str = "eu.europa.ec.eudi.pid.de.1";

/// The SD-JWT model key `age_equal_or_over.NN` for an mdoc element
/// `age_over_NN`, where `NN` is one or more ASCII digits and nothing else
/// (German PID Rulebook mapping table: `age_over_NN` to
/// `age_equal_or_over.NN`).
fn mdoc_age_over_key(element: &str) -> Option<String> {
    let digits = element.strip_prefix("age_over_")?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(format!("age_equal_or_over.{digits}"))
}

/// The claim-model key a requested claim path is judged under for purpose, or
/// `None` when an `mso_mdoc` path has no claim-model key.
///
/// The mapping is format-aware: a spelling is mapped only in the credential
/// format it belongs to (EU PID Rulebook, Annex 3.01, sections 3.1.2 and 4.1.1;
/// the German PID Rulebook agrees).
///
/// The SD-JWT VC formats (`dc+sd-jwt` and the earlier identifier `vc+sd-jwt`)
/// return the dotted path unchanged (or `None` when a segment itself contains
/// a dot, so a joined spelling never borrows a nested key), except these
/// SD-JWT spellings:
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
/// An `mso_mdoc` path maps only when it has exactly two segments,
/// `[namespace, element]`, and either:
///
/// - the namespace is [`PID_MDOC_NAMESPACE`] or [`PID_DE_MDOC_NAMESPACE`] and
///   the element is `age_over_NN` (`NN` one or more ASCII digits), which maps
///   to `age_equal_or_over.NN`, the key its SD-JWT counterpart is judged
///   under (German PID Rulebook mapping table; the element is in the German
///   namespace there); or
/// - the namespace is [`PID_MDOC_NAMESPACE`] and the element is one of:
///   - `given_name`, `family_name` (same name);
///   - `birth_date` to `birthdate`, `nationality` to `nationalities`;
///   - `resident_street`, `resident_city`, `resident_postal_code`,
///     `resident_country` to `address.resident_*`; `resident_state` to
///     `address.region`; `resident_address` to `address.formatted`;
///   - the legacy text element `birth_place` (one string, as the EUDIPLO PID
///     mdoc issues it) to `place_of_birth.locality`.
///
/// Every other format (`jwt_vc_json`, `ldp_vc`, or an unknown identifier)
/// returns `None`: the purpose baselines do not model its claim paths, so it
/// never borrows the SD-JWT VC spelling.
///
/// Every other mdoc path (for example the Rulebook structured `place_of_birth`,
/// which discloses the whole place structure, any other element of the German
/// namespace, an element of another namespace, or a three-segment path)
/// returns `None`: it is judged only against
/// [`PurposeBaseline::mdoc_elements`], never against a model key, so an mdoc
/// path cannot borrow an SD-JWT spelling. This mapping is for purpose
/// evaluation and the model lookup only; registration compares the typed
/// requested path ([`crate::regcert::path_covers`]) and over-disclosure the
/// raw path, so an alias never authorizes another path.
pub fn canonical_claim_key(format: &ClaimFormatDesignation, path: &[String]) -> Option<String> {
    let raw = path.join(".");
    if is_sd_jwt_vc_format(format) {
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
    if *format != ClaimFormatDesignation::MsoMDoc {
        return None;
    }
    let [namespace, element] = path else {
        return None;
    };
    if namespace == PID_MDOC_NAMESPACE || namespace == PID_DE_MDOC_NAMESPACE {
        if let Some(key) = mdoc_age_over_key(element) {
            return Some(key);
        }
    }
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

/// The SD-JWT VC format identifiers: `dc+sd-jwt` (OpenID4VP 1.0 appendix
/// B.3) and the earlier `vc+sd-jwt`, which `check` accepts as well.
const SD_JWT_VC_FORMATS: &[&str] = &["dc+sd-jwt", "vc+sd-jwt"];

fn is_sd_jwt_vc_format(format: &ClaimFormatDesignation) -> bool {
    SD_JWT_VC_FORMATS.contains(&format.to_string().as_str())
}

/// True when the purpose baselines model the claim paths of this format: the
/// SD-JWT VC formats and `mso_mdoc`.
fn purpose_models_format(format: &str) -> bool {
    SD_JWT_VC_FORMATS.contains(&format) || format == "mso_mdoc"
}

/// SD-JWT array claims whose element selectors (`null` for every element, an
/// integer index for one) select within the array the model key names.
const SD_JWT_ARRAY_CLAIMS: &[&str] = &["nationalities"];

/// The path purpose is judged under: an SD-JWT element selector of a known
/// array claim (`["nationalities", null]`, `["nationalities", 0]`) is judged as
/// the array itself; every other path is its dotted segments. A path with any
/// other integer segment has none (`None`): an integer selects an array
/// element (OpenID4VP 1.0 section 7), so `["age_equal_or_over", 18]` must not
/// be judged as the member `"18"` of the age object.
fn purpose_path(format: &ClaimFormatDesignation, segs: &[Seg]) -> Option<Vec<String>> {
    if is_sd_jwt_vc_format(format) {
        if let [Seg::String(parent), Seg::Null | Seg::Integer(_)] = segs {
            if SD_JWT_ARRAY_CLAIMS.contains(&parent.as_str()) {
                return Some(vec![parent.clone()]);
            }
        }
    }
    segs.iter()
        .map(|s| match s {
            Seg::Integer(_) => None,
            _ => Some(seg_key(s)),
        })
        .collect()
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
                model_key: purpose_path(cred.format(), segs)
                    .and_then(|path| canonical_claim_key(cred.format(), &path)),
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

/// Rationale for a claim of a credential format the purpose baselines do not
/// model: the purpose verdict fails closed instead of borrowing the SD-JWT VC
/// spelling.
const UNMODELLED_FORMAT: &str = "Purpose not judged for this credential format: the purpose baselines model only SD-JWT VC (dc+sd-jwt, vc+sd-jwt) and mso_mdoc claim paths, so the claim counts as beyond the purpose.";

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
                    _ if !purpose_models_format(&cred.format) => UNMODELLED_FORMAT,
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
        suggested_minimal_request: baseline.map(|b| suggested_request(b, query)),
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

// --- suggested minimal request in the request's own spelling ----------------

/// The SD-JWT VC type of the EU PID (EU PID Rulebook, section 4.2, "the base
/// type to be \"urn:eudi:pid:1\"").
pub const EU_PID_VCT: &str = "urn:eudi:pid:1";

/// The age groups of the German PID (German PID Rulebook, additional national
/// attributes: "Age groups are 12, 13, 14, 16, 18, 21 and 65").
pub const DE_PID_AGE_GROUPS: [&str; 7] = ["12", "13", "14", "16", "18", "21", "65"];

/// Profile mark for a PID mdoc element that only the German PID carries.
pub const GERMAN_PID_ONLY: &str = "German PID only";

/// Profile mark for a PID mdoc element that the German PID does not carry.
pub const NOT_IN_GERMAN_PID: &str = "not in the German PID";

/// One path of a suggested minimal request, spelled for the requested
/// credential's format: SD-JWT claim path segments, or `[namespace, element]`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SuggestedPath {
    pub path: Vec<String>,
    /// [`GERMAN_PID_ONLY`] or [`NOT_IN_GERMAN_PID`] when the PID mdoc doctype
    /// is shared by two profiles and only one carries the element.
    pub profile_note: Option<String>,
}

/// The suggested minimal request for one requested credential type.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SuggestedCredential {
    /// The id of the first selected credential query of this format and type.
    pub credential_id: String,
    pub format: String,
    /// `meta.vct_values` (SD-JWT VC) or `[meta.doctype_value]` (mdoc).
    pub types: Vec<String>,
    /// True when a spelling table is known for this format and type.
    pub known_type: bool,
    /// The baseline claims spelled for this type, in baseline order.
    pub paths: Vec<SuggestedPath>,
    /// Labels of baseline claims with no known spelling for this type (for an
    /// unknown type: every baseline claim).
    pub not_suggested: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SpellingTable {
    /// German PID, SD-JWT VC (`dc+sd-jwt`, vct `urn:eudi:pid:de:1`).
    GermanSdJwt,
    /// EU PID, SD-JWT VC (`dc+sd-jwt`, vct `urn:eudi:pid:1`).
    EuSdJwt,
    /// PID mdoc (doctype `eu.europa.ec.eudi.pid.1`, shared by the EU PID and
    /// the German PID).
    PidMdoc,
}

fn spelling_table(format: &str, types: &[String]) -> Option<SpellingTable> {
    let all = |t: &str| !types.is_empty() && types.iter().all(|x| x == t);
    if format == crate::pid::PID_FORMAT && all(crate::PID_VCT) {
        Some(SpellingTable::GermanSdJwt)
    } else if format == crate::pid::PID_FORMAT && all(EU_PID_VCT) {
        Some(SpellingTable::EuSdJwt)
    } else if format == regcert::FORMAT_MSO_MDOC && all(PID_MDOC_NAMESPACE) {
        Some(SpellingTable::PidMdoc)
    } else {
        None
    }
}

type Spelling = (
    &'static str,
    Option<&'static [&'static str]>,
    Option<&'static [&'static str]>,
    Option<(&'static str, Option<&'static str>)>,
);

/// Baseline model key, German PID SD-JWT path, EU PID SD-JWT path, and PID
/// mdoc element in the namespace [`PID_MDOC_NAMESPACE`] with its profile mark.
/// Sources: German PID Rulebook (mapping table; `place_of_birth` "Just
/// locality is present"; `resident_address` "not included in the German
/// PID"), BMI developer guide (`resident_house_number` not available in the
/// German PID), EU PID Rulebook sections 3.1.2 and 4.1.1.
const SPELLINGS: &[Spelling] = &[
    (
        "given_name",
        Some(&["given_name"]),
        Some(&["given_name"]),
        Some(("given_name", None)),
    ),
    (
        "family_name",
        Some(&["family_name"]),
        Some(&["family_name"]),
        Some(("family_name", None)),
    ),
    (
        "birthdate",
        Some(&["birthdate"]),
        Some(&["birthdate"]),
        Some(("birth_date", None)),
    ),
    (
        "place_of_birth.locality",
        Some(&["place_of_birth", "locality"]),
        Some(&["place_of_birth", "locality"]),
        Some(("place_of_birth", None)),
    ),
    (
        "place_of_birth.region",
        None,
        Some(&["place_of_birth", "region"]),
        Some(("place_of_birth", None)),
    ),
    (
        "place_of_birth.country",
        None,
        Some(&["place_of_birth", "country"]),
        Some(("place_of_birth", None)),
    ),
    (
        "nationalities",
        Some(&["nationalities"]),
        Some(&["nationalities"]),
        Some(("nationality", None)),
    ),
    (
        "address.resident_street",
        Some(&["address", "street_address"]),
        Some(&["address", "street_address"]),
        Some(("resident_street", None)),
    ),
    (
        "address.house_number",
        None,
        Some(&["address", "house_number"]),
        None,
    ),
    (
        "address.resident_city",
        Some(&["address", "locality"]),
        Some(&["address", "locality"]),
        Some(("resident_city", None)),
    ),
    (
        "address.resident_postal_code",
        Some(&["address", "postal_code"]),
        Some(&["address", "postal_code"]),
        Some(("resident_postal_code", None)),
    ),
    (
        "address.region",
        Some(&["address", "region"]),
        Some(&["address", "region"]),
        Some(("resident_state", None)),
    ),
    (
        "address.resident_country",
        Some(&["address", "country"]),
        Some(&["address", "country"]),
        Some(("resident_country", None)),
    ),
    (
        "address.formatted",
        None,
        Some(&["address", "formatted"]),
        Some(("resident_address", Some(NOT_IN_GERMAN_PID))),
    ),
];

fn owned(segs: &[&str]) -> Vec<String> {
    segs.iter().map(|s| s.to_string()).collect()
}

/// The path a baseline model key is spelled as in `table`, or `None` when the
/// type carries no such claim (or none is known).
fn spelled(table: SpellingTable, key: &str) -> Option<SuggestedPath> {
    let plain = |path: Vec<String>| SuggestedPath {
        path,
        profile_note: None,
    };
    if let Some(nn) = key.strip_prefix("age_equal_or_over.") {
        if !DE_PID_AGE_GROUPS.contains(&nn) {
            return None;
        }
        return match table {
            SpellingTable::GermanSdJwt => Some(plain(owned(&["age_equal_or_over", nn]))),
            // The EU PID Rulebook names no age attribute.
            SpellingTable::EuSdJwt => None,
            SpellingTable::PidMdoc => Some(SuggestedPath {
                path: vec![PID_DE_MDOC_NAMESPACE.to_string(), format!("age_over_{nn}")],
                profile_note: Some(GERMAN_PID_ONLY.to_string()),
            }),
        };
    }
    let (_, german, eu, mdoc) = SPELLINGS.iter().find(|(k, ..)| *k == key)?;
    match table {
        SpellingTable::GermanSdJwt => german.map(|p| plain(owned(p))),
        SpellingTable::EuSdJwt => eu.map(|p| plain(owned(p))),
        SpellingTable::PidMdoc => mdoc.map(|(element, note)| SuggestedPath {
            path: owned(&[PID_MDOC_NAMESPACE, element]),
            profile_note: note.map(str::to_string),
        }),
    }
}

/// The label a baseline claim is listed under when it is not spelled: the
/// claim-model label, or the mdoc element label.
fn baseline_label(model: &HashMap<String, String>, key: &str) -> String {
    model.get(key).cloned().unwrap_or_else(|| key.to_string())
}

/// The curated minimal request of `baseline`, spelled for each selected
/// requested credential type of `query` (OpenID4VP 1.0 section 6.4.2
/// selection, as [`analyze`] uses it): one entry per distinct format and type,
/// in request order. A known type (German PID SD-JWT, EU PID SD-JWT, PID mdoc)
/// gets paths in its own spelling and the labels of baseline claims it has no
/// spelling for; any other type gets no paths and every baseline label, so no
/// internal model key is ever offered as a path.
pub fn suggested_request(
    baseline: &PurposeBaseline,
    query: &DcqlQuery,
) -> Vec<SuggestedCredential> {
    let model: HashMap<String, String> = pid_claim_model()
        .into_iter()
        .map(|c| (c.key(), c.label))
        .collect();
    let creds = requested_credentials(query);
    let selected = selected_credentials(query);
    let mut out: Vec<SuggestedCredential> = Vec::new();
    for (index, cred) in query.credentials().iter().enumerate() {
        if !selected[index] {
            continue;
        }
        let RequestedCredential { format, types } = &creds[index];
        if out.iter().any(|s| &s.format == format && &s.types == types) {
            continue;
        }
        let table = spelling_table(format, types);
        let mut paths: Vec<SuggestedPath> = Vec::new();
        let mut not_suggested: Vec<String> = Vec::new();
        let push_label = |label: String, list: &mut Vec<String>| {
            if !list.contains(&label) {
                list.push(label);
            }
        };
        for key in &baseline.minimal_keys {
            match table.and_then(|t| spelled(t, key)) {
                Some(p) => {
                    if !paths.contains(&p) {
                        paths.push(p);
                    }
                }
                None => push_label(baseline_label(&model, key), &mut not_suggested),
            }
        }
        for element in &baseline.mdoc_elements {
            match table {
                Some(SpellingTable::PidMdoc) => {
                    let p = SuggestedPath {
                        path: element.to_vec(),
                        profile_note: None,
                    };
                    if !paths.contains(&p) {
                        paths.push(p);
                    }
                }
                // The SD-JWT tables spell the same claims from the model keys.
                Some(_) => {}
                None => {
                    let label = mdoc_element_meta(element)
                        .map(|(l, _)| l.to_string())
                        .unwrap_or_else(|| element.join("/"));
                    push_label(label, &mut not_suggested);
                }
            }
        }
        out.push(SuggestedCredential {
            credential_id: cred.id().to_string(),
            format: format.clone(),
            types: types.clone(),
            known_type: table.is_some(),
            paths,
            not_suggested,
        });
    }
    out
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
        // The age element maps to its SD-JWT key in both PID namespaces.
        for (segs, expected) in [
            (
                p(&[PID_MDOC_NAMESPACE, "age_over_18"]),
                "age_equal_or_over.18",
            ),
            (
                p(&[PID_DE_MDOC_NAMESPACE, "age_over_18"]),
                "age_equal_or_over.18",
            ),
            (
                p(&[PID_DE_MDOC_NAMESPACE, "age_over_21"]),
                "age_equal_or_over.21",
            ),
        ] {
            assert_eq!(
                canonical_claim_key(&mdoc, &segs).as_deref(),
                Some(expected),
                "{segs:?}"
            );
        }
        // No model key for any other mdoc path: unknown elements, the
        // structured place_of_birth, SD-JWT spellings, other namespaces (even
        // when the dotted key equals a model key), other shapes, other
        // elements of the German namespace, and near misses of the age
        // element.
        for segs in [
            p(&[PID_DE_MDOC_NAMESPACE, "given_name"]),
            p(&[PID_DE_MDOC_NAMESPACE, "age_over_"]),
            p(&[PID_DE_MDOC_NAMESPACE, "age_over_x"]),
            p(&[PID_DE_MDOC_NAMESPACE, "age_over_18a"]),
            p(&[PID_MDOC_NAMESPACE, "age_over_18a"]),
            p(&[PID_DE_MDOC_NAMESPACE, "age_over_\u{ff11}\u{ff18}"]),
            p(&[PID_DE_MDOC_NAMESPACE, "age_over_\u{0661}\u{0668}"]),
            p(&[PID_DE_MDOC_NAMESPACE, "age_over_18", "x"]),
            p(&[PID_DE_MDOC_NAMESPACE]),
            p(&["eu.europa.ec.eudi.pid.de", "1.age_over_18"]),
            p(&["org.iso.18013.5.1", "age_over_18"]),
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

    // --- mdoc age_over_NN: the SD-JWT verdict in both PID namespaces --------

    const PURPOSES: [&str; 4] = ["age_gate_18", "event_checkin", "car_rental", "bank_kyc"];
    /// The German PID age groups (German PID Rulebook, national attributes).
    const AGE_GROUPS: [&str; 7] = ["12", "13", "14", "16", "18", "21", "65"];

    /// An `mso_mdoc` credential query with the given `meta` and raw paths.
    fn mdoc_query_with_meta(meta: serde_json::Value, paths: &[serde_json::Value]) -> DcqlQuery {
        let mut credential = serde_json::json!({
            "id": "pid-mdoc",
            "format": "mso_mdoc",
            "claims": paths.iter().map(|p| serde_json::json!({ "path": p })).collect::<Vec<_>>(),
        });
        if !meta.is_null() {
            credential["meta"] = meta;
        }
        query_json(serde_json::json!({ "credentials": [credential] }))
    }

    #[test]
    fn mdoc_age_over_matches_sd_jwt_age_in_both_pid_namespaces() {
        for purpose in PURPOSES {
            for nn in AGE_GROUPS {
                let sd_jwt = single_status(
                    "dc+sd-jwt",
                    serde_json::json!(["age_equal_or_over", nn]),
                    purpose,
                );
                for ns in [PID_MDOC_NAMESPACE, PID_DE_MDOC_NAMESPACE] {
                    let element = format!("age_over_{nn}");
                    let mdoc = single_status("mso_mdoc", serde_json::json!([ns, element]), purpose);
                    assert_eq!(mdoc, sd_jwt, "{purpose} {ns} {element}");
                }
            }
        }
    }

    #[test]
    fn mdoc_age_over_fixed_cases() {
        // The verdicts 0.4.0 got wrong: BeyondPurpose for the mdoc element
        // while the SD-JWT claim was minimal.
        for (ns, element, purpose) in [
            (PID_MDOC_NAMESPACE, "age_over_18", "age_gate_18"),
            (PID_DE_MDOC_NAMESPACE, "age_over_18", "age_gate_18"),
            (PID_MDOC_NAMESPACE, "age_over_18", "event_checkin"),
            (PID_DE_MDOC_NAMESPACE, "age_over_18", "event_checkin"),
            (PID_MDOC_NAMESPACE, "age_over_21", "car_rental"),
            (PID_DE_MDOC_NAMESPACE, "age_over_21", "car_rental"),
        ] {
            let query = json_paths_query("mso_mdoc", &[serde_json::json!([ns, element])]);
            let report = analyze(PID_VCT, &query, None, baseline(purpose).as_ref(), &[]);
            let v = &report.requested[0];
            assert_eq!(
                v.status,
                ClaimStatus::MinimalForPurpose,
                "{purpose} {ns} {element}"
            );
            assert!(!report.has_over_ask(), "{purpose} {ns} {element}");
            assert_eq!(v.key, format!("{ns}.{element}"));
            assert_eq!(
                v.label,
                format!("Age over {}", &element["age_over_".len()..])
            );
            let row = report
                .claim_rows
                .iter()
                .find(|r| r.key == format!("age_equal_or_over.{}", &element["age_over_".len()..]))
                .expect("age row");
            assert!(row.requested);
        }
    }

    #[test]
    fn mdoc_age_over_non_string_segments_are_not_age() {
        for path in [
            serde_json::json!([PID_DE_MDOC_NAMESPACE, 18]),
            serde_json::json!([PID_DE_MDOC_NAMESPACE, null]),
        ] {
            assert_eq!(
                single_status("mso_mdoc", path.clone(), "age_gate_18"),
                ClaimStatus::BeyondPurpose,
                "{path}"
            );
        }
    }

    #[test]
    fn mdoc_age_over_with_birth_date_is_still_over_ask() {
        let query = json_paths_query(
            "mso_mdoc",
            &[
                serde_json::json!([PID_DE_MDOC_NAMESPACE, "age_over_18"]),
                serde_json::json!([PID_MDOC_NAMESPACE, "birth_date"]),
            ],
        );
        let report = analyze(PID_VCT, &query, None, baseline("age_gate_18").as_ref(), &[]);
        assert_eq!(
            status_of(&report, "eu.europa.ec.eudi.pid.de.1.age_over_18"),
            ClaimStatus::MinimalForPurpose
        );
        assert_eq!(
            status_of(&report, "eu.europa.ec.eudi.pid.1.birth_date"),
            ClaimStatus::BeyondPurpose
        );
        assert!(report.has_over_ask());
    }

    #[test]
    fn mdoc_age_alias_does_not_widen_registration() {
        let mdoc_scope = |ns: &str| {
            scope_json(serde_json::json!([{
                "format": "mso_mdoc", "meta": { "doctype_value": PID_MDOC_NAMESPACE },
                "claim": [{ "path": [ns, "age_over_18"] }],
            }]))
        };
        // (a) Registered in the German namespace, requested in the EU one;
        // (c) the converse.
        for (registered_ns, requested_ns) in [
            (PID_DE_MDOC_NAMESPACE, PID_MDOC_NAMESPACE),
            (PID_MDOC_NAMESPACE, PID_DE_MDOC_NAMESPACE),
        ] {
            let registered = mdoc_scope(registered_ns);
            let query = json_paths_query(
                "mso_mdoc",
                &[serde_json::json!([requested_ns, "age_over_18"])],
            );
            let report = analyze(
                PID_VCT,
                &query,
                Some(&registered),
                baseline("age_gate_18").as_ref(),
                &[],
            );
            assert_eq!(
                report.requested[0].status,
                ClaimStatus::BeyondRegistration,
                "registered {registered_ns}, requested {requested_ns}"
            );
            // The same namespace is covered.
            let query = json_paths_query(
                "mso_mdoc",
                &[serde_json::json!([registered_ns, "age_over_18"])],
            );
            let report = analyze(
                PID_VCT,
                &query,
                Some(&registered),
                baseline("age_gate_18").as_ref(),
                &[],
            );
            assert!(!report.has_over_ask(), "{:?}", report.requested);
        }
        // (b) Registered only as the SD-JWT claim: the mdoc element is outside.
        let registered = scope("dc+sd-jwt", &[&["age_equal_or_over", "18"]]);
        let query = json_paths_query(
            "mso_mdoc",
            &[serde_json::json!([PID_DE_MDOC_NAMESPACE, "age_over_18"])],
        );
        let report = analyze(
            PID_VCT,
            &query,
            Some(&registered),
            baseline("age_gate_18").as_ref(),
            &[],
        );
        assert_eq!(report.requested[0].status, ClaimStatus::BeyondRegistration);
    }

    #[test]
    fn mdoc_age_over_purpose_verdict_does_not_consult_doctype() {
        // Purpose verdicts take format and path only, as for every other key
        // in 0.4.0; the credential type is checked by registration coverage.
        let path = [serde_json::json!([PID_DE_MDOC_NAMESPACE, "age_over_18"])];
        let pid = mdoc_query_with_meta(
            serde_json::json!({ "doctype_value": PID_MDOC_NAMESPACE }),
            &path,
        );
        let mdl = mdoc_query_with_meta(
            serde_json::json!({ "doctype_value": "org.iso.18013.5.1.mDL" }),
            &path,
        );
        let untyped = mdoc_query_with_meta(serde_json::Value::Null, &path);
        for query in [&pid, &mdl, &untyped] {
            let report = analyze(PID_VCT, query, None, baseline("age_gate_18").as_ref(), &[]);
            assert_eq!(report.requested[0].status, ClaimStatus::MinimalForPurpose);
        }
        let registered = scope_json(serde_json::json!([{
            "format": "mso_mdoc", "meta": { "doctype_value": PID_MDOC_NAMESPACE },
            "claim": [{ "path": [PID_DE_MDOC_NAMESPACE, "age_over_18"] }],
        }]));
        let report = analyze(
            PID_VCT,
            &pid,
            Some(&registered),
            baseline("age_gate_18").as_ref(),
            &[],
        );
        assert!(!report.has_over_ask(), "{:?}", report.requested);
        for query in [&mdl, &untyped] {
            let report = analyze(
                PID_VCT,
                query,
                Some(&registered),
                baseline("age_gate_18").as_ref(),
                &[],
            );
            assert_eq!(report.requested[0].status, ClaimStatus::BeyondRegistration);
        }
    }

    // --- suggested minimal request in the request's spelling ---------------

    fn typed_query(format: &str, meta: serde_json::Value, path: serde_json::Value) -> DcqlQuery {
        query_json(serde_json::json!({ "credentials": [{
            "id": "req", "format": format, "meta": meta, "claims": [{ "path": path }],
        }]}))
    }

    fn suggestion(purpose: &str, query: &DcqlQuery) -> Vec<SuggestedCredential> {
        let report = analyze(PID_VCT, query, None, baseline(purpose).as_ref(), &[]);
        report.suggested_minimal_request.expect("baseline known")
    }

    fn paths_of(s: &SuggestedCredential) -> Vec<Vec<String>> {
        s.paths.iter().map(|p| p.path.clone()).collect()
    }

    fn p(segs: &[&str]) -> Vec<String> {
        segs.iter().map(|s| s.to_string()).collect()
    }

    const UNSPELLED_GERMAN_SD_JWT: [&str; 4] = [
        "Place of birth (region)",
        "Place of birth (country)",
        "Resident house number",
        "Resident address",
    ];

    #[test]
    fn german_sd_jwt_suggestion_uses_german_claim_paths() {
        let s = suggestion("bank_kyc", &pid::pid_query(&[&["given_name"]]));
        assert_eq!(s.len(), 1);
        let s = &s[0];
        assert!(s.known_type);
        assert_eq!(
            (s.format.as_str(), s.types.clone()),
            ("dc+sd-jwt", vec![PID_VCT.to_string()])
        );
        assert_eq!(
            paths_of(s),
            [
                p(&["given_name"]),
                p(&["family_name"]),
                p(&["birthdate"]),
                p(&["place_of_birth", "locality"]),
                p(&["nationalities"]),
                p(&["address", "street_address"]),
                p(&["address", "locality"]),
                p(&["address", "postal_code"]),
                p(&["address", "region"]),
                p(&["address", "country"]),
            ]
        );
        assert!(s.paths.iter().all(|p| p.profile_note.is_none()));
        assert_eq!(s.not_suggested, UNSPELLED_GERMAN_SD_JWT);

        let s = &suggestion("age_gate_18", &pid::pid_query(&[&["birthdate"]]))[0];
        assert_eq!(paths_of(s), [p(&["age_equal_or_over", "18"])]);
        assert!(s.not_suggested.is_empty());
    }

    const PID_MDOC_BANK_KYC: &[(&str, &str, Option<&str>)] = &[
        (PID_MDOC_NAMESPACE, "given_name", None),
        (PID_MDOC_NAMESPACE, "family_name", None),
        (PID_MDOC_NAMESPACE, "birth_date", None),
        (PID_MDOC_NAMESPACE, "place_of_birth", None),
        (PID_MDOC_NAMESPACE, "nationality", None),
        (PID_MDOC_NAMESPACE, "resident_street", None),
        (PID_MDOC_NAMESPACE, "resident_city", None),
        (PID_MDOC_NAMESPACE, "resident_postal_code", None),
        (PID_MDOC_NAMESPACE, "resident_state", None),
        (PID_MDOC_NAMESPACE, "resident_country", None),
        (
            PID_MDOC_NAMESPACE,
            "resident_address",
            Some(NOT_IN_GERMAN_PID),
        ),
    ];

    fn assert_pid_mdoc_bank_kyc(s: &SuggestedCredential) {
        assert!(s.known_type);
        let got: Vec<(Vec<String>, Option<String>)> = s
            .paths
            .iter()
            .map(|p| (p.path.clone(), p.profile_note.clone()))
            .collect();
        let want: Vec<(Vec<String>, Option<String>)> = PID_MDOC_BANK_KYC
            .iter()
            .map(|(ns, e, note)| (p(&[ns, e]), note.map(str::to_string)))
            .collect();
        assert_eq!(got, want);
        assert_eq!(s.not_suggested, ["Resident house number"]);
    }

    #[test]
    fn pid_mdoc_suggestion_uses_elements_and_marks_profile_members() {
        let s = suggestion("bank_kyc", &mdoc_pid_query(&["given_name"]));
        assert_pid_mdoc_bank_kyc(&s[0]);

        // A German style request does not change the suggestion: the request
        // does not show which PID profile the wallet holds.
        let query = json_paths_query(
            "mso_mdoc",
            &[
                serde_json::json!([PID_MDOC_NAMESPACE, "given_name"]),
                serde_json::json!([PID_DE_MDOC_NAMESPACE, "age_over_18"]),
            ],
        );
        assert_pid_mdoc_bank_kyc(&suggestion("bank_kyc", &query)[0]);

        let s = &suggestion("age_gate_18", &mdoc_pid_query(&["age_over_18"]))[0];
        assert_eq!(
            s.paths,
            [SuggestedPath {
                path: p(&[PID_DE_MDOC_NAMESPACE, "age_over_18"]),
                profile_note: Some(GERMAN_PID_ONLY.to_string()),
            }]
        );
        assert!(s.not_suggested.is_empty());
    }

    #[test]
    fn eu_sd_jwt_suggestion_spells_every_bank_kyc_claim() {
        let query = typed_query(
            "dc+sd-jwt",
            serde_json::json!({ "vct_values": [EU_PID_VCT] }),
            serde_json::json!(["given_name"]),
        );
        let s = &suggestion("bank_kyc", &query)[0];
        assert!(s.known_type);
        assert_eq!(s.paths.len(), 14);
        assert!(s.not_suggested.is_empty());
        assert!(paths_of(s).contains(&p(&["address", "house_number"])));
        assert!(paths_of(s).contains(&p(&["place_of_birth", "region"])));
        // The EU PID names no age claim.
        let s = &suggestion("age_gate_18", &query)[0];
        assert!(s.paths.is_empty());
        assert_eq!(s.not_suggested, ["Age over 18"]);
    }

    #[test]
    fn unknown_type_suggestion_names_labels_only() {
        for (format, meta) in [
            (
                "dc+sd-jwt",
                serde_json::json!({ "vct_values": ["urn:example:membership:1"] }),
            ),
            (
                "jwt_vc_json",
                serde_json::json!({ "vct_values": [PID_VCT] }),
            ),
            ("vc+sd-jwt", serde_json::json!({ "vct_values": [PID_VCT] })),
            (
                "dc+sd-jwt",
                serde_json::json!({ "vct_values": [PID_VCT, EU_PID_VCT] }),
            ),
            (
                "mso_mdoc",
                serde_json::json!({ "doctype_value": "org.iso.18013.5.1.mDL" }),
            ),
        ] {
            let query = typed_query(format, meta.clone(), serde_json::json!(["x"]));
            let s = &suggestion("age_gate_18", &query)[0];
            assert!(!s.known_type, "{format} {meta}");
            assert!(s.paths.is_empty(), "{format} {meta}");
            assert_eq!(s.not_suggested, ["Age over 18"], "{format} {meta}");
            let s = &suggestion("bank_kyc", &query)[0];
            assert!(s.paths.is_empty());
            // The mdoc place_of_birth element shares the label of the
            // locality key and is listed once.
            assert_eq!(s.not_suggested.len(), 14, "{:?}", s.not_suggested);
            assert!(
                s.not_suggested.iter().all(|l| !l.contains('.')),
                "{:?}",
                s.not_suggested
            );
        }
    }

    #[test]
    fn suggestion_has_one_block_per_selected_type_in_request_order() {
        let query = query_json(serde_json::json!({
            "credentials": [
                { "id": "sd", "format": "dc+sd-jwt", "meta": { "vct_values": [PID_VCT] },
                  "claims": [{ "path": ["given_name"] }] },
                { "id": "md", "format": "mso_mdoc", "meta": { "doctype_value": PID_MDOC_NAMESPACE },
                  "claims": [{ "path": [PID_MDOC_NAMESPACE, "given_name"] }] },
                { "id": "sd2", "format": "dc+sd-jwt", "meta": { "vct_values": [PID_VCT] },
                  "claims": [{ "path": ["family_name"] }] },
            ],
        }));
        let s = suggestion("age_gate_18", &query);
        let ids: Vec<&str> = s.iter().map(|b| b.credential_id.as_str()).collect();
        assert_eq!(ids, ["sd", "md"]);
        assert_eq!(s[0].format, "dc+sd-jwt");
        assert_eq!(s[1].format, "mso_mdoc");

        // A credential query that no option names gives no block.
        let mut value = serde_json::json!({
            "credentials": [
                { "id": "sd", "format": "dc+sd-jwt", "meta": { "vct_values": [PID_VCT] },
                  "claims": [{ "path": ["given_name"] }] },
                { "id": "md", "format": "mso_mdoc", "meta": { "doctype_value": PID_MDOC_NAMESPACE },
                  "claims": [{ "path": [PID_MDOC_NAMESPACE, "given_name"] }] },
            ],
        });
        value["credential_sets"] = serde_json::json!([{ "options": [["md"]] }]);
        let s = suggestion("age_gate_18", &query_json(value));
        let ids: Vec<&str> = s.iter().map(|b| b.credential_id.as_str()).collect();
        assert_eq!(ids, ["md"]);

        // No baseline, no suggestion.
        let report = analyze(PID_VCT, &query, None, None, &[]);
        assert!(report.suggested_minimal_request.is_none());
    }

    #[test]
    fn suggested_paths_never_use_internal_model_keys() {
        let internal = [
            "address.resident_street",
            "address.resident_city",
            "address.resident_postal_code",
            "address.resident_country",
        ];
        let queries = [
            pid::pid_query(&[&["given_name"]]),
            mdoc_pid_query(&["given_name"]),
            typed_query(
                "dc+sd-jwt",
                serde_json::json!({ "vct_values": [EU_PID_VCT] }),
                serde_json::json!(["given_name"]),
            ),
        ];
        for purpose in PURPOSES {
            for query in &queries {
                for block in suggestion(purpose, query) {
                    for sp in &block.paths {
                        let dotted = sp.path.join(".");
                        assert!(!internal.contains(&dotted.as_str()), "{purpose}: {dotted}");
                        assert!(
                            !sp.path
                                .iter()
                                .any(|s| s.starts_with("resident_") && block.format != "mso_mdoc"),
                            "{purpose}: {dotted}"
                        );
                        // No segment is a dotted model key such as
                        // `age_equal_or_over.18`; only an mdoc namespace has dots.
                        assert!(
                            sp.path.iter().all(|s| !s.contains('.')
                                || (block.format == "mso_mdoc" && sp.path[0] == *s)),
                            "{purpose}: {:?}",
                            sp.path
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn sd_jwt_integer_segment_is_not_a_member_name() {
        // An integer path segment selects an array element (OpenID4VP 1.0
        // section 7), so `["age_equal_or_over", 18]` does not name the member
        // "18" of the age object and gets no model key.
        for (purpose, member) in [
            ("age_gate_18", 18),
            ("event_checkin", 18),
            ("car_rental", 21),
        ] {
            for format in ["dc+sd-jwt", "vc+sd-jwt"] {
                let integer = serde_json::json!(["age_equal_or_over", member]);
                assert_eq!(
                    single_status(format, integer, purpose),
                    ClaimStatus::BeyondPurpose,
                    "{purpose} {format}"
                );
                let string = serde_json::json!(["age_equal_or_over", member.to_string()]);
                assert_eq!(
                    single_status(format, string, purpose),
                    ClaimStatus::MinimalForPurpose,
                    "{purpose} {format}"
                );
            }
        }
        // The array element selectors of a known array claim still count.
        assert_eq!(
            single_status(
                "dc+sd-jwt",
                serde_json::json!(["nationalities", 0]),
                "bank_kyc"
            ),
            ClaimStatus::MinimalForPurpose
        );
        // An integer segment below an object member is no model key either.
        assert_eq!(
            single_status("dc+sd-jwt", serde_json::json!(["address", 0]), "bank_kyc"),
            ClaimStatus::BeyondPurpose
        );
    }

    #[test]
    fn unmodelled_format_gets_no_purpose_verdict() {
        for format in ["org.example.format", "jwt_vc_json", "ldp_vc"] {
            for purpose in PURPOSES {
                let query = json_paths_query(
                    format,
                    &[
                        serde_json::json!(["age_equal_or_over", "18"]),
                        serde_json::json!(["given_name"]),
                    ],
                );
                let report = analyze(PID_VCT, &query, None, baseline(purpose).as_ref(), &[]);
                for v in &report.requested {
                    assert_eq!(v.status, ClaimStatus::BeyondPurpose, "{format} {purpose}");
                    assert_eq!(v.rationale, UNMODELLED_FORMAT, "{format} {purpose}");
                }
                assert!(report.has_over_ask(), "{format} {purpose}");
                assert!(!report.claim_rows.iter().any(|r| r.requested), "{format}");
            }
        }
        // Both SD-JWT VC format identifiers keep their purpose verdict.
        for format in ["dc+sd-jwt", "vc+sd-jwt"] {
            assert_eq!(
                single_status(
                    format,
                    serde_json::json!(["age_equal_or_over", "18"]),
                    "age_gate_18"
                ),
                ClaimStatus::MinimalForPurpose,
                "{format}"
            );
        }
    }
}
