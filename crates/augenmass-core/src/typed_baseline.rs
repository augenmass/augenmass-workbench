//! A purpose baseline loaded from a baseline file (schema id
//! [`SCHEMA_ID`]): typed claim paths per credential type, acceptable
//! alternatives, claims the author leaves open, and "one of these rows per
//! request" groups.
//!
//! This module is the pure model. It reads no file and parses no JSON: the
//! shell reads and validates the file and builds a [`TypedBaseline`] for one
//! entry. The comparison itself is [`crate::inspector::analyze_against`].
//!
//! A baseline file is its author's assessment. Nothing in it is checked
//! against a legal source by this crate.

use openid4vp::core::dcql_query::DcqlQuery;

use crate::inspector::{BaselineInfo, FileBaselineInfo, ModelledType, PurposeBaseline};
use crate::regcert::{self, PathSeg};

/// The schema id a baseline file must carry.
pub const SCHEMA_ID: &str = "augenmass-baselines/0.1";

/// The label of every entry whose status is not `reviewed`.
pub const DRAFT_NOTICE: &str = "draft baseline, no legal review";

/// The sentence every result under a loaded baseline carries.
pub const ASSESSMENT_NOTICE: &str =
    "A baseline file is its author's assessment, not law and not legal advice.";

/// The status an entry states about itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryStatus {
    Draft,
    Reviewed,
}

impl EntryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Reviewed => "reviewed",
        }
    }
}

/// A minimal row: one typed claims path pointer, optionally in a one-of group.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BaselineRow {
    pub path: Vec<PathSeg>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub one_of: Option<String>,
}

/// An alternative or an undecided row: a path with the author's reason.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReasonedRow {
    pub path: Vec<PathSeg>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub one_of: Option<String>,
    pub reason: String,
}

/// One credential block of an entry: a credential format, the credential
/// types the block models, and its three row lists. Serializes in the shape
/// of the file (`vct_values` or `doctype_value`, like the DCQL `meta`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TypedCredential {
    pub format: String,
    /// SD-JWT VC types; empty for `mso_mdoc`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub vct_values: Vec<String>,
    /// The mdoc doctype; `None` for the SD-JWT VC formats.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctype_value: Option<String>,
    /// The claims the entry's case needs.
    pub minimal: Vec<BaselineRow>,
    /// Claims that may be asked instead of a minimal claim.
    pub alternatives: Vec<ReasonedRow>,
    /// Claims the author leaves open.
    pub undecided: Vec<ReasonedRow>,
}

/// Which of the three row lists of a block a row is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RowList {
    Minimal,
    Alternatives,
    Undecided,
}

/// One row of an entry: block index, list, row index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RowId {
    pub block: usize,
    pub list: RowList,
    pub row: usize,
}

impl TypedCredential {
    pub fn is_mdoc(&self) -> bool {
        self.format == regcert::FORMAT_MSO_MDOC
    }

    /// The credential types this block models: the vct values, or the doctype.
    pub fn types(&self) -> Vec<&str> {
        match &self.doctype_value {
            Some(doctype) => vec![doctype.as_str()],
            None => self.vct_values.iter().map(String::as_str).collect(),
        }
    }

    /// Whether this block is for `format` and models `credential_type`.
    /// Formats and types compare as exact strings.
    pub fn has_type(&self, format: &str, credential_type: &str) -> bool {
        self.format == format && self.types().contains(&credential_type)
    }

    /// Every row of the block with its list, index, path and group.
    pub fn rows(&self) -> Vec<(RowList, usize, &[PathSeg], Option<&str>)> {
        fn reasoned(
            list: RowList,
            rows: &[ReasonedRow],
        ) -> impl Iterator<Item = (RowList, usize, &[PathSeg], Option<&str>)> {
            rows.iter()
                .enumerate()
                .map(move |(i, r)| (list, i, r.path.as_slice(), r.one_of.as_deref()))
        }
        self.minimal
            .iter()
            .enumerate()
            .map(|(i, r)| (RowList::Minimal, i, r.path.as_slice(), r.one_of.as_deref()))
            .chain(reasoned(RowList::Alternatives, &self.alternatives))
            .chain(reasoned(RowList::Undecided, &self.undecided))
            .collect()
    }

    /// The row that covers a requested path, by the coverage rule of the
    /// registration comparison ([`regcert::path_covers`]): typed segments, a
    /// row covers its descendants in the JSON formats, and for `mso_mdoc`
    /// only an equal pair of two strings. A valid file has no two rows of one
    /// block that overlap, so at most one row covers a path.
    pub fn match_row(&self, requested: &[PathSeg]) -> Option<(RowList, usize)> {
        let mdoc = self.is_mdoc();
        self.rows()
            .into_iter()
            .find(|(_, _, path, _)| regcert::path_covers(path, requested, mdoc))
            .map(|(list, row, _, _)| (list, row))
    }

    /// The block's credential type in the shape the report uses.
    pub fn modelled_type(&self) -> ModelledType {
        ModelledType {
            format: self.format.clone(),
            vct_values: self.vct_values.clone(),
            doctype_value: self.doctype_value.clone(),
        }
    }
}

/// A group of rows of which one request may ask for one.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct OneOfGroup {
    pub id: String,
    pub reason: String,
}

/// A legal source an entry states. Printed and serialized as written; this
/// crate does not check it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LegalSource {
    pub instrument: String,
    pub locator: String,
    pub quote: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retrieved: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// One entry of a baseline file, selected for a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedBaseline {
    /// The file name without any directory, set by the shell.
    pub file: String,
    pub id: String,
    pub version: String,
    pub status: EntryStatus,
    pub reviewer: Option<String>,
    pub label: Option<String>,
    /// The case this entry is for, in the author's words. Printed, never
    /// evaluated.
    pub applies_when: Option<String>,
    /// The blocks of `claims`, in file order.
    pub credentials: Vec<TypedCredential>,
    pub one_of: Vec<OneOfGroup>,
    pub legal_sources: Vec<LegalSource>,
}

impl TypedBaseline {
    /// The label printed as the baseline: the entry's label, or its id.
    pub fn display_label(&self) -> &str {
        self.label.as_deref().unwrap_or(&self.id)
    }

    /// True only when the entry states the status `reviewed`. The statement
    /// is the file's; it is not checked.
    pub fn legal_review(&self) -> bool {
        self.status == EntryStatus::Reviewed
    }

    /// The line under the baseline facts: [`DRAFT_NOTICE`] for every status
    /// other than `reviewed`, else the reviewer the file names.
    pub fn notice(&self) -> String {
        match (self.status, &self.reviewer) {
            (EntryStatus::Reviewed, Some(reviewer)) => {
                format!("reviewed by {reviewer} (as stated by the baseline file)")
            }
            (EntryStatus::Reviewed, None) => {
                "reviewed (as stated by the baseline file)".to_string()
            }
            (EntryStatus::Draft, _) => DRAFT_NOTICE.to_string(),
        }
    }

    /// Whether any block is for `format`.
    pub fn models_format(&self, format: &str) -> bool {
        self.credentials.iter().any(|c| c.format == format)
    }

    /// The index of the block that models `credential_type` in `format`. A
    /// valid file has no two blocks with the same format and a common type.
    pub fn block_for(&self, format: &str, credential_type: &str) -> Option<usize> {
        self.credentials
            .iter()
            .position(|c| c.has_type(format, credential_type))
    }

    /// The credential types of every block, in file order.
    pub fn credential_types(&self) -> Vec<ModelledType> {
        self.credentials
            .iter()
            .map(TypedCredential::modelled_type)
            .collect()
    }

    /// The one-of group id of a row, if it has one.
    pub fn group_of(&self, id: &RowId) -> Option<&str> {
        let block = self.credentials.get(id.block)?;
        match id.list {
            RowList::Minimal => block.minimal.get(id.row)?.one_of.as_deref(),
            RowList::Alternatives => block.alternatives.get(id.row)?.one_of.as_deref(),
            RowList::Undecided => block.undecided.get(id.row)?.one_of.as_deref(),
        }
    }

    /// What a report says about this baseline (the JSON member `baseline`).
    pub fn info(&self) -> BaselineInfo {
        BaselineInfo::File(Box::new(FileBaselineInfo {
            file: self.file.clone(),
            schema: SCHEMA_ID.to_string(),
            entry_id: self.id.clone(),
            label: self.display_label().to_string(),
            version: self.version.clone(),
            status: self.status,
            reviewer: self.reviewer.clone(),
            legal_review: self.legal_review(),
            notice: self.notice(),
            applies_when: self.applies_when.clone(),
            assessment_notice: ASSESSMENT_NOTICE.to_string(),
            credential_types: self.credential_types(),
            claims: self.credentials.clone(),
            one_of: self.one_of.clone(),
            legal_sources: self.legal_sources.clone(),
        }))
    }
}

/// What a comparison is made against.
#[derive(Debug, Clone, Copy)]
pub enum BaselineRef<'a> {
    /// One of the curated built-in baselines.
    BuiltIn(&'a PurposeBaseline),
    /// One entry of a loaded baseline file.
    Typed(&'a TypedBaseline),
}

/// What is being judged. A presentation request is one request; a
/// registration body lists everything a party may ask across requests, so a
/// rule "one claim per request" cannot be decided on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subject {
    Request,
    RegistrationBody,
}

/// Which claims and credentials of a request one response can hold together,
/// as far as the request proves it (OpenID4VP 1.0 sections 6.4.1 and 6.4.2).
/// Used only by the one-of rule. Two things count as returned together unless
/// the request proves that one response cannot hold both; `claim_sets` or
/// `credential_sets` that name an id the request does not carry prove nothing.
#[derive(Debug, Clone)]
pub struct Cooccurrence {
    claim_sets: Vec<Sets>,
    credential_sets: Sets,
    multiple: Vec<bool>,
}

/// The options of one `claim_sets` member, or of all `credential_sets`.
#[derive(Debug, Clone)]
enum Sets {
    /// The member is absent: everything is requested together.
    Absent,
    /// An option names an id that nothing carries: the options prove nothing.
    Unresolved,
    /// One list of options per set (a credential has one set of claim
    /// options); an option is the indices it names.
    Resolved(Vec<Vec<Vec<usize>>>),
}

/// Which claims and credentials of `query` one response can hold together.
pub fn returned_together(query: &DcqlQuery) -> Cooccurrence {
    let credentials = query.credentials();
    let claim_sets = credentials
        .iter()
        .map(|cred| {
            let (Some(claims), Some(sets)) = (cred.claims(), cred.claim_sets()) else {
                return Sets::Absent;
            };
            let options: Option<Vec<Vec<usize>>> = sets
                .iter()
                .map(|option| {
                    option
                        .iter()
                        .map(|id| {
                            let named: Vec<usize> = claims
                                .iter()
                                .enumerate()
                                .filter(|(_, c)| c.id() == Some(id))
                                .map(|(i, _)| i)
                                .collect();
                            (!named.is_empty()).then_some(named)
                        })
                        .collect::<Option<Vec<Vec<usize>>>>()
                        .map(|named| named.into_iter().flatten().collect())
                })
                .collect();
            match options {
                Some(options) => Sets::Resolved(vec![options]),
                None => Sets::Unresolved,
            }
        })
        .collect();

    let credential_sets = match query.credential_sets() {
        None => Sets::Absent,
        Some(sets) => {
            let resolved: Option<Vec<Vec<Vec<usize>>>> = sets
                .iter()
                .map(|set| {
                    set.options()
                        .iter()
                        .map(|option| {
                            option
                                .iter()
                                .map(|id| {
                                    let named: Vec<usize> = credentials
                                        .iter()
                                        .enumerate()
                                        .filter(|(_, c)| c.id() == id.as_str())
                                        .map(|(i, _)| i)
                                        .collect();
                                    (!named.is_empty()).then_some(named)
                                })
                                .collect::<Option<Vec<Vec<usize>>>>()
                                .map(|named| named.into_iter().flatten().collect())
                        })
                        .collect()
                })
                .collect();
            match resolved {
                Some(sets) => Sets::Resolved(sets),
                None => Sets::Unresolved,
            }
        }
    };

    Cooccurrence {
        claim_sets,
        credential_sets,
        multiple: credentials.iter().map(|c| c.multiple()).collect(),
    }
}

impl Cooccurrence {
    /// Whether one response can hold the claims with the indices `a` and `b`
    /// (positions in `claims`) of the credential query `credential`. False
    /// only when the credential has `claim_sets`, every id in them is the id
    /// of a claim of that credential, and no option names both claims.
    pub fn claims_together(&self, credential: usize, a: usize, b: usize) -> bool {
        if a == b {
            return true;
        }
        match self.claim_sets.get(credential) {
            Some(Sets::Resolved(sets)) => sets
                .iter()
                .flatten()
                .any(|option| option.contains(&a) && option.contains(&b)),
            _ => true,
        }
    }

    /// Whether one response can hold the credential queries `a` and `b`
    /// (positions in `credentials`). False only when the request has
    /// `credential_sets`, every id in every option is the id of a credential
    /// query, both credentials occur in options of exactly one credential
    /// set, that set is the same for both, and no option of it names both.
    pub fn credentials_together(&self, a: usize, b: usize) -> bool {
        if a == b {
            return true;
        }
        let Sets::Resolved(sets) = &self.credential_sets else {
            return true;
        };
        let sets_of = |credential: usize| -> Vec<usize> {
            sets.iter()
                .enumerate()
                .filter(|(_, options)| options.iter().any(|o| o.contains(&credential)))
                .map(|(i, _)| i)
                .collect()
        };
        let (of_a, of_b) = (sets_of(a), sets_of(b));
        match (of_a.as_slice(), of_b.as_slice()) {
            ([one], [other]) if one == other => sets[*one]
                .iter()
                .any(|option| option.contains(&a) && option.contains(&b)),
            _ => true,
        }
    }

    /// Whether the credential query asks for several credentials at once
    /// (`multiple: true`), so that one response can hold credentials of
    /// several of the types it accepts.
    pub fn multiple(&self, credential: usize) -> bool {
        self.multiple.get(credential).copied().unwrap_or(false)
    }

    /// True when the `claim_sets` of the credential query name an id that no
    /// claim of it carries.
    pub fn claim_sets_unresolved(&self, credential: usize) -> bool {
        matches!(self.claim_sets.get(credential), Some(Sets::Unresolved))
    }

    /// True when `credential_sets` name an id that no credential query
    /// carries.
    pub fn credential_sets_unresolved(&self) -> bool {
        matches!(self.credential_sets, Sets::Unresolved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspector::{analyze_against, ClaimStatus, Outcome, OverAskReport};
    use crate::regcert::RegisteredScope;
    use crate::PID_VCT;
    use serde_json::{json, Value};

    const DE_VCT: &str = "urn:eudi:pid:de:1";
    const EU_VCT: &str = "urn:eudi:pid:1";
    const PID_DOCTYPE: &str = "eu.europa.ec.eudi.pid.1";
    const DE_NAMESPACE: &str = "eu.europa.ec.eudi.pid.de.1";
    const AV_DOCTYPE: &str = "eu.europa.ec.av.1";

    fn path(v: Value) -> Vec<PathSeg> {
        regcert::parse_claim_path(&v).expect("claims path pointer")
    }

    fn minimal(v: Value, group: Option<&str>) -> BaselineRow {
        BaselineRow {
            path: path(v),
            one_of: group.map(String::from),
        }
    }

    fn reasoned(v: Value, group: Option<&str>, reason: &str) -> ReasonedRow {
        ReasonedRow {
            path: path(v),
            one_of: group.map(String::from),
            reason: reason.to_string(),
        }
    }

    fn sd_jwt_block(vcts: &[&str], minimal: Vec<BaselineRow>) -> TypedCredential {
        TypedCredential {
            format: "dc+sd-jwt".to_string(),
            vct_values: vcts.iter().map(|v| v.to_string()).collect(),
            doctype_value: None,
            minimal,
            alternatives: Vec::new(),
            undecided: Vec::new(),
        }
    }

    fn mdoc_block(doctype: &str) -> TypedCredential {
        TypedCredential {
            format: "mso_mdoc".to_string(),
            vct_values: Vec::new(),
            doctype_value: Some(doctype.to_string()),
            minimal: Vec::new(),
            alternatives: Vec::new(),
            undecided: Vec::new(),
        }
    }

    fn entry(credentials: Vec<TypedCredential>, groups: &[&str]) -> TypedBaseline {
        TypedBaseline {
            file: "test-baselines.json".to_string(),
            id: "example.test.entry".to_string(),
            version: "0.1".to_string(),
            status: EntryStatus::Draft,
            reviewer: None,
            label: None,
            applies_when: None,
            credentials,
            one_of: groups
                .iter()
                .map(|id| OneOfGroup {
                    id: id.to_string(),
                    reason: "invented rule: one age claim per request".to_string(),
                })
                .collect(),
            legal_sources: Vec::new(),
        }
    }

    /// An invented age entry in the shape of the example file: the German PID
    /// as SD-JWT VC and as mdoc, and the Proof of Age attestation, every age
    /// row in the group `age-claim`.
    fn age_entry() -> TypedBaseline {
        let mut pid_mdoc = mdoc_block(PID_DOCTYPE);
        pid_mdoc.minimal = vec![minimal(
            json!([DE_NAMESPACE, "age_over_18"]),
            Some("age-claim"),
        )];
        pid_mdoc.alternatives = vec![reasoned(
            json!([PID_DOCTYPE, "age_over_18"]),
            Some("age-claim"),
            "same boolean in the EU namespace",
        )];
        pid_mdoc.undecided = vec![reasoned(
            json!([DE_NAMESPACE, "status"]),
            None,
            "open question on the revocation element",
        )];
        let mut av = mdoc_block(AV_DOCTYPE);
        av.alternatives = vec![reasoned(
            json!([AV_DOCTYPE, "age_over_18"]),
            Some("age-claim"),
            "the attestation discloses one boolean",
        )];
        entry(
            vec![
                sd_jwt_block(
                    &[DE_VCT],
                    vec![minimal(
                        json!(["age_equal_or_over", "18"]),
                        Some("age-claim"),
                    )],
                ),
                pid_mdoc,
                av,
            ],
            &["age-claim"],
        )
    }

    /// An invented entry for a credential that is not a PID, with a grouped
    /// object row that covers its members.
    fn loyalty_entry() -> TypedBaseline {
        let mut block = sd_jwt_block(
            &["urn:example:loyalty:1"],
            vec![
                minimal(json!(["profile"]), Some("contact")),
                minimal(json!(["member_id"]), Some("contact")),
                minimal(json!(["visits", null]), None),
                minimal(json!(["codes", "18"]), None),
            ],
        );
        block.undecided = vec![reasoned(json!(["tier"]), Some("contact"), "left open")];
        entry(vec![block], &["contact"])
    }

    fn query(v: Value) -> DcqlQuery {
        serde_json::from_value(v).expect("DCQL query")
    }

    fn judge(baseline: &TypedBaseline, request: Value) -> OverAskReport {
        analyze_against(
            PID_VCT,
            &query(request),
            None,
            Some(BaselineRef::Typed(baseline)),
            Subject::Request,
            &[],
        )
    }

    fn sd_jwt_cred(id: &str, vcts: &[&str], paths: &[Value]) -> Value {
        let claims: Vec<Value> = paths.iter().map(|p| json!({ "path": p })).collect();
        json!({ "id": id, "format": "dc+sd-jwt", "meta": { "vct_values": vcts }, "claims": claims })
    }

    fn mdoc_cred(id: &str, doctype: &str, paths: &[Value]) -> Value {
        let claims: Vec<Value> = paths.iter().map(|p| json!({ "path": p })).collect();
        json!({ "id": id, "format": "mso_mdoc", "meta": { "doctype_value": doctype }, "claims": claims })
    }

    fn statuses(report: &OverAskReport) -> Vec<ClaimStatus> {
        report.requested.iter().map(|c| c.status).collect()
    }

    #[test]
    fn rows_give_minimal_alternative_undecided_and_beyond() {
        let b = age_entry();

        let report = judge(
            &b,
            json!({ "credentials": [sd_jwt_cred("pid", &[DE_VCT], &[json!(["age_equal_or_over", "18"])])] }),
        );
        assert_eq!(statuses(&report), vec![ClaimStatus::MinimalForPurpose]);
        assert_eq!(
            report.requested[0].rationale,
            "Minimal under this baseline entry."
        );
        assert_eq!(report.outcome, Outcome::Ok);
        assert_eq!(report.counts.minimal, 1);

        let report = judge(
            &b,
            json!({ "credentials": [mdoc_cred("pid", PID_DOCTYPE, &[json!([PID_DOCTYPE, "age_over_18"])])] }),
        );
        assert_eq!(statuses(&report), vec![ClaimStatus::AcceptableAlternative]);
        assert_eq!(
            report.requested[0].rationale,
            "Acceptable alternative, not an over-ask. Reason stated by the baseline: same boolean in the EU namespace"
        );
        assert_eq!(report.outcome, Outcome::Ok);
        assert_eq!(report.counts.acceptable_alternative, 1);
        assert_eq!(report.counts.minimal, 0);
        assert!(!report.has_over_ask());

        let report = judge(
            &b,
            json!({ "credentials": [mdoc_cred("pid", PID_DOCTYPE, &[json!([DE_NAMESPACE, "status"])])] }),
        );
        assert_eq!(statuses(&report), vec![ClaimStatus::NotEvaluated]);
        assert_eq!(
            report.requested[0].rationale,
            "Not evaluated: the baseline leaves this claim open. Reason stated by the baseline: open question on the revocation element"
        );
        assert_eq!(report.outcome, Outcome::NotEvaluated);
        assert_eq!(report.counts.could_not_judge, 1);

        let report = judge(
            &b,
            json!({ "credentials": [sd_jwt_cred("pid", &[DE_VCT], &[json!(["birthdate"])])] }),
        );
        assert_eq!(statuses(&report), vec![ClaimStatus::BeyondPurpose]);
        assert_eq!(
            report.requested[0].rationale,
            "Beyond the baseline: not a minimal claim and not an acceptable alternative of entry example.test.entry for dc+sd-jwt, urn:eudi:pid:de:1."
        );
        assert_eq!(report.outcome, Outcome::OverAsk);
        assert_eq!(report.counts.beyond_purpose, 1);
    }

    #[test]
    fn report_names_the_file_entry_and_has_no_built_in_suggestion() {
        let mut b = age_entry();
        b.applies_when = Some("the order holds wine".to_string());
        let report = judge(
            &b,
            json!({ "credentials": [sd_jwt_cred("pid", &[DE_VCT], &[json!(["age_equal_or_over", "18"])])] }),
        );
        assert_eq!(
            report.baseline_label.as_deref(),
            Some("example.test.entry"),
            "the id is the label when the entry has none"
        );
        assert_eq!(
            report.baseline_note.as_deref(),
            Some("draft baseline, no legal review. A baseline file is its author's assessment, not law and not legal advice.")
        );
        assert!(report.suggested_minimal.is_none());
        assert!(report.suggested_minimal_request.is_none());
        assert_eq!(report.legal_basis.len(), 3);
        assert!(report.counts.purpose_evaluated);

        let json = serde_json::to_value(&report).expect("json");
        let baseline = &json["baseline"];
        assert_eq!(baseline["source"], "file");
        assert_eq!(baseline["file"], "test-baselines.json");
        assert_eq!(baseline["schema"], SCHEMA_ID);
        assert_eq!(baseline["entry_id"], "example.test.entry");
        assert_eq!(baseline["version"], "0.1");
        assert_eq!(baseline["status"], "draft");
        assert_eq!(baseline["reviewer"], Value::Null);
        assert_eq!(baseline["legal_review"], false);
        assert_eq!(baseline["notice"], DRAFT_NOTICE);
        assert_eq!(baseline["applies_when"], "the order holds wine");
        assert_eq!(
            baseline["credential_types"],
            json!([
                { "format": "dc+sd-jwt", "vct_values": [DE_VCT] },
                { "format": "mso_mdoc", "doctype_value": PID_DOCTYPE },
                { "format": "mso_mdoc", "doctype_value": AV_DOCTYPE },
            ])
        );
        assert_eq!(
            baseline["claims"][0]["minimal"],
            json!([{ "path": ["age_equal_or_over", "18"], "one_of": "age-claim" }])
        );
        assert_eq!(baseline["one_of"][0]["id"], "age-claim");
        assert_eq!(baseline["legal_sources"], json!([]));
        assert_eq!(json["requested"][0]["status"], "MinimalForPurpose");
    }

    #[test]
    fn reviewed_entry_has_the_reviewer_and_no_draft_notice() {
        let mut b = age_entry();
        b.status = EntryStatus::Reviewed;
        b.reviewer = Some("Example Reviewer".to_string());
        assert!(b.legal_review());
        assert_eq!(
            b.notice(),
            "reviewed by Example Reviewer (as stated by the baseline file)"
        );
        let json = serde_json::to_value(b.info()).expect("json");
        assert_eq!(json["status"], "reviewed");
        assert_eq!(json["reviewer"], "Example Reviewer");
        assert_eq!(json["legal_review"], true);
        assert!(!json["notice"]
            .as_str()
            .expect("notice")
            .contains(DRAFT_NOTICE));
    }

    #[test]
    fn credential_the_entry_does_not_model_is_not_evaluated() {
        let b = age_entry();

        // A doctype no block models.
        let report = judge(
            &b,
            json!({ "credentials": [mdoc_cred("mdl", "org.iso.18013.5.1.mDL", &[json!(["org.iso.18013.5.1", "given_name"])])] }),
        );
        assert_eq!(statuses(&report), vec![ClaimStatus::NotEvaluated]);
        assert_eq!(
            report.requested[0].rationale,
            "Not evaluated: entry example.test.entry does not model the credential type org.iso.18013.5.1.mDL in format mso_mdoc. It models dc+sd-jwt with vct urn:eudi:pid:de:1, mso_mdoc with doctype eu.europa.ec.eudi.pid.1, and mso_mdoc with doctype eu.europa.ec.av.1."
        );
        assert_eq!(report.outcome, Outcome::NotEvaluated);

        // A vct no block models: the EU type is not the German type.
        let report = judge(
            &b,
            json!({ "credentials": [sd_jwt_cred("pid", &[EU_VCT], &[json!(["age_equal_or_over", "18"])])] }),
        );
        assert_eq!(statuses(&report), vec![ClaimStatus::NotEvaluated]);
        assert_eq!(report.outcome, Outcome::NotEvaluated);

        // A format without a block: vc+sd-jwt is not dc+sd-jwt here.
        let report = judge(
            &b,
            json!({ "credentials": [{
                "id": "pid", "format": "vc+sd-jwt", "meta": { "vct_values": [DE_VCT] },
                "claims": [{ "path": ["age_equal_or_over", "18"] }]
            }] }),
        );
        assert_eq!(statuses(&report), vec![ClaimStatus::NotEvaluated]);
        assert_eq!(
            report.requested[0].rationale,
            "Not evaluated: entry example.test.entry does not model the format vc+sd-jwt."
        );

        // No credential type named.
        let report = judge(
            &b,
            json!({ "credentials": [{
                "id": "pid", "format": "dc+sd-jwt", "meta": {},
                "claims": [{ "path": ["age_equal_or_over", "18"] }]
            }] }),
        );
        assert_eq!(statuses(&report), vec![ClaimStatus::NotEvaluated]);
        assert!(report.requested[0]
            .rationale
            .contains("names no credential type"));

        // A credential without claims: a row only when it cannot be judged.
        let report = judge(
            &b,
            json!({ "credentials": [
                { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": [DE_VCT] } },
                { "id": "mdl", "format": "mso_mdoc", "meta": { "doctype_value": "org.iso.18013.5.1.mDL" } },
            ] }),
        );
        assert_eq!(report.requested.len(), 1);
        assert_eq!(report.requested[0].key, "mdl (credential, no claims)");
        assert_eq!(report.requested[0].status, ClaimStatus::NotEvaluated);
        assert_eq!(report.outcome, Outcome::NotEvaluated);
    }

    #[test]
    fn several_accepted_types_are_judged_per_type() {
        // One block for the German type only (D4).
        let b = age_entry();
        let both = [DE_VCT, EU_VCT];

        let report = judge(
            &b,
            json!({ "credentials": [sd_jwt_cred("pid", &both, &[json!(["age_equal_or_over", "18"])])] }),
        );
        assert_eq!(statuses(&report), vec![ClaimStatus::NotEvaluated]);
        assert_eq!(
            report.requested[0].rationale,
            "Not evaluated: within entry example.test.entry for urn:eudi:pid:de:1; the request also accepts urn:eudi:pid:1, which the entry does not model."
        );

        let report = judge(
            &b,
            json!({ "credentials": [sd_jwt_cred("pid", &both, &[json!(["birthdate"])])] }),
        );
        assert_eq!(statuses(&report), vec![ClaimStatus::BeyondPurpose]);
        assert_eq!(report.outcome, Outcome::OverAsk);

        // Two types that fall into two blocks: the worst result counts.
        let two_blocks = entry(
            vec![
                sd_jwt_block(
                    &[DE_VCT],
                    vec![minimal(json!(["age_equal_or_over", "18"]), None)],
                ),
                sd_jwt_block(
                    &[EU_VCT],
                    vec![
                        minimal(json!(["age_equal_or_over", "18"]), None),
                        minimal(json!(["given_name"]), None),
                    ],
                ),
            ],
            &[],
        );
        let report = judge(
            &two_blocks,
            json!({ "credentials": [sd_jwt_cred("pid", &both, &[
                json!(["age_equal_or_over", "18"]),
                json!(["given_name"]),
            ])] }),
        );
        assert_eq!(
            statuses(&report),
            vec![ClaimStatus::MinimalForPurpose, ClaimStatus::BeyondPurpose]
        );
        assert!(report.requested[1].rationale.contains(DE_VCT));
    }

    #[test]
    fn coverage_is_typed_and_structural() {
        let b = loyalty_entry();
        let ask = |p: Value| {
            let report = judge(
                &b,
                json!({ "credentials": [sd_jwt_cred("card", &["urn:example:loyalty:1"], &[p])] }),
            );
            report.requested[0].status
        };
        // A child of a row is covered, a parent is not.
        assert_eq!(
            ask(json!(["profile", "name"])),
            ClaimStatus::MinimalForPurpose
        );
        assert_eq!(ask(json!(["codes"])), ClaimStatus::BeyondPurpose);
        // The string "18" and the integer 18 are different segments.
        assert_eq!(ask(json!(["codes", "18"])), ClaimStatus::MinimalForPurpose);
        assert_eq!(ask(json!(["codes", 18])), ClaimStatus::BeyondPurpose);
        // null covers an index, and itself.
        assert_eq!(ask(json!(["visits", 0])), ClaimStatus::MinimalForPurpose);
        assert_eq!(ask(json!(["visits", null])), ClaimStatus::MinimalForPurpose);
        assert_eq!(ask(json!(["visits"])), ClaimStatus::BeyondPurpose);

        // mso_mdoc: only the equal pair of two strings.
        let age = age_entry();
        let ask_mdoc = |p: Value| {
            let report = judge(
                &age,
                json!({ "credentials": [mdoc_cred("pid", PID_DOCTYPE, &[p])] }),
            );
            report.requested[0].status
        };
        assert_eq!(
            ask_mdoc(json!([DE_NAMESPACE, "age_over_18"])),
            ClaimStatus::MinimalForPurpose
        );
        assert_eq!(
            ask_mdoc(json!([DE_NAMESPACE, "age_over_18", "x"])),
            ClaimStatus::BeyondPurpose
        );
        assert_eq!(
            ask_mdoc(json!([DE_NAMESPACE, "age_over_16"])),
            ClaimStatus::BeyondPurpose
        );
        // The Proof of Age element under the PID doctype is not the row of
        // the Proof of Age block.
        assert_eq!(
            ask_mdoc(json!([AV_DOCTYPE, "age_over_18"])),
            ClaimStatus::BeyondPurpose
        );
    }

    #[test]
    fn registration_comparison_is_unchanged_under_a_typed_baseline() {
        let b = age_entry();
        let scope: RegisteredScope = regcert::scope_from_payload(&json!({
            "credentials": [{
                "format": "dc+sd-jwt",
                "meta": { "vct_values": [DE_VCT] },
                "claim": [{ "path": ["age_equal_or_over", "18"] }, { "path": ["birthdate"] }],
            }]
        }))
        .expect("scope");
        let run = |paths: &[Value]| {
            analyze_against(
                PID_VCT,
                &query(json!({ "credentials": [sd_jwt_cred("pid", &[DE_VCT], paths)] })),
                Some(&scope),
                Some(BaselineRef::Typed(&b)),
                Subject::Request,
                &[],
            )
        };

        let report = run(&[json!(["age_equal_or_over", "18"])]);
        assert_eq!(statuses(&report), vec![ClaimStatus::MinimalForPurpose]);
        assert_eq!(
            report.verdict_line,
            "Minimal: all 1 requested claims are within purpose and registration."
        );

        // Registered, beyond the baseline: over-ask vs purpose.
        let report = run(&[json!(["birthdate"])]);
        assert_eq!(statuses(&report), vec![ClaimStatus::BeyondPurpose]);

        // Not registered: beyond the registration comes first.
        let report = run(&[json!(["given_name"])]);
        assert_eq!(statuses(&report), vec![ClaimStatus::BeyondRegistration]);
        assert_eq!(report.outcome, Outcome::OverAsk);
    }

    #[test]
    fn outcome_follows_the_precedence_with_alternatives() {
        let b = age_entry();
        // An alternative and a claim beyond the baseline: over-ask.
        let report = judge(
            &b,
            json!({ "credentials": [mdoc_cred("pid", PID_DOCTYPE, &[
                json!([PID_DOCTYPE, "age_over_18"]),
                json!([PID_DOCTYPE, "family_name"]),
            ])] }),
        );
        assert_eq!(
            statuses(&report),
            vec![
                ClaimStatus::AcceptableAlternative,
                ClaimStatus::BeyondPurpose
            ]
        );
        assert_eq!(report.outcome, Outcome::OverAsk);

        // An alternative and an undecided claim: not evaluated.
        let report = judge(
            &b,
            json!({ "credentials": [mdoc_cred("pid", PID_DOCTYPE, &[
                json!([PID_DOCTYPE, "age_over_18"]),
                json!([DE_NAMESPACE, "status"]),
            ])] }),
        );
        assert_eq!(
            statuses(&report),
            vec![
                ClaimStatus::AcceptableAlternative,
                ClaimStatus::NotEvaluated
            ]
        );
        assert_eq!(report.outcome, Outcome::NotEvaluated);
        assert_eq!(report.verdict_class(), "");
    }

    // --- returned_together -------------------------------------------------

    #[test]
    fn claims_are_returned_together_unless_claim_sets_prove_otherwise() {
        let cred = |claim_sets: Option<Value>| {
            let mut c = json!({
                "id": "pid", "format": "mso_mdoc", "meta": { "doctype_value": PID_DOCTYPE },
                "claims": [
                    { "id": "de", "path": [DE_NAMESPACE, "age_over_18"] },
                    { "id": "eu", "path": [PID_DOCTYPE, "age_over_18"] },
                ],
            });
            if let Some(sets) = claim_sets {
                c["claim_sets"] = sets;
            }
            returned_together(&query(json!({ "credentials": [c] })))
        };

        let co = cred(None);
        assert!(co.claims_together(0, 0, 1));
        assert!(!co.claim_sets_unresolved(0));

        assert!(cred(Some(json!([["de", "eu"]]))).claims_together(0, 0, 1));
        assert!(cred(Some(json!([["de"], ["de", "eu"]]))).claims_together(0, 0, 1));
        assert!(!cred(Some(json!([["de"], ["eu"]]))).claims_together(0, 0, 1));

        // An id that no claim carries proves nothing.
        let co = cred(Some(json!([["misspelt"]])));
        assert!(co.claims_together(0, 0, 1));
        assert!(co.claim_sets_unresolved(0));
        let co = cred(Some(json!([["de"], ["misspelt"]])));
        assert!(co.claims_together(0, 0, 1));
        assert!(co.claim_sets_unresolved(0));

        // A claim is always returned together with itself.
        assert!(cred(Some(json!([["de"], ["eu"]]))).claims_together(0, 1, 1));
    }

    #[test]
    fn credentials_are_returned_together_unless_one_set_proves_otherwise() {
        let request = |credential_sets: Option<Value>| {
            let mut q = json!({ "credentials": [
                sd_jwt_cred("a", &[DE_VCT], &[json!(["age_equal_or_over", "18"])]),
                mdoc_cred("b", AV_DOCTYPE, &[json!([AV_DOCTYPE, "age_over_18"])]),
            ] });
            if let Some(sets) = credential_sets {
                q["credential_sets"] = sets;
            }
            returned_together(&query(q))
        };

        assert!(request(None).credentials_together(0, 1));
        assert!(!request(Some(json!([{ "options": [["a"], ["b"]] }]))).credentials_together(0, 1));
        assert!(
            request(Some(json!([{ "options": [["a", "b"], ["b"]] }]))).credentials_together(0, 1)
        );
        // Two sets: each is answered, so both credentials can be returned.
        assert!(request(Some(json!([
            { "options": [["a"]] },
            { "options": [["b"]] },
        ])))
        .credentials_together(0, 1));
        assert!(request(Some(json!([
            { "options": [["a"]], "required": false },
            { "options": [["b"]] },
        ])))
        .credentials_together(0, 1));
        // One credential in two sets.
        assert!(request(Some(json!([
            { "options": [["a"], ["b"]] },
            { "options": [["a"]] },
        ])))
        .credentials_together(0, 1));
        // An id that no credential carries proves nothing.
        let co = request(Some(json!([{ "options": [["a"], ["nosuch"]] }])));
        assert!(co.credentials_together(0, 1));
        assert!(co.credential_sets_unresolved());
        assert!(!request(None).credential_sets_unresolved());
    }

    // --- the one-of rule ---------------------------------------------------

    const BROKEN: &str =
        "Beyond the baseline: entry example.test.entry allows one claim of the group";

    fn mdoc_two_namespaces(claim_sets: Option<Value>) -> Value {
        let mut c = json!({
            "id": "pid", "format": "mso_mdoc", "meta": { "doctype_value": PID_DOCTYPE },
            "claims": [
                { "id": "de", "path": [DE_NAMESPACE, "age_over_18"] },
                { "id": "eu", "path": [PID_DOCTYPE, "age_over_18"] },
            ],
        });
        if let Some(sets) = claim_sets {
            c["claim_sets"] = sets;
        }
        json!({ "credentials": [c] })
    }

    #[test]
    fn two_rows_of_a_group_in_one_credential() {
        let b = age_entry();

        // No claim_sets: both are returned.
        let report = judge(&b, mdoc_two_namespaces(None));
        assert_eq!(
            statuses(&report),
            vec![ClaimStatus::BeyondPurpose, ClaimStatus::BeyondPurpose]
        );
        assert_eq!(
            report.requested[0].rationale,
            "Beyond the baseline: entry example.test.entry allows one claim of the group \"age-claim\" per request (invented rule: one age claim per request); this request asks for 2 of them, and 2 of these can each be returned in one response together with another claim of the group."
        );
        assert_eq!(report.outcome, Outcome::OverAsk);

        // One option that names both.
        let report = judge(&b, mdoc_two_namespaces(Some(json!([["de", "eu"]]))));
        assert_eq!(report.outcome, Outcome::OverAsk);
        assert!(report.requested[1].rationale.starts_with(BROKEN));

        // Separate options, every id resolves: one or the other.
        let report = judge(&b, mdoc_two_namespaces(Some(json!([["de"], ["eu"]]))));
        assert_eq!(
            statuses(&report),
            vec![
                ClaimStatus::MinimalForPurpose,
                ClaimStatus::AcceptableAlternative
            ]
        );
        assert_eq!(report.outcome, Outcome::Ok);

        // An id no claim carries: the sets prove nothing.
        for sets in [json!([["misspelt"]]), json!([["de"], ["misspelt"]])] {
            let report = judge(&b, mdoc_two_namespaces(Some(sets.clone())));
            assert_eq!(report.outcome, Outcome::OverAsk, "{sets}");
            for claim in &report.requested {
                assert!(claim.rationale.starts_with(BROKEN), "{sets}");
                assert!(
                    claim.rationale.ends_with(
                        "claim_sets names an id the request does not carry, so its claims count as requested together."
                    ),
                    "{sets}: {}",
                    claim.rationale
                );
            }
        }
    }

    /// `claim_sets` keeps two claims apart within one returned credential.
    /// With `multiple: true` the response can hold several credentials of the
    /// query, each answering another option (OpenID4VP 1.0 section 6.1:
    /// "multiple Credentials can be returned for this Credential Query").
    #[test]
    fn multiple_defeats_separate_claim_sets_options() {
        let b = age_entry();
        let mut request = mdoc_two_namespaces(Some(json!([["de"], ["eu"]])));

        request["credentials"][0]["multiple"] = json!(false);
        assert_eq!(judge(&b, request.clone()).outcome, Outcome::Ok);

        request["credentials"][0]["multiple"] = json!(true);
        let report = judge(&b, request);
        assert_eq!(report.outcome, Outcome::OverAsk);
        assert_eq!(statuses(&report), vec![ClaimStatus::BeyondPurpose; 2]);
        for claim in &report.requested {
            assert!(claim.rationale.starts_with(BROKEN), "{}", claim.rationale);
            assert!(
                claim.rationale.ends_with(
                    "The credential query sets multiple, so one response can hold several credentials, each answering another claim_sets option."
                ),
                "{}",
                claim.rationale
            );
        }

        // Without claim_sets the two claims are together in one credential
        // already; the sentence about multiple is not added.
        let mut request = mdoc_two_namespaces(None);
        request["credentials"][0]["multiple"] = json!(true);
        let report = judge(&b, request);
        assert_eq!(report.outcome, Outcome::OverAsk);
        assert!(!report.requested[0].rationale.contains("multiple"));
    }

    /// The rationale counts the requested rows of the group and those that a
    /// response can hold next to another one. It never says that one response
    /// holds all of them.
    #[test]
    fn the_rationale_does_not_claim_that_one_response_holds_every_row() {
        let b = entry(
            vec![sd_jwt_block(
                &["urn:example:three:1"],
                vec![
                    minimal(json!(["a"]), Some("g")),
                    minimal(json!(["b"]), Some("g")),
                    minimal(json!(["c"]), Some("g")),
                ],
            )],
            &["g"],
        );
        let request = |claim_sets: Value| {
            json!({ "credentials": [{
                "id": "c", "format": "dc+sd-jwt",
                "meta": { "vct_values": ["urn:example:three:1"] },
                "claims": [
                    { "id": "a", "path": ["a"] },
                    { "id": "b", "path": ["b"] },
                    { "id": "c", "path": ["c"] },
                ],
                "claim_sets": claim_sets,
            }] })
        };

        // No option holds all three; each row has a partner in some option.
        let report = judge(&b, request(json!([["a", "b"], ["b", "c"]])));
        assert_eq!(statuses(&report), vec![ClaimStatus::BeyondPurpose; 3]);
        for claim in &report.requested {
            assert!(
                claim.rationale.ends_with(
                    "this request asks for 3 of them, and 3 of these can each be returned in one response together with another claim of the group."
                ),
                "{}",
                claim.rationale
            );
            assert!(!claim.rationale.contains("hold them together"));
        }

        // The third row is alone in its option: it stays minimal, and the
        // count of rows with a partner is 2 of 3.
        let report = judge(&b, request(json!([["a", "b"], ["c"]])));
        assert_eq!(
            statuses(&report),
            vec![
                ClaimStatus::BeyondPurpose,
                ClaimStatus::BeyondPurpose,
                ClaimStatus::MinimalForPurpose
            ]
        );
        assert!(report.requested[0].rationale.ends_with(
            "this request asks for 3 of them, and 2 of these can each be returned in one response together with another claim of the group."
        ));
    }

    #[test]
    fn the_rule_counts_matched_rows_not_requested_paths() {
        let b = loyalty_entry();
        let card = |paths: &[Value]| {
            judge(
                &b,
                json!({ "credentials": [sd_jwt_cred("card", &["urn:example:loyalty:1"], paths)] }),
            )
        };

        // Two requested paths under one grouped row are one unit.
        let report = card(&[json!(["profile", "name"]), json!(["profile", "country"])]);
        assert_eq!(
            statuses(&report),
            vec![
                ClaimStatus::MinimalForPurpose,
                ClaimStatus::MinimalForPurpose
            ]
        );
        assert_eq!(report.outcome, Outcome::Ok);

        // A second row of the group breaks it, for all three paths.
        let report = card(&[
            json!(["profile", "name"]),
            json!(["profile", "country"]),
            json!(["member_id"]),
        ]);
        assert_eq!(statuses(&report), vec![ClaimStatus::BeyondPurpose; 3]);
        assert!(report.requested[0]
            .rationale
            .contains("this request asks for 2 of them"));

        // A minimal row and an undecided row of one group: over-ask.
        let report = card(&[json!(["member_id"]), json!(["tier"])]);
        assert_eq!(statuses(&report), vec![ClaimStatus::BeyondPurpose; 2]);
        assert_eq!(report.outcome, Outcome::OverAsk);

        // The undecided row alone stays not evaluated.
        let report = card(&[json!(["tier"])]);
        assert_eq!(statuses(&report), vec![ClaimStatus::NotEvaluated]);

        // An ungrouped row never counts.
        let report = card(&[json!(["member_id"]), json!(["visits", null])]);
        assert_eq!(report.outcome, Outcome::Ok);
    }

    fn pid_and_av(credential_sets: Option<Value>) -> Value {
        let mut q = json!({ "credentials": [
            sd_jwt_cred("a", &[DE_VCT], &[json!(["age_equal_or_over", "18"])]),
            mdoc_cred("b", AV_DOCTYPE, &[json!([AV_DOCTYPE, "age_over_18"])]),
        ] });
        if let Some(sets) = credential_sets {
            q["credential_sets"] = sets;
        }
        q
    }

    #[test]
    fn rows_of_a_group_in_two_credentials() {
        let b = age_entry();
        let broken = |sets: Option<Value>| {
            let report = judge(&b, pid_and_av(sets.clone()));
            assert_eq!(report.outcome, Outcome::OverAsk, "{sets:?}");
            assert_eq!(
                statuses(&report),
                vec![ClaimStatus::BeyondPurpose; 2],
                "{sets:?}"
            );
            report
        };

        broken(None);
        broken(Some(json!([{ "options": [["a", "b"], ["b"]] }])));
        broken(Some(
            json!([{ "options": [["a"]] }, { "options": [["b"]] }]),
        ));
        broken(Some(json!([
            { "options": [["a"]], "required": false },
            { "options": [["b"]] },
        ])));
        let report = broken(Some(json!([{ "options": [["a"], ["nosuch"]] }])));
        assert!(report.requested[0].rationale.ends_with(
            "credential_sets names an id the request does not carry, so its credentials count as requested together."
        ));

        // Options of one set: the wallet returns one of them.
        let report = judge(&b, pid_and_av(Some(json!([{ "options": [["a"], ["b"]] }]))));
        assert_eq!(
            statuses(&report),
            vec![
                ClaimStatus::MinimalForPurpose,
                ClaimStatus::AcceptableAlternative
            ]
        );
        assert_eq!(report.outcome, Outcome::Ok);
    }

    #[test]
    fn the_same_row_in_two_credential_queries_counts_twice() {
        let b = age_entry();
        let request = json!({ "credentials": [
            sd_jwt_cred("first", &[DE_VCT], &[json!(["age_equal_or_over", "18"])]),
            sd_jwt_cred("second", &[DE_VCT], &[json!(["age_equal_or_over", "18"])]),
        ] });
        let report = judge(&b, request);
        assert_eq!(statuses(&report), vec![ClaimStatus::BeyondPurpose; 2]);
    }

    #[test]
    fn one_credential_query_with_two_types_in_two_blocks() {
        let b = entry(
            vec![
                sd_jwt_block(
                    &[DE_VCT],
                    vec![minimal(
                        json!(["age_equal_or_over", "18"]),
                        Some("age-claim"),
                    )],
                ),
                sd_jwt_block(
                    &[EU_VCT],
                    vec![minimal(
                        json!(["age_equal_or_over", "18"]),
                        Some("age-claim"),
                    )],
                ),
            ],
            &["age-claim"],
        );
        let request = |multiple: bool| {
            let mut c = sd_jwt_cred(
                "pid",
                &[DE_VCT, EU_VCT],
                &[json!(["age_equal_or_over", "18"])],
            );
            if multiple {
                c["multiple"] = json!(true);
            }
            json!({ "credentials": [c] })
        };
        // One returned credential has one type: one row.
        let report = judge(&b, request(false));
        assert_eq!(statuses(&report), vec![ClaimStatus::MinimalForPurpose]);
        // With multiple, one response can hold a credential of each type.
        let report = judge(&b, request(true));
        assert_eq!(statuses(&report), vec![ClaimStatus::BeyondPurpose]);
    }

    #[test]
    fn a_registration_body_with_two_rows_of_a_group_is_not_evaluated() {
        let b = age_entry();
        let body_query = query(json!({ "credentials": [
            sd_jwt_cred("c0", &[DE_VCT], &[json!(["age_equal_or_over", "18"])]),
            mdoc_cred("c1", PID_DOCTYPE, &[json!([DE_NAMESPACE, "age_over_18"])]),
        ] }));
        let report = analyze_against(
            PID_VCT,
            &body_query,
            None,
            Some(BaselineRef::Typed(&b)),
            Subject::RegistrationBody,
            &[],
        );
        assert_eq!(statuses(&report), vec![ClaimStatus::NotEvaluated; 2]);
        assert_eq!(
            report.requested[0].rationale,
            "Not evaluated: entry example.test.entry allows one claim of the group \"age-claim\" per request. A registration may list more than one where the intended use needs each; this tool cannot check that."
        );
        assert_eq!(report.outcome, Outcome::NotEvaluated);
        assert_eq!(report.counts.could_not_judge, 2);

        // A claim beyond the baseline stays an over-ask on a body.
        let body_query = query(json!({ "credentials": [
            sd_jwt_cred("c0", &[DE_VCT], &[json!(["age_equal_or_over", "18"]), json!(["birthdate"])]),
        ] }));
        let report = analyze_against(
            PID_VCT,
            &body_query,
            None,
            Some(BaselineRef::Typed(&b)),
            Subject::RegistrationBody,
            &[],
        );
        assert_eq!(
            statuses(&report),
            vec![ClaimStatus::MinimalForPurpose, ClaimStatus::BeyondPurpose]
        );
    }

    #[test]
    fn built_in_baselines_are_unchanged_by_the_new_entry_point() {
        let request = query(json!({ "credentials": [
            sd_jwt_cred("pid", &[DE_VCT], &[json!(["age_equal_or_over", "18"]), json!(["birthdate"])]),
        ] }));
        let built_in = crate::inspector::baseline("age_gate_18").expect("baseline");
        let old = crate::inspector::analyze(PID_VCT, &request, None, Some(&built_in), &[]);
        let new = analyze_against(
            PID_VCT,
            &request,
            None,
            Some(BaselineRef::BuiltIn(&built_in)),
            Subject::RegistrationBody,
            &[],
        );
        assert_eq!(
            serde_json::to_value(&old).expect("json"),
            serde_json::to_value(&new).expect("json")
        );
        assert_eq!(old.counts.acceptable_alternative, 0);
    }
}
