//! Export and replay local evidence captured by `serve --unsafe-debug-artifacts`.
//!
//! The bundle is intentionally local and sensitive. Command output and replay
//! output stay redacted, while the bundle file contains the raw artifacts needed
//! for an auditor-grade offline check.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openid4vp::core::response::AuthorizationResponse;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey, LineEnding};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use ssi::claims::sd_jwt::SdJwt;
use ssi::jwk::JWK;

use augenmass_core::crypto::decrypt_jwe;
use augenmass_core::disclosure::revealed_claims;
use augenmass_core::trust::TrustAnchors;
use augenmass_core::{
    verify_pid_presentation_full, RequestBinding, StatusInput, TrustOptions, PID_VCT,
};

use crate::jose;
use crate::output::{emit, OutputFormat};
use crate::serve::artifacts::sha256_hex;
use crate::serve::state::StatusFetcher;
use crate::x509util::signer_jwk_from_pem;

const BUNDLE_KIND: &str = "augenmass-evidence-bundle";
const SOURCE_KIND: &str = "serve-unsafe-debug-artifacts";
const SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone)]
pub struct ExportArgs {
    pub session_dir: PathBuf,
    pub out: PathBuf,
    pub signing_key: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct VerifyArgs {
    pub bundle: PathBuf,
    pub verify_key: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct TrustStatusArgs {
    pub bundle: PathBuf,
    pub verify_key: Option<PathBuf>,
    pub trust_anchor: String,
    pub status_token: Option<String>,
    pub fetch_status_token: bool,
    pub status_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceBundle {
    schema_version: u8,
    kind: String,
    tool: ToolInfo,
    payload_sha256: String,
    payload: EvidencePayload,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<EvidenceSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ToolInfo {
    name: String,
    version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EvidencePayload {
    source_kind: String,
    session: String,
    source_manifest_sha256: String,
    sensitive: bool,
    entries: Vec<EvidenceEntry>,
    replay_trace: ReplayTrace,
    caveats: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceEntry {
    label: String,
    filename: String,
    len: usize,
    sha256: String,
    media_type: String,
    content_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceSignature {
    alg: String,
    public_key_pem: String,
    public_key_sha256: String,
    signature_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReplayTrace {
    pub session: String,
    pub redacted: bool,
    pub events: Vec<ReplayEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReplayEvent {
    pub seq: u64,
    pub code: String,
    pub level: String,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct EvidenceProfile {
    session: String,
    signature: String,
    entries: usize,
    replay_events: usize,
    presentations: Vec<PresentationProfile>,
    readiness: ProfileReadiness,
    redacted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct PresentationProfile {
    presentation_sha256: String,
    issuer_header: IssuerHeaderProfile,
    issuer_claim_fields: Vec<String>,
    vct: Option<String>,
    disclosed_claim_keys: Vec<String>,
    status_list: StatusListProfile,
    redacted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct IssuerHeaderProfile {
    alg: Option<String>,
    typ: Option<String>,
    x5c_count: usize,
    leaf_cert_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct StatusListProfile {
    present: bool,
    idx_present: bool,
    uri_present: bool,
    uri_https: bool,
    uri_host: Option<String>,
    uri_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct ProfileReadiness {
    live_wallet_proven: bool,
    issuer_x5c_present: bool,
    status_list_ref_present: bool,
    trust_anchor_claim_possible: bool,
    live_status_claim_possible: bool,
    notes: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct TrustStatusProof {
    valid: bool,
    session: String,
    signature: String,
    payload_sha256: String,
    status_token_source: String,
    presentations: Vec<TrustStatusPresentationProof>,
    redacted: bool,
    notes: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct TrustStatusPresentationProof {
    presentation_sha256: String,
    vct: String,
    holder_bound: bool,
    trust_anchored: bool,
    status_checked: bool,
    status_list_ref_present: bool,
    status_uri_sha256: Option<String>,
    disclosed_claim_keys: Vec<String>,
    redacted: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SourceManifest {
    schema_version: u8,
    kind: String,
    session: String,
    sensitive: bool,
    entries: Vec<SourceEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SourceEntry {
    label: String,
    filename: String,
    len: usize,
    sha256: String,
}

#[derive(Debug)]
struct BundleCheck {
    bundle: EvidenceBundle,
    payload_sha256: String,
    signature_status: String,
}

pub fn export(args: ExportArgs, format: OutputFormat) -> Result<()> {
    let bundle = build_bundle(&args.session_dir, args.signing_key.as_deref())?;
    write_bundle(&args.out, &bundle)?;
    let text = format!(
        "EVIDENCE BUNDLE EXPORTED\nsession: {}\nout: {}\nentries: {}\npayloadSha256: {}\nsignature: {}\nsensitive: true\n",
        bundle.payload.session,
        args.out.display(),
        bundle.payload.entries.len(),
        bundle.payload_sha256,
        if bundle.signature.is_some() { "present" } else { "absent" }
    );
    let value = json!({
        "status": "exported",
        "session": bundle.payload.session,
        "out": args.out,
        "entries": bundle.payload.entries.len(),
        "payloadSha256": bundle.payload_sha256,
        "signature": bundle.signature.is_some(),
        "sensitive": true,
    });
    emit(format, &value, &text)
}

pub fn verify(args: VerifyArgs, format: OutputFormat) -> Result<bool> {
    let check = check_bundle(&args.bundle, args.verify_key.as_deref())?;
    let text = format!(
        "EVIDENCE BUNDLE VALID\nsession: {}\nentries: {}\nreplayEvents: {}\npayloadSha256: {}\nsignature: {}\nsensitive: {}\n",
        check.bundle.payload.session,
        check.bundle.payload.entries.len(),
        check.bundle.payload.replay_trace.events.len(),
        check.payload_sha256,
        check.signature_status,
        check.bundle.payload.sensitive,
    );
    let value = json!({
        "valid": true,
        "session": check.bundle.payload.session,
        "entries": check.bundle.payload.entries.len(),
        "replayEvents": check.bundle.payload.replay_trace.events.len(),
        "payloadSha256": check.payload_sha256,
        "signature": check.signature_status,
        "sensitive": check.bundle.payload.sensitive,
    });
    emit(format, &value, &text)?;
    Ok(true)
}

pub fn replay(args: VerifyArgs, format: OutputFormat) -> Result<bool> {
    let check = check_bundle(&args.bundle, args.verify_key.as_deref())?;
    let replay = check.bundle.payload.replay_trace;
    let text = render_replay(&replay, &check.signature_status);
    emit(format, &json!(replay), &text)?;
    Ok(true)
}

pub fn profile(args: VerifyArgs, format: OutputFormat) -> Result<bool> {
    let check = check_bundle(&args.bundle, args.verify_key.as_deref())?;
    let profile = profile_from_bundle(&check.bundle, &check.signature_status)?;
    let text = render_profile(&profile);
    let value = serde_json::to_value(&profile).context("serialize evidence profile")?;
    emit(format, &value, &text)?;
    Ok(true)
}

pub fn assert_live(args: VerifyArgs, format: OutputFormat) -> Result<bool> {
    let check = check_bundle(&args.bundle, args.verify_key.as_deref())?;
    let proof = assert_live_wallet_trace(&check.bundle.payload.replay_trace)?;
    let text = format!(
        "LIVE WALLET EVIDENCE PROVEN\nsession: {}\nrequiredEvents: {}\nreplayEvents: {}\npayloadSha256: {}\nsignature: {}\nredacted: true\nnotes: trust/status/over-ask are not claimed by evidence assert-live; use the live trace and explicit gates for those.\n",
        check.bundle.payload.session,
        proof.required_events.join(", "),
        check.bundle.payload.replay_trace.events.len(),
        check.payload_sha256,
        check.signature_status,
    );
    let value = json!({
        "valid": true,
        "session": check.bundle.payload.session,
        "requiredEvents": proof.required_events,
        "replayEvents": check.bundle.payload.replay_trace.events.len(),
        "payloadSha256": check.payload_sha256,
        "signature": check.signature_status,
        "redacted": true,
        "claims": {
            "encryptedWalletResponseReceived": true,
            "responseDecrypted": true,
            "presentationVerified": true,
            "trustChecked": false,
            "statusChecked": false,
            "overAskAnalyzed": false
        }
    });
    emit(format, &value, &text)?;
    Ok(true)
}

pub async fn prove_trust_status(args: TrustStatusArgs, format: OutputFormat) -> Result<bool> {
    prove_trust_status_with_fetcher(args, format, &StatusFetcher::Http).await
}

async fn prove_trust_status_with_fetcher(
    args: TrustStatusArgs,
    format: OutputFormat,
    fetcher: &StatusFetcher,
) -> Result<bool> {
    let check = check_bundle(&args.bundle, args.verify_key.as_deref())?;
    let token_source = match (&args.status_token, args.fetch_status_token) {
        (Some(_), false) => "supplied",
        (None, true) => "fetched",
        (Some(_), true) => {
            bail!("use either --status-token or --fetch-status-token, not both");
        }
        (None, false) => {
            bail!("set --status-token <jwt> or --fetch-status-token");
        }
    };

    let trust_anchor_pem = read_text_arg(&args.trust_anchor)?;
    let supplied_status_token = args
        .status_token
        .as_deref()
        .map(read_text_arg)
        .transpose()?;
    let status_key_pem = read_text_arg(&args.status_key)?;
    let anchors = TrustAnchors::from_pem(&trust_anchor_pem).context("load trust anchor PEM")?;
    let status_signer = signer_jwk_from_pem(&status_key_pem).context("load status signer PEM")?;
    let context = verification_context(&check.bundle.payload.entries)?;
    let decrypted = decrypted_response(&check.bundle.payload.entries)?
        .context("evidence bundle does not contain a decrypted authorization response")?;
    let presentations = presentations_from_decrypted(&decrypted);
    if presentations.is_empty() {
        bail!("evidence bundle does not contain an SD-JWT VC presentation");
    }

    let mut proofs = Vec::new();
    let mut last_rejection = None;
    for presentation in presentations {
        let binding = RequestBinding {
            nonce: context.nonce.clone(),
            aud: context.aud.clone(),
        };
        let status_token = match supplied_status_token.as_ref() {
            Some(token) => token.trim().to_string(),
            None => {
                fetch_status_token_for_presentation(
                    presentation,
                    &binding,
                    &context,
                    &anchors,
                    fetcher,
                )
                .await?
            }
        };
        let options = TrustOptions {
            anchors: Some(&anchors),
            status: StatusInput::Token {
                jws: status_token,
                signer: status_signer.clone(),
            },
        };
        match verify_pid_presentation_full(
            presentation,
            &binding,
            &context.vct,
            context.max_age_secs,
            context.now_unix,
            &options,
        ) {
            Ok(pid) => {
                if pid.status_ref.is_none() {
                    last_rejection =
                        Some("presentation has no token-status-list reference".to_string());
                    continue;
                }
                let mut disclosed_claim_keys = pid
                    .view
                    .disclosed
                    .iter()
                    .map(|claim| claim.key())
                    .collect::<Vec<_>>();
                disclosed_claim_keys.sort();
                disclosed_claim_keys.dedup();
                proofs.push(TrustStatusPresentationProof {
                    presentation_sha256: sha256_hex(presentation.as_bytes()),
                    vct: pid.vct,
                    holder_bound: pid.holder_bound,
                    trust_anchored: true,
                    status_checked: true,
                    status_list_ref_present: true,
                    status_uri_sha256: pid
                        .status_ref
                        .as_ref()
                        .map(|status_ref| sha256_hex(status_ref.uri.as_bytes())),
                    disclosed_claim_keys,
                    redacted: true,
                });
            }
            Err(reason) => {
                last_rejection = Some(format!("{:?}: {}", reason.kind, reason.reason));
            }
        }
    }

    if proofs.is_empty() {
        let reason = last_rejection.unwrap_or_else(|| "no presentation verified".to_string());
        let session = check.bundle.payload.session.clone();
        let payload_sha256 = check.payload_sha256.clone();
        let signature = check.signature_status.clone();
        let value = json!({
            "valid": false,
            "session": session.clone(),
            "payloadSha256": payload_sha256.clone(),
            "signature": signature.clone(),
            "reason": reason.clone(),
            "redacted": true,
        });
        let text = format!("EVIDENCE TRUST/STATUS REJECTED\nsession: {}\nreason: {}\npayloadSha256: {}\nsignature: {}\nredacted: true\n",
            session,
            reason,
            payload_sha256,
            signature,
        );
        emit(format, &value, &text)?;
        return Ok(false);
    }

    let proof = TrustStatusProof {
        valid: true,
        session: check.bundle.payload.session,
        signature: check.signature_status,
        payload_sha256: check.payload_sha256,
        status_token_source: token_source.to_string(),
        presentations: proofs,
        redacted: true,
        notes: vec![
            "bundle hashes, replay determinism, issuer trust, and supplied status-list token all verified"
                .to_string(),
            "pair this with evidence assert-live when the claim also needs a completed encrypted phone-wallet exchange"
                .to_string(),
            "output is redacted; disclosed claim values and raw wallet material stay inside the local evidence bundle"
                .to_string(),
        ],
    };
    let text = render_trust_status_proof(&proof);
    let value = serde_json::to_value(&proof).context("serialize trust/status proof")?;
    emit(format, &value, &text)?;
    Ok(true)
}

async fn fetch_status_token_for_presentation(
    presentation: &str,
    binding: &RequestBinding,
    context: &VerificationContext,
    anchors: &TrustAnchors,
    fetcher: &StatusFetcher,
) -> Result<String> {
    let verified = verify_pid_presentation_full(
        presentation,
        binding,
        &context.vct,
        context.max_age_secs,
        context.now_unix,
        &TrustOptions {
            anchors: Some(anchors),
            status: StatusInput::None,
        },
    )
    .map_err(|reason| anyhow::anyhow!("{:?}: {}", reason.kind, reason.reason))?;
    let status_ref = verified
        .status_ref
        .as_ref()
        .context("presentation has no token-status-list reference")?;
    fetcher.fetch(&status_ref.uri).await
}

fn build_bundle(session_dir: &Path, signing_key: Option<&Path>) -> Result<EvidenceBundle> {
    let manifest_path = session_dir.join("debug-manifest.json");
    let manifest_bytes = fs::read(&manifest_path)
        .with_context(|| format!("read source manifest {}", manifest_path.display()))?;
    let manifest: SourceManifest = serde_json::from_slice(&manifest_bytes)
        .with_context(|| format!("parse source manifest {}", manifest_path.display()))?;
    validate_source_manifest(&manifest)?;

    let mut entries = manifest.entries.clone();
    entries.sort_by(|a, b| a.filename.cmp(&b.filename));
    let evidence_entries = entries
        .iter()
        .map(|entry| evidence_entry(session_dir, entry))
        .collect::<Result<Vec<_>>>()?;
    let replay_trace = replay_from_entries(&manifest.session, &evidence_entries)?;
    let payload = EvidencePayload {
        source_kind: manifest.kind,
        session: manifest.session,
        source_manifest_sha256: sha256_hex(&manifest_bytes),
        sensitive: true,
        entries: evidence_entries,
        replay_trace,
        caveats: vec![
            "contains raw wallet direct_post material and decrypted authorization-response material when present".to_string(),
            "contains verifier session response encryption key material when captured".to_string(),
            evidence_bundle_permission_caveat().to_string(),
            "share only through an explicit evidence handling process".to_string(),
        ],
    };
    let payload_bytes = payload_bytes(&payload)?;
    let payload_sha256 = sha256_hex(&payload_bytes);
    let signature = match signing_key {
        Some(path) => Some(sign_payload(path, &payload_bytes)?),
        None => None,
    };
    Ok(EvidenceBundle {
        schema_version: SCHEMA_VERSION,
        kind: BUNDLE_KIND.to_string(),
        tool: ToolInfo {
            name: "augenmass".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        payload_sha256,
        payload,
        signature,
    })
}

fn validate_source_manifest(manifest: &SourceManifest) -> Result<()> {
    if manifest.schema_version != SCHEMA_VERSION {
        bail!(
            "unsupported source manifest schemaVersion {}, expected {}",
            manifest.schema_version,
            SCHEMA_VERSION
        );
    }
    if manifest.kind != SOURCE_KIND {
        bail!(
            "unsupported source manifest kind {}, expected {}",
            manifest.kind,
            SOURCE_KIND
        );
    }
    if !manifest.sensitive {
        bail!("source manifest is not marked sensitive");
    }
    if manifest.session.trim().is_empty() {
        bail!("source manifest has no session id");
    }
    Ok(())
}

fn evidence_entry(session_dir: &Path, entry: &SourceEntry) -> Result<EvidenceEntry> {
    if !is_plain_filename(&entry.filename) {
        bail!(
            "source manifest entry has unsafe filename {}",
            entry.filename
        );
    }
    let path = session_dir.join(&entry.filename);
    let bytes = fs::read(&path).with_context(|| format!("read artifact {}", path.display()))?;
    let sha256 = sha256_hex(&bytes);
    if bytes.len() != entry.len {
        bail!(
            "artifact {} length mismatch: manifest {}, actual {}",
            entry.filename,
            entry.len,
            bytes.len()
        );
    }
    if sha256 != entry.sha256 {
        bail!(
            "artifact {} hash mismatch: manifest {}, actual {}",
            entry.filename,
            entry.sha256,
            sha256
        );
    }
    Ok(EvidenceEntry {
        label: entry.label.clone(),
        filename: entry.filename.clone(),
        len: entry.len,
        sha256,
        media_type: media_type(&entry.filename).to_string(),
        content_b64: URL_SAFE_NO_PAD.encode(bytes),
    })
}

fn is_plain_filename(filename: &str) -> bool {
    !filename.is_empty()
        && !filename.contains('/')
        && !filename.contains('\\')
        && filename != "."
        && filename != ".."
}

fn media_type(filename: &str) -> &'static str {
    if filename.ends_with(".json") || filename.ends_with(".jwk") {
        "application/json"
    } else if filename.ends_with(".jwt") {
        "application/oauth-authz-req+jwt"
    } else {
        "text/plain"
    }
}

#[cfg(unix)]
fn evidence_bundle_permission_caveat() -> &'static str {
    "bundle file permissions are tightened to owner-only mode on Unix (0600)"
}

#[cfg(not(unix))]
fn evidence_bundle_permission_caveat() -> &'static str {
    "bundle file permissions are not tightened by this build; store the bundle in a private or encrypted workspace"
}

fn write_bundle(path: &Path, bundle: &EvidenceBundle) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let data = serde_json::to_string_pretty(bundle)? + "\n";
    fs::write(path, data).with_context(|| format!("write evidence bundle {}", path.display()))?;
    tighten_file_permissions(path)
}

fn check_bundle(path: &Path, verify_key: Option<&Path>) -> Result<BundleCheck> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("read evidence bundle {}", path.display()))?;
    let bundle: EvidenceBundle = serde_json::from_str(&text)
        .with_context(|| format!("parse evidence bundle {}", path.display()))?;
    if bundle.schema_version != SCHEMA_VERSION {
        bail!(
            "unsupported evidence bundle schemaVersion {}, expected {}",
            bundle.schema_version,
            SCHEMA_VERSION
        );
    }
    if bundle.kind != BUNDLE_KIND {
        bail!("unsupported evidence bundle kind {}", bundle.kind);
    }
    if bundle.payload.source_kind != SOURCE_KIND {
        bail!(
            "unsupported evidence source kind {}",
            bundle.payload.source_kind
        );
    }
    if !bundle.payload.sensitive {
        bail!("evidence payload is not marked sensitive");
    }
    for entry in &bundle.payload.entries {
        check_entry(entry)?;
    }
    let replay = replay_from_entries(&bundle.payload.session, &bundle.payload.entries)?;
    if replay != bundle.payload.replay_trace {
        bail!("bundle replay trace does not match its embedded artifacts");
    }
    let payload_bytes = payload_bytes(&bundle.payload)?;
    let payload_sha256 = sha256_hex(&payload_bytes);
    if payload_sha256 != bundle.payload_sha256 {
        bail!(
            "payload hash mismatch: bundle {}, actual {}",
            bundle.payload_sha256,
            payload_sha256
        );
    }
    let signature_status = verify_signature(&bundle, &payload_bytes, verify_key)?;
    Ok(BundleCheck {
        bundle,
        payload_sha256,
        signature_status,
    })
}

fn check_entry(entry: &EvidenceEntry) -> Result<()> {
    if !is_plain_filename(&entry.filename) {
        bail!("bundle entry has unsafe filename {}", entry.filename);
    }
    let bytes = entry_bytes(entry)?;
    let sha256 = sha256_hex(&bytes);
    if bytes.len() != entry.len {
        bail!(
            "bundle entry {} length mismatch: declared {}, actual {}",
            entry.filename,
            entry.len,
            bytes.len()
        );
    }
    if sha256 != entry.sha256 {
        bail!(
            "bundle entry {} hash mismatch: declared {}, actual {}",
            entry.filename,
            entry.sha256,
            sha256
        );
    }
    Ok(())
}

struct LiveEvidenceProof {
    required_events: Vec<String>,
}

fn assert_live_wallet_trace(replay: &ReplayTrace) -> Result<LiveEvidenceProof> {
    if !replay.redacted {
        bail!("evidence replay trace is not marked redacted");
    }
    for event in &replay.events {
        if matches!(event.code.as_str(), "REJECTED" | "ERROR") {
            bail!(
                "evidence replay contains terminal failure event {}: {}",
                event.code,
                event.summary
            );
        }
        if let Some(detail) = &event.detail {
            let redacted = detail
                .get("redacted")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if !redacted {
                bail!(
                    "evidence replay event {} detail is not redacted",
                    event.code
                );
            }
        }
    }

    let required = [
        "SESSION_CREATED",
        "REQUEST_BUILT",
        "REQUEST_OBJECT_FETCHED",
        "RESPONSE_RECEIVED",
        "RESPONSE_DECRYPTED",
        "VERIFIED",
    ];
    for code in required {
        if !replay.events.iter().any(|event| event.code == code) {
            bail!("evidence replay does not contain required event {code}");
        }
    }
    let verified = replay
        .events
        .iter()
        .find(|event| event.code == "VERIFIED")
        .context("evidence replay does not contain required event VERIFIED")?;
    if verified.level != "good" {
        bail!("evidence replay VERIFIED event is not good");
    }

    Ok(LiveEvidenceProof {
        required_events: required.iter().map(|code| (*code).to_string()).collect(),
    })
}

fn payload_bytes(payload: &EvidencePayload) -> Result<Vec<u8>> {
    serde_json::to_vec(payload).context("serialize evidence payload")
}

fn sign_payload(path: &Path, payload_bytes: &[u8]) -> Result<EvidenceSignature> {
    let pem =
        fs::read_to_string(path).with_context(|| format!("read signing key {}", path.display()))?;
    let key = SigningKey::from_pkcs8_pem(&pem).context("parse P-256 PKCS#8 signing key")?;
    let signature: Signature = key.sign(payload_bytes);
    let public_key_pem = VerifyingKey::from(&key)
        .to_public_key_pem(LineEnding::LF)
        .context("encode public key")?;
    Ok(EvidenceSignature {
        alg: "ES256".to_string(),
        public_key_sha256: sha256_hex(public_key_pem.as_bytes()),
        public_key_pem,
        signature_b64: URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
    })
}

fn verify_signature(
    bundle: &EvidenceBundle,
    payload_bytes: &[u8],
    verify_key: Option<&Path>,
) -> Result<String> {
    let Some(signature) = bundle.signature.as_ref() else {
        if verify_key.is_some() {
            bail!("bundle is unsigned but --verify-key was provided");
        }
        return Ok("absent".to_string());
    };
    if signature.alg != "ES256" {
        bail!("unsupported evidence signature alg {}", signature.alg);
    }
    let public_key_pem = match verify_key {
        Some(path) => fs::read_to_string(path)
            .with_context(|| format!("read verify key {}", path.display()))?,
        None => signature.public_key_pem.clone(),
    };
    let actual_key_hash = sha256_hex(public_key_pem.as_bytes());
    if verify_key.is_none() && actual_key_hash != signature.public_key_sha256 {
        bail!(
            "embedded public key hash mismatch: declared {}, actual {}",
            signature.public_key_sha256,
            actual_key_hash
        );
    }
    let key =
        VerifyingKey::from_public_key_pem(&public_key_pem).context("parse P-256 public key")?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(&signature.signature_b64)
        .context("decode evidence signature")?;
    let sig = Signature::from_der(&sig_bytes).context("parse ECDSA signature")?;
    key.verify(payload_bytes, &sig)
        .context("verify evidence bundle signature")?;
    Ok(if verify_key.is_some() {
        "valid with supplied key".to_string()
    } else {
        "valid with embedded key".to_string()
    })
}

fn replay_from_entries(session: &str, entries: &[EvidenceEntry]) -> Result<ReplayTrace> {
    let mut replay = ReplayBuilder::new(session);
    replay.push(
        "SESSION_CREATED",
        "info",
        "replayed session from an evidence bundle",
        Some(json!({
            "source": "evidence bundle",
            "redacted": true,
        })),
    );
    if let Some(payload) = json_entry(entries, "request.payload.json")? {
        replay.push(
            "REQUEST_BUILT",
            "info",
            "rebuilt redacted authorization request context",
            Some(request_context_detail(&payload)),
        );
    }
    if let Some(entry) = find_entry(entries, "request.jwt") {
        replay.push(
            "REQUEST_OBJECT_FETCHED",
            "info",
            "replayed signed request object fetch",
            Some(compact_jwt_detail(entry)?),
        );
    }
    for entry in entries {
        replay.push(
            "ARTIFACT_SAVED",
            "info",
            format!("bundle contains {}", safe_artifact_label(&entry.filename)),
            Some(artifact_detail(entry)),
        );
    }
    if let Some(entry) = find_entry(entries, "direct-post.body") {
        let body = String::from_utf8(entry_bytes(entry)?)
            .with_context(|| format!("artifact {} is not UTF-8", entry.filename))?;
        let fields = form_fields(&body);
        let mode = if fields.iter().any(|field| field == "response") {
            "direct_post.jwt (encrypted)"
        } else {
            "direct_post (plaintext)"
        };
        replay.push(
            "RESPONSE_RECEIVED",
            "info",
            format!("replayed wallet response ({mode})"),
            Some(redacted_response_detail(mode, &body)),
        );
        if mode == "direct_post (plaintext)" {
            replay.push(
                "REJECTED",
                "bad",
                "plaintext direct_post response rejected in original safety model",
                Some(json!({
                    "reason": "plaintext direct_post response rejected",
                    "redacted": true,
                })),
            );
        }
    }
    if let Some(decrypted) = decrypted_response(entries)? {
        replay.push(
            "RESPONSE_DECRYPTED",
            "info",
            "replayed decrypted JWE response metadata",
            Some(redacted_decrypted_detail(&decrypted)),
        );
        if let Some(result) = offline_verify_detail(entries, &decrypted)? {
            replay.push(
                if result.verified {
                    "VERIFIED"
                } else {
                    "REJECTED"
                },
                if result.verified { "good" } else { "bad" },
                result.summary,
                Some(result.detail),
            );
        }
    }
    Ok(replay.finish())
}

fn decrypted_response(entries: &[EvidenceEntry]) -> Result<Option<Value>> {
    let from_raw = decrypt_from_direct_post(entries)?;
    let from_artifact = json_entry(entries, "auth-response.json")?;
    match (from_raw, from_artifact) {
        (Some(raw), Some(artifact)) => {
            if raw != artifact {
                bail!("auth-response.json does not match direct-post.body decrypted with session-enc-key.jwk");
            }
            Ok(Some(raw))
        }
        (Some(raw), None) => Ok(Some(raw)),
        (None, Some(artifact)) => Ok(Some(artifact)),
        (None, None) => Ok(None),
    }
}

fn decrypt_from_direct_post(entries: &[EvidenceEntry]) -> Result<Option<Value>> {
    let (Some(body_entry), Some(key_entry)) = (
        find_entry(entries, "direct-post.body"),
        find_entry(entries, "session-enc-key.jwk"),
    ) else {
        return Ok(None);
    };
    let body = String::from_utf8(entry_bytes(body_entry)?)
        .with_context(|| format!("artifact {} is not UTF-8", body_entry.filename))?;
    let response = AuthorizationResponse::from_x_www_form_urlencoded(body.as_bytes())
        .context("parse direct_post body")?;
    let AuthorizationResponse::Jwt(jwt) = response else {
        return Ok(None);
    };
    let key_bytes = entry_bytes(key_entry)?;
    let key: JWK = serde_json::from_slice(&key_bytes).context("parse session response JWK")?;
    decrypt_jwe(&jwt.response, &key)
        .context("decrypt direct_post.jwt from evidence bundle")
        .map(Some)
}

struct ReplayBuilder {
    session: String,
    seq: u64,
    events: Vec<ReplayEvent>,
}

impl ReplayBuilder {
    fn new(session: &str) -> Self {
        Self {
            session: session.to_string(),
            seq: 1,
            events: Vec::new(),
        }
    }

    fn push(
        &mut self,
        code: impl Into<String>,
        level: impl Into<String>,
        summary: impl Into<String>,
        detail: Option<Value>,
    ) {
        let event = ReplayEvent {
            seq: self.seq,
            code: code.into(),
            level: level.into(),
            summary: summary.into(),
            detail,
        };
        self.seq += 1;
        self.events.push(event);
    }

    fn finish(self) -> ReplayTrace {
        ReplayTrace {
            session: self.session,
            redacted: true,
            events: self.events,
        }
    }
}

struct OfflineVerify {
    verified: bool,
    summary: String,
    detail: Value,
}

struct VerificationContext {
    nonce: String,
    aud: String,
    now_unix: i64,
    max_age_secs: i64,
    vct: String,
}

fn offline_verify_detail(
    entries: &[EvidenceEntry],
    decrypted: &Value,
) -> Result<Option<OfflineVerify>> {
    let Some(context) = json_entry(entries, "verification-context.json")? else {
        return Ok(Some(OfflineVerify {
            verified: false,
            summary: "offline verification skipped: verification-context.json not captured"
                .to_string(),
            detail: json!({
                "reason": "missing verification-context.json",
                "redacted": true,
            }),
        }));
    };
    let nonce = context
        .get("nonce")
        .and_then(Value::as_str)
        .context("verification-context.json missing nonce")?;
    let aud = context
        .get("aud")
        .and_then(Value::as_str)
        .context("verification-context.json missing aud")?;
    let now = context
        .get("nowUnix")
        .and_then(Value::as_i64)
        .context("verification-context.json missing nowUnix")?;
    let max_age = context
        .get("maxAgeSecs")
        .and_then(Value::as_i64)
        .unwrap_or(300);
    let vct = context
        .get("vct")
        .and_then(Value::as_str)
        .unwrap_or(PID_VCT);
    let binding = RequestBinding {
        nonce: nonce.to_string(),
        aud: aud.to_string(),
    };
    let presentations = presentations_from_decrypted(decrypted);
    if presentations.is_empty() {
        return Ok(Some(OfflineVerify {
            verified: false,
            summary: "offline verification rejected: no SD-JWT VC presentation found".to_string(),
            detail: json!({
                "reason": "no SD-JWT VC presentation found",
                "redacted": true,
            }),
        }));
    }
    let mut last_detail = None;
    for presentation in presentations {
        match verify_pid_presentation_full(
            presentation,
            &binding,
            vct,
            max_age,
            now,
            &TrustOptions {
                anchors: None,
                status: StatusInput::None,
            },
        ) {
            Ok(verified) => {
                let disclosed = verified
                    .view
                    .disclosed
                    .iter()
                    .map(|claim| claim.key())
                    .collect::<Vec<_>>();
                last_detail = Some(OfflineVerify {
                    verified: true,
                    summary: format!(
                        "offline replay verified presentation: {} ({} claim(s) disclosed)",
                        verified.vct,
                        disclosed.len()
                    ),
                    detail: json!({
                        "vct": verified.vct,
                        "disclosed": disclosed,
                        "holderBound": verified.holder_bound,
                        "trust": "not checked by evidence replay",
                        "status": "not checked by evidence replay",
                        "redacted": true,
                    }),
                });
            }
            Err(e) => {
                return Ok(Some(OfflineVerify {
                    verified: false,
                    summary: format!("offline verification rejected: {e}"),
                    detail: json!({
                        "reason": e.to_string(),
                        "redacted": true,
                    }),
                }));
            }
        }
    }
    Ok(last_detail)
}

fn verification_context(entries: &[EvidenceEntry]) -> Result<VerificationContext> {
    let context = json_entry(entries, "verification-context.json")?
        .context("evidence bundle does not contain verification-context.json")?;
    Ok(VerificationContext {
        nonce: context
            .get("nonce")
            .and_then(Value::as_str)
            .context("verification-context.json missing nonce")?
            .to_string(),
        aud: context
            .get("aud")
            .and_then(Value::as_str)
            .context("verification-context.json missing aud")?
            .to_string(),
        now_unix: context
            .get("nowUnix")
            .and_then(Value::as_i64)
            .context("verification-context.json missing nowUnix")?,
        max_age_secs: context
            .get("maxAgeSecs")
            .and_then(Value::as_i64)
            .unwrap_or(300),
        vct: context
            .get("vct")
            .and_then(Value::as_str)
            .unwrap_or(PID_VCT)
            .to_string(),
    })
}

fn presentations_from_decrypted(value: &Value) -> Vec<&str> {
    let vp = value.get("vp_token").unwrap_or(&Value::Null);
    let entries: Vec<&Value> = match vp {
        Value::Object(map) => map.values().collect(),
        other => vec![other],
    };
    let mut presentations = Vec::new();
    for entry in entries {
        match entry {
            Value::Array(arr) => presentations.extend(arr.iter().filter_map(Value::as_str)),
            Value::String(s) => presentations.push(s.as_str()),
            _ => {}
        }
    }
    presentations
}

fn profile_from_bundle(bundle: &EvidenceBundle, signature_status: &str) -> Result<EvidenceProfile> {
    let decrypted = decrypted_response(&bundle.payload.entries)?;
    let presentations = decrypted
        .as_ref()
        .map(presentations_from_decrypted)
        .unwrap_or_default()
        .into_iter()
        .map(presentation_profile)
        .collect::<Result<Vec<_>>>()?;
    let live_wallet_proven = assert_live_wallet_trace(&bundle.payload.replay_trace).is_ok();
    let issuer_x5c_present = presentations
        .iter()
        .any(|profile| profile.issuer_header.x5c_count > 0);
    let status_list_ref_present = presentations
        .iter()
        .any(|profile| profile.status_list.present);
    let live_status_claim_possible = presentations
        .iter()
        .any(|profile| profile.status_list.present && profile.status_list.uri_https);
    let trust_anchor_claim_possible = issuer_x5c_present;
    let mut notes = Vec::new();
    if trust_anchor_claim_possible {
        notes.push(
            "issuer x5c is present; a trust claim still needs the matching external issuer anchor PEM"
                .to_string(),
        );
    } else {
        notes.push(
            "issuer x5c is absent; this bundle cannot support a trust-anchor claim".to_string(),
        );
    }
    if live_status_claim_possible {
        notes.push(
            "status-list reference is present and HTTPS; a live-status claim still needs the fetched token and trusted status signer"
                .to_string(),
        );
    } else if status_list_ref_present {
        notes.push(
            "status-list reference is present but is not an HTTPS URI in the redacted profile"
                .to_string(),
        );
    } else {
        notes.push("status-list reference is absent; no live-status check is possible from this credential".to_string());
    }

    Ok(EvidenceProfile {
        session: bundle.payload.session.clone(),
        signature: signature_status.to_string(),
        entries: bundle.payload.entries.len(),
        replay_events: bundle.payload.replay_trace.events.len(),
        presentations,
        readiness: ProfileReadiness {
            live_wallet_proven,
            issuer_x5c_present,
            status_list_ref_present,
            trust_anchor_claim_possible,
            live_status_claim_possible,
            notes,
        },
        redacted: true,
    })
}

fn presentation_profile(presentation: &str) -> Result<PresentationProfile> {
    let issuer_jwt = presentation.split('~').next().unwrap_or(presentation);
    let decoded = jose::decode_compact(issuer_jwt).ok();
    let header = decoded.as_ref().map(|jwt| &jwt.header);
    let payload = decoded.as_ref().map(|jwt| &jwt.payload);
    let issuer_header = issuer_header_profile(header);
    let issuer_claim_fields = payload.map(object_keys).unwrap_or_default();
    let vct = payload
        .and_then(|value| value.get("vct"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let disclosed_claim_keys = disclosed_claim_keys(presentation);
    let status_list = payload
        .map(status_list_profile)
        .unwrap_or_else(absent_status_list_profile);

    Ok(PresentationProfile {
        presentation_sha256: sha256_hex(presentation.as_bytes()),
        issuer_header,
        issuer_claim_fields,
        vct,
        disclosed_claim_keys,
        status_list,
        redacted: true,
    })
}

fn issuer_header_profile(header: Option<&Value>) -> IssuerHeaderProfile {
    let alg = header
        .and_then(|value| value.get("alg"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let typ = header
        .and_then(|value| value.get("typ"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let x5c_count = header
        .and_then(|value| value.get("x5c"))
        .map(|x5c| match x5c {
            Value::Array(items) => items.len(),
            Value::String(_) => 1,
            _ => 0,
        })
        .unwrap_or(0);
    let leaf_cert_sha256 = header
        .and_then(|value| jose::leaf_der_from_x5c(value).ok())
        .map(|der| sha256_hex(&der));
    IssuerHeaderProfile {
        alg,
        typ,
        x5c_count,
        leaf_cert_sha256,
    }
}

fn disclosed_claim_keys(presentation: &str) -> Vec<String> {
    let Some(view) = SdJwt::new(presentation)
        .ok()
        .and_then(|sd_jwt| revealed_claims(sd_jwt).ok())
    else {
        return Vec::new();
    };
    let mut keys = view
        .disclosed
        .iter()
        .map(|claim| claim.key())
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    keys
}

fn status_list_profile(payload: &Value) -> StatusListProfile {
    let Some(status_list) = payload.pointer("/status/status_list") else {
        return absent_status_list_profile();
    };
    let idx_present = status_list.get("idx").and_then(Value::as_u64).is_some();
    let uri = status_list.get("uri").and_then(Value::as_str);
    let uri_present = uri.is_some();
    let uri_sha256 = uri.map(|value| sha256_hex(value.as_bytes()));
    let parsed = uri.and_then(|value| url::Url::parse(value).ok());
    let uri_https = parsed
        .as_ref()
        .map(|value| value.scheme() == "https")
        .unwrap_or(false);
    let uri_host = parsed
        .as_ref()
        .and_then(url::Url::host_str)
        .map(ToString::to_string);
    StatusListProfile {
        present: true,
        idx_present,
        uri_present,
        uri_https,
        uri_host,
        uri_sha256,
    }
}

fn absent_status_list_profile() -> StatusListProfile {
    StatusListProfile {
        present: false,
        idx_present: false,
        uri_present: false,
        uri_https: false,
        uri_host: None,
        uri_sha256: None,
    }
}

fn object_keys(value: &Value) -> Vec<String> {
    let mut keys = value
        .as_object()
        .map(|map| map.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    keys.sort();
    keys
}

fn request_context_detail(payload: &Value) -> Value {
    let dcql_count = payload
        .get("dcql_query")
        .and_then(|dcql| dcql.get("credentials"))
        .and_then(Value::as_array)
        .map(|items| items.len())
        .unwrap_or(0);
    let key_id = payload
        .pointer("/client_metadata/jwks/keys/0/kid")
        .and_then(Value::as_str);
    let mut keys = payload
        .as_object()
        .map(|map| map.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    keys.sort();
    json!({
        "clientId": payload.get("client_id").and_then(Value::as_str),
        "nonce": payload.get("nonce").and_then(Value::as_str),
        "responseEncryptionKeyId": key_id,
        "dcqlCredentialCount": dcql_count,
        "payloadFields": keys,
        "redacted": true,
    })
}

fn compact_jwt_detail(entry: &EvidenceEntry) -> Result<Value> {
    let jwt = String::from_utf8(entry_bytes(entry)?)
        .with_context(|| format!("artifact {} is not UTF-8", entry.filename))?;
    let decoded = jose::decode_compact(&jwt).ok();
    Ok(json!({
        "jwtLen": jwt.len(),
        "jwtSha256": sha256_hex(jwt.as_bytes()),
        "partCount": jwt.split('.').count(),
        "header": decoded.as_ref().map(|d| d.header.clone()),
        "payloadFields": decoded
            .as_ref()
            .and_then(|d| d.payload.as_object())
            .map(|map| {
                let mut keys = map.keys().cloned().collect::<Vec<_>>();
                keys.sort();
                keys
            })
            .unwrap_or_default(),
        "redacted": true,
    }))
}

fn redacted_response_detail(mode: &str, body: &str) -> Value {
    let fields = form_fields(body);
    let state = url::form_urlencoded::parse(body.as_bytes())
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned());
    let response = url::form_urlencoded::parse(body.as_bytes())
        .find(|(key, _)| key == "response")
        .map(|(_, value)| compact_jwe_summary(&value))
        .unwrap_or_else(|| {
            json!({
                "present": false,
                "plaintext": true,
                "redacted": true,
            })
        });
    json!({
        "mode": mode,
        "bodyLen": body.len(),
        "bodySha256": sha256_hex(body.as_bytes()),
        "fields": fields,
        "state": state,
        "response": response,
        "redacted": true,
        "redaction": "direct_post body and wallet tokens are not exposed by evidence replay"
    })
}

fn compact_jwe_summary(response: &str) -> Value {
    let parts = response.split('.').collect::<Vec<_>>();
    json!({
        "present": true,
        "len": response.len(),
        "sha256": sha256_hex(response.as_bytes()),
        "partCount": parts.len(),
        "compactJwe": parts.len() == 5,
        "protectedHeaderB64Len": parts.first().map(|part| part.len()).unwrap_or(0),
        "redacted": true,
    })
}

fn redacted_decrypted_detail(value: &Value) -> Value {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    let body = value
        .get("authorization_response")
        .or_else(|| value.get("auth_response"))
        .or_else(|| value.get("body"))
        .and_then(Value::as_object)
        .or_else(|| value.as_object());
    let mut fields = body
        .map(|body| body.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    fields.sort();
    let vp_token = body
        .and_then(|body| body.get("vp_token"))
        .unwrap_or(&Value::Null);
    json!({
        "bodyLen": bytes.len(),
        "bodySha256": sha256_hex(&bytes),
        "fields": fields,
        "state": body.and_then(|body| body.get("state")).and_then(Value::as_str),
        "vpTokenPresent": !vp_token.is_null(),
        "vpTokenShape": value_shape(vp_token),
        "redacted": true,
        "redaction": "decrypted authorization response and wallet tokens are not exposed by evidence replay"
    })
}

fn value_shape(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn form_fields(body: &str) -> Vec<String> {
    let mut fields = url::form_urlencoded::parse(body.as_bytes())
        .map(|(key, _)| key.into_owned())
        .collect::<Vec<_>>();
    fields.sort();
    fields.dedup();
    fields
}

fn artifact_detail(entry: &EvidenceEntry) -> Value {
    json!({
        "artifact": {
            "label": safe_artifact_label(&entry.filename),
            "filename": entry.filename,
            "len": entry.len,
            "sha256": entry.sha256,
        },
        "unsafeDebugArtifacts": true,
        "pathRedacted": true,
        "redacted": true,
    })
}

fn safe_artifact_label(filename: &str) -> &'static str {
    match filename {
        "request.jwt" => "signed authorization request JAR",
        "request.payload.json" => "decoded authorization request payload",
        "direct-post.body" => "raw direct_post form body",
        "auth-response.json" => "decrypted authorization response",
        "session-enc-key.jwk" => "session response encryption private JWK",
        "verification-context.json" => "verification replay context",
        _ => "additional local artifact",
    }
}

fn read_text_arg(arg: &str) -> Result<String> {
    let path = Path::new(arg);
    if path.is_file() {
        fs::read_to_string(path).with_context(|| format!("read {arg}"))
    } else {
        Ok(arg.to_string())
    }
}

fn json_entry(entries: &[EvidenceEntry], filename: &str) -> Result<Option<Value>> {
    let Some(entry) = find_entry(entries, filename) else {
        return Ok(None);
    };
    let bytes = entry_bytes(entry)?;
    let value = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse JSON artifact {}", entry.filename))?;
    Ok(Some(value))
}

fn find_entry<'a>(entries: &'a [EvidenceEntry], filename: &str) -> Option<&'a EvidenceEntry> {
    entries.iter().find(|entry| entry.filename == filename)
}

fn entry_bytes(entry: &EvidenceEntry) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(&entry.content_b64)
        .with_context(|| format!("decode bundle entry {}", entry.filename))
}

fn render_replay(replay: &ReplayTrace, signature_status: &str) -> String {
    let mut out = format!(
        "EVIDENCE REPLAY (redacted)\nsession: {}\nsignature: {}\n",
        replay.session, signature_status
    );
    for event in &replay.events {
        out.push_str(&format!(
            "{:02} {:<22} {:<5} {}\n",
            event.seq, event.code, event.level, event.summary
        ));
    }
    out
}

fn render_trust_status_proof(proof: &TrustStatusProof) -> String {
    let mut out = format!(
        "EVIDENCE TRUST/STATUS PROVEN\nsession: {}\npayloadSha256: {}\nsignature: {}\nstatusTokenSource: {}\npresentations: {}\nredacted: true\n",
        proof.session,
        proof.payload_sha256,
        proof.signature,
        proof.status_token_source,
        proof.presentations.len(),
    );
    for (idx, presentation) in proof.presentations.iter().enumerate() {
        out.push_str(&format!(
            "\npresentation #{}\n  sha256: {}\n  vct: {}\n  holder binding: {}\n  trust anchored: {}\n  status checked: {}\n  status-list ref: {}\n  disclosed keys: {}\n",
            idx + 1,
            presentation.presentation_sha256,
            presentation.vct,
            presentation.holder_bound,
            presentation.trust_anchored,
            presentation.status_checked,
            presentation.status_list_ref_present,
            list_or_dash(&presentation.disclosed_claim_keys),
        ));
        if let Some(hash) = &presentation.status_uri_sha256 {
            out.push_str(&format!("  status uri sha256: {hash}\n"));
        }
    }
    out.push_str("\nnotes:\n");
    for note in &proof.notes {
        out.push_str(&format!("  - {note}\n"));
    }
    out
}

fn render_profile(profile: &EvidenceProfile) -> String {
    let mut out = format!(
        "EVIDENCE PROFILE (redacted)\nsession: {}\nsignature: {}\nentries: {}\nreplayEvents: {}\npresentations: {}\n",
        profile.session,
        profile.signature,
        profile.entries,
        profile.replay_events,
        profile.presentations.len()
    );
    out.push_str(&format!(
        "liveWalletProven: {}\nissuerX5cPresent: {}\nstatusListRefPresent: {}\ntrustAnchorClaimPossible: {}\nliveStatusClaimPossible: {}\n",
        profile.readiness.live_wallet_proven,
        profile.readiness.issuer_x5c_present,
        profile.readiness.status_list_ref_present,
        profile.readiness.trust_anchor_claim_possible,
        profile.readiness.live_status_claim_possible
    ));
    for (idx, presentation) in profile.presentations.iter().enumerate() {
        out.push_str(&format!(
            "\npresentation #{}\n  sha256: {}\n  vct: {}\n  issuer alg/typ: {}/{}\n  x5c count: {}\n",
            idx + 1,
            presentation.presentation_sha256,
            presentation.vct.as_deref().unwrap_or("unknown"),
            presentation.issuer_header.alg.as_deref().unwrap_or("unknown"),
            presentation.issuer_header.typ.as_deref().unwrap_or("unknown"),
            presentation.issuer_header.x5c_count,
        ));
        if let Some(hash) = &presentation.issuer_header.leaf_cert_sha256 {
            out.push_str(&format!("  leaf cert sha256: {hash}\n"));
        }
        out.push_str(&format!(
            "  issuer fields: {}\n  disclosed keys: {}\n",
            list_or_dash(&presentation.issuer_claim_fields),
            list_or_dash(&presentation.disclosed_claim_keys)
        ));
        if presentation.status_list.present {
            out.push_str(&format!(
                "  status-list: present, idx={}, uri={}, https={}, host={}\n",
                presentation.status_list.idx_present,
                presentation.status_list.uri_present,
                presentation.status_list.uri_https,
                presentation
                    .status_list
                    .uri_host
                    .as_deref()
                    .unwrap_or("redacted")
            ));
            if let Some(hash) = &presentation.status_list.uri_sha256 {
                out.push_str(&format!("  status-list uri sha256: {hash}\n"));
            }
        } else {
            out.push_str("  status-list: absent\n");
        }
    }
    out.push_str("\nnotes:\n");
    for note in &profile.readiness.notes {
        out.push_str(&format!("  - {note}\n"));
    }
    out
}

fn list_or_dash(items: &[String]) -> String {
    if items.is_empty() {
        "-".to_string()
    } else {
        items.join(", ")
    }
}

#[cfg(unix)]
fn tighten_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn tighten_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("{name}-{}", uuid::Uuid::new_v4()))
    }

    fn write_source_artifact(root: &Path, filename: &str, label: &str, text: &str) -> Value {
        fs::write(root.join(filename), text).expect("write source artifact");
        json!({
            "label": label,
            "filename": filename,
            "path": root.join(filename).display().to_string(),
            "len": text.len(),
            "sha256": sha256_hex(text.as_bytes()),
        })
    }

    fn b64_json(value: Value) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).expect("json bytes"))
    }

    fn fake_compact_jwt(header: Value, payload: Value) -> String {
        format!("{}.{}.", b64_json(header), b64_json(payload))
    }

    fn fixture(path: &str) -> String {
        fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures")
                .join(path),
        )
        .unwrap_or_else(|err| panic!("read fixture {path}: {err}"))
    }

    fn source_session() -> PathBuf {
        let root = unique_temp("augenmass-evidence-source");
        fs::create_dir_all(&root).expect("create temp source");
        let entries = vec![
            write_source_artifact(
                &root,
                "request.payload.json",
                "decoded authorization request payload",
                r#"{"client_id":"https://self-issued.me/v2","nonce":"b4ba2623-76a2-486b-a1f6-f1656025d07b","client_metadata":{"jwks":{"keys":[{"kid":"enc-1"}]}},"dcql_query":{"credentials":[{"id":"pid"}]}}"#,
            ),
            write_source_artifact(
                &root,
                "direct-post.body",
                "raw direct_post form body",
                "vp_token=secret-claim&state=abc",
            ),
            write_source_artifact(
                &root,
                "verification-context.json",
                "verification replay context",
                r#"{"nonce":"b4ba2623-76a2-486b-a1f6-f1656025d07b","aud":"https://self-issued.me/v2","nowUnix":1780435200,"maxAgeSecs":300,"vct":"urn:eudi:pid:de:1"}"#,
            ),
        ];
        let manifest = json!({
            "schemaVersion": 1,
            "kind": SOURCE_KIND,
            "session": "11111111-1111-4111-8111-111111111111",
            "sensitive": true,
            "entries": entries,
        });
        fs::write(
            root.join("debug-manifest.json"),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .expect("write manifest");
        root
    }

    fn source_session_with_auth_response(auth_response: &str) -> PathBuf {
        let root = source_session();
        fs::write(root.join("auth-response.json"), auth_response).expect("write auth response");
        let manifest_path = root.join("debug-manifest.json");
        let mut manifest: Value =
            serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
        manifest["entries"]
            .as_array_mut()
            .expect("entries")
            .push(json!({
                "label": "decrypted authorization response",
                "filename": "auth-response.json",
                "path": root.join("auth-response.json").display().to_string(),
                "len": auth_response.len(),
                "sha256": sha256_hex(auth_response.as_bytes()),
            }));
        fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .expect("rewrite manifest");
        root
    }

    #[test]
    fn export_verify_and_replay_are_redacted() {
        let source = source_session();
        let out = unique_temp("augenmass-evidence-bundle").join("bundle.json");
        let bundle = build_bundle(&source, None).expect("build bundle");
        write_bundle(&out, &bundle).expect("write bundle");

        let check = check_bundle(&out, None).expect("bundle verifies");
        assert_eq!(check.signature_status, "absent");
        let replay = serde_json::to_string(&check.bundle.payload.replay_trace).unwrap();
        assert!(replay.contains("bodySha256"));
        assert!(!replay.contains("secret-claim"));
        assert!(check
            .bundle
            .payload
            .caveats
            .iter()
            .any(|caveat| caveat == evidence_bundle_permission_caveat()));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&out).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let _ = fs::remove_dir_all(source);
        let _ = fs::remove_file(out);
    }

    #[test]
    fn replay_uses_canonical_labels_not_manifest_labels() {
        let source = source_session();
        let manifest_path = source.join("debug-manifest.json");
        let mut manifest: Value =
            serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
        manifest["entries"][1]["label"] = Value::String("secret-claim".to_string());
        fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .expect("rewrite manifest");

        let bundle = build_bundle(&source, None).expect("build bundle");
        let replay = serde_json::to_string(&bundle.payload.replay_trace).unwrap();
        assert!(!replay.contains("secret-claim"));
        assert!(replay.contains("raw direct_post form body"));

        let _ = fs::remove_dir_all(source);
    }

    #[test]
    fn profile_reports_status_readiness_without_payload_values() {
        let issuer = fake_compact_jwt(
            json!({
                "alg": "ES256",
                "typ": "vc+sd-jwt",
                "x5c": ["not-a-real-cert"],
            }),
            json!({
                "vct": PID_VCT,
                "secretValue": "Alice Example",
                "status": {
                    "status_list": {
                        "idx": 42,
                        "uri": "https://status.example.test/list.jwt"
                    }
                }
            }),
        );
        let presentation = format!("{issuer}~disclosure~kb.jwt.sig");
        let auth_response = serde_json::to_string(&json!({
            "vp_token": presentation,
            "state": "abc",
        }))
        .unwrap();
        let source = source_session_with_auth_response(&auth_response);
        let bundle = build_bundle(&source, None).expect("build bundle");

        let profile = profile_from_bundle(&bundle, "absent").expect("profile");
        assert_eq!(profile.presentations.len(), 1);
        assert!(profile.readiness.issuer_x5c_present);
        assert!(profile.readiness.status_list_ref_present);
        assert!(profile.readiness.live_status_claim_possible);
        assert_eq!(
            profile.presentations[0].status_list.uri_host.as_deref(),
            Some("status.example.test")
        );

        let rendered = serde_json::to_string(&profile).unwrap();
        assert!(rendered.contains("secretValue"));
        assert!(!rendered.contains("Alice Example"));
        assert!(!rendered.contains("https://status.example.test/list.jwt"));

        let _ = fs::remove_dir_all(source);
    }

    #[tokio::test]
    async fn prove_trust_status_accepts_fixture_bundle() {
        let presentation = fixture("presentations/synthetic-pid-with-status.sdjwt")
            .trim()
            .to_string();
        let auth_response = serde_json::to_string(&json!({
            "vp_token": presentation,
            "state": "abc",
        }))
        .unwrap();
        let source = source_session_with_auth_response(&auth_response);
        let bundle = build_bundle(&source, None).expect("build bundle");
        let out = unique_temp("augenmass-evidence-trust-status").join("bundle.json");
        write_bundle(&out, &bundle).expect("write bundle");

        let ok = prove_trust_status(
            TrustStatusArgs {
                bundle: out.clone(),
                verify_key: None,
                trust_anchor: "fixtures/certs/synthetic-pid-anchor.pem".to_string(),
                status_token: Some("fixtures/status/status-list-CLEAR.jwt".to_string()),
                fetch_status_token: false,
                status_key: "fixtures/status/status-list-verify-key.pub.pem".to_string(),
            },
            OutputFormat::Json,
        )
        .await
        .expect("trust/status proof runs");

        assert!(ok);

        let check = check_bundle(&out, None).expect("bundle still verifies");
        let trust_anchor = fixture("certs/synthetic-pid-anchor.pem");
        let status_token = fixture("status/status-list-CLEAR.jwt");
        let status_key = fixture("status/status-list-verify-key.pub.pem");
        let anchors = TrustAnchors::from_pem(&trust_anchor).expect("anchor");
        let signer = signer_jwk_from_pem(&status_key).expect("status signer");
        let context = verification_context(&check.bundle.payload.entries).expect("context");
        let decrypted = decrypted_response(&check.bundle.payload.entries)
            .expect("decrypted")
            .expect("auth response");
        let binding = RequestBinding {
            nonce: context.nonce,
            aud: context.aud,
        };
        let pid = verify_pid_presentation_full(
            presentations_from_decrypted(&decrypted)[0],
            &binding,
            &context.vct,
            context.max_age_secs,
            context.now_unix,
            &TrustOptions {
                anchors: Some(&anchors),
                status: StatusInput::Token {
                    jws: status_token,
                    signer,
                },
            },
        )
        .expect("fixture verifies with trust/status");
        assert!(pid.status_ref.is_some());

        let profile = profile_from_bundle(&check.bundle, "absent").expect("profile");
        let rendered = serde_json::to_string(&profile).unwrap();
        assert!(!rendered.contains("Alice Example"));

        let _ = fs::remove_dir_all(source);
        let _ = fs::remove_file(out);
    }

    #[tokio::test]
    async fn prove_trust_status_can_fetch_status_token_with_safe_fetcher() {
        let presentation = fixture("presentations/synthetic-pid-with-status.sdjwt")
            .trim()
            .to_string();
        let auth_response = serde_json::to_string(&json!({
            "vp_token": presentation,
            "state": "abc",
        }))
        .unwrap();
        let source = source_session_with_auth_response(&auth_response);
        let bundle = build_bundle(&source, None).expect("build bundle");
        let out = unique_temp("augenmass-evidence-fetch-status").join("bundle.json");
        write_bundle(&out, &bundle).expect("write bundle");
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let fetcher = StatusFetcher::Recording(counter.clone());

        let ok = prove_trust_status_with_fetcher(
            TrustStatusArgs {
                bundle: out.clone(),
                verify_key: None,
                trust_anchor: "fixtures/certs/synthetic-pid-anchor.pem".to_string(),
                status_token: None,
                fetch_status_token: true,
                status_key: "fixtures/status/status-list-verify-key.pub.pem".to_string(),
            },
            OutputFormat::Json,
            &fetcher,
        )
        .await
        .expect("trust/status proof fetches status token");

        assert!(ok);
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);

        let _ = fs::remove_dir_all(source);
        let _ = fs::remove_file(out);
    }

    #[test]
    fn tampered_entry_content_is_rejected() {
        let source = source_session();
        let mut bundle = build_bundle(&source, None).expect("build bundle");
        let entry = bundle
            .payload
            .entries
            .iter_mut()
            .find(|entry| entry.filename == "direct-post.body")
            .expect("direct post entry");
        entry.content_b64 = URL_SAFE_NO_PAD.encode("vp_token=changed");
        let out = unique_temp("augenmass-evidence-tamper").join("bundle.json");
        write_bundle(&out, &bundle).expect("write bundle");

        let err = check_bundle(&out, None).expect_err("tamper should fail");
        assert!(err.to_string().contains("mismatch"));

        let _ = fs::remove_dir_all(source);
        let _ = fs::remove_file(out);
    }

    #[test]
    fn signed_bundle_verifies_with_embedded_key() {
        use p256::pkcs8::EncodePrivateKey;

        let source = source_session();
        let key = SigningKey::random(&mut rand::thread_rng());
        let key_pem = key.to_pkcs8_pem(LineEnding::LF).expect("private pem");
        let key_path = unique_temp("augenmass-evidence-key");
        fs::write(&key_path, key_pem.as_bytes()).expect("write key");
        let bundle = build_bundle(&source, Some(&key_path)).expect("build signed bundle");
        let out = unique_temp("augenmass-evidence-signed").join("bundle.json");
        write_bundle(&out, &bundle).expect("write bundle");

        let check = check_bundle(&out, None).expect("signature verifies");
        assert_eq!(check.signature_status, "valid with embedded key");

        let _ = fs::remove_dir_all(source);
        let _ = fs::remove_file(key_path);
        let _ = fs::remove_file(out);
    }
}
