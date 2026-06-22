//! SD-JWT VC + Key Binding JWT verification for the German PID.
//!
//! This mirrors the in-tree HAIP blueprint
//! (`openid4vp/examples/verifier-conformance-adapter/server/handlers.rs`) and
//! adds the `vct` equality check and disclosed-claim extraction, returning a
//! rich [`VerifiedPid`] the inspector can render. The checks, in order:
//! 1. the credential is a well-formed SD-JWT VC ending in a KB-JWT;
//! 2. the issuer JWT signature verifies against the public key in its `x5c` leaf;
//! 3. the credential `vct` equals the expected German PID type;
//! 4. the KB-JWT signature verifies against the holder key in the issuer JWT's
//!    `cnf.jwk` (RFC 7800);
//! 5. the KB-JWT `nonce` and `aud` bind to this Authorization Request;
//! 6. the KB-JWT `sd_hash` matches the presented SD-JWT;
//! 7. the KB-JWT time claims are valid and the presentation is fresh.
//!
//! Honest scope (Slice 1): step 2 trusts the `x5c` leaf key directly. On its own
//! that is a labelled sandbox shortcut, not production issuer-trust: trusting a
//! valid signature without anchoring the chain would be a silent catastrophic
//! pass. [`verify_pid_presentation_full`] is the Slice-3 entry point that layers
//! the two missing checks on top, both fail-closed: anchoring the issuer leaf to
//! a trust-listed PID issuer ([`crate::trust`]) and the token-status-list
//! revocation check ([`crate::status`]). The base functions keep the Slice-1
//! behaviour for the conformance vectors.

use serde_json::Value;
use ssi::claims::jws::{decode_unverified, decode_verify};
use ssi::claims::sd_jwt::{KbJwtPayload, SdAlg, SdJwt};
use ssi::claims::{DateTimeProvider, ValidateClaims};
use ssi::jwk::JWK;

use crate::crypto::issuer_key_from_x5c;
use crate::disclosure::{revealed_claims, RevealedView};
use crate::error::{RejectKind, RejectReason, VerifyResult};
use crate::status::{
    check_status_list_token, status_ref_from_claims, CredentialStatus, StatusListRef,
};
use crate::trust::{issuer_trusted_at, TrustAnchors};

/// The request-bound values a presentation must echo back (OID4VP holder binding).
#[derive(Debug, Clone)]
pub struct RequestBinding {
    /// The Authorization Request `nonce`.
    pub nonce: String,
    /// The `client_id` (the KB-JWT `aud` must equal this).
    pub aud: String,
}

/// A verified German PID presentation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifiedPid {
    pub vct: String,
    pub view: RevealedView,
    /// The credential's token-status-list reference, read from signed issuer claims.
    #[serde(skip)]
    pub status_ref: Option<StatusListRef>,
    /// The KB-JWT was present and verified (holder binding holds).
    pub holder_bound: bool,
}

/// Default freshness window for the KB-JWT `iat` (verifier policy).
pub const DEFAULT_MAX_AGE_SECS: i64 = 300;

/// Verify a German PID presentation with the default freshness window.
pub fn verify_pid_presentation(
    presentation: &str,
    binding: &RequestBinding,
    expected_vct: &str,
) -> VerifyResult<VerifiedPid> {
    verify_pid_presentation_with_age(presentation, binding, expected_vct, DEFAULT_MAX_AGE_SECS)
}

/// Verify a German PID presentation, with an explicit freshness window, against
/// the current wall-clock time.
pub fn verify_pid_presentation_with_age(
    presentation: &str,
    binding: &RequestBinding,
    expected_vct: &str,
    max_age_secs: i64,
) -> VerifyResult<VerifiedPid> {
    verify_pid_presentation_at(
        presentation,
        binding,
        expected_vct,
        max_age_secs,
        now_unix(),
    )
}

/// Verify a German PID presentation at a given verification time (Unix seconds).
/// Injecting the clock keeps offline fixture tests deterministic; production
/// callers use [`verify_pid_presentation`] / [`verify_pid_presentation_with_age`].
pub fn verify_pid_presentation_at(
    presentation: &str,
    binding: &RequestBinding,
    expected_vct: &str,
    max_age_secs: i64,
    now_unix: i64,
) -> VerifyResult<VerifiedPid> {
    let sd_jwt = SdJwt::new(presentation)
        .map_err(|e| reject(RejectKind::MalformedSdJwt, format!("invalid SD-JWT: {e}")))?;
    let issuer_jwt = sd_jwt.jwt().as_str();

    // 2. Issuer signature against the x5c leaf key.
    let (header, _) = decode_unverified(issuer_jwt).map_err(|e| {
        reject(
            RejectKind::MalformedSdJwt,
            format!("decode issuer JWT: {e}"),
        )
    })?;
    let issuer_key = issuer_key_from_x5c(&header.x509_certificate_chain)
        .map_err(|e| reject(RejectKind::MissingX5c, e.to_string()))?;
    let (_, payload) = decode_verify(issuer_jwt, &issuer_key).map_err(|e| {
        reject(
            RejectKind::IssuerSignature,
            format!("issuer SD-JWT signature verification failed: {e}"),
        )
    })?;
    let claims: Value = serde_json::from_slice(&payload).map_err(|e| {
        reject(
            RejectKind::MalformedSdJwt,
            format!("issuer payload not JSON: {e}"),
        )
    })?;
    if let Some(exp) = claims.get("exp").and_then(|v| v.as_i64()) {
        if now_unix >= exp {
            return Err(reject(
                RejectKind::CredentialExpired,
                format!("credential expired at {exp}"),
            ));
        }
    }
    if let Some(nbf) = claims.get("nbf").and_then(|v| v.as_i64()) {
        if now_unix < nbf {
            return Err(reject(
                RejectKind::CredentialNotYetValid,
                format!("credential is not valid before {nbf}"),
            ));
        }
    }

    // 3. vct equality.
    let vct = claims
        .get("vct")
        .and_then(|v| v.as_str())
        .ok_or_else(|| reject(RejectKind::VctMismatch, "issuer JWT has no vct"))?;
    if vct != expected_vct {
        return Err(reject(
            RejectKind::VctMismatch,
            format!("vct '{vct}' is not the expected '{expected_vct}'"),
        ));
    }
    let vct = vct.to_string();
    let status_ref = status_ref_from_claims(&claims);

    // 4. Holder key from cnf.jwk, then KB-JWT signature.
    let cnf_jwk = claims
        .get("cnf")
        .and_then(|c| c.get("jwk"))
        .ok_or_else(|| {
            reject(
                RejectKind::MissingHolderBinding,
                "issuer JWT has no cnf.jwk",
            )
        })?;
    let holder_key: JWK = serde_json::from_value(cnf_jwk.clone()).map_err(|e| {
        reject(
            RejectKind::MissingHolderBinding,
            format!("invalid cnf.jwk: {e}"),
        )
    })?;

    let kb_jwt = sd_jwt
        .kb()
        .ok_or_else(|| {
            reject(
                RejectKind::MissingHolderBinding,
                "Key Binding JWT is missing",
            )
        })?
        .as_str();
    let (_, kb_payload) = decode_verify(kb_jwt, &holder_key).map_err(|e| {
        reject(
            RejectKind::KbSignature,
            format!("KB-JWT signature verification failed: {e}"),
        )
    })?;
    let kb: KbJwtPayload = serde_json::from_slice(&kb_payload)
        .map_err(|e| reject(RejectKind::KbSignature, format!("KB-JWT is not valid: {e}")))?;

    // 5. Transaction binding.
    if kb.nonce.0 != binding.nonce {
        return Err(reject(
            RejectKind::NonceMismatch,
            "KB-JWT nonce does not match the request",
        ));
    }
    if kb.aud != binding.aud {
        return Err(reject(
            RejectKind::AudienceMismatch,
            "KB-JWT aud does not match the client_id",
        ));
    }

    // 6. sd_hash over the presented SD-JWT.
    if !kb.sd_hash.verify(SdAlg::Sha256, sd_jwt) {
        return Err(reject(
            RejectKind::SdHashMismatch,
            "KB-JWT sd_hash does not match the presented SD-JWT",
        ));
    }

    // 7. Time claims + freshness.
    kb.validate_claims(&FixedTime(now_unix), &()).map_err(|e| {
        reject(
            RejectKind::KbTimeInvalid,
            format!("KB-JWT time invalid: {e}"),
        )
    })?;
    let iat = kb.iat.0.as_seconds();
    if iat < now_unix as f64 - max_age_secs as f64 {
        return Err(reject(
            RejectKind::StalePresentation,
            "KB-JWT iat is too far in the past",
        ));
    }

    let view = revealed_claims(sd_jwt).map_err(|e| {
        reject(
            RejectKind::MalformedSdJwt,
            format!("reveal disclosures: {e}"),
        )
    })?;

    Ok(VerifiedPid {
        vct,
        view,
        status_ref,
        holder_bound: true,
    })
}

/// How the revocation check is supplied to [`verify_pid_presentation_full`].
///
/// The core does no I/O, so the caller fetches the status-list token and brings
/// the trusted status-signer key; [`StatusInput::None`] skips the check.
// The `Token` variant carries an inline `JWK` by design (it is the trust input,
// constructed once per verification, never in a hot collection), so the size gap
// to the empty `None` variant is not worth boxing.
#[allow(clippy::large_enum_variant)]
pub enum StatusInput {
    /// Do not perform a token-status-list check.
    None,
    /// Check against this already-fetched `statuslist+jwt` token, trusting
    /// signatures made by `signer`.
    Token {
        /// The compact `statuslist+jwt` JWS the credential's `uri` points at.
        jws: String,
        /// The trusted status-signer public key.
        signer: JWK,
    },
}

/// The Slice-3 trust-and-validity options layered on top of Slice-1 verification.
///
/// Both are optional and additive: with `anchors: None` and
/// `status: StatusInput::None` the full verifier behaves exactly like
/// [`verify_pid_presentation_at`] (save for stripping a `status` claim, a no-op
/// when none is present).
pub struct TrustOptions<'a> {
    /// If set, the issuer leaf must chain to one of these anchors.
    pub anchors: Option<&'a TrustAnchors>,
    /// If a token is supplied, the credential's status bit must read `VALID`.
    pub status: StatusInput,
}

/// Verify a German PID presentation, then layer the Slice-3 issuer-trust and
/// token-status-list (revocation) checks on top, all fail-closed.
///
/// Steps, after the Slice-1 verification in [`verify_pid_presentation_at`]:
/// - if `trust.anchors` is set, the issuer leaf must chain to one of them, else
///   [`RejectKind::UntrustedIssuer`];
/// - if `trust.status` carries a token and the credential references a status
///   list, the referenced bit must read `VALID`, else [`RejectKind::Revoked`]
///   (a suspended credential also rejects: there is no `Suspended` reject kind,
///   and fail-closed means a non-`VALID` credential is not accepted);
/// - the verifier-internal `status` pointer is stripped from the returned view,
///   so it never appears as a disclosed claim (it is plumbing, not over-ask).
pub fn verify_pid_presentation_full(
    presentation: &str,
    binding: &RequestBinding,
    expected_vct: &str,
    max_age_secs: i64,
    now_unix: i64,
    trust: &TrustOptions,
) -> VerifyResult<VerifiedPid> {
    let mut verified =
        verify_pid_presentation_at(presentation, binding, expected_vct, max_age_secs, now_unix)?;

    // Issuer trust anchoring.
    if let Some(anchors) = trust.anchors {
        if !issuer_trusted_at(presentation, anchors, now_unix) {
            return Err(reject(
                RejectKind::UntrustedIssuer,
                "issuer leaf does not chain to a trusted PID issuer anchor, or a certificate is outside its validity window",
            ));
        }
    }

    // Token-status-list (revocation) check.
    if let StatusInput::Token { jws, signer } = &trust.status {
        if let Some(sref) = verified.status_ref.as_ref() {
            match check_status_list_token(jws, signer, sref)? {
                CredentialStatus::Valid => {}
                CredentialStatus::Revoked => {
                    return Err(reject(
                        RejectKind::Revoked,
                        "credential is revoked (status-list entry is INVALID)",
                    ));
                }
                CredentialStatus::Suspended => {
                    return Err(reject(
                        RejectKind::Revoked,
                        "credential is suspended (status-list entry is SUSPENDED); rejecting fail-closed",
                    ));
                }
            }
        }
    }

    // The status pointer is verifier-internal plumbing: strip it from the view so
    // it never leaks into the disclosed / over-ask surface.
    if let Some(obj) = verified.view.claims.as_object_mut() {
        obj.remove("status");
    }
    verified
        .view
        .disclosed
        .retain(|claim| claim.path != ["status"]);

    Ok(verified)
}

fn reject(kind: RejectKind, reason: impl Into<String>) -> RejectReason {
    RejectReason::new(kind, reason)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A [`DateTimeProvider`] fixed at a given Unix time, so the verification clock
/// is injectable: the real wall clock in production, the capture time in tests.
struct FixedTime(i64);

impl DateTimeProvider for FixedTime {
    fn date_time(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::<chrono::Utc>::from_timestamp(self.0, 0).unwrap_or_default()
    }
}
