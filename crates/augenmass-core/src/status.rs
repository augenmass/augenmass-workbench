//! Token-status-list (revocation) check: the Slice-3 validity layer.
//!
//! A German PID SD-JWT VC can carry an issuer claim
//! `status.status_list.{idx,uri}` (IETF draft-ietf-oauth-status-list) that
//! points at one bit of a signed status-list token. This module reads that
//! pointer, verifies the referenced `statuslist+jwt` token against the trusted
//! status-signer key, decodes the credential's bit, and maps it to a
//! [`CredentialStatus`].
//!
//! It is **fail-closed**: anything not provably `VALID` rejects. A signature
//! that does not verify under the trusted key is [`RejectKind::StatusListUntrusted`];
//! a token that cannot be decoded, has the wrong `typ`, or whose index is out of
//! range is [`RejectKind::StatusListUnavailable`]; a set bit (`INVALID`, and here
//! also `SUSPENDED`) is a revocation. There is no "unknown is fine" path: an
//! attacker who can strip or corrupt the status token must not thereby downgrade
//! a revoked credential to accepted.
//!
//! This module is pure: it does no I/O and no network. The caller supplies both
//! the already-fetched status-list token and the trusted signer key.
//!
//! Sandbox same-entity caveat: in production the verifier anchors the
//! status-signer key to the issuing entity (the status list and the credential
//! must come from the same issuer, e.g. the token's `iss` is bound to the PID
//! issuer's trust anchor). Here that binding is delegated to the caller: the
//! trusted signer key is passed in, and verifying the token's signature against
//! it is the trust decision. Wiring the issuer-to-status-signer anchoring is a
//! later step.

use serde_json::Value;
use ssi::claims::jws::{decode_unverified, decode_verify};
use ssi::claims::sd_jwt::SdJwt;
use ssi::jwk::JWK;
use ssi::status::token_status_list::json::JsonStatusList;
use ssi::status::token_status_list::{BitString, INVALID, JWT_TYPE, SUSPENDED, VALID};

use crate::error::{RejectKind, RejectReason, VerifyResult};

/// A credential's pointer into a token status list: which bit, in which list.
#[derive(Debug, Clone)]
pub struct StatusListRef {
    /// The index of this credential's status bit within the list.
    pub idx: usize,
    /// The URI of the status-list token that conveys the bit.
    pub uri: String,
}

/// The resolved status of a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialStatus {
    /// The status bit is `VALID` (0): not revoked, not suspended.
    Valid,
    /// The status bit is `INVALID` (1): the credential is revoked.
    Revoked,
    /// The status bit is `SUSPENDED` (2): the credential is suspended.
    Suspended,
}

/// Read a credential's status-list reference from its issuer claims.
///
/// Returns `None` if there is no `status.status_list`, or if it is malformed
/// (missing/non-integer `idx`, or missing/non-string `uri`).
pub fn status_ref_from_claims(claims: &Value) -> Option<StatusListRef> {
    let status_list = claims.get("status")?.get("status_list")?;
    let idx = usize::try_from(status_list.get("idx")?.as_u64()?).ok()?;
    let uri = status_list.get("uri")?.as_str()?.to_string();
    Some(StatusListRef { idx, uri })
}

/// Verify a status-list token under the trusted signer key and read the bit at
/// `sref.idx`.
///
/// Fail-closed: the signature is checked first; only then is the (now trusted)
/// payload decoded and the bit read.
pub fn check_status_list_token(
    token_jws: &str,
    signer: &JWK,
    sref: &StatusListRef,
) -> VerifyResult<CredentialStatus> {
    // 1. The signature, against the trusted status-signer key. This is the
    //    trust decision: a token we cannot verify tells us nothing.
    let (header, payload) = decode_verify(token_jws, signer).map_err(|e| {
        reject(
            RejectKind::StatusListUntrusted,
            format!("status-list token signature did not verify under the trusted key: {e}"),
        )
    })?;

    // 2. It must be a status-list token, not some other JWS reusing the key.
    if header.type_.as_deref() != Some(JWT_TYPE) {
        return Err(reject(
            RejectKind::StatusListUnavailable,
            "status token is not a statuslist+jwt",
        ));
    }

    // 3. Decode the list and read the credential's bit.
    let claims: Value = serde_json::from_slice(&payload).map_err(|e| {
        reject(
            RejectKind::StatusListUnavailable,
            format!("status token payload is not JSON: {e}"),
        )
    })?;
    let mut status_list = claims.get("status_list").cloned().ok_or_else(|| {
        reject(
            RejectKind::StatusListUnavailable,
            "status token has no status_list claim",
        )
    })?;
    normalize_status_list_encoding(&mut status_list);
    let jsl: JsonStatusList = serde_json::from_value(status_list).map_err(|e| {
        reject(
            RejectKind::StatusListUnavailable,
            format!("status_list claim is malformed: {e}"),
        )
    })?;
    let bits = jsl.decode(Some(BitString::DEFAULT_LIMIT)).map_err(|e| {
        reject(
            RejectKind::StatusListUnavailable,
            format!("status list could not be decoded: {e}"),
        )
    })?;

    match bits.get(sref.idx) {
        None => Err(reject(
            RejectKind::StatusListUnavailable,
            format!("status index {} is out of range", sref.idx),
        )),
        Some(VALID) => Ok(CredentialStatus::Valid),
        Some(INVALID) => Ok(CredentialStatus::Revoked),
        Some(SUSPENDED) => Ok(CredentialStatus::Suspended),
        Some(other) => Err(reject(
            RejectKind::StatusListUnavailable,
            format!("unexpected status value {other} at index {}", sref.idx),
        )),
    }
}

/// Resolve the status of an SD-JWT VC presentation.
///
/// Reads the issuer claims (without trusting them; signature verification is the
/// caller's job via [`crate::verify`]) to find the status-list reference. If the
/// credential carries no status pointer there is nothing to revoke, so the result
/// is [`CredentialStatus::Valid`]; otherwise the referenced token is checked via
/// [`check_status_list_token`].
pub fn check_presentation_status(
    presentation: &str,
    signer: &JWK,
    token_jws: &str,
) -> VerifyResult<CredentialStatus> {
    let sd_jwt = SdJwt::new(presentation)
        .map_err(|e| reject(RejectKind::MalformedSdJwt, format!("invalid SD-JWT: {e}")))?;
    let (_, payload) = decode_unverified(sd_jwt.jwt().as_str()).map_err(|e| {
        reject(
            RejectKind::MalformedSdJwt,
            format!("decode issuer JWT: {e}"),
        )
    })?;
    let claims: Value = serde_json::from_slice(&payload).map_err(|e| {
        reject(
            RejectKind::MalformedSdJwt,
            format!("issuer payload not JSON: {e}"),
        )
    })?;

    match status_ref_from_claims(&claims) {
        None => Ok(CredentialStatus::Valid),
        Some(sref) => check_status_list_token(token_jws, signer, &sref),
    }
}

fn normalize_status_list_encoding(status_list: &mut Value) {
    let Some(lst) = status_list.get_mut("lst") else {
        return;
    };
    let Some(raw) = lst.as_str() else {
        return;
    };
    let mut padded = raw.replace('-', "+").replace('_', "/");
    let remainder = padded.len() % 4;
    if remainder == 0 || remainder == 1 {
        if padded != raw {
            *lst = Value::String(padded);
        }
        return;
    }
    for _ in 0..(4 - remainder) {
        padded.push('=');
    }
    *lst = Value::String(padded);
}

fn reject(kind: RejectKind, reason: impl Into<String>) -> RejectReason {
    RejectReason::new(kind, reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalizes_unpadded_status_list_encoding() {
        let mut value = json!({
            "bits": 1,
            "lst": "eNpjYEAFAAAQAAE"
        });
        normalize_status_list_encoding(&mut value);
        assert_eq!(value["lst"], "eNpjYEAFAAAQAAE=");
    }

    #[test]
    fn normalizes_url_safe_status_list_encoding() {
        let mut value = json!({
            "bits": 1,
            "lst": "ab-_"
        });
        normalize_status_list_encoding(&mut value);
        assert_eq!(value["lst"], "ab+/");
    }

    #[test]
    fn leaves_invalid_base64_length_unchanged() {
        let mut value = json!({
            "bits": 1,
            "lst": "abcde"
        });
        normalize_status_list_encoding(&mut value);
        assert_eq!(value["lst"], "abcde");
    }
}
