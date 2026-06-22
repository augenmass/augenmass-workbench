//! Typed rejection reasons.
//!
//! Each [`RejectKind`] maps to a way a presentation can be wrong, aligned with
//! ERICA's wallet-simulator broken modes (VALID, INVALID_SIGNATURE,
//! MISSING_CLAIMS, OVER_DISCLOSURE, WRONG_NONCE, MISSING_HOLDER_BINDING,
//! WRONG_AUDIENCE, ...). The typed kind lets the test suite assert that a given
//! broken fixture is rejected for the *right* reason, and lets the inspector
//! label a failure precisely rather than as an opaque string.

use thiserror::Error;

/// The machine-stable category of a verification failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectKind {
    /// The presentation is not a well-formed SD-JWT VC ending in a KB-JWT.
    MalformedSdJwt,
    /// The issuer JWT header carries no usable `x5c` leaf certificate.
    MissingX5c,
    /// The leaf public key is not a supported (uncompressed P-256) key.
    UnsupportedKey,
    /// The issuer SD-JWT signature did not verify against the `x5c` leaf key.
    IssuerSignature,
    /// The issuer JWT declares no `cnf.jwk`, so there is no holder key to bind.
    MissingHolderBinding,
    /// The KB-JWT signature did not verify against the holder key.
    KbSignature,
    /// The KB-JWT `nonce` does not match the request.
    NonceMismatch,
    /// The KB-JWT `aud` does not match the `client_id`.
    AudienceMismatch,
    /// The KB-JWT `sd_hash` does not match the presented SD-JWT.
    SdHashMismatch,
    /// A KB-JWT time claim is invalid (`iat` in the future, or `exp`/`nbf`).
    KbTimeInvalid,
    /// The presentation is older than the verifier's freshness window.
    StalePresentation,
    /// The credential `vct` is not the expected German PID type.
    VctMismatch,
    /// The issuer JWT credential validity window has expired.
    CredentialExpired,
    /// The issuer JWT credential validity window has not started yet.
    CredentialNotYetValid,
    /// The issuer leaf does not chain to a trusted PID issuer anchor.
    UntrustedIssuer,
    /// The credential is revoked: its token-status-list entry is not `VALID`.
    Revoked,
    /// The status-list token's signature did not verify against the trusted
    /// status-signer key, so its contents cannot be trusted.
    StatusListUntrusted,
    /// The status-list token could not be used to decide the credential's
    /// status (wrong `typ`, undecodable list, or index out of range).
    StatusListUnavailable,
}

/// A verification failure: a stable [`RejectKind`] plus a human-readable reason.
#[derive(Debug, Clone, Error)]
#[error("{kind:?}: {reason}")]
pub struct RejectReason {
    pub kind: RejectKind,
    pub reason: String,
}

impl RejectReason {
    pub fn new(kind: RejectKind, reason: impl Into<String>) -> Self {
        Self {
            kind,
            reason: reason.into(),
        }
    }
}

/// Result of a verification step.
pub type VerifyResult<T> = Result<T, RejectReason>;
