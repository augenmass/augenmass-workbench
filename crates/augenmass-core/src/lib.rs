//! `verifier-core`: the reusable, HTTP-free core of a German-PID OpenID4VP
//! verifier plus a data-minimization ("over-ask") inspector engine.
//!
//! The crate is split so the protocol/crypto substrate stays cheap and correct
//! (it mirrors the in-tree HAIP blueprint in `openid4vp`'s
//! `verifier-conformance-adapter` example) while the differentiating value, the
//! human-legible inspector, sits on top as a pure, deterministic rules engine.
//!
//! Layers:
//! - [`pid`]: the German PID profile (the `vct`, the claim model, the
//!   minimal-disclosure DCQL query).
//! - [`crypto`], [`verify`], [`disclosure`]: the protocol substrate (JWE
//!   decrypt, SD-JWT issuer + KB-JWT verification, disclosed-claim extraction).
//! - [`regcert`], [`inspector`]: the over-ask layer (decode the registered
//!   scope, compare requested vs minimum vs registered).
//!
//! Nothing here does I/O or HTTP; fetching and serving live in the binaries.

pub mod crypto;
pub mod disclosure;
pub mod error;
pub mod inspector;
pub mod pid;
pub mod regcert;
pub mod status;
pub mod trust;
pub mod verify;

/// The German PID credential type identifier (SD-JWT VC `vct`).
pub const PID_VCT: &str = "urn:eudi:pid:de:1";

pub use disclosure::{DisclosedClaim, RevealedView};
pub use error::{RejectKind, RejectReason, VerifyResult};
pub use inspector::{analyze, ClaimStatus, OverAskReport};
pub use regcert::{
    decode_registration_jwt, scope_from_payload, RegisteredCredential, RegisteredScope,
};
pub use status::{
    check_presentation_status, check_status_list_token, status_ref_from_claims, CredentialStatus,
    StatusListRef,
};
pub use trust::{issuer_trusted, issuer_trusted_at, TrustAnchors};
pub use verify::{
    verify_pid_presentation, verify_pid_presentation_at, verify_pid_presentation_full,
    verify_pid_presentation_with_age, RequestBinding, StatusInput, TrustOptions, VerifiedPid,
    DEFAULT_FUTURE_SKEW_SECS, DEFAULT_MAX_AGE_SECS,
};
