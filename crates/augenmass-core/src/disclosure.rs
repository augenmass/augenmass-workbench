//! Disclosed-claim extraction.
//!
//! After the signature checks pass, the inspector needs to know exactly which
//! selectively-disclosable claims the holder chose to reveal, and their values.
//! `ssi`'s `decode_reveal_any` applies the disclosures to the issuer payload and
//! records each revealed value at its JSON pointer, which handles nested and
//! recursive disclosures correctly. The keys of that map are precisely the
//! selectively-disclosed paths; everything else in the PID model is "withheld".

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use ssi::claims::sd_jwt::SdJwt;

/// A single disclosed claim: its path segments and the revealed value.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DisclosedClaim {
    pub path: Vec<String>,
    pub value: Value,
}

impl DisclosedClaim {
    /// The dotted path key, e.g. `age_equal_or_over.18`.
    pub fn key(&self) -> String {
        self.path.join(".")
    }
}

/// The revealed view of a presented SD-JWT VC.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RevealedView {
    /// The full revealed claim object (always-visible claims plus disclosed).
    pub claims: Value,
    /// The selectively-disclosed claims (path plus value), sorted by path.
    pub disclosed: Vec<DisclosedClaim>,
}

/// Reveal the disclosed claim set of a (already signature-checked) SD-JWT VC.
pub fn revealed_claims(sd_jwt: &SdJwt) -> Result<RevealedView> {
    let revealed = sd_jwt
        .decode_reveal_any()
        .map_err(|e| anyhow!("reveal failed: {e}"))?;

    let claims: Value =
        serde_json::to_value(revealed.claims()).context("serialize revealed claims")?;

    let mut disclosed = Vec::new();
    for pointer in revealed.disclosures.keys() {
        // JSON pointer form, e.g. "/given_name" or "/age_equal_or_over/18".
        let ptr = pointer.to_string();
        let value = claims.pointer(&ptr).cloned().unwrap_or(Value::Null);
        let path: Vec<String> = ptr
            .trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        disclosed.push(DisclosedClaim { path, value });
    }
    disclosed.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(RevealedView { claims, disclosed })
}
