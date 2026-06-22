//! Slice 3 (partial): X.509 issuer trust anchoring.
//!
//! Slice 1 verifies the SD-JWT issuer signature against the leaf key carried in
//! the `x5c` header. On its own that is a silent pass: any self-signed leaf
//! verifies against itself. Trust comes from anchoring the leaf to a known PID
//! issuer. This module checks that the issuer leaf (`x5c[0]`) is signed by one
//! of the configured trust anchors (the leaf's ECDSA signature verifies under an
//! anchor's public key).
//!
//! Revocation (the token-status-list check) is implemented in [`crate::status`],
//! wired through [`crate::verify::verify_pid_presentation_full`], and covered by
//! `tests/status.rs`. The "(partial)" above now refers to the remaining gap in
//! this module alone: full X.509 path validation (CA basic-constraints and
//! key-usage, multi-link chains). Today it does a single leaf-signed-by-anchor
//! check plus certificate validity-window enforcement.

use anyhow::{anyhow, Context, Result};
use base64::prelude::*;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use ssi::claims::jws::decode_unverified;
use ssi::claims::sd_jwt::SdJwt;
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;

/// A set of trusted issuer anchors.
pub struct TrustAnchors {
    certs: Vec<Certificate>,
}

impl TrustAnchors {
    /// Parse one or more PEM `CERTIFICATE` blocks into a trust set.
    pub fn from_pem(pem: &str) -> Result<Self> {
        let mut certs = Vec::new();
        let mut body = String::new();
        let mut inside = false;
        for line in pem.lines() {
            if line.contains("BEGIN CERTIFICATE") {
                inside = true;
                body.clear();
                continue;
            }
            if line.contains("END CERTIFICATE") {
                let der = BASE64_STANDARD
                    .decode(body.trim())
                    .context("decode PEM certificate body")?;
                certs.push(Certificate::from_der(&der).context("parse certificate DER")?);
                inside = false;
                continue;
            }
            if inside {
                body.push_str(line.trim());
            }
        }
        if certs.is_empty() {
            return Err(anyhow!("no CERTIFICATE blocks found in PEM"));
        }
        Ok(Self { certs })
    }

    pub fn len(&self) -> usize {
        self.certs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.certs.is_empty()
    }
}

/// Whether the SD-JWT issuer (the leaf in its `x5c`) is signed by a trust anchor.
pub fn issuer_trusted(presentation: &str, anchors: &TrustAnchors) -> bool {
    issuer_trusted_at(presentation, anchors, now_unix())
}

/// Whether the SD-JWT issuer is trusted at a given Unix timestamp.
pub fn issuer_trusted_at(presentation: &str, anchors: &TrustAnchors, now_unix: i64) -> bool {
    let Ok(sd_jwt) = SdJwt::new(presentation) else {
        return false;
    };
    let Ok((header, _)) = decode_unverified(sd_jwt.jwt().as_str()) else {
        return false;
    };
    let Some(x5c) = header.x509_certificate_chain.as_ref() else {
        return false;
    };
    let Some(leaf_b64) = x5c.first() else {
        return false;
    };
    let Ok(leaf_der) = BASE64_STANDARD.decode(leaf_b64) else {
        return false;
    };
    let Ok(leaf) = Certificate::from_der(&leaf_der) else {
        return false;
    };
    anchors.certs.iter().any(|anchor| {
        cert_valid_at(&leaf, now_unix)
            && cert_valid_at(anchor, now_unix)
            && leaf_signed_by(&leaf, anchor)
    })
}

/// Verify `leaf`'s signature under `anchor`'s public key (ECDSA P-256 / SHA-256).
fn leaf_signed_by(leaf: &Certificate, anchor: &Certificate) -> bool {
    let Ok(tbs) = leaf.tbs_certificate.to_der() else {
        return false;
    };
    let Ok(vk) = verifying_key(anchor) else {
        return false;
    };
    let Some(sig_bytes) = leaf.signature.as_bytes() else {
        return false;
    };
    let Ok(sig) = Signature::from_der(sig_bytes) else {
        return false;
    };
    vk.verify(&tbs, &sig).is_ok()
}

fn verifying_key(cert: &Certificate) -> Result<VerifyingKey> {
    let point = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    VerifyingKey::from_sec1_bytes(point).map_err(|e| anyhow!("anchor public key: {e}"))
}

fn cert_valid_at(cert: &Certificate, now_unix: i64) -> bool {
    let validity = &cert.tbs_certificate.validity;
    let not_before = validity.not_before.to_unix_duration();
    let not_after = validity.not_after.to_unix_duration();
    let not_before = not_before.as_secs() as i64;
    let not_after = not_after.as_secs() as i64;
    not_before <= now_unix && now_unix <= not_after
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
