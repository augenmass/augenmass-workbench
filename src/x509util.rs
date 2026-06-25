//! X.509 certificate helpers: parse a certificate from PEM or base64 DER, and
//! compute the `x509_hash` client_id binding (base64url-no-pad SHA-256 of the
//! leaf DER) via the engine's `crypto::leaf_cert_hash`.

use anyhow::{Context, Result};
use base64::prelude::*;
use x509_cert::der::Decode;
use x509_cert::Certificate;

use crate::jose::{looks_like_pem, pem_to_der};

pub struct CertInfo {
    pub der: Vec<u8>,
    pub subject: String,
    pub issuer: String,
    pub not_before_unix: i64,
    pub not_after_unix: i64,
    pub serial: String,
    pub x509_hash: String,
    pub client_id: String,
}

/// Parse a certificate from a PEM block or base64 (standard) DER.
pub fn parse_certificate(input: &str) -> Result<CertInfo> {
    let der = der_from_input(input)?;
    cert_info_from_der(der)
}

/// Get the leaf DER from a PEM/base64 cert, a compact JWT (its `x5c` leaf), or
/// raw base64 DER.
pub fn leaf_der_from_input(input: &str) -> Result<Vec<u8>> {
    let trimmed = input.trim();
    if crate::jose::looks_like_jwt(trimmed) {
        let decoded = crate::jose::decode_compact(trimmed)?;
        return crate::jose::leaf_der_from_x5c(&decoded.header);
    }
    der_from_input(trimmed)
}

fn der_from_input(input: &str) -> Result<Vec<u8>> {
    let trimmed = input.trim();
    if looks_like_pem(trimmed) {
        return pem_to_der(trimmed);
    }
    BASE64_STANDARD
        .decode(trimmed)
        .context("certificate is not PEM and not base64 DER")
}

pub fn cert_info_from_der(der: Vec<u8>) -> Result<CertInfo> {
    let cert = Certificate::from_der(&der).context("parse X.509 certificate DER")?;
    let tbs = &cert.tbs_certificate;
    let x509_hash = augenmass_core::crypto::leaf_cert_hash(&der);
    Ok(CertInfo {
        subject: tbs.subject.to_string(),
        issuer: tbs.issuer.to_string(),
        not_before_unix: tbs.validity.not_before.to_unix_duration().as_secs() as i64,
        not_after_unix: tbs.validity.not_after.to_unix_duration().as_secs() as i64,
        serial: hex_upper(tbs.serial_number.as_bytes()),
        client_id: format!("x509_hash:{x509_hash}"),
        x509_hash,
        der,
    })
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Build a P-256 verification JWK from a PEM. Accepts an SPKI public-key PEM
/// (`-----BEGIN PUBLIC KEY-----`) or a certificate PEM (`BEGIN CERTIFICATE`),
/// from which the leaf SubjectPublicKeyInfo key is taken.
pub fn signer_jwk_from_pem(pem: &str) -> Result<ssi::jwk::JWK> {
    let cert_count = pem.matches("BEGIN CERTIFICATE").count();
    if cert_count > 1 {
        anyhow::bail!(
            "expected a single signer certificate or public key PEM, but the PEM contains {cert_count} certificates"
        );
    }
    if cert_count == 1 {
        let der = pem_to_der(pem)?;
        return augenmass_core::crypto::public_key_from_cert_der(&der)
            .context("derive verification key from certificate");
    }
    use p256::pkcs8::DecodePublicKey;
    let pk =
        p256::PublicKey::from_public_key_pem(pem.trim()).context("parse SPKI public-key PEM")?;
    let jwk_str = pk.to_jwk_string();
    serde_json::from_str(jwk_str.trim()).context("convert public key to JWK")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_jwk_from_pem_rejects_multi_certificate_pem() {
        let cert = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/certs/synthetic-pid-anchor.pem"
        ));
        let err = signer_jwk_from_pem(&format!("{cert}\n{cert}"))
            .expect_err("multi-certificate signer PEM must fail closed");

        assert!(err.to_string().contains("single signer certificate"));
    }
}
