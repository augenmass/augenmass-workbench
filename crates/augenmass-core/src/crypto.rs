//! Crypto primitives the verifier reuses.
//!
//! Three small pieces sit beside the `openid4vp` crate's transport:
//! - [`decrypt_jwe`]: decrypt a `direct_post.jwt` response (ECDH-ES). The
//!   `openid4vp` crate only encrypts, so this 16-line helper is copied from the
//!   in-tree HAIP blueprint (`verifier-conformance-adapter/crypto/jwe.rs`).
//! - [`issuer_key_from_x5c`] / [`public_key_from_cert_der`]: recover the issuer
//!   P-256 public key from the leaf certificate in a JWS `x5c` header.
//! - [`leaf_cert_hash`]: the `x509_hash` client_id binding.

use anyhow::{bail, Context, Result};
use base64::prelude::*;
use josekit::jwe::ECDH_ES;
use josekit::jwk::Jwk as JosekitJwk;
use serde_json::Value;
use sha2::{Digest, Sha256};
use ssi::jwk::JWK;
use x509_cert::{der::Decode, Certificate};

/// Decrypt a JWE (compact serialization) using ECDH-ES with our private key.
pub fn decrypt_jwe(jwe: &str, private_key_jwk: &JWK) -> Result<Value> {
    let jwk_str = serde_json::to_string(private_key_jwk)?;
    let jwk = JosekitJwk::from_bytes(jwk_str.as_bytes()).context("invalid private key JWK")?;

    let decrypter: josekit::jwe::alg::ecdh_es::EcdhEsJweDecrypter<p256::NistP256> = ECDH_ES
        .decrypter_from_jwk(&jwk)
        .context("failed to create ECDH-ES decrypter")?;

    let (payload, _header) =
        josekit::jwe::deserialize_compact(jwe, &decrypter).context("failed to decrypt JWE")?;

    serde_json::from_slice(&payload).context("decrypted payload is not JSON")
}

/// Build a P-256 JWK from the leaf certificate of a JWS `x5c` header.
pub fn issuer_key_from_x5c(x5c: &Option<Vec<String>>) -> Result<JWK> {
    let leaf_b64 = x5c
        .as_ref()
        .and_then(|chain| chain.first())
        .context("JWT header has no x5c certificate")?;
    let der = BASE64_STANDARD
        .decode(leaf_b64)
        .context("invalid base64 in x5c")?;
    public_key_from_cert_der(&der)
}

/// Build a P-256 JWK from a DER-encoded certificate's SubjectPublicKeyInfo.
///
/// For an EC key the SPKI subject public key is the SEC1 uncompressed point:
/// `0x04 || X(32) || Y(32)`.
pub fn public_key_from_cert_der(der: &[u8]) -> Result<JWK> {
    let cert = Certificate::from_der(der).context("invalid certificate DER")?;
    let point = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    if point.len() != 65 || point[0] != 0x04 {
        bail!("unsupported key (expected uncompressed P-256 point)");
    }
    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": BASE64_URL_SAFE_NO_PAD.encode(&point[1..33]),
        "y": BASE64_URL_SAFE_NO_PAD.encode(&point[33..65]),
    });
    serde_json::from_value(jwk).context("failed to build issuer JWK")
}

/// The `x509_hash` client_id binding: `base64url-nopad(SHA-256(leaf DER))`.
///
/// The full `client_id` is `format!("x509_hash:{}", leaf_cert_hash(der))`.
pub fn leaf_cert_hash(leaf_der: &[u8]) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(leaf_der))
}
