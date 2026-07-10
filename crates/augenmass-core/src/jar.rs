//! JWT-Secured Authorization Request (JAR) signature verification.
//!
//! `decode request` and `doctor` read and lint a JAR's JOSE header and claims
//! but verify nothing. This module is the request-side analogue of
//! [`crate::verify`] (which verifies an SD-JWT VC presentation): it proves the
//! OpenID4VP Authorization Request was actually signed by the key in its `x5c`
//! leaf, optionally that the leaf chains directly to a trust anchor, and that an
//! `x509_hash` `client_id` binds to that leaf. Every check fails closed, and the
//! verification clock is injectable so fixture tests stay deterministic.
//!
//! Scope, and what is deliberately deferred:
//! - Algorithm: `ES256` only, the P-256 profile the sandbox and every committed
//!   fixture use. Any other `alg`, including `none`, is rejected before any key
//!   or signature handling runs. That ordering is the alg-confusion / `none`
//!   defense: the header `alg` is never used to *select* a verification
//!   algorithm, only checked against a one-item allowlist.
//! - Key resolution: the JOSE `x5c` leaf (the first entry). Resolving a key from
//!   `kid`, a `jwks`/`jwks_uri`, or a DID is out of scope here.
//! - Trust: a single leaf-signed-by-anchor check plus certificate validity
//!   windows, reusing [`crate::trust::leaf_der_trusted_at`]. Full RFC 5280 path
//!   validation (multi-link chains, basic-constraints, key-usage, name
//!   constraints, signer-cert revocation) is deferred, matching the honest scope
//!   already documented in [`crate::trust`].
//! - `client_id` binding: the `x509_hash` scheme only. Other schemes
//!   (`x509_san_dns`, `redirect_uri`, `did`, pre-registered) reject because
//!   success means the request identity is bound to the verified leaf.
//!
//! A leaf with no supplied anchor still verifies its signature, exactly as
//! [`crate::verify::verify_pid_presentation_at`] trusts the SD-JWT `x5c` leaf
//! directly: that is a self-consistency proof, not third-party trust. The
//! [`VerifiedJar::self_signed`] and [`VerifiedJar::trust_anchored`] fields make
//! that distinction explicit so a caller never mistakes "well-formed signature"
//! for "trusted verifier".

use base64::prelude::*;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde_json::Value;
use x509_cert::der::Decode;
use x509_cert::Certificate;

use crate::crypto::leaf_cert_hash;
use crate::error::{RejectKind, RejectReason, VerifyResult};
use crate::trust::{leaf_der_trusted_at, TrustAnchors};
use crate::verify::{format_numeric_date, numeric_date_claim};

/// The only JOSE signature algorithm this verifier accepts.
const ES256: &str = "ES256";
/// The `x509_hash` `client_id` scheme prefix.
const X509_HASH_PREFIX: &str = "x509_hash:";

/// The Slice-3 trust-and-validity options for [`verify_jar`].
pub struct JarOptions<'a> {
    /// If set, the `x5c` leaf must chain to one of these anchors within their
    /// validity windows; otherwise the request is [`RejectKind::UntrustedIssuer`].
    /// If `None`, trust anchoring is skipped and only the signature is proven.
    pub anchors: Option<&'a TrustAnchors>,
    /// The verification clock (Unix seconds): pins anchor validity windows and
    /// the request `exp`/`nbf` check so offline fixtures are reproducible.
    pub now_unix: i64,
}

/// A verified JAR (JWT-Secured Authorization Request).
///
/// Construction implies the signature verified against the `x5c` leaf key and
/// (when anchors were supplied) that the leaf chained to one of them. The fields
/// carry what a caller needs to render the result and to reason about how much
/// trust the signature actually establishes.
#[derive(Debug, Clone)]
pub struct VerifiedJar {
    /// The JOSE `alg` (always `ES256` on success).
    pub alg: String,
    /// The JOSE `typ`, if present (e.g. `oauth-authz-req+jwt`).
    pub typ: Option<String>,
    /// The request `client_id`, proven to use `x509_hash` and bind to the
    /// verified `x5c` leaf.
    pub client_id: String,
    /// The `x509_hash` binding computed from the verified `x5c` leaf DER.
    pub leaf_x509_hash: String,
    /// The leaf certificate subject distinguished name.
    pub leaf_subject: String,
    /// The leaf certificate issuer distinguished name.
    pub leaf_issuer: String,
    /// True when the leaf is self-issued (subject == issuer): its signature then
    /// only proves self-consistency, never third-party trust.
    pub self_signed: bool,
    /// Whether the caller supplied trust anchors (so `trust_anchored` is
    /// meaningful rather than "not checked").
    pub anchors_supplied: bool,
    /// Whether the leaf chained to a supplied anchor. Always `false` when no
    /// anchors were supplied.
    pub trust_anchored: bool,
    /// The request `iat`, if present.
    pub iat: Option<f64>,
    /// The request `exp`, if present.
    pub exp: Option<f64>,
    /// The request `nbf`, if present.
    pub nbf: Option<f64>,
}

/// Verify a JAR's signature (and, per [`JarOptions`], its trust anchoring and
/// `client_id` binding), returning a rich [`VerifiedJar`] or a typed
/// [`RejectReason`]. The checks, in order and all fail-closed:
///
/// 1. the token is a signed compact JWS (`header.payload.signature`);
/// 2. the `alg` is `ES256` (rejects `none` and any confusion algorithm first);
/// 3. the `x5c` leaf yields a usable P-256 key;
/// 4. the ES256 signature verifies over `base64url(header).base64url(payload)`;
/// 5. the `client_id` is present, uses `x509_hash`, and binds to the verified
///    leaf (anything else rejects);
/// 6. if anchors were supplied, the leaf chains to one within validity;
/// 7. the request `exp`/`nbf`, if present, hold at the verification clock.
pub fn verify_jar(token: &str, opts: &JarOptions) -> VerifyResult<VerifiedJar> {
    // 1. Split the compact JWS. Require exactly three segments and a non-empty
    // signature: a two-segment or empty-signature token is unsigned.
    let token = token.trim();
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts[2].is_empty() {
        return Err(reject(
            RejectKind::MalformedJar,
            "not a signed compact JWS (need header.payload.signature)",
        ));
    }
    // The signing input is the original ASCII bytes, never a re-serialization:
    // re-encoding the JSON could reorder keys or change spacing and break the
    // signature even for an authentic request.
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let header = b64url_json(parts[0]).map_err(|e| {
        reject(
            RejectKind::MalformedJar,
            format!("JOSE header is not base64url JSON: {e}"),
        )
    })?;
    let payload = b64url_json(parts[1]).map_err(|e| {
        reject(
            RejectKind::MalformedJar,
            format!("payload is not base64url JSON: {e}"),
        )
    })?;

    // 2. Algorithm allowlist. Checked before any key handling: the header `alg`
    // never selects the verification algorithm, so declaring `none`, `HS256`, or
    // `RS256` cannot coerce a different (or absent) check.
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if alg != ES256 {
        return Err(reject(
            RejectKind::JarAlgUnsupported,
            format!(
                "unsupported JAR alg '{alg}': only ES256 is accepted (this also rejects 'none')"
            ),
        ));
    }

    // 3. Resolve the verification key from the x5c leaf.
    let leaf_der = leaf_der_from_header(&header)?;
    let cert = Certificate::from_der(&leaf_der).map_err(|e| {
        reject(
            RejectKind::UnsupportedKey,
            format!("parse x5c leaf certificate: {e}"),
        )
    })?;
    let point = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let verifying_key = VerifyingKey::from_sec1_bytes(point).map_err(|e| {
        reject(
            RejectKind::UnsupportedKey,
            format!("x5c leaf key is not a usable P-256 key: {e}"),
        )
    })?;

    // 4. Verify the ES256 JWS signature. JWS carries the fixed 64-byte (r || s)
    // form, not the DER form X.509 certificate signatures use.
    let sig_bytes = BASE64_URL_SAFE_NO_PAD.decode(parts[2]).map_err(|e| {
        reject(
            RejectKind::JarSignature,
            format!("signature is not base64url: {e}"),
        )
    })?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|e| {
        reject(
            RejectKind::JarSignature,
            format!("signature is not a 64-byte ES256 value: {e}"),
        )
    })?;
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| {
            reject(
                RejectKind::JarSignature,
                "request signature does not verify against the x5c leaf key",
            )
        })?;

    // The signature is authentic from here. Gather the rest of the report and
    // apply the remaining fail-closed policy checks.
    let leaf_x509_hash = leaf_cert_hash(&leaf_der);
    let client_id = payload
        .get("client_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            reject(
                RejectKind::JarClientIdUnbound,
                "request has no client_id, so x509_hash binding cannot be established",
            )
        })?;

    // 5. client_id binding (x509_hash scheme only).
    if !client_id.starts_with(X509_HASH_PREFIX) {
        return Err(reject(
            RejectKind::JarClientIdUnbound,
            format!(
                "client_id uses scheme '{}', not x509_hash, so binding to the x5c leaf cannot be established",
                client_id_scheme_name(client_id)
            ),
        ));
    }
    let expected = format!("{X509_HASH_PREFIX}{leaf_x509_hash}");
    if client_id != expected {
        return Err(reject(
            RejectKind::JarClientIdMismatch,
            format!(
                "client_id '{client_id}' does not bind to the x5c leaf (expected '{expected}')"
            ),
        ));
    }

    // 6. Trust anchoring (optional).
    let anchors_supplied = opts.anchors.is_some();
    let trust_anchored = match opts.anchors {
        Some(anchors) => {
            if !leaf_der_trusted_at(&leaf_der, anchors, opts.now_unix) {
                return Err(reject(
                    RejectKind::UntrustedIssuer,
                    "x5c leaf does not chain to a supplied trust anchor, or a certificate is outside its validity window",
                ));
            }
            true
        }
        None => false,
    };

    // 7. Request validity window (optional claims).
    let exp = numeric_date_claim(&payload, "exp", RejectKind::MalformedJar)?;
    let nbf = numeric_date_claim(&payload, "nbf", RejectKind::MalformedJar)?;
    // `iat` is informational and gates nothing, so a non-numeric value is
    // ignored rather than rejected; only `exp`/`nbf` parse strictly.
    let iat = payload.get("iat").and_then(Value::as_f64);
    if let Some(exp) = exp {
        if opts.now_unix as f64 >= exp {
            return Err(reject(
                RejectKind::JarExpired,
                format!(
                    "request expired at {} (verification clock {})",
                    format_numeric_date(exp),
                    opts.now_unix
                ),
            ));
        }
    }
    if let Some(nbf) = nbf {
        if (opts.now_unix as f64) < nbf {
            return Err(reject(
                RejectKind::JarNotYetValid,
                format!(
                    "request is not valid before {} (verification clock {})",
                    format_numeric_date(nbf),
                    opts.now_unix
                ),
            ));
        }
    }

    Ok(VerifiedJar {
        alg: alg.to_string(),
        typ: header
            .get("typ")
            .and_then(Value::as_str)
            .map(str::to_string),
        client_id: client_id.to_string(),
        leaf_x509_hash,
        leaf_subject: cert.tbs_certificate.subject.to_string(),
        leaf_issuer: cert.tbs_certificate.issuer.to_string(),
        self_signed: cert.tbs_certificate.subject == cert.tbs_certificate.issuer,
        anchors_supplied,
        trust_anchored,
        iat,
        exp,
        nbf,
    })
}

fn client_id_scheme_name(client_id: &str) -> &str {
    client_id
        .split_once(':')
        .map(|(scheme, _)| scheme)
        .filter(|scheme| !scheme.is_empty())
        .unwrap_or("unknown")
}

/// Decode a base64url-no-pad JWS segment into JSON.
fn b64url_json(segment: &str) -> Result<Value, String> {
    let bytes = BASE64_URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| e.to_string())?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

/// Extract the leaf certificate DER from the JOSE `x5c` header. The `x5c`
/// entries are base64 (standard alphabet, RFC 7515); the leaf is the first.
fn leaf_der_from_header(header: &Value) -> VerifyResult<Vec<u8>> {
    let x5c = header
        .get("x5c")
        .ok_or_else(|| reject(RejectKind::MissingX5c, "JOSE header has no x5c"))?;
    let leaf_b64 = match x5c {
        Value::Array(items) => items
            .first()
            .and_then(Value::as_str)
            .ok_or_else(|| reject(RejectKind::MissingX5c, "x5c is empty"))?,
        // A bare-string x5c is itself a JAR gotcha (`doctor` flags it), but read
        // it leniently so a malformed x5c still reaches a signature verdict.
        Value::String(s) => s.as_str(),
        _ => {
            return Err(reject(
                RejectKind::MissingX5c,
                "x5c is neither a list nor a string",
            ))
        }
    };
    BASE64_STANDARD.decode(leaf_b64.trim()).map_err(|e| {
        reject(
            RejectKind::MissingX5c,
            format!("x5c leaf is not base64: {e}"),
        )
    })
}

fn reject(kind: RejectKind, reason: impl Into<String>) -> RejectReason {
    RejectReason::new(kind, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_780_435_200;

    fn fixture() -> &'static str {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/requests/eudiplo-request.jwt"
        ))
        .trim()
    }

    fn no_anchor() -> JarOptions<'static> {
        JarOptions {
            anchors: None,
            now_unix: NOW,
        }
    }

    /// Replace one segment of a compact JWS, keeping the other two.
    fn with_segment(token: &str, index: usize, replacement: &str) -> String {
        let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
        parts[index] = replacement.to_string();
        parts.join(".")
    }

    fn b64url(bytes: &[u8]) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(bytes)
    }

    #[test]
    fn valid_fixture_verifies_against_its_x5c_leaf() {
        let v = verify_jar(fixture(), &no_anchor()).expect("real captured JAR must verify");
        assert_eq!(v.alg, ES256);
        assert_eq!(v.typ.as_deref(), Some("oauth-authz-req+jwt"));
        assert!(v.self_signed, "the eudiplo fixture leaf is self-issued");
        assert!(!v.trust_anchored);
        assert!(!v.anchors_supplied);
        assert_eq!(
            v.client_id,
            "x509_hash:7zvIjJaM1KQPpN7IZBuVLuh8anw1gcbZ0a6Wj3M9i4w"
        );
    }

    #[test]
    fn tampered_signature_is_rejected() {
        // Flip the final signature character (still valid base64url, still 64
        // bytes) so the signature no longer matches the signing input.
        let token = fixture();
        let sig = token.rsplit('.').next().unwrap();
        let last = sig.chars().last().unwrap();
        let flipped = if last == 'A' { 'B' } else { 'A' };
        let bad_sig: String = sig[..sig.len() - 1].chars().chain([flipped]).collect();
        let bad = with_segment(token, 2, &bad_sig);
        let err = verify_jar(&bad, &no_anchor()).expect_err("tampered signature must reject");
        assert_eq!(err.kind, RejectKind::JarSignature);
    }

    #[test]
    fn tampered_payload_breaks_the_signature() {
        // Re-encode a payload with a different nonce; the original signature no
        // longer covers it, so verification fails.
        let token = fixture();
        let original = b64url_json(token.split('.').nth(1).unwrap()).unwrap();
        let mut payload = original.as_object().unwrap().clone();
        payload.insert("nonce".into(), Value::String("tampered".into()));
        let seg = b64url(
            serde_json::to_vec(&Value::Object(payload))
                .unwrap()
                .as_slice(),
        );
        let bad = with_segment(token, 1, &seg);
        let err = verify_jar(&bad, &no_anchor()).expect_err("tampered payload must reject");
        assert_eq!(err.kind, RejectKind::JarSignature);
    }

    #[test]
    fn alg_none_is_rejected_before_any_signature_check() {
        // alg=none, empty signature: the classic unsigned-token downgrade.
        let token = fixture();
        let header = json_header(token);
        let none_header = with_alg(&header, "none");
        let unsigned = format!("{}.{}.", none_header, token.split('.').nth(1).unwrap());
        let err = verify_jar(&unsigned, &no_anchor()).expect_err("alg=none must reject");
        // Empty signature trips the shape check first; both are fail-closed.
        assert_eq!(err.kind, RejectKind::MalformedJar);

        // alg=none but carrying the original signature bytes: rejected on alg.
        let none_with_sig = with_segment(
            &with_segment(token, 0, &none_header),
            2,
            token.rsplit('.').next().unwrap(),
        );
        let err = verify_jar(&none_with_sig, &no_anchor()).expect_err("alg=none must reject");
        assert_eq!(err.kind, RejectKind::JarAlgUnsupported);
    }

    #[test]
    fn alg_confusion_hs256_is_rejected() {
        // An attacker who swaps ES256 for a symmetric alg (hoping the public key
        // is used as an HMAC secret) is rejected on the algorithm allowlist,
        // before any key handling.
        let token = fixture();
        let confused = with_segment(token, 0, &with_alg(&json_header(token), "HS256"));
        let err = verify_jar(&confused, &no_anchor()).expect_err("HS256 must reject");
        assert_eq!(err.kind, RejectKind::JarAlgUnsupported);
    }

    #[test]
    fn key_mismatch_when_x5c_leaf_is_not_the_signer() {
        // Swap the x5c leaf for an unrelated certificate. The signature was made
        // by the real key, so it cannot verify against the substituted leaf.
        let token = fixture();
        let other = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/certs/erica-trust-anchor.pem"
        ));
        let other_der = pem_first_cert(other);
        let header = json_header(token);
        let mut header_obj: Value = serde_json::from_str(&header_json(&header)).unwrap();
        header_obj["x5c"] = Value::Array(vec![Value::String(BASE64_STANDARD.encode(&other_der))]);
        let swapped_header = b64url(serde_json::to_vec(&header_obj).unwrap().as_slice());
        let bad = with_segment(token, 0, &swapped_header);
        let err = verify_jar(&bad, &no_anchor()).expect_err("wrong x5c leaf must reject");
        assert_eq!(err.kind, RejectKind::JarSignature);
    }

    #[test]
    fn missing_x5c_is_reported() {
        let token = fixture();
        let header = json!({ "typ": "oauth-authz-req+jwt", "alg": "ES256" });
        let seg = b64url(serde_json::to_vec(&header).unwrap().as_slice());
        let bad = with_segment(token, 0, &seg);
        let err = verify_jar(&bad, &no_anchor()).expect_err("no x5c must reject");
        assert_eq!(err.kind, RejectKind::MissingX5c);
    }

    #[test]
    fn self_anchor_is_trusted_and_wrong_anchor_is_not() {
        // The fixture leaf is self-signed, so anchoring to the leaf itself
        // chains; anchoring to an unrelated CA does not.
        let leaf_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/certs/eudiplo-verifier-leaf.pem"
        ));
        let anchors = TrustAnchors::from_pem(leaf_pem).unwrap();
        let v = verify_jar(
            fixture(),
            &JarOptions {
                anchors: Some(&anchors),
                now_unix: NOW,
            },
        )
        .expect("self-anchored fixture must verify and be trusted");
        assert!(v.trust_anchored);
        assert!(v.anchors_supplied);

        let wrong_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/certs/erica-trust-anchor.pem"
        ));
        let wrong = TrustAnchors::from_pem(wrong_pem).unwrap();
        let err = verify_jar(
            fixture(),
            &JarOptions {
                anchors: Some(&wrong),
                now_unix: NOW,
            },
        )
        .expect_err("an unrelated anchor must not trust the leaf");
        assert_eq!(err.kind, RejectKind::UntrustedIssuer);
    }

    #[test]
    fn expired_request_is_rejected_after_its_exp() {
        // One second past the fixture's exp (1780438572).
        let err = verify_jar(
            fixture(),
            &JarOptions {
                anchors: None,
                now_unix: 1_780_438_573,
            },
        )
        .expect_err("a request past its exp must reject");
        assert_eq!(err.kind, RejectKind::JarExpired);
    }

    #[test]
    fn unsigned_two_segment_token_is_malformed() {
        let token = fixture();
        let two = token.rsplitn(2, '.').last().unwrap().to_string();
        let err = verify_jar(&two, &no_anchor()).expect_err("two-segment token must reject");
        assert_eq!(err.kind, RejectKind::MalformedJar);
    }

    // --- small test helpers -------------------------------------------------

    use serde_json::json;

    fn json_header(token: &str) -> String {
        token.split('.').next().unwrap().to_string()
    }

    fn header_json(header_b64: &str) -> String {
        String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(header_b64).unwrap()).unwrap()
    }

    fn with_alg(header_b64: &str, alg: &str) -> String {
        let mut obj: Value = serde_json::from_str(&header_json(header_b64)).unwrap();
        obj["alg"] = Value::String(alg.to_string());
        b64url(serde_json::to_vec(&obj).unwrap().as_slice())
    }

    fn pem_first_cert(pem: &str) -> Vec<u8> {
        let body: String = pem
            .lines()
            .skip_while(|l| !l.contains("BEGIN CERTIFICATE"))
            .skip(1)
            .take_while(|l| !l.contains("END CERTIFICATE"))
            .collect();
        BASE64_STANDARD.decode(body.trim()).unwrap()
    }
}
