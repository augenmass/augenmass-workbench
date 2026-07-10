//! Cryptographic verification commands: the full SD-JWT VC + KB-JWT path,
//! issuer trust anchoring, and token-status-list revocation. All offline and
//! deterministic when a verification clock is pinned with `--now`.

use anyhow::{Context, Result};
use augenmass_core::jar::{verify_jar, JarOptions};
use augenmass_core::status::{
    check_presentation_status, check_status_list_token, CredentialStatus, StatusListRef,
};
use augenmass_core::trust::{issuer_trusted_at, TrustAnchors};
use augenmass_core::verify::{
    format_numeric_date, verify_pid_presentation_full, RequestBinding, StatusInput, TrustOptions,
};
use augenmass_core::PID_VCT;
use serde_json::{json, Value};

use crate::commands::decode::client_id_scheme;
use crate::output::{emit, OutputFormat};
use crate::x509util::signer_jwk_from_pem;

fn now_or_clock(now: Option<i64>) -> i64 {
    now.unwrap_or_else(|| chrono::Utc::now().timestamp())
}

/// Inputs for `verify presentation`.
pub struct PresentationArgs {
    pub presentation: String,
    pub nonce: String,
    pub aud: String,
    pub vct: Option<String>,
    pub max_age: i64,
    pub now: Option<i64>,
    pub trust_anchor_pem: Option<String>,
    pub status_token: Option<String>,
    pub status_key_pem: Option<String>,
}

/// Returns true if the presentation verified.
pub fn verify_presentation(args: PresentationArgs, format: OutputFormat) -> Result<bool> {
    let binding = RequestBinding {
        nonce: args.nonce.clone(),
        aud: args.aud.clone(),
    };
    let expected_vct = args.vct.as_deref().unwrap_or(PID_VCT).to_string();
    let now = now_or_clock(args.now);

    let anchors = match &args.trust_anchor_pem {
        Some(pem) => Some(TrustAnchors::from_pem(pem).context("load trust anchor PEM")?),
        None => None,
    };

    let status = match (&args.status_token, &args.status_key_pem) {
        (Some(token), Some(key_pem)) => {
            let signer = signer_jwk_from_pem(key_pem)?;
            StatusInput::Token {
                jws: token.trim().to_string(),
                signer,
            }
        }
        _ => StatusInput::None,
    };

    let options = TrustOptions {
        anchors: anchors.as_ref(),
        status,
    };

    let result = verify_pid_presentation_full(
        args.presentation.trim(),
        &binding,
        &expected_vct,
        args.max_age,
        now,
        &options,
    );

    match result {
        Ok(pid) => {
            let json = json!({
                "verified": true,
                "vct": pid.vct,
                "holderBound": pid.holder_bound,
                "disclosed": pid.view.disclosed.iter().map(|d| json!({
                    "key": d.key(),
                    "value": d.value,
                })).collect::<Vec<_>>(),
                "trustAnchored": anchors.is_some(),
                "statusChecked": args.status_token.is_some(),
            });
            let mut text = String::new();
            text.push_str("VERIFIED\n");
            text.push_str(&format!("  vct: {}\n", pid.vct));
            text.push_str(&format!("  holder binding: {}\n", pid.holder_bound));
            text.push_str(&format!("  trust anchored: {}\n", anchors.is_some()));
            text.push_str(&format!(
                "  status checked: {}\n",
                args.status_token.is_some()
            ));
            text.push_str("  disclosed claims:\n");
            for d in &pid.view.disclosed {
                text.push_str(&format!("    {} = {}\n", d.key(), value_str(&d.value)));
            }
            emit(format, &json, &text)?;
            Ok(true)
        }
        Err(reason) => {
            let kind = format!("{:?}", reason.kind);
            let json = json!({
                "verified": false,
                "rejectKind": kind,
                "reason": reason.reason,
            });
            let text = format!("REJECTED [{kind}]: {}\n", reason.reason);
            emit(format, &json, &text)?;
            Ok(false)
        }
    }
}

/// Inputs for `verify request` (JAR signature verification).
pub struct RequestArgs {
    pub request: String,
    pub now: Option<i64>,
    pub anchor_pem: Option<String>,
}

/// `verify request`: prove a JWT-Secured Authorization Request (JAR) was signed
/// by the key in its `x5c` leaf, that an `x509_hash` `client_id` binds to that
/// leaf, and (with `--anchor`) that the leaf chains directly to a trust anchor.
/// Returns true if the request verified.
pub fn verify_request(args: RequestArgs, format: OutputFormat) -> Result<bool> {
    let anchors = match &args.anchor_pem {
        Some(pem) => Some(TrustAnchors::from_pem(pem).context("load trust anchor PEM")?),
        None => None,
    };
    let now = now_or_clock(args.now);
    let options = JarOptions {
        anchors: anchors.as_ref(),
        now_unix: now,
    };

    match verify_jar(args.request.trim(), &options) {
        Ok(v) => {
            let scheme = client_id_scheme(&v.client_id);
            let json = json!({
                "verified": true,
                "alg": v.alg,
                "typ": v.typ,
                "clientId": v.client_id,
                "clientIdScheme": scheme,
                "clientIdBound": true,
                "leafX509Hash": v.leaf_x509_hash,
                "leafSubject": v.leaf_subject,
                "leafIssuer": v.leaf_issuer,
                "selfSigned": v.self_signed,
                "anchorsSupplied": v.anchors_supplied,
                "trustAnchored": v.trust_anchored,
                "iat": numeric_date_json(v.iat),
                "nbf": numeric_date_json(v.nbf),
                "exp": numeric_date_json(v.exp),
            });

            let mut text = String::new();
            text.push_str("VERIFIED: the request is signed by the key in its x5c leaf.\n");
            text.push_str(&format!("  alg: {}\n", v.alg));
            if let Some(typ) = &v.typ {
                text.push_str(&format!("  typ: {typ}\n"));
            }
            text.push_str(&format!("  client_id: {}\n", v.client_id));
            text.push_str("  client_id binding: matches the x5c leaf\n");
            text.push_str(&format!("  leaf subject: {}\n", v.leaf_subject));
            text.push_str(&format!("  leaf issuer:  {}\n", v.leaf_issuer));
            if v.trust_anchored && v.self_signed {
                text.push_str(
                    "  trust anchored: yes, but the verified leaf is self-issued; this pins \
                     trust to the supplied anchor material and does not by itself establish \
                     third-party trust.\n",
                );
            } else if v.trust_anchored {
                text.push_str("  trust anchored: yes (the leaf chains to a supplied anchor)\n");
            } else if v.self_signed {
                text.push_str(
                    "  trust anchored: no; the leaf is self-issued, so the signature proves \
                     self-consistency only. Supply --anchor to establish third-party trust.\n",
                );
            } else {
                text.push_str(
                    "  trust anchored: no anchor supplied; the signature verifies against the \
                     x5c leaf but is not chained to a trust anchor. Supply --anchor to check.\n",
                );
            }
            text.push_str(&format!(
                "  request window: {} (verification clock {now})\n",
                window_summary(v.iat, v.nbf, v.exp)
            ));
            emit(format, &json, &text)?;
            Ok(true)
        }
        Err(reason) => {
            let kind = format!("{:?}", reason.kind);
            let json = json!({
                "verified": false,
                "rejectKind": kind,
                "reason": reason.reason,
            });
            let text = format!("REJECTED [{kind}]: {}\n", reason.reason);
            emit(format, &json, &text)?;
            Ok(false)
        }
    }
}

/// A compact `iat / nbf / exp` summary for the human report.
fn window_summary(iat: Option<f64>, nbf: Option<f64>, exp: Option<f64>) -> String {
    let mut parts = Vec::new();
    if let Some(iat) = iat {
        parts.push(format!("iat {}", format_numeric_date(iat)));
    }
    if let Some(nbf) = nbf {
        parts.push(format!("nbf {}", format_numeric_date(nbf)));
    }
    if let Some(exp) = exp {
        parts.push(format!("exp {}", format_numeric_date(exp)));
    }
    if parts.is_empty() {
        "no iat/nbf/exp claims".to_string()
    } else {
        parts.join(", ")
    }
}

fn numeric_date_json(value: Option<f64>) -> Value {
    match value {
        None => Value::Null,
        Some(value)
            if value.fract().abs() < f64::EPSILON
                && value >= i64::MIN as f64
                // `i64::MAX as f64` rounds up to 2^63, which is not a valid
                // i64, so exactly that value must stay on the f64 path.
                && value < i64::MAX as f64 =>
        {
            json!(value as i64)
        }
        Some(value) => json!(value),
    }
}

/// `verify trust`: does the presentation's issuer chain to a trust anchor?
pub fn verify_trust(
    presentation: &str,
    anchor_pem: &str,
    now: Option<i64>,
    format: OutputFormat,
) -> Result<bool> {
    let anchors = TrustAnchors::from_pem(anchor_pem).context("load trust anchor PEM")?;
    let trusted = issuer_trusted_at(presentation.trim(), &anchors, now_or_clock(now));
    let json = json!({
        "trusted": trusted,
        "anchorCount": anchors.len(),
    });
    let text = if trusted {
        format!(
            "TRUSTED: the issuer chains to one of {} anchor(s).\n",
            anchors.len()
        )
    } else {
        format!(
            "UNTRUSTED: the issuer does not chain to any of the {} anchor(s) (or is out of its validity window).\n",
            anchors.len()
        )
    };
    emit(format, &json, &text)?;
    Ok(trusted)
}

/// `verify status`: read the presentation's status pointer, verify the token,
/// and report the credential's status.
pub fn verify_status(
    presentation: &str,
    token_jws: &str,
    key_pem: &str,
    format: OutputFormat,
) -> Result<bool> {
    let signer = signer_jwk_from_pem(key_pem)?;
    let status = check_presentation_status(presentation.trim(), &signer, token_jws.trim());
    emit_status(status, format)
}

/// `verify status-list`: verify a status-list token and read a specific index.
pub fn verify_status_list(
    token_jws: &str,
    key_pem: &str,
    index: usize,
    format: OutputFormat,
) -> Result<bool> {
    let signer = signer_jwk_from_pem(key_pem)?;
    let sref = StatusListRef {
        idx: index,
        uri: String::new(),
    };
    let status = check_status_list_token(token_jws.trim(), &signer, &sref);
    emit_status(status, format)
}

fn emit_status(
    status: augenmass_core::error::VerifyResult<CredentialStatus>,
    format: OutputFormat,
) -> Result<bool> {
    match status {
        Ok(s) => {
            let (label, ok) = match s {
                CredentialStatus::Valid => ("VALID", true),
                CredentialStatus::Revoked => ("REVOKED", false),
                CredentialStatus::Suspended => ("SUSPENDED", false),
            };
            let json = json!({ "status": label, "ok": ok });
            let text = format!("{label}\n");
            emit(format, &json, &text)?;
            Ok(ok)
        }
        Err(reason) => {
            let kind = format!("{:?}", reason.kind);
            let json = json!({
                "status": "ERROR",
                "ok": false,
                "rejectKind": kind,
                "reason": reason.reason,
            });
            let text = format!("ERROR [{kind}]: {}\n", reason.reason);
            emit(format, &json, &text)?;
            Ok(false)
        }
    }
}

fn value_str(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod jar_tests {
    //! Minted-token coverage for `verify request`. These complement the
    //! fixture-based engine tests in `augenmass_core::jar`: only a freshly signed
    //! token (we hold the private key) can exercise a *valid* signature paired
    //! with a bad `client_id` binding, a substituted signing key, or a real
    //! CA-issued (non-self-signed) leaf chaining to an anchor.

    use augenmass_core::crypto::leaf_cert_hash;
    use augenmass_core::error::RejectKind;
    use augenmass_core::jar::{verify_jar, JarOptions};
    use augenmass_core::trust::TrustAnchors;
    use base64::prelude::*;
    use p256::ecdsa::signature::Signer;
    use p256::pkcs8::DecodePrivateKey;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256,
    };
    use serde_json::{json, Value};

    const NOW: i64 = 1_780_435_200;

    fn p256_key() -> KeyPair {
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate P-256 key")
    }

    fn cert_pem(der: &[u8]) -> String {
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            BASE64_STANDARD.encode(der)
        )
    }

    fn signing_key(kp: &KeyPair) -> p256::ecdsa::SigningKey {
        let secret =
            p256::SecretKey::from_pkcs8_der(&kp.serialize_der()).expect("PKCS#8 private key");
        p256::ecdsa::SigningKey::from_bytes(&secret.to_bytes()).expect("signing key")
    }

    /// Assemble a compact ES256 JAR: `x5c_der` goes in the header, optional
    /// binding and time claims go in the payload, and the signature is made by
    /// `signer` over the signing input.
    fn mint(
        client_id: Option<&str>,
        x5c_der: &[u8],
        signer: &KeyPair,
        exp: Value,
        nbf: Option<Value>,
    ) -> String {
        mint_with_iat(client_id, x5c_der, signer, json!(NOW - 3600), exp, nbf)
    }

    fn mint_with_iat(
        client_id: Option<&str>,
        x5c_der: &[u8],
        signer: &KeyPair,
        iat: Value,
        exp: Value,
        nbf: Option<Value>,
    ) -> String {
        let header = json!({
            "typ": "oauth-authz-req+jwt",
            "alg": "ES256",
            "x5c": [BASE64_STANDARD.encode(x5c_der)],
        });
        let mut payload = json!({
            "response_type": "vp_token",
            "nonce": "b4ba2623-76a2-486b-a1f6-f1656025d07b",
            "iat": iat,
            "exp": exp,
        });
        let payload_obj = payload.as_object_mut().expect("payload object");
        if let Some(client_id) = client_id {
            payload_obj.insert("client_id".to_string(), json!(client_id));
        }
        if let Some(nbf) = nbf {
            payload_obj.insert("nbf".to_string(), nbf);
        }
        let h = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{h}.{p}");
        let sig: p256::ecdsa::Signature = signing_key(signer).sign(signing_input.as_bytes());
        let s = BASE64_URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{signing_input}.{s}")
    }

    fn self_signed(kp: &KeyPair, cn: &str) -> Vec<u8> {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, cn);
        params
            .self_signed(kp)
            .expect("self-sign leaf")
            .der()
            .as_ref()
            .to_vec()
    }

    fn opts_now() -> JarOptions<'static> {
        JarOptions {
            anchors: None,
            now_unix: NOW,
        }
    }

    #[test]
    fn minted_valid_token_verifies_and_binds() {
        let kp = p256_key();
        let der = self_signed(&kp, "Minted Verifier");
        let client_id = format!("x509_hash:{}", leaf_cert_hash(&der));
        let token = mint(Some(&client_id), &der, &kp, json!(NOW + 60), None);

        let v = verify_jar(&token, &opts_now()).expect("minted token must verify");
        assert_eq!(v.client_id, client_id);
        assert!(v.self_signed);
        assert!(!v.trust_anchored);
    }

    #[test]
    fn minted_valid_signature_with_wrong_client_id_binding_rejects() {
        // The signature is authentic, but the client_id points at a different
        // certificate hash: the binding is decorative and must be caught.
        let kp = p256_key();
        let der = self_signed(&kp, "Minted Verifier");
        let wrong = "x509_hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let token = mint(Some(wrong), &der, &kp, json!(NOW + 60), None);

        let err = verify_jar(&token, &opts_now()).expect_err("mismatched binding must reject");
        assert_eq!(err.kind, RejectKind::JarClientIdMismatch);
    }

    #[test]
    fn minted_valid_signature_without_client_id_rejects() {
        let kp = p256_key();
        let der = self_signed(&kp, "Minted Verifier");
        let token = mint(None, &der, &kp, json!(NOW + 60), None);

        let err = verify_jar(&token, &opts_now()).expect_err("missing client_id must reject");
        assert_eq!(err.kind, RejectKind::JarClientIdUnbound);
        assert_eq!(
            err.reason,
            "request has no client_id, so x509_hash binding cannot be established"
        );
    }

    #[test]
    fn minted_valid_signature_with_non_x509_client_id_rejects() {
        let kp = p256_key();
        let der = self_signed(&kp, "Minted Verifier");
        let token = mint(
            Some("redirect_uri:https://example.test/callback"),
            &der,
            &kp,
            json!(NOW + 60),
            None,
        );

        let err = verify_jar(&token, &opts_now()).expect_err("non-x509 client_id must reject");
        assert_eq!(err.kind, RejectKind::JarClientIdUnbound);
        assert!(err.reason.contains("scheme 'redirect_uri'"));
    }

    #[test]
    fn minted_future_nbf_rejects() {
        let kp = p256_key();
        let der = self_signed(&kp, "Minted Verifier");
        let client_id = format!("x509_hash:{}", leaf_cert_hash(&der));
        let token = mint(
            Some(&client_id),
            &der,
            &kp,
            json!(NOW + 60),
            Some(json!(NOW + 1)),
        );

        let err = verify_jar(&token, &opts_now()).expect_err("future nbf must reject");
        assert_eq!(err.kind, RejectKind::JarNotYetValid);
    }

    #[test]
    fn minted_past_nbf_verifies() {
        let kp = p256_key();
        let der = self_signed(&kp, "Minted Verifier");
        let client_id = format!("x509_hash:{}", leaf_cert_hash(&der));
        let token = mint(
            Some(&client_id),
            &der,
            &kp,
            json!(NOW + 60),
            Some(json!(NOW - 1)),
        );

        let v = verify_jar(&token, &opts_now()).expect("past nbf must verify");
        assert_eq!(v.nbf, Some((NOW - 1) as f64));
    }

    #[test]
    fn minted_fractional_just_past_exp_rejects() {
        let kp = p256_key();
        let der = self_signed(&kp, "Minted Verifier");
        let client_id = format!("x509_hash:{}", leaf_cert_hash(&der));
        let token = mint(Some(&client_id), &der, &kp, json!(NOW as f64 - 0.5), None);

        let err = verify_jar(&token, &opts_now()).expect_err("past fractional exp must reject");
        assert_eq!(err.kind, RejectKind::JarExpired);
    }

    #[test]
    fn minted_string_exp_rejects_as_malformed() {
        let kp = p256_key();
        let der = self_signed(&kp, "Minted Verifier");
        let client_id = format!("x509_hash:{}", leaf_cert_hash(&der));
        let token = mint(Some(&client_id), &der, &kp, json!("1780435260"), None);

        let err = verify_jar(&token, &opts_now()).expect_err("string exp must reject");
        assert_eq!(err.kind, RejectKind::MalformedJar);
    }

    #[test]
    fn minted_string_iat_still_verifies() {
        // `iat` is informational: a non-numeric value is dropped, not rejected,
        // unlike `exp`/`nbf` which gate validity and parse strictly.
        let kp = p256_key();
        let der = self_signed(&kp, "Minted Verifier");
        let client_id = format!("x509_hash:{}", leaf_cert_hash(&der));
        let token = mint_with_iat(
            Some(&client_id),
            &der,
            &kp,
            json!("not-a-date"),
            json!(NOW + 60),
            None,
        );

        let v = verify_jar(&token, &opts_now()).expect("string iat must not reject");
        assert_eq!(v.iat, None);
    }

    #[test]
    fn minted_valid_signature_with_substituted_x5c_key_rejects() {
        // Sign with `signer`, but advertise a different key's certificate in x5c.
        // The signature is valid over the signing input, yet cannot verify under
        // the substituted leaf key: the leaf is not the true signer.
        let signer = p256_key();
        let other = p256_key();
        let other_der = self_signed(&other, "Not The Signer");
        let client_id = format!("x509_hash:{}", leaf_cert_hash(&other_der));
        let token = mint(Some(&client_id), &other_der, &signer, json!(NOW + 60), None);

        let err = verify_jar(&token, &opts_now()).expect_err("substituted key must reject");
        assert_eq!(err.kind, RejectKind::JarSignature);
    }

    #[test]
    fn minted_leaf_chains_to_ca_anchor() {
        // A genuine two-link chain: a CA-issued (not self-signed) leaf verifies
        // and chains to the CA anchor.
        let ca_kp = p256_key();
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Minted PID Root");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_kp).expect("self-sign CA");

        let leaf_kp = p256_key();
        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "Minted PID Issuer");
        let leaf_cert = leaf_params
            .signed_by(&leaf_kp, &ca_cert, &ca_kp)
            .expect("CA-sign leaf");
        let leaf_der = leaf_cert.der().as_ref().to_vec();

        let client_id = format!("x509_hash:{}", leaf_cert_hash(&leaf_der));
        let token = mint(Some(&client_id), &leaf_der, &leaf_kp, json!(NOW + 60), None);

        let anchors = TrustAnchors::from_pem(&cert_pem(ca_cert.der().as_ref())).unwrap();
        let v = verify_jar(
            &token,
            &JarOptions {
                anchors: Some(&anchors),
                now_unix: NOW,
            },
        )
        .expect("CA-chained leaf must verify and be trusted");
        assert!(v.trust_anchored);
        assert!(!v.self_signed);
        assert_eq!(v.client_id, client_id);
    }
}
