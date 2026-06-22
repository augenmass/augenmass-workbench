//! Cryptographic verification commands: the full SD-JWT VC + KB-JWT path,
//! issuer trust anchoring, and token-status-list revocation. All offline and
//! deterministic when a verification clock is pinned with `--now`.

use anyhow::{Context, Result};
use augenmass_core::status::{
    check_presentation_status, check_status_list_token, CredentialStatus, StatusListRef,
};
use augenmass_core::trust::{issuer_trusted_at, TrustAnchors};
use augenmass_core::verify::{
    verify_pid_presentation_full, RequestBinding, StatusInput, TrustOptions,
};
use augenmass_core::PID_VCT;
use serde_json::{json, Value};

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
