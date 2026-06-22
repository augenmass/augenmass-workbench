//! Registration certificate decoding and the registered-scope model.
//!
//! A relying party's registration certificate (WRPRC, `typ rc-wrp+jwt`) is the
//! machine-readable declaration of what it may ask for: a `purpose`, a
//! `privacy_policy` and `support_uri`, and an authorized `credentials` set
//! (`format`, `meta.vct_values`, and `claim[].path`). A verifier can fetch it
//! publicly from the registrar; the inspector reads it as the real "registered
//! scope" rather than a hand-built mock.
//!
//! Field shapes here are grounded in a real registration certificate fetched
//! from the live registrar (`fixtures/live/rc-payload.json`, 2026-06-02): the
//! payload uses snake_case `privacy_policy`/`support_uri`, `purpose` is an array
//! of `{lang, content}`, and each credential's claims are under the singular key
//! `claim` (we also accept `claims` defensively).
//!
//! This decodes the JWT payload only. Verifying the WRPRC signature against the
//! registrar CA (the `x5c` chain in the header) is a separate trust step.

use anyhow::{Context, Result};
use base64::prelude::*;
use serde_json::Value;

/// A localized string, `{lang, content}`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LangString {
    pub lang: String,
    pub content: String,
}

/// One credential a relying party is authorized to request.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegisteredCredential {
    pub format: String,
    pub vct_values: Vec<String>,
    /// Authorized claim paths, each a list of path segments.
    pub claims: Vec<Vec<String>>,
}

impl RegisteredCredential {
    /// Dotted keys of the authorized claims, e.g. `age_equal_or_over.18`.
    pub fn claim_keys(&self) -> Vec<String> {
        self.claims.iter().map(|p| p.join(".")).collect()
    }

    /// Canonical fingerprint over (format, sorted vct_values, sorted claim
    /// keys). This is set-membership oriented (is every requested claim
    /// authorized), which is what an over-ask check needs; it deliberately does
    /// not preserve DCQL array order the way an exact-match cache key would.
    pub fn fingerprint(&self) -> String {
        let mut vcts = self.vct_values.clone();
        vcts.sort();
        let mut keys = self.claim_keys();
        keys.sort();
        format!("{}|{}|{}", self.format, vcts.join(","), keys.join(","))
    }
}

/// The registered scope read from a registration certificate.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegisteredScope {
    pub purpose: Vec<LangString>,
    pub privacy_policy: Option<String>,
    pub support_uri: Option<String>,
    pub credentials: Vec<RegisteredCredential>,
}

impl RegisteredScope {
    /// The purpose text, preferring an English locale, else the first entry.
    pub fn purpose_text(&self) -> Option<&str> {
        self.purpose
            .iter()
            .find(|p| p.lang.starts_with("en"))
            .or_else(|| self.purpose.first())
            .map(|p| p.content.as_str())
    }

    /// Every authorized claim key across all credentials.
    pub fn all_claim_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self
            .credentials
            .iter()
            .flat_map(|c| c.claim_keys())
            .collect();
        keys.sort();
        keys.dedup();
        keys
    }

    /// Whether a credential of the given format and vct is authorized at all.
    pub fn authorizes_vct(&self, format: &str, vct: &str) -> bool {
        self.credentials
            .iter()
            .any(|c| c.format == format && c.vct_values.iter().any(|v| v == vct))
    }
}

/// Decode the payload of a WRPRC JWT (no signature check) into a scope.
pub fn decode_registration_jwt(jwt: &str) -> Result<RegisteredScope> {
    let payload_b64 = jwt.split('.').nth(1).context("not a compact JWT")?;
    let bytes = BASE64_URL_SAFE_NO_PAD
        .decode(payload_b64)
        .context("invalid base64url payload")?;
    let payload: Value = serde_json::from_slice(&bytes).context("payload not JSON")?;
    scope_from_payload(&payload)
}

/// Build the registered scope from a decoded WRPRC payload.
pub fn scope_from_payload(payload: &Value) -> Result<RegisteredScope> {
    let purpose = payload
        .get("purpose")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(parse_lang_string).collect())
        .unwrap_or_default();

    let credentials = payload
        .get("credentials")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(parse_credential).collect())
        .unwrap_or_default();

    Ok(RegisteredScope {
        purpose,
        privacy_policy: str_field(payload, "privacy_policy"),
        support_uri: str_field(payload, "support_uri"),
        credentials,
    })
}

fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(String::from)
}

fn parse_lang_string(v: &Value) -> Option<LangString> {
    Some(LangString {
        lang: v.get("lang")?.as_str()?.to_string(),
        content: v.get("content")?.as_str()?.to_string(),
    })
}

fn parse_credential(v: &Value) -> Option<RegisteredCredential> {
    let format = v.get("format")?.as_str()?.to_string();
    let vct_values = v
        .get("meta")
        .and_then(|m| m.get("vct_values"))
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // The registrar payload uses the singular key `claim`; accept `claims` too.
    let claims = v
        .get("claim")
        .or_else(|| v.get("claims"))
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|c| {
                    c.get("path").and_then(|p| p.as_array()).map(|segs| {
                        segs.iter()
                            .filter_map(seg_to_string)
                            .collect::<Vec<String>>()
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Some(RegisteredCredential {
        format,
        vct_values,
        claims,
    })
}

fn seg_to_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}
