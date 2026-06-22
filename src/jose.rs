//! Compact JOSE (JWT/JWS) decoding primitives, plus PEM/DER certificate
//! helpers. Pure string and base64 work; no signature verification happens
//! here (that is the job of the `verify` commands and the engine).

use anyhow::{anyhow, Context, Result};
use base64::prelude::*;
use serde_json::{json, Value};

/// A decoded compact JWS/JWT: the JOSE header, the payload, and whether a
/// signature segment is present. No signature is verified.
#[derive(Debug, Clone)]
pub struct DecodedJwt {
    pub header: Value,
    pub payload: Value,
    pub signature_present: bool,
    pub segments: usize,
}

impl DecodedJwt {
    pub fn typ(&self) -> Option<&str> {
        self.header.get("typ").and_then(Value::as_str)
    }

    pub fn alg(&self) -> Option<&str> {
        self.header.get("alg").and_then(Value::as_str)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "header": self.header,
            "payload": self.payload,
            "signaturePresent": self.signature_present,
            "segments": self.segments,
        })
    }
}

/// Decode a base64url-no-pad segment into JSON.
pub fn b64url_json(segment: &str) -> Result<Value> {
    let bytes = BASE64_URL_SAFE_NO_PAD
        .decode(segment.trim())
        .context("segment is not base64url")?;
    serde_json::from_slice(&bytes).context("segment is not JSON")
}

/// Decode a compact JWS/JWT (`header.payload[.signature]`). Accepts a missing
/// or empty signature segment (an unsecured or detached JWS).
pub fn decode_compact(token: &str) -> Result<DecodedJwt> {
    let trimmed = token.trim();
    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.len() < 2 {
        return Err(anyhow!("not a compact JWT (need at least header.payload)"));
    }
    let header = b64url_json(parts[0]).context("JWT header is not base64url JSON")?;
    let payload = b64url_json(parts[1]).context("JWT payload is not base64url JSON")?;
    let signature_present = parts.len() >= 3 && !parts[2].is_empty();
    Ok(DecodedJwt {
        header,
        payload,
        signature_present,
        segments: parts.len(),
    })
}

/// Heuristic: does this string look like a single compact JWS/JWT? (Two or
/// three dot-separated segments whose first segment decodes to a JSON object.)
pub fn looks_like_jwt(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.contains(char::is_whitespace) {
        return false;
    }
    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.len() < 2 || parts.len() > 3 {
        return false;
    }
    b64url_json(parts[0])
        .map(|v| v.is_object())
        .unwrap_or(false)
}

/// Extract the leaf certificate DER from an `x5c` JOSE header value. The `x5c`
/// entries are base64 (standard alphabet, with padding) per RFC 7515. The leaf
/// is the first entry.
pub fn leaf_der_from_x5c(header: &Value) -> Result<Vec<u8>> {
    let x5c = header
        .get("x5c")
        .ok_or_else(|| anyhow!("no x5c in the JOSE header"))?;
    let first = match x5c {
        Value::Array(items) => items
            .first()
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("x5c is empty"))?,
        // A bare string x5c is itself a gotcha, but be lenient when reading.
        Value::String(s) => s.as_str(),
        _ => return Err(anyhow!("x5c is neither a list nor a string")),
    };
    BASE64_STANDARD
        .decode(first.trim())
        .context("x5c leaf is not base64 (standard alphabet)")
}

/// Decode a PEM-armored certificate (or any single PEM block) into its DER bytes.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let body: String = pem
        .lines()
        .filter(|line| !line.trim_start().starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    if body.trim().is_empty() {
        return Err(anyhow!("no base64 body found between PEM markers"));
    }
    BASE64_STANDARD
        .decode(body.trim())
        .context("PEM body is not base64")
}

/// Is this text a PEM block?
pub fn looks_like_pem(s: &str) -> bool {
    s.contains("-----BEGIN")
}
