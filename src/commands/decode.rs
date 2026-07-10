//! Offline decoders for the EUDI artifacts a developer or auditor meets every
//! day. None of these verify a signature; they answer "what is in this thing?".
//! The `verify` commands answer "is it cryptographically sound?".

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use ssi::claims::sd_jwt::SdJwt;
use url::Url;

use crate::jose::{self, decode_compact};

/// A decoded artifact in both machine (JSON) and human (text) form.
pub struct Decoded {
    pub json: Value,
    pub text: String,
}

// --- Generic JWT -----------------------------------------------------------

pub fn decode_jwt(input: &str) -> Result<Decoded> {
    let decoded = decode_compact(input)?;
    let mut text = String::new();
    text.push_str("JWT / JWS (no signature verified)\n");
    if let Some(typ) = decoded.typ() {
        text.push_str(&format!("  typ: {typ}\n"));
    }
    if let Some(alg) = decoded.alg() {
        text.push_str(&format!("  alg: {alg}\n"));
    }
    text.push_str(&format!(
        "  segments: {}   signature present: {}\n\n",
        decoded.segments, decoded.signature_present
    ));
    text.push_str("Header:\n");
    text.push_str(&indent(&pretty(&decoded.header)));
    text.push_str("\nPayload:\n");
    text.push_str(&indent(&pretty(&decoded.payload)));
    text.push('\n');
    Ok(Decoded {
        json: decoded.to_json(),
        text,
    })
}

// --- SD-JWT VC -------------------------------------------------------------

pub fn decode_sd_jwt(input: &str) -> Result<Decoded> {
    let trimmed = input.trim();
    let sd = SdJwt::new(trimmed).map_err(|e| anyhow!("not a valid SD-JWT: {e}"))?;
    let issuer = decode_compact(sd.jwt().as_str()).context("decode issuer JWT")?;

    let revealed = augenmass_core::disclosure::revealed_claims(sd).context("apply disclosures")?;

    // The KB-JWT is the trailing `~`-separated segment, if present and non-empty.
    let kb = trimmed
        .rsplit('~')
        .next()
        .filter(|s| !s.is_empty() && jose::looks_like_jwt(s))
        .and_then(|s| decode_compact(s).ok());
    let holder_bound = kb.is_some();

    let vct = issuer
        .payload
        .get("vct")
        .and_then(Value::as_str)
        .unwrap_or("(none)")
        .to_string();

    let json = json!({
        "artifact": "sd-jwt-vc",
        "vct": vct,
        "issuer": { "header": issuer.header, "payload": issuer.payload },
        "disclosures": revealed.disclosed.iter().map(|d| json!({
            "path": d.path,
            "key": d.key(),
            "value": d.value,
        })).collect::<Vec<_>>(),
        "resolvedClaims": revealed.claims,
        "keyBinding": kb.as_ref().map(|k| json!({
            "header": k.header,
            "payload": k.payload,
        })),
        "holderBound": holder_bound,
    });

    let mut text = String::new();
    text.push_str("SD-JWT VC presentation (no signature verified)\n");
    text.push_str(&format!("  vct: {vct}\n"));
    text.push_str(&format!(
        "  issuer alg: {}\n",
        issuer.alg().unwrap_or("(none)")
    ));
    text.push_str(&format!("  holder binding (KB-JWT): {holder_bound}\n"));
    text.push_str(&format!(
        "  disclosed claims: {}\n\n",
        revealed.disclosed.len()
    ));
    text.push_str("Disclosed claims:\n");
    if revealed.disclosed.is_empty() {
        text.push_str("  (none)\n");
    }
    for d in &revealed.disclosed {
        text.push_str(&format!("  {} = {}\n", d.key(), compact_value(&d.value)));
    }
    if let Some(kb) = &kb {
        text.push_str("\nKey Binding JWT:\n");
        if let Some(nonce) = kb.payload.get("nonce").and_then(Value::as_str) {
            text.push_str(&format!("  nonce: {nonce}\n"));
        }
        if let Some(aud) = kb.payload.get("aud").and_then(Value::as_str) {
            text.push_str(&format!("  aud: {aud}\n"));
        }
    }
    Ok(Decoded { json, text })
}

// --- WRPRC registration certificate ----------------------------------------

/// Extract a compact WRPRC JWT from a JWT string, an entity JSON with a `.jwt`
/// field, or an array of such entities (the registrar list response).
pub fn extract_regcert_jwt(content: &str) -> Result<String> {
    let trimmed = content.trim();
    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        let jwt = if value.is_array() {
            value
                .get(0)
                .and_then(|e| e.get("jwt"))
                .and_then(Value::as_str)
        } else {
            value.get("jwt").and_then(Value::as_str)
        };
        if let Some(jwt) = jwt {
            return Ok(jwt.to_string());
        }
    }
    Ok(trimmed.to_string())
}

pub fn decode_regcert(input: &str) -> Result<Decoded> {
    let jwt = extract_regcert_jwt(input)?;
    let scope = augenmass_core::regcert::decode_registration_jwt(&jwt)
        .context("decode registration certificate (payload-only)")?;
    let header = decode_compact(&jwt).ok().map(|d| d.header);

    let json = json!({
        "artifact": "registration-certificate",
        "header": header,
        "scope": serde_json::to_value(&scope).unwrap_or(Value::Null),
        "claimKeys": scope.all_claim_keys(),
    });

    let mut text = String::new();
    text.push_str("WRPRC registration certificate (payload-only, no signature verified)\n");
    text.push_str(&format!(
        "  purpose: \"{}\"\n",
        scope.purpose_text().unwrap_or("not stated")
    ));
    if let Some(pp) = &scope.privacy_policy {
        text.push_str(&format!("  privacy_policy: {pp}\n"));
    }
    if let Some(su) = &scope.support_uri {
        text.push_str(&format!("  support_uri: {su}\n"));
    }
    text.push_str(&format!("  credentials: {}\n", scope.credentials.len()));
    for cred in &scope.credentials {
        text.push_str(&format!(
            "    format {}  vct {}\n",
            cred.format,
            cred.vct_values.join(", ")
        ));
        for key in cred.claim_keys() {
            text.push_str(&format!("      claim {key}\n"));
        }
    }
    Ok(Decoded { json, text })
}

// --- OpenID4VP authorization request (JAR) ---------------------------------

pub fn decode_request(input: &str) -> Result<Decoded> {
    let decoded = decode_compact(input).context("decode authorization request JAR")?;
    let p = &decoded.payload;
    let get = |k: &str| p.get(k).and_then(Value::as_str).map(str::to_string);

    let client_id = get("client_id");
    let scheme = client_id.as_deref().and_then(client_id_scheme);
    let x5c_present = decoded.header.get("x5c").is_some();
    let query = p
        .get("dcql_query")
        .cloned()
        .or_else(|| p.get("presentation_definition").cloned());

    let json = json!({
        "artifact": "authorization-request",
        "header": decoded.header,
        "x5cPresent": x5c_present,
        "clientId": client_id,
        "clientIdScheme": scheme,
        "responseType": get("response_type"),
        "responseMode": get("response_mode"),
        "responseUri": get("response_uri").or_else(|| get("redirect_uri")),
        "nonce": get("nonce"),
        "state": get("state"),
        "aud": p.get("aud").cloned(),
        "query": query,
        "payload": decoded.payload,
    });

    let mut text = String::new();
    text.push_str("OpenID4VP authorization request / JAR (no signature verified)\n");
    text.push_str(&format!("  typ: {}\n", decoded.typ().unwrap_or("(none)")));
    text.push_str(&format!("  alg: {}\n", decoded.alg().unwrap_or("(none)")));
    text.push_str(&format!("  x5c present: {x5c_present}\n"));
    if let Some(cid) = &client_id {
        text.push_str(&format!("  client_id: {cid}\n"));
    }
    if let Some(s) = scheme {
        text.push_str(&format!("  client_id scheme: {s}\n"));
    }
    for (label, key) in [
        ("response_type", "response_type"),
        ("response_mode", "response_mode"),
        ("nonce", "nonce"),
        ("state", "state"),
    ] {
        if let Some(v) = get(key) {
            text.push_str(&format!("  {label}: {v}\n"));
        }
    }
    if p.get("dcql_query").is_some() {
        text.push_str("  query: dcql_query present\n");
    } else if p.get("presentation_definition").is_some() {
        text.push_str("  query: presentation_definition present (legacy PE)\n");
    }
    Ok(Decoded { json, text })
}

pub(crate) fn client_id_scheme(client_id: &str) -> Option<&'static str> {
    if client_id.starts_with("x509_hash:") {
        Some("x509_hash")
    } else if client_id.starts_with("x509_san_dns:") {
        Some("x509_san_dns")
    } else if client_id.starts_with("redirect_uri:") {
        Some("redirect_uri")
    } else if client_id.starts_with("did:") {
        Some("did")
    } else if client_id.starts_with("https://") {
        Some("https / pre-registered")
    } else {
        Some("pre-registered")
    }
}

// --- OpenID4VCI credential offer / OpenID4VP request URI -------------------

pub fn decode_offer(input: &str) -> Result<Decoded> {
    let trimmed = input.trim();

    // If JSON, it may be the registrar/issuer offer wrapper {uri, ...} or the
    // raw offer object itself.
    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        if let Some(uri) = value.get("uri").and_then(Value::as_str) {
            return decode_offer_uri(uri);
        }
        return decode_offer_object(&value);
    }

    decode_offer_uri(trimmed)
}

fn decode_offer_uri(uri: &str) -> Result<Decoded> {
    let parsed = Url::parse(uri).context("offer is not a valid URI")?;
    let params: Vec<(String, String)> = parsed
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    let mut fields = serde_json::Map::new();
    let mut inline_offer = None;
    for (k, v) in &params {
        // credential_offer / request params may be inline JSON.
        if (k == "credential_offer" || k == "request") && v.trim_start().starts_with('{') {
            if let Ok(j) = serde_json::from_str::<Value>(v) {
                inline_offer = Some(j.clone());
                fields.insert(k.clone(), j);
                continue;
            }
        }
        fields.insert(k.clone(), Value::String(v.clone()));
    }

    let is_offer = uri.starts_with("openid-credential-offer://")
        || fields.contains_key("credential_offer")
        || fields.contains_key("credential_offer_uri");
    let kind = if is_offer {
        "credential-offer"
    } else {
        "openid4vp-request-uri"
    };

    let json = json!({
        "artifact": kind,
        "scheme": parsed.scheme(),
        "params": Value::Object(fields.clone()),
        "inlineOffer": inline_offer,
    });

    let mut text = String::new();
    if is_offer {
        text.push_str("OpenID4VCI credential offer\n");
    } else {
        text.push_str("OpenID4VP request URI\n");
    }
    text.push_str(&format!("  scheme: {}\n", parsed.scheme()));
    for (k, v) in &params {
        let shown = if v.len() > 200 {
            format!("{}…", &v[..200])
        } else {
            v.clone()
        };
        text.push_str(&format!("  {k}: {shown}\n"));
    }
    if let Some(offer) = &inline_offer {
        if let Some(issuer) = offer.get("credential_issuer").and_then(Value::as_str) {
            text.push_str(&format!("  credential_issuer: {issuer}\n"));
        }
        if let Some(ids) = offer.get("credential_configuration_ids") {
            text.push_str(&format!(
                "  credential_configuration_ids: {}\n",
                compact_value(ids)
            ));
        }
        if let Some(grants) = offer.get("grants").and_then(Value::as_object) {
            for g in grants.keys() {
                text.push_str(&format!("  grant: {g}\n"));
            }
        }
    }
    Ok(Decoded { json, text })
}

fn decode_offer_object(value: &Value) -> Result<Decoded> {
    let json = json!({
        "artifact": "credential-offer",
        "offer": value,
    });
    let mut text = String::new();
    text.push_str("OpenID4VCI credential offer (inline)\n");
    if let Some(issuer) = value.get("credential_issuer").and_then(Value::as_str) {
        text.push_str(&format!("  credential_issuer: {issuer}\n"));
    }
    if let Some(ids) = value.get("credential_configuration_ids") {
        text.push_str(&format!(
            "  credential_configuration_ids: {}\n",
            compact_value(ids)
        ));
    }
    if let Some(grants) = value.get("grants").and_then(Value::as_object) {
        for g in grants.keys() {
            text.push_str(&format!("  grant: {g}\n"));
        }
    }
    Ok(Decoded { json, text })
}

// --- Token status list -----------------------------------------------------

pub fn decode_status_list(input: &str) -> Result<Decoded> {
    let decoded = decode_compact(input).context("decode status list token")?;
    let p = &decoded.payload;
    let status_list = p.get("status_list");
    let bits = status_list.and_then(|s| s.get("bits")).cloned();
    let lst_len = status_list
        .and_then(|s| s.get("lst"))
        .and_then(Value::as_str)
        .map(str::len);

    let json = json!({
        "artifact": "status-list-token",
        "header": decoded.header,
        "iss": p.get("iss"),
        "sub": p.get("sub"),
        "iat": p.get("iat"),
        "bits": bits,
        "lstBase64Len": lst_len,
        "payload": decoded.payload,
    });

    let mut text = String::new();
    text.push_str("Token status list (no signature verified)\n");
    text.push_str(&format!("  typ: {}\n", decoded.typ().unwrap_or("(none)")));
    text.push_str(&format!("  alg: {}\n", decoded.alg().unwrap_or("(none)")));
    if let Some(iss) = p.get("iss").and_then(Value::as_str) {
        text.push_str(&format!("  iss: {iss}\n"));
    }
    if let Some(sub) = p.get("sub").and_then(Value::as_str) {
        text.push_str(&format!("  sub: {sub}\n"));
    }
    if let Some(b) = &bits {
        text.push_str(&format!("  bits per entry: {b}\n"));
    }
    if let Some(len) = lst_len {
        text.push_str(&format!("  compressed list length (base64 chars): {len}\n"));
    }
    text.push_str("\nTo read a specific index and verify the signature, use:\n");
    text.push_str("  augenmass verify status-list --token <file> --key <pem> --index <n>\n");
    Ok(Decoded { json, text })
}

// --- helpers ---------------------------------------------------------------

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

fn indent(s: &str) -> String {
    s.lines()
        .map(|l| format!("  {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn compact_value(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}
