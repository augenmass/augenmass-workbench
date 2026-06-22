//! Artifact type detection. Given an arbitrary EUDI artifact (a token, a URI,
//! or a JSON document), guess what it is so `inspect` can dispatch to the right
//! decoder. The detection is heuristic but deterministic and documented; the
//! explicit `decode <type>` subcommands bypass it when you already know.

use serde_json::Value;

use crate::jose::{decode_compact, looks_like_jwt, looks_like_pem};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    /// SD-JWT VC presentation: `issuer-jwt~disclosure~...~kb-jwt`.
    SdJwtVc,
    /// WRPRC registration certificate (JWT typ `rc-wrp+jwt`).
    RegistrationCert,
    /// Token status list (JWT typ `statuslist+jwt`).
    StatusListToken,
    /// OpenID4VP authorization request / signed JAR.
    AuthorizationRequest,
    /// Key Binding JWT (typ `kb+jwt`).
    KbJwt,
    /// A generic JWT/JWS we could not classify further.
    Jwt,
    /// OpenID4VCI credential offer (URI or JSON).
    CredentialOffer,
    /// OpenID4VP request URI (`openid4vp://...`).
    Openid4vpUri,
    /// A DCQL query document.
    DcqlQuery,
    /// A registrar registration body (POST body with `rpId`).
    RegistrationBody,
    /// An X.509 certificate (PEM).
    Certificate,
    /// An ISO 18013-5 mdoc (CBOR, given as hex or base64).
    Mdoc,
    /// Some other JSON document.
    Json,
    /// Could not classify.
    Unknown,
}

impl ArtifactKind {
    pub fn label(self) -> &'static str {
        match self {
            ArtifactKind::SdJwtVc => "SD-JWT VC presentation",
            ArtifactKind::RegistrationCert => "WRPRC registration certificate",
            ArtifactKind::StatusListToken => "token status list",
            ArtifactKind::AuthorizationRequest => "OpenID4VP authorization request (JAR)",
            ArtifactKind::KbJwt => "Key Binding JWT",
            ArtifactKind::Jwt => "JWT/JWS",
            ArtifactKind::CredentialOffer => "OpenID4VCI credential offer",
            ArtifactKind::Openid4vpUri => "OpenID4VP request URI",
            ArtifactKind::DcqlQuery => "DCQL query",
            ArtifactKind::RegistrationBody => "registrar registration body",
            ArtifactKind::Certificate => "X.509 certificate (PEM)",
            ArtifactKind::Mdoc => "ISO 18013-5 mdoc",
            ArtifactKind::Json => "JSON document",
            ArtifactKind::Unknown => "unknown",
        }
    }
}

/// Classify an artifact from its text form.
pub fn sniff(input: &str) -> ArtifactKind {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return ArtifactKind::Unknown;
    }

    // URIs first.
    if trimmed.starts_with("openid-credential-offer://") {
        return ArtifactKind::CredentialOffer;
    }
    if trimmed.starts_with("openid4vp://")
        || trimmed.starts_with("eudi-openid4vp://")
        || trimmed.starts_with("haip://")
    {
        return ArtifactKind::Openid4vpUri;
    }

    // SD-JWT VC: contains `~` and the part before the first `~` is a JWT.
    if let Some((head, _)) = trimmed.split_once('~') {
        if looks_like_jwt(head) {
            return ArtifactKind::SdJwtVc;
        }
    }

    // A single compact JWT/JWS: branch on typ, then on payload shape.
    if looks_like_jwt(trimmed) {
        if let Ok(decoded) = decode_compact(trimmed) {
            return classify_jwt(&decoded.header, &decoded.payload);
        }
        return ArtifactKind::Jwt;
    }

    // PEM certificate.
    if looks_like_pem(trimmed) {
        return ArtifactKind::Certificate;
    }

    // JSON documents.
    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        return classify_json(&value);
    }

    // ISO 18013-5 mdoc given as hex or base64/base64url of CBOR. (A raw binary
    // mdoc is not text, so reach it with the explicit `decode mdoc`.)
    if crate::mdoc::looks_like_mdoc(trimmed) {
        return ArtifactKind::Mdoc;
    }

    ArtifactKind::Unknown
}

fn classify_jwt(header: &Value, payload: &Value) -> ArtifactKind {
    match header.get("typ").and_then(Value::as_str) {
        Some("rc-wrp+jwt") => return ArtifactKind::RegistrationCert,
        Some("statuslist+jwt") => return ArtifactKind::StatusListToken,
        Some("oauth-authz-req+jwt") => return ArtifactKind::AuthorizationRequest,
        Some("kb+jwt") => return ArtifactKind::KbJwt,
        _ => {}
    }
    // Fall back to payload shape.
    if payload.get("status_list").is_some() {
        return ArtifactKind::StatusListToken;
    }
    if payload.get("response_type").is_some()
        || payload.get("dcql_query").is_some()
        || payload.get("presentation_definition").is_some()
    {
        return ArtifactKind::AuthorizationRequest;
    }
    if payload.get("credentials").is_some() && payload.get("purpose").is_some() {
        return ArtifactKind::RegistrationCert;
    }
    ArtifactKind::Jwt
}

fn classify_json(value: &Value) -> ArtifactKind {
    // Credential offer (inline or by reference).
    if value.get("credential_issuer").is_some()
        || value.get("credential_offer").is_some()
        || value.get("credential_configuration_ids").is_some()
        || value.get("uri").and_then(Value::as_str).is_some_and(|u| {
            u.starts_with("openid-credential-offer://") || u.starts_with("openid4vp://")
        })
    {
        return ArtifactKind::CredentialOffer;
    }
    // Registrar registration body.
    if value.get("rpId").is_some() {
        return ArtifactKind::RegistrationBody;
    }
    // A registrar entity envelope (the read-back / list shape): a `jwt` field
    // alongside `intendedUse`/`relyingPartyId`/`cwt`, or an array of them.
    if is_regcert_entity(value)
        || value
            .as_array()
            .and_then(|a| a.first())
            .is_some_and(is_regcert_entity)
    {
        return ArtifactKind::RegistrationCert;
    }
    // Authorization request (object form).
    if value.get("response_type").is_some()
        || value.get("client_metadata").is_some()
        || (value.get("dcql_query").is_some() && value.get("client_id").is_some())
    {
        return ArtifactKind::AuthorizationRequest;
    }
    // DCQL query: a top-level `credentials` array of query objects, or a wrapper
    // carrying a `dcql_query` field, with no registrar-only fields.
    if value.get("dcql_query").is_some() && value.get("rpId").is_none() {
        return ArtifactKind::DcqlQuery;
    }
    if let Some(creds) = value.get("credentials").and_then(Value::as_array) {
        let looks_dcql = creds
            .iter()
            .all(|c| c.get("id").is_some() || c.get("format").is_some());
        if looks_dcql && value.get("purpose").is_none() && value.get("rpId").is_none() {
            return ArtifactKind::DcqlQuery;
        }
    }
    // A registration-cert payload pasted as JSON.
    if value.get("credentials").is_some() && value.get("purpose").is_some() {
        return ArtifactKind::RegistrationCert;
    }
    ArtifactKind::Json
}

fn is_regcert_entity(value: &Value) -> bool {
    value.get("jwt").and_then(Value::as_str).is_some()
        && (value.get("intendedUse").is_some()
            || value.get("relyingPartyId").is_some()
            || value.get("cwt").is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_offer_uri() {
        assert_eq!(
            sniff("openid-credential-offer://?credential_offer=%7B%7D"),
            ArtifactKind::CredentialOffer
        );
    }

    #[test]
    fn detects_openid4vp_uri() {
        assert_eq!(
            sniff("openid4vp://?client_id=x&request_uri=y"),
            ArtifactKind::Openid4vpUri
        );
    }

    #[test]
    fn detects_registration_body() {
        assert_eq!(
            sniff(r#"{"rpId":"x","credentials":[]}"#),
            ArtifactKind::RegistrationBody
        );
    }

    #[test]
    fn detects_dcql() {
        assert_eq!(
            sniff(r#"{"credentials":[{"id":"pid","format":"dc+sd-jwt"}]}"#),
            ArtifactKind::DcqlQuery
        );
    }

    #[test]
    fn detects_mdoc_hex() {
        let hex =
            std::fs::read_to_string("fixtures/mdoc/issuer-signed.hex").expect("read mdoc fixture");
        assert_eq!(sniff(hex.trim()), ArtifactKind::Mdoc);
    }
}
