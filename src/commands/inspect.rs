//! The universal `inspect`: sniff what an artifact is, then decode it. This is
//! the "what is this?" tool. It never verifies a signature and never exits
//! nonzero on content; it just tells you what you are holding.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

use crate::artifact::{sniff, ArtifactKind};
use crate::checkbody::check_body_str;
use crate::commands::decode;
use crate::dcql;
use crate::output::{emit, OutputFormat};
use crate::x509util::parse_certificate;

pub fn run(input: &str, format: OutputFormat) -> Result<()> {
    let kind = sniff(input);
    eprintln!("Detected: {}", kind.label());

    let decoded = match kind {
        ArtifactKind::SdJwtVc => decode::decode_sd_jwt(input)?,
        ArtifactKind::RegistrationCert => decode::decode_regcert(input)?,
        ArtifactKind::StatusListToken => decode::decode_status_list(input)?,
        ArtifactKind::AuthorizationRequest => decode::decode_request(input)?,
        ArtifactKind::KbJwt | ArtifactKind::Jwt => decode::decode_jwt(input)?,
        ArtifactKind::CredentialOffer | ArtifactKind::Openid4vpUri => decode::decode_offer(input)?,
        ArtifactKind::DcqlQuery => decode_dcql(input)?,
        ArtifactKind::RegistrationBody => decode_registration_body(input)?,
        ArtifactKind::Certificate => decode_certificate(input)?,
        ArtifactKind::Json => decode_json(input)?,
        ArtifactKind::Unknown => {
            return Err(anyhow!(
                "could not classify this input. Try an explicit decoder, e.g. `augenmass decode jwt <file>`."
            ));
        }
    };

    emit(format, &decoded.json, &decoded.text)?;
    Ok(())
}

fn decode_dcql(input: &str) -> Result<decode::Decoded> {
    let query = dcql::parse_dcql(input)?;
    let keys = augenmass_core::inspector::requested_keys(&query);
    let json = json!({
        "artifact": "dcql-query",
        "requestedKeys": keys,
        "query": serde_json::to_value(&query).unwrap_or(Value::Null),
    });
    let mut text = String::new();
    text.push_str("DCQL query\n");
    text.push_str(&format!("  requested claims: {}\n", keys.len()));
    for key in &keys {
        text.push_str(&format!("    {key}\n"));
    }
    Ok(decode::Decoded { json, text })
}

fn decode_registration_body(input: &str) -> Result<decode::Decoded> {
    let (_, outcome) = check_body_str(input)?;
    let json = outcome.to_json("(input)");
    let text = crate::render::render_check("(input)", &outcome);
    Ok(decode::Decoded { json, text })
}

fn decode_certificate(input: &str) -> Result<decode::Decoded> {
    let info = parse_certificate(input)?;
    let json = json!({
        "artifact": "x509-certificate",
        "subject": info.subject,
        "issuer": info.issuer,
        "serial": info.serial,
        "notBeforeUnix": info.not_before_unix,
        "notAfterUnix": info.not_after_unix,
        "x509Hash": info.x509_hash,
        "clientId": info.client_id,
    });
    let mut text = String::new();
    text.push_str("X.509 certificate\n");
    text.push_str(&format!("  subject:   {}\n", info.subject));
    text.push_str(&format!("  issuer:    {}\n", info.issuer));
    text.push_str(&format!("  serial:    {}\n", info.serial));
    text.push_str(&format!("  x509_hash: {}\n", info.x509_hash));
    text.push_str(&format!("  client_id: {}\n", info.client_id));
    Ok(decode::Decoded { json, text })
}

fn decode_json(input: &str) -> Result<decode::Decoded> {
    let value: Value = serde_json::from_str(input.trim())?;
    let text = format!("{}\n", serde_json::to_string_pretty(&value)?);
    Ok(decode::Decoded { json: value, text })
}
