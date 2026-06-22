//! Compute and verify the `x509_hash` client_id binding: the single most-cited
//! verifier gotcha. From a JAR (its `x5c` leaf), a PEM certificate, or base64
//! DER, derive `x509_hash:base64url-nopad(SHA-256(leaf DER))` and optionally
//! compare it to a stated `client_id`.

use anyhow::Result;
use serde_json::json;

use crate::output::{emit, OutputFormat};
use crate::x509util::{cert_info_from_der, leaf_der_from_input};

/// Returns true if no `--client-id` was supplied (informational) or it matches.
pub fn run(input: &str, client_id: Option<&str>, format: OutputFormat) -> Result<bool> {
    let der = leaf_der_from_input(input)?;
    let info = cert_info_from_der(der)?;

    let matches = client_id.map(|cid| cid.trim() == info.client_id);

    let json = json!({
        "x509Hash": info.x509_hash,
        "clientId": info.client_id,
        "subject": info.subject,
        "issuer": info.issuer,
        "serial": info.serial,
        "notBeforeUnix": info.not_before_unix,
        "notAfterUnix": info.not_after_unix,
        "claimedClientId": client_id,
        "matches": matches,
    });

    let mut text = String::new();
    text.push_str(&format!("x509_hash:   {}\n", info.x509_hash));
    text.push_str(&format!("client_id:   {}\n", info.client_id));
    text.push_str(&format!("subject:     {}\n", info.subject));
    text.push_str(&format!("issuer:      {}\n", info.issuer));
    text.push_str(&format!("serial:      {}\n", info.serial));
    if let Some(cid) = client_id {
        match matches {
            Some(true) => text.push_str(&format!("\nMATCH: {cid} matches the computed binding.\n")),
            Some(false) => text.push_str(&format!(
                "\nMISMATCH: claimed client_id\n  {cid}\ndoes not equal the computed\n  {}\n",
                info.client_id
            )),
            None => {}
        }
    }

    emit(format, &json, &text)?;
    Ok(matches.unwrap_or(true))
}
