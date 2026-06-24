//! `cache`: serve a read-through mirror for sandbox GET routes.

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Serialize;
use serde_json::{json, Value};
use std::time::Duration;

use crate::cache_server::{self, ServeConfig};
use crate::config::trim_base;
use crate::output::{emit, OutputFormat};

pub struct ServeArgs {
    pub db: String,
    pub host: String,
    pub port: u16,
    pub upstream: String,
    pub ttl_secs: u64,
    pub timeout_secs: u64,
    pub max_entries: usize,
    pub admin_token: Option<String>,
    pub allowed_rps: Vec<String>,
}

pub struct WarmArgs {
    pub api_base: String,
    pub admin_token: Option<String>,
    pub rp: String,
    pub timeout_secs: u64,
}

#[derive(Debug, Serialize)]
struct WarmEntry {
    route: String,
    rp: Option<String>,
    status: u16,
    disposition: Option<String>,
    cache_key: Option<String>,
    bytes: usize,
    sha256: Option<String>,
    items: Option<usize>,
}

pub async fn serve(args: ServeArgs) -> Result<()> {
    cache_server::serve(ServeConfig {
        db_path: args.db,
        host: args.host,
        port: args.port,
        upstream: args.upstream,
        ttl_secs: args.ttl_secs,
        timeout_secs: args.timeout_secs,
        max_entries: args.max_entries,
        admin_token: args.admin_token,
        allowed_rps: args.allowed_rps,
    })
    .await
}

pub async fn warm(args: WarmArgs, format: OutputFormat) -> Result<()> {
    let client = Client::builder()
        .user_agent(concat!("augenmass/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(args.timeout_secs))
        .build()?;
    let api_base = trim_base(&args.api_base);
    let routes = [
        ("schema-metadata", None),
        ("schema-metadata/vocabularies", None),
        ("registration-certificates", Some(args.rp.as_str())),
    ];
    let mut entries = Vec::new();

    for (route, rp) in routes {
        entries
            .push(refresh_route(&client, &api_base, args.admin_token.as_deref(), route, rp).await?);
    }

    let json = json!({
        "kind": "augenmass-cache-warm",
        "apiBase": api_base,
        "rp": args.rp,
        "timeoutSecs": args.timeout_secs,
        "entries": entries,
    });
    let mut text = format!("Cache warm complete for {api_base}\n");
    for entry in &entries {
        let label = entry
            .rp
            .as_deref()
            .map(|rp| format!("{}?rp={rp}", entry.route))
            .unwrap_or_else(|| entry.route.clone());
        let disposition = entry.disposition.as_deref().unwrap_or("NO-CACHE-HEADER");
        text.push_str(&format!("  {label}: {disposition}, {} bytes", entry.bytes));
        if let Some(items) = entry.items {
            text.push_str(&format!(", {items} item(s)"));
        }
        if let Some(sha256) = entry.sha256.as_deref() {
            text.push_str(&format!(", sha256 {sha256}"));
        }
        text.push('\n');
    }
    emit(format, &json, &text)
}

async fn refresh_route(
    client: &Client,
    api_base: &str,
    admin_token: Option<&str>,
    route: &str,
    rp: Option<&str>,
) -> Result<WarmEntry> {
    let mut url = reqwest::Url::parse(&format!("{api_base}/cache/refresh"))
        .with_context(|| format!("invalid cache API base URL {api_base}"))?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("route", route);
        if let Some(rp) = rp {
            query.append_pair("rp", rp);
        }
    }

    let mut request = client.post(url.clone());
    if let Some(token) = admin_token.map(str::trim).filter(|token| !token.is_empty()) {
        request = request.bearer_auth(token);
    }
    let response = request
        .send()
        .await
        .with_context(|| format!("POST {url} failed"))?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .bytes()
        .await
        .with_context(|| format!("read POST {url} response"))?;
    if !status.is_success() {
        let text = String::from_utf8_lossy(&body);
        anyhow::bail!("POST {url} returned {status}: {text}");
    }
    let items = validate_warm_body(route, &body)
        .with_context(|| format!("validate warmed {route} response"))?;

    Ok(WarmEntry {
        route: route.to_string(),
        rp: rp.map(ToString::to_string),
        status: status.as_u16(),
        disposition: header_value(&headers, "x-augenmass-cache"),
        cache_key: header_value(&headers, "x-augenmass-cache-key"),
        bytes: body.len(),
        sha256: header_value(&headers, "x-augenmass-cache-sha256"),
        items,
    })
}

fn header_value(headers: &reqwest::header::HeaderMap, name: &'static str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
}

fn validate_warm_body(route: &str, body: &[u8]) -> Result<Option<usize>> {
    let value: Value = serde_json::from_slice(body)
        .with_context(|| format!("{route} warm response did not return JSON"))?;
    match route {
        "registration-certificates" => {
            let registrations = value
                .as_array()
                .context("registration-certificates warm response must be a JSON array")?;
            for (index, item) in registrations.iter().enumerate() {
                let jwt = item
                    .get("jwt")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|jwt| !jwt.is_empty());
                if jwt.is_none() {
                    anyhow::bail!(
                        "registration-certificates warm response item {index} has no jwt"
                    );
                }
            }
            Ok(Some(registrations.len()))
        }
        "schema-metadata" | "schema-metadata/vocabularies" => {
            Ok(value.as_array().map(|items| items.len()))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::validate_warm_body;

    #[test]
    fn warm_registration_body_requires_jwt_rows() {
        validate_warm_body(
            "registration-certificates",
            br#"[{"jwt":"header.payload.signature"}]"#,
        )
        .expect("valid registration rows");
        let err = validate_warm_body("registration-certificates", br#"[{"id":"reg-1"}]"#)
            .expect_err("missing jwt rejected");
        assert!(err.to_string().contains("has no jwt"));
    }

    #[test]
    fn warm_body_rejects_non_json() {
        let err =
            validate_warm_body("schema-metadata", b"<html>nope</html>").expect_err("not JSON");
        assert!(err.to_string().contains("did not return JSON"));
    }
}
