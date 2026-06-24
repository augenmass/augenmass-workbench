//! The registrar write/read transport for `register` and `list`.
//!
//! Targets stay deliberately separate: `clone` is a mutable local demo store,
//! `sandbox` is the live registrar with Keycloak bearer auth, and
//! `cached-sandbox` is a read-through mirror for sandbox GET routes.

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

use crate::config::{trim_base, Config};

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum Target {
    Clone,
    CachedSandbox,
    Sandbox,
}

impl Target {
    pub fn as_str(self) -> &'static str {
        match self {
            Target::Clone => "clone",
            Target::CachedSandbox => "cached-sandbox",
            Target::Sandbox => "sandbox",
        }
    }
}

const USER_AGENT: &str = concat!("augenmass/", env!("CARGO_PKG_VERSION"));

pub async fn post_registration(target: Target, body: &Value, config: &Config) -> Result<Value> {
    if matches!(target, Target::CachedSandbox) {
        anyhow::bail!(
            "cached-sandbox is read-only; use --target sandbox for real writes or --target clone for offline demo writes"
        );
    }

    let client = http_client(config)?;
    let base = base_url(target, config);
    if matches!(target, Target::Sandbox) {
        validate_sandbox_urls(config)?;
    }
    let url = format!("{base}/registration-certificates");
    let mut request = client.post(&url).json(body);
    if needs_bearer(target) {
        let token = bearer_token(&client, config).await?;
        request = request.bearer_auth(token);
    }
    let response = request
        .send()
        .await
        .with_context(|| format!("POST {url} failed"))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .with_context(|| format!("read POST {url} response"))?;
    if !status.is_success() {
        anyhow::bail!("POST {url} returned {status}: {text}");
    }
    serde_json::from_str(&text).with_context(|| format!("POST {url} did not return JSON"))
}

pub async fn list_registrations(target: Target, rp_id: &str, config: &Config) -> Result<Value> {
    let client = http_client(config)?;
    let base = base_url(target, config);
    if matches!(target, Target::Sandbox) {
        validate_sandbox_urls(config)?;
    }
    let url = registration_list_url(&base, rp_id)?;
    let mut request = client.get(url.clone());
    if needs_bearer(target) {
        let token = bearer_token(&client, config).await?;
        request = request.bearer_auth(token);
    }
    let response = request
        .send()
        .await
        .with_context(|| format!("GET {url} failed"))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .with_context(|| format!("read GET {url} response"))?;
    if !status.is_success() {
        anyhow::bail!("GET {url} returned {status}: {text}");
    }
    serde_json::from_str(&text).with_context(|| format!("GET {url} did not return JSON"))
}

fn base_url(target: Target, config: &Config) -> String {
    match target {
        Target::Clone => config.clone_api_base.clone(),
        Target::CachedSandbox => config.cache_api_base.clone(),
        Target::Sandbox => config.sandbox_api_base.clone(),
    }
}

fn needs_bearer(target: Target) -> bool {
    matches!(target, Target::Sandbox)
}

fn http_client(config: &Config) -> Result<Client> {
    Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(config.http_timeout_secs))
        .build()
        .context("build HTTP client")
}

fn registration_list_url(base: &str, rp_id: &str) -> Result<reqwest::Url> {
    let mut url = reqwest::Url::parse(&format!("{}/registration-certificates", trim_base(base)))
        .with_context(|| format!("invalid registrar API base URL {base}"))?;
    url.query_pairs_mut().append_pair("rp", rp_id);
    Ok(url)
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

async fn bearer_token(client: &Client, config: &Config) -> Result<String> {
    let url = config.require_token_url()?;
    validate_sensitive_url("AUGENMASS_OIDC_TOKEN_URL", url, config.unsafe_sandbox_urls)?;
    let username = config.require_username()?;
    let password = config.require_password()?;

    let mut form = vec![
        ("grant_type", "password"),
        ("client_id", "swagger"),
        ("username", username),
        ("password", password),
    ];
    if let Some(secret) = config.oidc_client_secret.as_deref() {
        form.push(("client_secret", secret));
    }

    let response = client
        .post(trim_base(url))
        .form(&form)
        .send()
        .await
        .context("OIDC token request failed")?;
    let status = response.status();
    let text = response.text().await.context("read OIDC token response")?;
    if !status.is_success() {
        anyhow::bail!("OIDC token request returned {status}: {text}");
    }
    let token: TokenResponse =
        serde_json::from_str(&text).context("OIDC token response did not match expected shape")?;
    Ok(token.access_token)
}

fn validate_sandbox_urls(config: &Config) -> Result<()> {
    validate_sensitive_url(
        "AUGENMASS_API_BASE",
        &config.sandbox_api_base,
        config.unsafe_sandbox_urls,
    )?;
    validate_sensitive_url(
        "AUGENMASS_OIDC_TOKEN_URL",
        config.require_token_url()?,
        config.unsafe_sandbox_urls,
    )
}

fn validate_sensitive_url(name: &str, value: &str, allow_unsafe_loopback: bool) -> Result<()> {
    let url = reqwest::Url::parse(&trim_base(value))
        .with_context(|| format!("{name} is not a valid URL"))?;
    if !url.username().is_empty() || url.password().is_some() {
        anyhow::bail!("{name} must not contain URL userinfo");
    }
    if url.query().is_some() || url.fragment().is_some() {
        anyhow::bail!("{name} must not contain a query string or fragment");
    }
    if url.scheme() == "https" {
        return Ok(());
    }
    if url.scheme() == "http" && allow_unsafe_loopback && is_loopback_url(&url) {
        return Ok(());
    }
    anyhow::bail!("{name} must use https; loopback http requires AUGENMASS_UNSAFE_SANDBOX_URLS=1")
}

fn is_loopback_url(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>().map(is_loopback_ip).unwrap_or(false)
}

fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => {
            ip == Ipv6Addr::LOCALHOST || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{registration_list_url, validate_sensitive_url};

    #[test]
    fn registration_list_url_percent_encodes_rp() {
        let url =
            registration_list_url("http://127.0.0.1:8081/api/", "rp 1&x=y").expect("valid URL");
        assert_eq!(
            url.as_str(),
            "http://127.0.0.1:8081/api/registration-certificates?rp=rp+1%26x%3Dy"
        );
    }

    #[test]
    fn sensitive_sandbox_urls_reject_unsafe_shapes() {
        assert!(
            validate_sensitive_url("AUGENMASS_API_BASE", "https://example.test/api", false).is_ok()
        );
        assert!(
            validate_sensitive_url("AUGENMASS_API_BASE", "http://example.test/api", false).is_err()
        );
        assert!(
            validate_sensitive_url("AUGENMASS_API_BASE", "http://127.0.0.1:8080/api", true).is_ok()
        );
        assert!(validate_sensitive_url(
            "AUGENMASS_API_BASE",
            "https://user@example.test/api",
            false
        )
        .is_err());
        assert!(validate_sensitive_url(
            "AUGENMASS_API_BASE",
            "https://example.test/api?x=1",
            false
        )
        .is_err());
    }
}
