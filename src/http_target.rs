//! The registrar write/read transport for `register` and `list`.
//!
//! Targets stay deliberately separate: `clone` is a mutable local demo store,
//! `sandbox` is the live registrar with Keycloak bearer auth, and
//! `cached-sandbox` is a read-through mirror for sandbox GET routes.

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
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

#[cfg(test)]
mod tests {
    use super::registration_list_url;

    #[test]
    fn registration_list_url_percent_encodes_rp() {
        let url =
            registration_list_url("http://127.0.0.1:8081/api/", "rp 1&x=y").expect("valid URL");
        assert_eq!(
            url.as_str(),
            "http://127.0.0.1:8081/api/registration-certificates?rp=rp+1%26x%3Dy"
        );
    }
}
