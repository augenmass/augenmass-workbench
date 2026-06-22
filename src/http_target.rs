//! The registrar write/read transport for `register` and `list`. Two targets:
//! `clone` (the local demo store, no auth) and `sandbox` (the real registrar,
//! Keycloak bearer). Same POST body and read shape for both; only base URL and
//! auth differ.

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;

use crate::config::{trim_base, Config};

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum Target {
    Clone,
    Sandbox,
}

impl Target {
    pub fn as_str(self) -> &'static str {
        match self {
            Target::Clone => "clone",
            Target::Sandbox => "sandbox",
        }
    }
}

const USER_AGENT: &str = concat!("augenmass/", env!("CARGO_PKG_VERSION"));

pub async fn post_registration(target: Target, body: &Value, config: &Config) -> Result<Value> {
    let client = Client::builder().user_agent(USER_AGENT).build()?;
    let base = base_url(target, config);
    let url = format!("{base}/registration-certificates");
    let mut request = client.post(&url).json(body);
    if matches!(target, Target::Sandbox) {
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
    let client = Client::builder().user_agent(USER_AGENT).build()?;
    let base = base_url(target, config);
    let url = format!("{base}/registration-certificates?rp={rp_id}");
    let mut request = client.get(&url);
    if matches!(target, Target::Sandbox) {
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
        Target::Sandbox => config.sandbox_api_base.clone(),
    }
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
