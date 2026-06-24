//! Environment configuration for the registrar and cached-sandbox targets.

use anyhow::{Context, Result};

pub const DEFAULT_API_BASE: &str = "https://sandbox.eudi-wallet.org/api";
pub const DEFAULT_CLONE_API_BASE: &str = "http://127.0.0.1:8080/api";
pub const DEFAULT_CACHE_API_BASE: &str = "http://127.0.0.1:8081/api";
pub const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Clone)]
pub struct Config {
    pub clone_api_base: String,
    pub cache_api_base: String,
    pub sandbox_api_base: String,
    pub oidc_token_url: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub oidc_client_secret: Option<String>,
    pub http_timeout_secs: u64,
    pub unsafe_sandbox_urls: bool,
}

impl Config {
    pub fn from_env() -> Self {
        let sandbox_api_base = std::env::var("AUGENMASS_API_BASE")
            .or_else(|_| std::env::var("API_BASE"))
            .unwrap_or_else(|_| DEFAULT_API_BASE.to_string());
        let clone_api_base = std::env::var("AUGENMASS_CLONE_API_BASE")
            .unwrap_or_else(|_| DEFAULT_CLONE_API_BASE.to_string());
        let cache_api_base = std::env::var("AUGENMASS_CACHE_API_BASE")
            .unwrap_or_else(|_| DEFAULT_CACHE_API_BASE.to_string());

        Self {
            clone_api_base: trim_base(&clone_api_base),
            cache_api_base: trim_base(&cache_api_base),
            sandbox_api_base: trim_base(&sandbox_api_base),
            oidc_token_url: std::env::var("AUGENMASS_OIDC_TOKEN_URL").ok(),
            username: std::env::var("AUGENMASS_USERNAME").ok(),
            password: std::env::var("AUGENMASS_PASSWORD").ok(),
            oidc_client_secret: std::env::var("AUGENMASS_OIDC_CLIENT_SECRET").ok(),
            http_timeout_secs: parse_positive_u64(
                std::env::var("AUGENMASS_HTTP_TIMEOUT_SECS").ok(),
                DEFAULT_HTTP_TIMEOUT_SECS,
            ),
            unsafe_sandbox_urls: parse_bool_env("AUGENMASS_UNSAFE_SANDBOX_URLS"),
        }
    }

    pub fn require_token_url(&self) -> Result<&str> {
        self.oidc_token_url
            .as_deref()
            .context("AUGENMASS_OIDC_TOKEN_URL is required for --target sandbox")
    }

    pub fn require_username(&self) -> Result<&str> {
        self.username
            .as_deref()
            .context("AUGENMASS_USERNAME is required for --target sandbox")
    }

    pub fn require_password(&self) -> Result<&str> {
        self.password
            .as_deref()
            .context("AUGENMASS_PASSWORD is required for --target sandbox")
    }
}

pub fn trim_base(input: &str) -> String {
    input.trim_end_matches('/').to_string()
}

fn parse_positive_u64(value: Option<String>, default: u64) -> u64 {
    value
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn parse_bool_env(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::{parse_positive_u64, DEFAULT_HTTP_TIMEOUT_SECS};

    #[test]
    fn timeout_parser_uses_positive_values_only() {
        assert_eq!(parse_positive_u64(Some("5".to_string()), 10), 5);
        assert_eq!(parse_positive_u64(Some("0".to_string()), 10), 10);
        assert_eq!(parse_positive_u64(Some("bad".to_string()), 10), 10);
        assert_eq!(parse_positive_u64(None, DEFAULT_HTTP_TIMEOUT_SECS), 10);
    }
}
