//! Environment configuration for the registrar and cached-sandbox targets.

use anyhow::{Context, Result};

pub const DEFAULT_API_BASE: &str = "https://sandbox.eudi-wallet.org/api";
pub const DEFAULT_CLONE_API_BASE: &str = "http://127.0.0.1:8080/api";
pub const DEFAULT_CACHE_API_BASE: &str = "http://127.0.0.1:8081/api";
pub const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 10;

/// What the landing page of the German sandbox registrar said when it was read
/// on 13 November 2026 (wording as in README.md and docs/SANDBOX.md).
pub const SANDBOX_REGISTRAR_NOTICE: &str = "The landing page of the German sandbox registrar (sandbox.eudi-wallet.org, read on 13 November 2026) says that testing in it is possible until 19 November 2026, that the new wallet app version then no longer accepts certificates from it, and that it admits no new users.";

#[derive(Debug, Clone)]
pub struct Config {
    pub clone_api_base: String,
    pub cache_api_base: String,
    pub sandbox_api_base: String,
    /// True when `sandbox_api_base` is the built-in [`DEFAULT_API_BASE`]
    /// because neither `AUGENMASS_API_BASE` nor `API_BASE` is set.
    pub sandbox_api_base_is_default: bool,
    pub oidc_token_url: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub oidc_client_secret: Option<String>,
    pub http_timeout_secs: u64,
    pub unsafe_sandbox_urls: bool,
}

impl Config {
    pub fn from_env() -> Self {
        let (sandbox_api_base, sandbox_api_base_is_default) = sandbox_api_base_from(
            std::env::var("AUGENMASS_API_BASE").ok(),
            std::env::var("API_BASE").ok(),
        );
        let clone_api_base = std::env::var("AUGENMASS_CLONE_API_BASE")
            .unwrap_or_else(|_| DEFAULT_CLONE_API_BASE.to_string());
        let cache_api_base = std::env::var("AUGENMASS_CACHE_API_BASE")
            .unwrap_or_else(|_| DEFAULT_CACHE_API_BASE.to_string());

        Self {
            clone_api_base: trim_base(&clone_api_base),
            cache_api_base: trim_base(&cache_api_base),
            sandbox_api_base: trim_base(&sandbox_api_base),
            sandbox_api_base_is_default,
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

/// The sandbox registrar API base: `AUGENMASS_API_BASE`, else the legacy
/// `API_BASE`, else [`DEFAULT_API_BASE`]; the flag is true only in the last
/// case. A variable set to the built-in address counts as configured.
pub fn sandbox_api_base_from(primary: Option<String>, legacy: Option<String>) -> (String, bool) {
    match primary.or(legacy) {
        Some(base) => (base, false),
        None => (DEFAULT_API_BASE.to_string(), true),
    }
}

/// The stderr line `--target sandbox` prints when it uses the built-in
/// registrar address without explicit configuration.
pub fn sandbox_target_notice(config: &Config) -> Option<String> {
    config.sandbox_api_base_is_default.then(|| {
        format!(
            "note: --target sandbox uses the built-in registrar {DEFAULT_API_BASE} because AUGENMASS_API_BASE is not set. {SANDBOX_REGISTRAR_NOTICE}"
        )
    })
}

/// The stderr line `cache serve` prints when its upstream is the built-in
/// registrar address because neither `--upstream` nor
/// `AUGENMASS_CACHE_UPSTREAM` is set.
pub fn cache_upstream_notice(upstream_is_default: bool) -> Option<String> {
    upstream_is_default.then(|| {
        format!(
            "note: cache serve uses the built-in upstream {DEFAULT_API_BASE} because neither --upstream nor AUGENMASS_CACHE_UPSTREAM is set. {SANDBOX_REGISTRAR_NOTICE}"
        )
    })
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
    use super::*;

    #[test]
    fn timeout_parser_uses_positive_values_only() {
        assert_eq!(parse_positive_u64(Some("5".to_string()), 10), 5);
        assert_eq!(parse_positive_u64(Some("0".to_string()), 10), 10);
        assert_eq!(parse_positive_u64(Some("bad".to_string()), 10), 10);
        assert_eq!(parse_positive_u64(None, DEFAULT_HTTP_TIMEOUT_SECS), 10);
    }

    fn config_with(base_is_default: bool) -> Config {
        Config {
            clone_api_base: DEFAULT_CLONE_API_BASE.to_string(),
            cache_api_base: DEFAULT_CACHE_API_BASE.to_string(),
            sandbox_api_base: DEFAULT_API_BASE.to_string(),
            sandbox_api_base_is_default: base_is_default,
            oidc_token_url: None,
            username: None,
            password: None,
            oidc_client_secret: None,
            http_timeout_secs: DEFAULT_HTTP_TIMEOUT_SECS,
            unsafe_sandbox_urls: false,
        }
    }

    #[test]
    fn sandbox_api_base_precedence_and_default_flag() {
        let s = |v: &str| Some(v.to_string());
        assert_eq!(
            sandbox_api_base_from(None, None),
            (DEFAULT_API_BASE.to_string(), true)
        );
        assert_eq!(
            sandbox_api_base_from(s("https://registrar.example.org/api"), None),
            ("https://registrar.example.org/api".to_string(), false)
        );
        // Only the legacy variable: explicit configuration, no notice.
        assert_eq!(
            sandbox_api_base_from(None, s("https://registrar.example.org/api")),
            ("https://registrar.example.org/api".to_string(), false)
        );
        assert_eq!(
            sandbox_api_base_from(
                s("https://a.example.org/api"),
                s("https://b.example.org/api")
            ),
            ("https://a.example.org/api".to_string(), false)
        );
        // The built-in address set explicitly is configuration too.
        assert_eq!(
            sandbox_api_base_from(s(DEFAULT_API_BASE), None),
            (DEFAULT_API_BASE.to_string(), false)
        );
    }

    #[test]
    fn sandbox_notices_appear_only_for_the_built_in_default() {
        let notice = sandbox_target_notice(&config_with(true)).expect("notice");
        assert_eq!(
            notice,
            format!("note: --target sandbox uses the built-in registrar https://sandbox.eudi-wallet.org/api because AUGENMASS_API_BASE is not set. {SANDBOX_REGISTRAR_NOTICE}")
        );
        assert!(!notice.contains('\n'));
        assert!(sandbox_target_notice(&config_with(false)).is_none());

        let notice = cache_upstream_notice(true).expect("notice");
        assert_eq!(
            notice,
            format!("note: cache serve uses the built-in upstream https://sandbox.eudi-wallet.org/api because neither --upstream nor AUGENMASS_CACHE_UPSTREAM is set. {SANDBOX_REGISTRAR_NOTICE}")
        );
        assert!(cache_upstream_notice(false).is_none());
        assert!(SANDBOX_REGISTRAR_NOTICE.contains("until 19 November 2026"));
    }
}
