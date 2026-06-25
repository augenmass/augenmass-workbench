use std::env;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use anyhow::{Context, Result};
use augenmass_relay_proto::max_body_for_ws_cap;

pub const DEFAULT_HOST: &str = "127.0.0.1";
pub const DEFAULT_PORT: u16 = 8082;
pub const DEFAULT_BODY_LIMIT_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_INFLIGHT: usize = 32;
pub const DEFAULT_REQ_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_RUN_TTL_SECS: u64 = 600;
pub const HARD_MAX_RUN_TTL_SECS: u64 = 720;
pub const DEFAULT_MAX_QUERY_BYTES: usize = 2 * 1024;
pub const DEFAULT_MAX_HEADER_BYTES: usize = 8 * 1024;
pub const DEFAULT_MAX_RUNS: usize = 256;
pub const DEFAULT_TOMBSTONE_TTL_SECS: u64 = 120;
pub const DEFAULT_MAX_TOMBSTONES: usize = 1024;
pub const DEFAULT_RATE_WINDOW_SECS: u64 = 60;
pub const DEFAULT_MAX_TUNNEL_CREATES_PER_WINDOW: usize = 60;
pub const DEFAULT_MAX_FORWARD_REQUESTS_PER_WINDOW: usize = 600;
pub const DEFAULT_MAX_RATE_ENTRIES: usize = 4096;

#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub bind_addr: SocketAddr,
    pub auth_tokens: Vec<String>,
    pub public_base: Option<String>,
    pub max_body_bytes: usize,
    pub max_inflight: usize,
    pub req_timeout: Duration,
    pub run_ttl: Duration,
    pub max_query_bytes: usize,
    pub max_header_bytes: usize,
    pub max_runs: usize,
    pub tombstone_ttl: Duration,
    pub max_tombstones: usize,
    pub rate_window: Duration,
    pub max_tunnel_creates_per_window: usize,
    pub max_forward_requests_per_window: usize,
    pub max_rate_entries: usize,
}

impl RelayConfig {
    pub fn from_env() -> Result<Self> {
        let host = env::var("AUGENMASS_RELAY_HOST").unwrap_or_else(|_| DEFAULT_HOST.to_string());
        let port = env_u16("PORT")?
            .or(env_u16("AUGENMASS_RELAY_PORT")?)
            .unwrap_or(DEFAULT_PORT);
        let bind_addr = resolve_bind_addr(&host, port)?;
        let auth_tokens = env::var("AUGENMASS_RELAY_AUTH_TOKEN")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .map(str::trim)
                    .filter(|token| !token.is_empty())
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let public_base = env::var("AUGENMASS_RELAY_PUBLIC_BASE")
            .ok()
            .map(normalize_public_base)
            .transpose()?;

        require_public_bind_config(bind_addr, &auth_tokens, public_base.as_deref())?;

        let max_body_bytes = env_usize("AUGENMASS_RELAY_BODY_LIMIT_BYTES")?
            .unwrap_or(DEFAULT_BODY_LIMIT_BYTES)
            .min(max_body_for_ws_cap());
        let max_inflight =
            env_usize("AUGENMASS_RELAY_MAX_INFLIGHT")?.unwrap_or(DEFAULT_MAX_INFLIGHT);
        let req_timeout = Duration::from_secs(
            env_u64("AUGENMASS_RELAY_REQ_TIMEOUT_SECS")?.unwrap_or(DEFAULT_REQ_TIMEOUT_SECS),
        );
        let requested_ttl =
            env_u64("AUGENMASS_RELAY_RUN_TTL_SECS")?.unwrap_or(DEFAULT_RUN_TTL_SECS);
        let run_ttl = Duration::from_secs(requested_ttl.clamp(1, HARD_MAX_RUN_TTL_SECS));
        let max_query_bytes =
            env_usize("AUGENMASS_RELAY_MAX_QUERY_BYTES")?.unwrap_or(DEFAULT_MAX_QUERY_BYTES);
        let max_header_bytes =
            env_usize("AUGENMASS_RELAY_MAX_HEADER_BYTES")?.unwrap_or(DEFAULT_MAX_HEADER_BYTES);
        let max_runs = env_usize("AUGENMASS_RELAY_MAX_RUNS")?.unwrap_or(DEFAULT_MAX_RUNS);
        let tombstone_ttl = Duration::from_secs(
            env_u64("AUGENMASS_RELAY_TOMBSTONE_TTL_SECS")?.unwrap_or(DEFAULT_TOMBSTONE_TTL_SECS),
        );
        let max_tombstones =
            env_usize("AUGENMASS_RELAY_MAX_TOMBSTONES")?.unwrap_or(DEFAULT_MAX_TOMBSTONES);
        let rate_window = Duration::from_secs(
            env_u64("AUGENMASS_RELAY_RATE_WINDOW_SECS")?.unwrap_or(DEFAULT_RATE_WINDOW_SECS),
        );
        let max_tunnel_creates_per_window =
            env_usize("AUGENMASS_RELAY_MAX_TUNNEL_CREATES_PER_WINDOW")?
                .unwrap_or(DEFAULT_MAX_TUNNEL_CREATES_PER_WINDOW);
        let max_forward_requests_per_window =
            env_usize("AUGENMASS_RELAY_MAX_FORWARD_REQUESTS_PER_WINDOW")?
                .unwrap_or(DEFAULT_MAX_FORWARD_REQUESTS_PER_WINDOW);
        let max_rate_entries =
            env_usize("AUGENMASS_RELAY_MAX_RATE_ENTRIES")?.unwrap_or(DEFAULT_MAX_RATE_ENTRIES);

        Ok(Self {
            bind_addr,
            auth_tokens,
            public_base,
            max_body_bytes,
            max_inflight,
            req_timeout,
            run_ttl,
            max_query_bytes,
            max_header_bytes,
            max_runs,
            tombstone_ttl,
            max_tombstones,
            rate_window,
            max_tunnel_creates_per_window,
            max_forward_requests_per_window,
            max_rate_entries,
        })
    }

    pub fn public_base_for(&self, local_addr: SocketAddr) -> Result<String> {
        match self.public_base.as_ref() {
            Some(base) => Ok(base.clone()),
            None if local_addr.ip().is_loopback() => Ok(format!("http://{local_addr}")),
            None => anyhow::bail!(
                "AUGENMASS_RELAY_PUBLIC_BASE is required when relay binds to non-loopback {local_addr}"
            ),
        }
    }

    pub fn clamp_requested_ttl(&self, requested: Option<u64>) -> Duration {
        let requested = requested.unwrap_or(self.run_ttl.as_secs());
        Duration::from_secs(
            requested
                .min(self.run_ttl.as_secs())
                .clamp(1, HARD_MAX_RUN_TTL_SECS),
        )
    }
}

pub fn resolve_bind_addr(host: &str, port: u16) -> Result<SocketAddr> {
    (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolve relay bind host {host}:{port}"))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("relay bind host {host}:{port} did not resolve"))
}

fn require_public_bind_config(
    addr: SocketAddr,
    auth_tokens: &[String],
    public_base: Option<&str>,
) -> Result<()> {
    if addr.ip().is_loopback() {
        return Ok(());
    }
    if auth_tokens.is_empty() {
        anyhow::bail!(
            "AUGENMASS_RELAY_AUTH_TOKEN is required when relay binds to non-loopback {addr}; bind AUGENMASS_RELAY_HOST=127.0.0.1 for local-only use"
        );
    }
    if public_base.is_none() {
        anyhow::bail!(
            "AUGENMASS_RELAY_PUBLIC_BASE is required when relay binds to non-loopback {addr}"
        );
    }
    Ok(())
}

fn normalize_public_base(raw: String) -> Result<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        anyhow::bail!("AUGENMASS_RELAY_PUBLIC_BASE must not be empty");
    }
    if !(trimmed.starts_with("https://") || trimmed.starts_with("http://")) {
        anyhow::bail!("AUGENMASS_RELAY_PUBLIC_BASE must be http or https");
    }
    Ok(trimmed.to_string())
}

fn env_u16(name: &str) -> Result<Option<u16>> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            value
                .parse::<u16>()
                .with_context(|| format!("parse {name}={value} as u16"))
        })
        .transpose()
}

fn env_u64(name: &str) -> Result<Option<u64>> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            value
                .parse::<u64>()
                .with_context(|| format!("parse {name}={value} as u64"))
        })
        .transpose()
}

fn env_usize(name: &str) -> Result<Option<usize>> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            value
                .parse::<usize>()
                .with_context(|| format!("parse {name}={value} as usize"))
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_bind_requires_token_and_base() {
        let addr = "0.0.0.0:8082".parse().unwrap();
        assert!(require_public_bind_config(addr, &[], Some("https://wallet.example")).is_err());
        assert!(require_public_bind_config(addr, &[String::from("t")], None).is_err());
        assert!(require_public_bind_config(
            addr,
            &[String::from("t")],
            Some("https://wallet.example")
        )
        .is_ok());
    }

    #[test]
    fn loopback_bind_can_derive_public_base() {
        let cfg = RelayConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            auth_tokens: Vec::new(),
            public_base: None,
            max_body_bytes: DEFAULT_BODY_LIMIT_BYTES,
            max_inflight: DEFAULT_MAX_INFLIGHT,
            req_timeout: Duration::from_secs(DEFAULT_REQ_TIMEOUT_SECS),
            run_ttl: Duration::from_secs(DEFAULT_RUN_TTL_SECS),
            max_query_bytes: DEFAULT_MAX_QUERY_BYTES,
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            max_runs: DEFAULT_MAX_RUNS,
            tombstone_ttl: Duration::from_secs(DEFAULT_TOMBSTONE_TTL_SECS),
            max_tombstones: DEFAULT_MAX_TOMBSTONES,
            rate_window: Duration::from_secs(DEFAULT_RATE_WINDOW_SECS),
            max_tunnel_creates_per_window: DEFAULT_MAX_TUNNEL_CREATES_PER_WINDOW,
            max_forward_requests_per_window: DEFAULT_MAX_FORWARD_REQUESTS_PER_WINDOW,
            max_rate_entries: DEFAULT_MAX_RATE_ENTRIES,
        };
        assert_eq!(
            cfg.public_base_for("127.0.0.1:1234".parse().unwrap())
                .unwrap(),
            "http://127.0.0.1:1234"
        );
    }
}
