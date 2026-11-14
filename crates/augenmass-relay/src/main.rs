mod config;
mod forward;
mod id;
mod ratelimit;
mod registry;
mod routes;
mod tunnel;

use std::io::{IsTerminal, Write};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use crate::config::RelayConfig;
use crate::ratelimit::RateLimiter;
use crate::registry::RunRegistry;
use crate::routes::{router, RelayState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if handle_early_cli()? {
        return Ok(());
    }

    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("warn,augenmass_relay=info")),
        )
        .with_ansi(std::io::stdout().is_terminal())
        // The layer reports a failed write of a log line with a print macro,
        // which panics when standard error is closed too. A log line is a
        // note: a failed write is dropped.
        .log_internal_errors(false)
        .try_init();

    let config = RelayConfig::from_env()?;
    let listener = TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("bind {}", config.bind_addr))?;
    let local_addr = listener.local_addr().context("read relay bind address")?;
    let public_base = config.public_base_for(local_addr)?;
    let rate_limiter = RateLimiter::new(config.rate_window, config.max_rate_entries);
    let state = Arc::new(RelayState {
        public_base,
        registry: RunRegistry::new(config.tombstone_ttl, config.max_tombstones, config.max_runs),
        rate_limiter,
        config,
    });
    let sweep_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            sweep_state.registry.sweep_expired().await;
        }
    });

    tracing::info!(addr = %local_addr, "augenmass relay listening");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn handle_early_cli() -> anyhow::Result<bool> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        return Ok(false);
    }
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        write_stdout(help_text())?;
        return Ok(true);
    }
    if args.iter().any(|arg| arg == "--version" || arg == "-V") {
        write_stdout(&format!("augenmass-relay {}\n", env!("CARGO_PKG_VERSION")))?;
        return Ok(true);
    }
    anyhow::bail!(
        "augenmass-relay is configured through environment variables; run augenmass-relay --help"
    )
}

/// Write `text` to standard output. A reader that closed the pipe is not an
/// error (the print macros would panic and exit with code 101); every other
/// write error is returned.
fn write_stdout(text: &str) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout().lock();
    let written = match stdout.write_all(text.as_bytes()) {
        Ok(()) => stdout.flush(),
        Err(error) => Err(error),
    };
    match written {
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        other => other.context("write standard output"),
    }
}

fn help_text() -> &'static str {
    "Hosted wallet-only relay for Augenmass Workbench serve\n\
\n\
Usage: augenmass-relay [--help] [--version]\n\
\n\
The relay is configured with environment variables so it maps cleanly to Railway,\n\
Docker, and systemd deployments. It forwards only GET /request/<session> and\n\
POST /response/<session> for each temporary run. Trace, inspect, session APIs,\n\
and unsafe debug artifacts stay local to augenmass serve.\n\
\n\
Environment:\n\
  AUGENMASS_RELAY_HOST                         Bind host (default 127.0.0.1)\n\
  AUGENMASS_RELAY_PORT                         Bind port (default 8082; PORT wins when set)\n\
  PORT                                         Platform bind port, e.g. Railway\n\
  AUGENMASS_RELAY_AUTH_TOKEN                   Comma-separated bearer token(s); required on public binds\n\
  AUGENMASS_RELAY_PUBLIC_BASE                  Public https/http base; required on public binds\n\
  AUGENMASS_RELAY_BODY_LIMIT_BYTES             Max forwarded body bytes (default 1048576)\n\
  AUGENMASS_RELAY_MAX_INFLIGHT                 Per-run in-flight forwards (default 32)\n\
  AUGENMASS_RELAY_REQ_TIMEOUT_SECS             Local serve request timeout (default 30)\n\
  AUGENMASS_RELAY_RUN_TTL_SECS                 Run TTL, hard-clamped by the relay (default 600)\n\
  AUGENMASS_RELAY_MAX_RUNS                     Concurrent runs (default 256)\n\
  AUGENMASS_RELAY_RATE_WINDOW_SECS             Per-IP rate-limit window (default 60)\n\
  AUGENMASS_RELAY_MAX_TUNNEL_CREATES_PER_WINDOW  Per-IP run creations/window (default 60)\n\
  AUGENMASS_RELAY_MAX_FORWARD_REQUESTS_PER_WINDOW Per-IP wallet forwards/window (default 600)\n\
\n\
Health: GET /healthz\n"
}
