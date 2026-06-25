//! `augenmass serve`: a live wallet-interaction debugger (a verifier-in-a-box).
//!
//! Runs a local OpenID4VP verifier for the German PID profile so a real EUDI
//! wallet can present to it (scan the QR, follow the deep link), and records the
//! whole exchange as a per-session trace: the request built, the signed request
//! object fetched by the wallet, the encrypted `direct_post.jwt` response, the
//! JWE decrypt, the SD-JWT VC + KB-JWT verification, and (optionally) issuer
//! trust and revocation. The trace streams to the console, renders as a browser
//! timeline at `/trace/:id`, and serializes at `/api/trace/:id`.
//!
//! Zero-config: runs on a throwaway certificate. To sign with the real registrar
//! leaf (so the client_id matches the registered identity), set `--key`/`--leaf`
//! (or `RP_KEY_PATH`/`RP_LEAF_PATH`).

pub mod artifacts;
pub mod handlers;
pub mod relay_client;
pub mod state;
pub mod trace;
pub mod view;

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;
use url::Url;

use augenmass_core::pid;

use state::{AppState, CertSource};

/// Arguments for `augenmass serve`.
#[derive(Args, Debug)]
pub struct ServeArgs {
    /// Port to listen on.
    #[arg(long, env = "PORT", default_value_t = 8080)]
    pub port: u16,
    /// Host/interface to bind.
    #[arg(long, env = "HOST", default_value = "127.0.0.1")]
    pub host: String,
    /// Public base URL (used for request_uri and response_uri); must end in '/'.
    #[arg(long, env = "PUBLIC_URL", default_value = "http://127.0.0.1:8080/")]
    pub public_url: Url,
    /// EC private key PEM for the registrar-issued leaf (optional).
    #[arg(long, env = "RP_KEY_PATH")]
    pub key: Option<PathBuf>,
    /// Leaf certificate PEM matching the key (optional).
    #[arg(long, env = "RP_LEAF_PATH")]
    pub leaf: Option<PathBuf>,
    /// Purpose baseline id for the over-ask inspector.
    #[arg(long, env = "PURPOSE", default_value = "event_checkin")]
    pub purpose: String,
    /// PEM trust anchor(s) for PID issuers. If set, the response path rejects
    /// issuers that do not chain to one. If unset, issuer trust is not enforced.
    #[arg(long, env = "TRUST_ANCHOR_PATH")]
    pub trust_anchor: Option<PathBuf>,
    /// Resolve the token-status-list over the network on the response path and
    /// reject a revoked/suspended PID. Off by default so the service stays
    /// offline-friendly; only takes effect when a trust anchor is set.
    #[arg(long, env = "LIVE_STATUS", default_value_t = false)]
    pub live_status: bool,
    /// PEM certificate or public key that verifies token-status-list signatures.
    /// If omitted, live status falls back to the trust-anchor key for
    /// single-signer fixtures; real PID providers usually need this explicitly.
    #[arg(long, env = "STATUS_SIGNER_PATH")]
    pub status_signer: Option<PathBuf>,
    /// Suppress the live per-step trace on the console (it still records and is
    /// served at /trace/:id and /api/trace/:id).
    #[arg(long, env = "QUIET", default_value_t = false)]
    pub quiet: bool,
    /// Opt in to writing raw wallet material and session key material to local
    /// disk under <dir>/<session> for private debugging.
    #[arg(long, env = "AUGENMASS_UNSAFE_DEBUG_ARTIFACTS")]
    pub unsafe_debug_artifacts: Option<PathBuf>,
    /// Publish the wallet request and response endpoints through a hosted relay.
    #[arg(long, env = "AUGENMASS_RELAY")]
    pub relay: Option<String>,
    /// Bearer token for the relay control connection. Prefer the env var.
    #[arg(long, env = "AUGENMASS_RELAY_TOKEN")]
    pub relay_token: Option<String>,
    /// Requested relay run TTL in seconds. The relay clamps this value.
    #[arg(long, env = "AUGENMASS_RELAY_TTL")]
    pub relay_ttl: Option<u64>,
    /// Continue local-only if relay setup fails.
    #[arg(long, env = "AUGENMASS_RELAY_OPTIONAL", default_value_t = false)]
    pub relay_optional: bool,
    /// Ask only for the German PID over-18 predicate. Useful for live phone demos
    /// where the sandbox wallet profile cannot satisfy the named event-check-in set.
    #[arg(long, env = "AUGENMASS_SERVE_AGE_ONLY", default_value_t = false)]
    pub age_only: bool,
}

pub async fn run(args: ServeArgs) -> Result<()> {
    // Keep the human trace (printed by the trace store) readable: default the
    // tracing subscriber to warn so axum/tower info logs do not interleave.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("warn,augenmass=info")),
        )
        .try_init();

    // The public URL is baked into the request_uri, response_uri, QR, and every
    // link the wallet and browser use, and the openid4vp builder joins paths onto
    // it, so it must end in '/'. Auto-fix and say so rather than silently serving
    // broken endpoints.
    let mut args = args;
    normalize_base_url(&mut args.public_url, "--public-url");

    let source = match (args.key.as_ref(), args.leaf.as_ref()) {
        (Some(k), Some(l)) => {
            let key_pem =
                std::fs::read_to_string(k).with_context(|| format!("read {}", k.display()))?;
            let leaf_pem =
                std::fs::read_to_string(l).with_context(|| format!("read {}", l.display()))?;
            CertSource::Files { key_pem, leaf_pem }
        }
        _ => CertSource::Ephemeral,
    };

    // Keep the anchor PEM alongside the parsed anchors: the live-status resolver
    // derives the trusted status-signer key from the anchor certificate.
    let anchor_pem = match args.trust_anchor.as_ref() {
        Some(p) => {
            Some(std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?)
        }
        None => None,
    };
    let trust_anchors = match anchor_pem.as_ref() {
        Some(pem) => Some(augenmass_core::TrustAnchors::from_pem(pem)?),
        None => None,
    };
    let status_signer = match args.status_signer.as_ref() {
        Some(p) => {
            let pem =
                std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
            Some(
                state::status_signer_from_pem(&pem)
                    .with_context(|| format!("load status signer {}", p.display()))?,
            )
        }
        None => None,
    };
    let enforce_trust = trust_anchors.is_some();
    let console_trace = !args.quiet;

    let relay_target = args.relay.clone();
    let bind_host = if relay_target.is_some() {
        if !is_loopback_host(&args.host) {
            eprintln!(
                "note: --relay makes the relay the public ingress; binding local serve to 127.0.0.1 instead of {}",
                args.host
            );
        }
        "127.0.0.1".to_string()
    } else {
        args.host.clone()
    };
    let listener = TcpListener::bind((bind_host.as_str(), args.port))
        .await
        .with_context(|| format!("bind {}:{}", bind_host, args.port))?;
    let local_addr = listener
        .local_addr()
        .context("read local listener address")?;
    let operator_url = loopback_operator_url(local_addr)?;

    let (public_url, relay_connection) = if let Some(target) = relay_target.as_deref() {
        let relay_url = relay_client::resolve_relay_url(target)?;
        let token = args.relay_token.clone().unwrap_or_default();
        if target == relay_client::HOSTED_RELAY_ALIAS && token.trim().is_empty() {
            anyhow::bail!(
                "AUGENMASS_RELAY_TOKEN is required for --relay augenmass; use --relay-optional only when a local-only fallback is acceptable"
            );
        }
        match relay_client::connect(&relay_url, &token, args.relay_ttl).await {
            Ok(mut conn) => {
                normalize_base_url(&mut conn.public_url, "relay public URL");
                (conn.public_url.clone(), Some(conn))
            }
            Err(err) if args.relay_optional => {
                eprintln!(
                    "warning: relay setup failed ({err}); continuing local-only because --relay-optional is set"
                );
                (operator_url.clone(), None)
            }
            Err(err) => {
                return Err(err).with_context(|| format!("connect relay {relay_url}"));
            }
        }
    } else {
        (args.public_url.clone(), None)
    };

    // The listener binds to host and port; everything the wallet sees is built
    // from public_url. If they disagree outside relay mode, the wallet is told
    // to reach an address we are not serving. Detect and warn.
    let advertised_host = public_url.host_str().unwrap_or_default().to_string();
    let advertised_port = public_url.port_or_known_default();
    let bind_mismatch = relay_connection.is_none()
        && relay_target.is_none()
        && (advertised_host != args.host || advertised_port != Some(args.port));

    let mut app_state = AppState::new(
        public_url,
        operator_url,
        source,
        &args.purpose,
        trust_anchors,
        args.live_status,
        anchor_pem,
        status_signer,
        args.unsafe_debug_artifacts.clone(),
        console_trace,
    )
    .await?;
    if args.age_only {
        app_state = app_state.with_request_query(
            "age-only German PID query (age_equal_or_over.18)",
            pid::pid_query(&[&["age_equal_or_over", "18"]]),
        );
    }
    let state = std::sync::Arc::new(app_state);

    let relay_summary = relay_connection.as_ref().map(|conn| {
        (
            conn.run_id.clone(),
            conn.ttl_secs,
            state.public_url.to_string(),
        )
    });

    if relay_summary.is_some() {
        eprintln!("augenmass serve: wallet-interaction debugger (relay)");
    } else {
        eprintln!("augenmass serve: wallet-interaction debugger");
    }
    eprintln!("  open         : {}", state.operator_url);
    eprintln!("  listening    : http://{}", local_addr);
    if let Some((run_id, ttl_secs, public_url)) = relay_summary.as_ref() {
        eprintln!(
            "  relay        : {}",
            relay_target.as_deref().unwrap_or("custom")
        );
        eprintln!(
            "  run          : {} (TTL {}s)",
            short_for_display(run_id),
            ttl_secs
        );
        eprintln!("  public       : {}", public_url);
        eprintln!("  scope        : relay carries only /request and /response; trace and evidence stay local");
    }
    eprintln!("  client_id    : {}", state.client_id);
    eprintln!(
        "  cert         : {}",
        if state.ephemeral {
            "throwaway (development); set --key + --leaf for the real registrar leaf"
        } else {
            "registrar-issued leaf"
        }
    );
    eprintln!(
        "  issuer trust : {}",
        if enforce_trust {
            "enforced (--trust-anchor set)"
        } else {
            "not enforced (set --trust-anchor to anchor PID issuers)"
        }
    );
    eprintln!(
        "  status check : {}",
        if args.live_status && enforce_trust && args.status_signer.is_some() {
            "live (--status-signer set; revocation resolved over the network)"
        } else if args.live_status && enforce_trust {
            "live (status signer falls back to --trust-anchor; set --status-signer for dedicated revocation keys)"
        } else if args.live_status {
            "requested, but inactive until --trust-anchor is set"
        } else {
            "offline (set --live-status to resolve token-status-list revocation)"
        }
    );
    eprintln!(
        "  trace        : {}",
        if console_trace {
            "redacted by default; live on this console; also at <local>/trace/<session> and /api/trace/<session>"
        } else {
            "redacted by default; quiet on console; at <local>/trace/<session> and /api/trace/<session>"
        }
    );
    eprintln!(
        "  artifacts    : {}",
        args.unsafe_debug_artifacts
            .as_ref()
            .map(|path| format!(
                "UNSAFE local capture ON, writing raw wallet material to {} ({}); never served over HTTP",
                path.display(),
                unsafe_artifact_banner_hint()
            ))
            .unwrap_or_else(|| {
                "off (set --unsafe-debug-artifacts <dir> to capture raw wallet material locally; UNSAFE)"
                    .to_string()
            })
    );
    if bind_mismatch {
        eprintln!();
        eprintln!(
            "  warning: binding {}:{} but --public-url advertises {} (port {}); a wallet will fetch the wrong address. Set --public-url to match the bind address.",
            args.host,
            args.port,
            advertised_host,
            advertised_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "?".to_string()),
        );
    }
    if relay_summary.is_none() && is_loopback_host(&args.host) {
        eprintln!(
            "  note: bound to loopback; a phone wallet on your LAN cannot reach this. Use --host 0.0.0.0 with a --public-url that has your LAN IP, or a tunnel."
        );
    }
    eprintln!();
    eprintln!("  Open the URL above, scan the QR with a wallet, and watch the trace below.");
    eprintln!();

    let app = handlers::router(state);
    tracing::info!("listening on http://{}", local_addr);
    if let Some(conn) = relay_connection {
        let local_base = loopback_operator_url(local_addr)?;
        tokio::select! {
            serve = axum::serve(listener, app) => {
                serve?;
            }
            tunnel = relay_client::run_tunnel(conn, local_base) => {
                tunnel?;
            }
        }
    } else {
        axum::serve(listener, app).await?;
    }
    Ok(())
}

#[cfg(unix)]
fn unsafe_artifact_banner_hint() -> &'static str {
    "owner-only on Unix"
}

#[cfg(not(unix))]
fn unsafe_artifact_banner_hint() -> &'static str {
    "store in a private or encrypted workspace"
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "::1" | "localhost")
}

fn normalize_base_url(url: &mut Url, label: &str) {
    if !url.path().ends_with('/') {
        let fixed = format!("{}/", url.path());
        url.set_path(&fixed);
        eprintln!("note: {label} did not end in '/'; using {url}");
    }
}

fn loopback_operator_url(addr: SocketAddr) -> Result<Url> {
    let host = if addr.is_ipv6() {
        format!("[{}]", addr.ip())
    } else {
        addr.ip().to_string()
    };
    Url::parse(&format!("http://{}:{}/", host, addr.port())).context("build operator URL")
}

fn short_for_display(id: &str) -> &str {
    id.get(..8).unwrap_or(id)
}
