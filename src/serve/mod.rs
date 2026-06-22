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

pub mod handlers;
pub mod state;
pub mod trace;
pub mod view;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;
use url::Url;

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
    /// Suppress the live per-step trace on the console (it still records and is
    /// served at /trace/:id and /api/trace/:id).
    #[arg(long, env = "QUIET", default_value_t = false)]
    pub quiet: bool,
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
    if !args.public_url.path().ends_with('/') {
        let fixed = format!("{}/", args.public_url.path());
        args.public_url.set_path(&fixed);
        eprintln!(
            "note: --public-url did not end in '/'; using {}",
            args.public_url
        );
    }

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
    let enforce_trust = trust_anchors.is_some();
    let console_trace = !args.quiet;

    // The listener binds to (host, port); everything the wallet sees is built
    // from public_url. If they disagree, the wallet is told to reach an address
    // we are not serving, and the exchange breaks silently. Detect and warn.
    let advertised_host = args.public_url.host_str().unwrap_or_default().to_string();
    let advertised_port = args.public_url.port_or_known_default();
    let bind_mismatch = advertised_host != args.host || advertised_port != Some(args.port);

    let state = std::sync::Arc::new(
        AppState::new(
            args.public_url.clone(),
            source,
            &args.purpose,
            trust_anchors,
            args.live_status,
            anchor_pem,
            console_trace,
        )
        .await?,
    );

    eprintln!("augenmass serve: wallet-interaction debugger");
    eprintln!("  open         : {}", state.public_url);
    eprintln!("  listening    : http://{}:{}", args.host, args.port);
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
        if args.live_status {
            "live (revocation resolved over the network when an anchor is set)"
        } else {
            "offline (set --live-status to resolve token-status-list revocation)"
        }
    );
    eprintln!(
        "  trace        : {}",
        if console_trace {
            "live on this console; also at <base>/trace/<session> and /api/trace/<session>"
        } else {
            "quiet on console; at <base>/trace/<session> and /api/trace/<session>"
        }
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
    if is_loopback_host(&args.host) {
        eprintln!(
            "  note: bound to loopback; a phone wallet on your LAN cannot reach this. Use --host 0.0.0.0 with a --public-url that has your LAN IP, or a tunnel."
        );
    }
    eprintln!();
    eprintln!("  Open the URL above, scan the QR with a wallet, and watch the trace below.");
    eprintln!();

    let app = handlers::router(state);
    let listener = TcpListener::bind((args.host.as_str(), args.port))
        .await
        .with_context(|| format!("bind {}:{}", args.host, args.port))?;
    tracing::info!("listening on http://{}:{}", args.host, args.port);
    axum::serve(listener, app).await?;
    Ok(())
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "::1" | "localhost")
}
