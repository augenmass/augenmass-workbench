use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;

use crate::config::RelayConfig;
use crate::ratelimit::RateLimiter;
use crate::registry::RunRegistry;

pub struct RelayState {
    pub config: RelayConfig,
    pub public_base: String,
    pub registry: RunRegistry,
    pub rate_limiter: RateLimiter,
}

pub fn router(state: Arc<RelayState>) -> Router {
    Router::new()
        .route("/", get(root))
        .route("/healthz", get(healthz))
        .route("/_relay/tunnel", get(crate::tunnel::tunnel))
        .route(
            "/r/:run_id/request/:session",
            get(crate::forward::forward_request),
        )
        .route(
            "/r/:run_id/response/:session",
            post(crate::forward::forward_response),
        )
        .layer(DefaultBodyLimit::max(state.config.max_body_bytes))
        .with_state(state)
}

async fn healthz() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok", "service": "augenmass-relay" }))
}

async fn root() -> &'static str {
    "Augenmaß relay. Byte-forwarding relay for local EUDI verifier debugging. Not a verifier; never decrypts wallet payloads; the relay code persists no bodies.\n"
}
