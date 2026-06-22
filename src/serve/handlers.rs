//! HTTP surface: the OpenID4VP request/response endpoints, the over-ask
//! inspector, and the wallet-interaction trace.
//!
//! - `GET  /`               landing page: a QR/deep-link to present, links to inspect + trace
//! - `GET  /request/:id`    the signed JAR (the `request_uri`); records the wallet's fetch
//! - `POST /response/:id`   the wallet response (`direct_post.jwt`): decrypt, verify, trace
//! - `GET  /inspect/:id`    the over-ask inspector view for this session
//! - `GET  /trace/:id`      the human-readable wallet-interaction timeline
//! - `GET  /api/trace/:id`  the same trace as JSON (for programmatic debugging)
//! - `GET  /api/sessions`   the list of sessions seen this run
//! - `GET  /health`         health check

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use openid4vp::core::authorization_request::parameters::Nonce;
use openid4vp::core::response::AuthorizationResponse;
use openid4vp::verifier::session::{Outcome, Session};
use serde_json::{json, Value};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use augenmass_core::crypto::decrypt_jwe;
use augenmass_core::{
    check_status_list_token, inspector, pid, verify_pid_presentation_full, CredentialStatus,
    RequestBinding, StatusInput, TrustOptions, VerifiedPid, PID_VCT,
};

use crate::serve::state::{status_signer_from_anchor, AppState, SessionResult};
use crate::serve::trace::{TraceKind, TraceLevel};
use crate::serve::view;

/// Verifier freshness window for a presentation's KB-JWT (matches the core's
/// `verify::DEFAULT_MAX_AGE_SECS`, which is not re-exported at the crate root).
const DEFAULT_MAX_AGE_SECS: i64 = 300;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/request/:id", get(get_request_object))
        .route("/response/:id", post(receive_response))
        .route("/inspect/:id", get(inspect))
        .route("/trace/:id", get(trace_view))
        .route("/api/trace/:id", get(trace_json))
        .route("/api/sessions", get(sessions_json))
        .route("/health", get(health))
        .with_state(state)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
}

async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok", "service": "augenmass serve" }))
}

/// Create a fresh presentation request and render the landing page.
async fn index(State(state): State<Arc<AppState>>) -> Result<Html<String>, AppError> {
    let (session_id, auth_url) = create_request(&state).await?;
    Ok(Html(view::landing_page(&state, &session_id, &auth_url)))
}

/// The wallet (or ERICA) fetches the signed request object here.
async fn get_request_object(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let uuid: Uuid = id
        .parse()
        .map_err(|_| AppError::bad("invalid session id"))?;
    let jwt = state
        .verifier
        .retrieve_authorization_request(uuid)
        .await
        .map_err(|e| AppError::not_found(format!("session not found: {e}")))?;

    // Record the wallet's fetch with the decoded request object, so the trace
    // shows exactly what the wallet was handed (client_id, response_uri, dcql).
    let decoded = crate::jose::decode_compact(&jwt).ok();
    let detail = json!({
        "jwt": jwt,
        "header": decoded.as_ref().map(|d| d.header.clone()),
        "payload": decoded.as_ref().map(|d| d.payload.clone()),
    });
    state
        .trace
        .record(
            uuid,
            TraceKind::RequestObjectFetched,
            "wallet fetched the signed request object (JAR)",
            Some(detail),
        )
        .await;

    Ok((
        StatusCode::OK,
        [("content-type", "application/oauth-authz-req+jwt")],
        jwt,
    )
        .into_response())
}

/// Receive and verify the wallet response (`direct_post.jwt`).
async fn receive_response(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: String,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let uuid: Uuid = id
        .parse()
        .map_err(|_| AppError::bad("invalid session id"))?;
    let response = AuthorizationResponse::from_x_www_form_urlencoded(body.as_bytes())
        .map_err(|e| AppError::bad(format!("invalid authorization response: {e}")))?;
    let now_unix = now_unix();

    let mode = match &response {
        AuthorizationResponse::Jwt(_) => "direct_post.jwt (encrypted)",
        AuthorizationResponse::Unencoded(_) => "direct_post (plaintext)",
    };
    state
        .trace
        .record(
            uuid,
            TraceKind::ResponseReceived,
            format!("wallet posted its response ({mode})"),
            Some(json!({ "mode": mode, "rawBody": body })),
        )
        .await;

    let st = state.clone();
    state
        .verifier
        .verify_response(uuid, response, move |session, response| {
            let st = st.clone();
            Box::pin(async move {
                match verify_any(&st, &session, &response, now_unix).await {
                    Ok(verified) => {
                        let info = json!({
                            "vct": &verified.vct,
                            "disclosed": verified.view.disclosed.iter().map(|d| d.key()).collect::<Vec<_>>(),
                        });
                        st.results
                            .lock()
                            .await
                            .insert(session.uuid, SessionResult::Verified(Box::new(verified)));
                        Outcome::Success { info }
                    }
                    Err(reason) => {
                        st.results
                            .lock()
                            .await
                            .insert(session.uuid, SessionResult::Rejected(reason.clone()));
                        Outcome::Failure { reason }
                    }
                }
            })
        })
        .await
        .map_err(|e| AppError::internal(format!("verification error: {e}")))?;

    let inspect = format!("{}inspect/{}", state.public_url, uuid);
    let trace = format!("{}trace/{}", state.public_url, uuid);
    let results = state.results.lock().await;
    match results.get(&uuid) {
        Some(SessionResult::Verified(_)) => Ok((
            StatusCode::OK,
            Json(json!({ "status": "verified", "inspect": inspect, "trace": trace })),
        )),
        Some(SessionResult::Rejected(reason)) => Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "status": "rejected",
                "reason": reason,
                "inspect": inspect,
                "trace": trace,
            })),
        )),
        None => Err(AppError::internal(
            "verification callback did not produce an outcome",
        )),
    }
}

/// Verify the presentation(s) in either an encrypted or plain response.
async fn verify_any(
    st: &AppState,
    session: &Session,
    response: &AuthorizationResponse,
    now_unix: i64,
) -> Result<VerifiedPid, String> {
    let binding = request_binding(session);
    let sid = session.uuid;
    match response {
        AuthorizationResponse::Jwt(jwt) => {
            let decrypted = match decrypt_jwe(&jwt.response, &st.encryption_key_jwk) {
                Ok(v) => v,
                Err(e) => {
                    let reason = format!("failed to decrypt response: {e}");
                    st.trace
                        .record_at(sid, TraceKind::Rejected, TraceLevel::Bad, &reason, None)
                        .await;
                    return Err(reason);
                }
            };
            st.trace
                .record(
                    sid,
                    TraceKind::ResponseDecrypted,
                    "decrypted the JWE response (ECDH-ES)",
                    Some(decrypted.clone()),
                )
                .await;
            verify_vp_token(st, sid, &decrypted, &binding, now_unix).await
        }
        AuthorizationResponse::Unencoded(unencoded) => {
            let value = serde_json::to_value(&unencoded.vp_token)
                .map_err(|e| format!("vp_token not serializable: {e}"))?;
            let wrapped = json!({ "vp_token": value });
            st.trace
                .record(
                    sid,
                    TraceKind::ResponseDecrypted,
                    "response was plaintext (no JWE to decrypt)",
                    Some(wrapped.clone()),
                )
                .await;
            verify_vp_token(st, sid, &wrapped, &binding, now_unix).await
        }
    }
}

/// Verify every SD-JWT VC presentation carried in a `vp_token` object.
///
/// Each presentation is first verified and trust-anchored without I/O. Only
/// after that succeeds do live-status checks fetch the signed status-list token
/// for the verified credential's status pointer.
async fn verify_vp_token(
    st: &AppState,
    sid: Uuid,
    decrypted: &Value,
    binding: &RequestBinding,
    now_unix: i64,
) -> Result<VerifiedPid, String> {
    let vp = decrypted
        .get("vp_token")
        .ok_or("decrypted response has no vp_token")?;
    let mut last: Option<VerifiedPid> = None;
    let entries: Vec<&Value> = match vp {
        Value::Object(map) => map.values().collect(),
        other => vec![other],
    };
    // Flatten every presentation across the vp_token. The German PID profile is
    // single-credential, so flag a multi-credential response loudly: each is
    // still verified and traced, but only the last is surfaced to the inspector.
    let mut presentations: Vec<&str> = Vec::new();
    for entry in entries {
        match entry {
            Value::Array(arr) => presentations.extend(arr.iter().filter_map(|v| v.as_str())),
            Value::String(s) => presentations.push(s.as_str()),
            _ => {}
        }
    }
    if presentations.len() > 1 {
        st.trace
            .record_at(
                sid,
                TraceKind::Note,
                TraceLevel::Warn,
                format!(
                    "received {} presentations; this German PID profile expects one, the inspector reflects the last verified credential (all are traced)",
                    presentations.len()
                ),
                Some(json!({ "presentationCount": presentations.len() })),
            )
            .await;
    }
    for p in presentations {
        let verified = match verify_pid_presentation_full(
            p,
            binding,
            PID_VCT,
            DEFAULT_MAX_AGE_SECS,
            now_unix,
            &TrustOptions {
                anchors: st.trust_anchors.as_ref(),
                status: StatusInput::None,
            },
        ) {
            Ok(v) => v,
            Err(e) => {
                let reason = e.to_string();
                st.trace
                    .record_at(
                        sid,
                        TraceKind::Rejected,
                        TraceLevel::Bad,
                        format!("presentation rejected: {reason}"),
                        Some(json!({ "reason": reason })),
                    )
                    .await;
                return Err(reason);
            }
        };

        let disclosed: Vec<String> = verified.view.disclosed.iter().map(|d| d.key()).collect();
        st.trace
            .record_at(
                sid,
                TraceKind::Verified,
                TraceLevel::Good,
                format!(
                    "presentation verified: {} ({} claim(s) disclosed, holder binding {})",
                    verified.vct,
                    disclosed.len(),
                    if verified.holder_bound {
                        "ok"
                    } else {
                        "absent"
                    }
                ),
                Some(json!({
                    "vct": verified.vct,
                    "disclosed": disclosed,
                    "holderBound": verified.holder_bound,
                })),
            )
            .await;

        if st.live_status && st.trust_anchors.is_some() {
            if let (Some(anchor_pem), Some(sref)) =
                (st.anchor_pem.as_ref(), verified.status_ref.as_ref())
            {
                // A transport or signature failure here is an INFRASTRUCTURE
                // problem, not a revocation. Record it as an error and say so,
                // so it is never confused with a genuine "revoked" outcome.
                let jws = match st.status_fetcher.fetch(&sref.uri).await {
                    Ok(j) => j,
                    Err(e) => {
                        let reason = format!(
                            "status-list could not be retrieved (infrastructure failure, not a revocation): {e}"
                        );
                        st.trace
                            .record_at(
                                sid,
                                TraceKind::Error,
                                TraceLevel::Bad,
                                &reason,
                                Some(json!({ "uri": sref.uri, "error": e.to_string() })),
                            )
                            .await;
                        return Err(reason);
                    }
                };
                let signer = match status_signer_from_anchor(anchor_pem) {
                    Ok(s) => s,
                    Err(e) => {
                        let reason = format!(
                            "status-signer key could not be derived from the trust anchor: {e}"
                        );
                        st.trace
                            .record_at(
                                sid,
                                TraceKind::Error,
                                TraceLevel::Bad,
                                &reason,
                                Some(json!({ "error": e.to_string() })),
                            )
                            .await;
                        return Err(reason);
                    }
                };
                let status = match check_status_list_token(&jws, &signer, sref) {
                    Ok(s) => s,
                    Err(e) => {
                        let reason = format!("status-list token failed verification: {e}");
                        st.trace
                            .record_at(
                                sid,
                                TraceKind::Error,
                                TraceLevel::Bad,
                                &reason,
                                Some(json!({ "error": e.to_string() })),
                            )
                            .await;
                        return Err(reason);
                    }
                };
                match status {
                    CredentialStatus::Valid => {
                        st.trace
                            .record_at(
                                sid,
                                TraceKind::StatusChecked,
                                TraceLevel::Good,
                                format!("status-list entry {} is VALID", sref.idx),
                                Some(json!({ "status": "valid", "index": sref.idx, "uri": sref.uri })),
                            )
                            .await;
                    }
                    CredentialStatus::Revoked => {
                        let reason =
                            "credential is revoked (status-list entry is INVALID)".to_string();
                        st.trace
                            .record_at(
                                sid,
                                TraceKind::StatusChecked,
                                TraceLevel::Bad,
                                &reason,
                                Some(json!({ "status": "revoked", "index": sref.idx, "uri": sref.uri })),
                            )
                            .await;
                        st.trace
                            .record_at(
                                sid,
                                TraceKind::Rejected,
                                TraceLevel::Bad,
                                format!("presentation rejected: {reason}"),
                                Some(json!({ "reason": reason })),
                            )
                            .await;
                        return Err(reason);
                    }
                    CredentialStatus::Suspended => {
                        let reason =
                            "credential is suspended (status-list entry is SUSPENDED); rejecting fail-closed"
                                .to_string();
                        st.trace
                            .record_at(
                                sid,
                                TraceKind::StatusChecked,
                                TraceLevel::Bad,
                                &reason,
                                Some(json!({ "status": "suspended", "index": sref.idx, "uri": sref.uri })),
                            )
                            .await;
                        st.trace
                            .record_at(
                                sid,
                                TraceKind::Rejected,
                                TraceLevel::Bad,
                                format!("presentation rejected: {reason}"),
                                Some(json!({ "reason": reason })),
                            )
                            .await;
                        return Err(reason);
                    }
                }
            }
        }

        record_over_ask(st, sid, &disclosed).await;
        last = Some(verified);
    }
    last.ok_or_else(|| "no SD-JWT VC presentation found".to_string())
}

/// Record the over-ask analysis for what the wallet actually disclosed.
async fn record_over_ask(st: &AppState, sid: Uuid, disclosed: &[String]) {
    let report = inspector::analyze(
        PID_VCT,
        &pid::pid_dcql_minimal(),
        st.registered_scope.as_ref(),
        st.baseline.as_ref(),
        disclosed,
    );
    let over = report.has_over_ask();
    let level = if over {
        TraceLevel::Warn
    } else {
        TraceLevel::Good
    };
    st.trace
        .record_at(
            sid,
            TraceKind::OverAskAnalyzed,
            level,
            report.verdict_line.clone(),
            Some(json!({
                "verdict": report.verdict_line,
                "overAsk": over,
                "purpose": report.purpose,
                "beyondPurpose": report.counts.beyond_purpose,
                "beyondRegistration": report.counts.beyond_registration,
            })),
        )
        .await;
}

fn request_binding(session: &Session) -> RequestBinding {
    let nonce = session.authorization_request_object.nonce().to_string();
    let aud = session
        .authorization_request_object
        .client_id()
        .map(|c| c.0.clone())
        .unwrap_or_default();
    RequestBinding { nonce, aud }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(serde::Deserialize)]
pub struct InspectQuery {
    /// Which request to analyze: "minimal" (default) or "overask".
    demo: Option<String>,
}

/// The over-ask inspector view for a session.
async fn inspect(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(q): Query<InspectQuery>,
) -> Result<Html<String>, AppError> {
    let uuid: Uuid = id
        .parse()
        .map_err(|_| AppError::bad("invalid session id"))?;
    let query = match q.demo.as_deref() {
        Some("overask") => pid::pid_dcql_overask_example(),
        _ => pid::pid_dcql_minimal(),
    };
    let stored = {
        let results = state.results.lock().await;
        match results.get(&uuid) {
            Some(SessionResult::Verified(v)) => {
                Ok(v.view.disclosed.iter().map(|d| d.key()).collect())
            }
            Some(SessionResult::Rejected(reason)) => Err(reason.clone()),
            None => Ok(Vec::new()),
        }
    };
    let disclosed: Vec<String> = match stored {
        Ok(disclosed) => disclosed,
        Err(reason) => return Ok(Html(view::rejection_page(&reason, state.ephemeral))),
    };

    let report = inspector::analyze(
        PID_VCT,
        &query,
        state.registered_scope.as_ref(),
        state.baseline.as_ref(),
        &disclosed,
    );
    Ok(Html(view::inspect_page(&report, state.ephemeral)))
}

/// The human-readable wallet-interaction timeline for a session.
async fn trace_view(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Html<String>, AppError> {
    let uuid: Uuid = id
        .parse()
        .map_err(|_| AppError::bad("invalid session id"))?;
    let trace = state.trace.get(uuid).await;
    Ok(Html(view::trace_page(&state, &uuid, trace.as_ref())))
}

/// The same trace as JSON, for programmatic debugging.
async fn trace_json(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let uuid: Uuid = id
        .parse()
        .map_err(|_| AppError::bad("invalid session id"))?;
    match state.trace.get(uuid).await {
        Some(trace) => Ok(Json(serde_json::to_value(trace).unwrap_or(Value::Null))),
        None => Err(AppError::not_found("no trace for this session yet")),
    }
}

/// The list of sessions seen this run.
async fn sessions_json(State(state): State<Arc<AppState>>) -> Json<Value> {
    let sessions = state.trace.sessions().await;
    Json(json!({ "sessions": sessions }))
}

async fn create_request(state: &AppState) -> Result<(Uuid, String), AppError> {
    let nonce = Uuid::new_v4().to_string();
    let (session_id, url) = state
        .verifier
        .build_authorization_request()
        .with_dcql_query(pid::pid_dcql_minimal())
        .with_request_parameter(Nonce::from(nonce.clone()))
        .build(state.wallet_metadata.clone())
        .await
        .map_err(|e| AppError::internal(format!("failed to build request: {e}")))?;
    let auth_url = url.to_string();

    state
        .trace
        .record(
            session_id,
            TraceKind::SessionCreated,
            "new presentation session created",
            None,
        )
        .await;
    state
        .trace
        .record(
            session_id,
            TraceKind::RequestBuilt,
            "built the authorization request (minimal German PID query)",
            Some(json!({
                "authorizationRequest": auth_url,
                "nonce": nonce,
                "clientId": state.client_id,
            })),
        )
        .await;
    Ok((session_id, auth_url))
}

pub enum AppError {
    Bad(String),
    NotFound(String),
    Internal(String),
}

impl AppError {
    fn bad(m: impl Into<String>) -> Self {
        Self::Bad(m.into())
    }
    fn not_found(m: impl Into<String>) -> Self {
        Self::NotFound(m.into())
    }
    fn internal(m: impl Into<String>) -> Self {
        Self::Internal(m.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            AppError::Bad(m) => (StatusCode::BAD_REQUEST, m),
            AppError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            AppError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        (status, Json(json!({ "error": msg }))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use url::Url;

    use super::*;
    use crate::serve::state::{CertSource, StatusFetcher};
    use augenmass_core::TrustAnchors;

    const NOW: i64 = 1780435200;
    const NONCE: &str = "b4ba2623-76a2-486b-a1f6-f1656025d07b";
    const AUD: &str = "https://self-issued.me/v2";

    fn fixture(rel: &str) -> String {
        let path = format!("{}/fixtures/{rel}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {path}: {e}"))
            .trim()
            .to_string()
    }

    fn binding(nonce: &str) -> RequestBinding {
        RequestBinding {
            nonce: nonce.to_string(),
            aud: AUD.to_string(),
        }
    }

    async fn state_with_anchor(anchor_pem: String, counter: Arc<AtomicUsize>) -> AppState {
        let trust_anchors =
            TrustAnchors::from_pem(&anchor_pem).expect("parse PID issuer trust anchor");
        let mut st = AppState::new(
            Url::parse("http://127.0.0.1:0/").unwrap(),
            CertSource::Ephemeral,
            "event_checkin",
            Some(trust_anchors),
            true,
            Some(anchor_pem),
            false,
        )
        .await
        .expect("build offline app state");
        st.status_fetcher = StatusFetcher::Recording(counter);
        st
    }

    #[tokio::test]
    async fn live_status_fetch_happens_only_after_verify_and_trust() {
        let sid = Uuid::new_v4();
        let vp = fixture("presentations/synthetic-pid-with-status.sdjwt");
        let decrypted = json!({ "vp_token": vp });

        // Wrong nonce: rejects on the binding before any status fetch.
        let counter = Arc::new(AtomicUsize::new(0));
        let st =
            state_with_anchor(fixture("certs/synthetic-pid-anchor.pem"), counter.clone()).await;
        let err = verify_vp_token(&st, sid, &decrypted, &binding("wrong-nonce"), NOW)
            .await
            .expect_err("wrong nonce rejects before live-status fetch");
        assert!(
            err.to_lowercase().contains("nonce"),
            "wrong-nonce case should reject on nonce, got: {err}"
        );
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        // Untrusted issuer: rejects on trust before any status fetch.
        let counter = Arc::new(AtomicUsize::new(0));
        let st = state_with_anchor(fixture("certs/registrar-ca.pem"), counter.clone()).await;
        let err = verify_vp_token(&st, sid, &decrypted, &binding(NONCE), NOW)
            .await
            .expect_err("untrusted PID rejects before live-status fetch");
        assert!(
            err.contains("trusted PID issuer anchor"),
            "untrusted case should reject on issuer trust, got: {err}"
        );
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        // Verified + trusted: the status fetch happens exactly once.
        let counter = Arc::new(AtomicUsize::new(0));
        let st =
            state_with_anchor(fixture("certs/synthetic-pid-anchor.pem"), counter.clone()).await;
        let _ = verify_vp_token(&st, sid, &decrypted, &binding(NONCE), NOW).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }
}
