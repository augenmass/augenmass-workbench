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
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use openid4vp::core::authorization_request::parameters::{
    Nonce, RequestUriMethod, State as AuthorizationState,
};
use openid4vp::core::object::TypedParameter;
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

use crate::serve::artifacts::sha256_hex;
use crate::serve::state::{
    build_client_metadata, generate_encryption_key, status_signer_from_anchor, AppState,
    SessionResult,
};
use crate::serve::trace::{TraceKind, TraceLevel};
use crate::serve::view;

/// Verifier freshness window for a presentation's KB-JWT (matches the core's
/// `verify::DEFAULT_MAX_AGE_SECS`, which is not re-exported at the crate root).
const DEFAULT_MAX_AGE_SECS: i64 = 300;
const REQUEST_OBJECT_TTL_SECS: i64 = 600;

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
    if let Some(root) = state.unsafe_debug_artifacts.as_ref() {
        let artifact = crate::serve::artifacts::write_text(
            root,
            uuid,
            "request.jwt",
            "signed authorization request JAR",
            &jwt,
        )
        .map_err(|e| AppError::internal(format!("write unsafe debug request JAR: {e}")))?;
        state
            .trace
            .record(
                uuid,
                TraceKind::ArtifactSaved,
                "saved unsafe debug request JAR artifact",
                Some(artifact.trace_detail()),
            )
            .await;
        if let Some(payload) = detail.get("payload") {
            if !payload.is_null() {
                let artifact = crate::serve::artifacts::write_json(
                    root,
                    uuid,
                    "request.payload.json",
                    "decoded authorization request payload",
                    payload,
                )
                .map_err(|e| {
                    AppError::internal(format!("write unsafe debug request payload: {e}"))
                })?;
                state
                    .trace
                    .record(
                        uuid,
                        TraceKind::ArtifactSaved,
                        "saved unsafe debug request payload artifact",
                        Some(artifact.trace_detail()),
                    )
                    .await;
            }
        }
    }
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
    state
        .verifier
        .retrieve_authorization_request(uuid)
        .await
        .map_err(|e| AppError::not_found(format!("session not found: {e}")))?;
    if let Some(root) = state.unsafe_debug_artifacts.as_ref() {
        let artifact = crate::serve::artifacts::write_text(
            root,
            uuid,
            "direct-post.body",
            "raw direct_post form body",
            &body,
        )
        .map_err(|e| AppError::internal(format!("write unsafe debug direct_post body: {e}")))?;
        state
            .trace
            .record(
                uuid,
                TraceKind::ArtifactSaved,
                "saved unsafe debug direct_post body artifact",
                Some(artifact.trace_detail()),
            )
            .await;
    }
    let response = match AuthorizationResponse::from_x_www_form_urlencoded(body.as_bytes()) {
        Ok(response) => response,
        Err(e) => {
            state.encryption_keys.lock().await.remove(&uuid);
            return Err(AppError::bad(format!(
                "invalid authorization response: {e}"
            )));
        }
    };
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
            Some(redacted_response_detail(mode, &body, &response)),
        )
        .await;

    if matches!(response, AuthorizationResponse::Unencoded(_)) {
        let reason = "plaintext direct_post response rejected: this verifier advertises direct_post.jwt and requires response encryption";
        state
            .trace
            .record_at(
                uuid,
                TraceKind::Rejected,
                TraceLevel::Bad,
                reason,
                Some(json!({
                    "reason": reason,
                    "redacted": true,
                })),
            )
            .await;
        state
            .results
            .lock()
            .await
            .insert(uuid, SessionResult::Rejected(reason.to_string()));
        state.encryption_keys.lock().await.remove(&uuid);
        let inspect = format!("{}inspect/{}", state.operator_url, uuid);
        let trace = format!("{}trace/{}", state.operator_url, uuid);
        return Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "status": "rejected",
                "reason": reason,
                "inspect": inspect,
                "trace": trace,
            })),
        ));
    }

    let st = state.clone();
    let verify_result = state
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
        .await;
    state.encryption_keys.lock().await.remove(&uuid);
    verify_result.map_err(|e| AppError::internal(format!("verification error: {e}")))?;

    let inspect = format!("{}inspect/{}", state.operator_url, uuid);
    let trace = format!("{}trace/{}", state.operator_url, uuid);
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
    if let Some(root) = st.unsafe_debug_artifacts.as_ref() {
        match crate::serve::artifacts::write_json(
            root,
            sid,
            "verification-context.json",
            "verification replay context",
            &json!({
                "nonce": &binding.nonce,
                "aud": &binding.aud,
                "nowUnix": now_unix,
                "maxAgeSecs": DEFAULT_MAX_AGE_SECS,
                "vct": PID_VCT,
            }),
        ) {
            Ok(artifact) => {
                st.trace
                    .record(
                        sid,
                        TraceKind::ArtifactSaved,
                        "saved unsafe debug verification context artifact",
                        Some(artifact.trace_detail()),
                    )
                    .await;
            }
            Err(e) => {
                let reason = format!("failed to write unsafe debug verification context: {e}");
                st.trace
                    .record_at(sid, TraceKind::Error, TraceLevel::Bad, &reason, None)
                    .await;
                return Err(reason);
            }
        }
    }
    match response {
        AuthorizationResponse::Jwt(jwt) => {
            let encryption_key = {
                let keys = st.encryption_keys.lock().await;
                keys.get(&sid).cloned()
            };
            let Some(encryption_key) = encryption_key else {
                let reason =
                    "missing session encryption key for direct_post.jwt response".to_string();
                st.trace
                    .record_at(sid, TraceKind::Rejected, TraceLevel::Bad, &reason, None)
                    .await;
                return Err(reason);
            };
            let decrypted = match decrypt_jwe(&jwt.response, &encryption_key) {
                Ok(v) => v,
                Err(e) => {
                    let reason = format!("failed to decrypt response: {e}");
                    st.trace
                        .record_at(sid, TraceKind::Rejected, TraceLevel::Bad, &reason, None)
                        .await;
                    return Err(reason);
                }
            };
            if let Some(root) = st.unsafe_debug_artifacts.as_ref() {
                match crate::serve::artifacts::write_json(
                    root,
                    sid,
                    "auth-response.json",
                    "decrypted authorization response",
                    &decrypted,
                ) {
                    Ok(artifact) => {
                        st.trace
                            .record(
                                sid,
                                TraceKind::ArtifactSaved,
                                "saved unsafe debug decrypted authorization response artifact",
                                Some(artifact.trace_detail()),
                            )
                            .await;
                    }
                    Err(e) => {
                        let reason =
                            format!("failed to write unsafe debug decrypted response: {e}");
                        st.trace
                            .record_at(sid, TraceKind::Error, TraceLevel::Bad, &reason, None)
                            .await;
                        return Err(reason);
                    }
                }
            }
            st.trace
                .record(
                    sid,
                    TraceKind::ResponseDecrypted,
                    "decrypted the JWE response (ECDH-ES)",
                    Some(redacted_decrypted_detail(&decrypted)),
                )
                .await;
            verify_vp_token(st, sid, &decrypted, &binding, now_unix).await
        }
        AuthorizationResponse::Unencoded(unencoded) => {
            let value = serde_json::to_value(&unencoded.vp_token)
                .unwrap_or_else(|_| Value::String("<unserializable>".to_string()));
            st.trace
                .record_at(
                    sid,
                    TraceKind::Rejected,
                    TraceLevel::Bad,
                    "plaintext direct_post response rejected",
                    Some(json!({
                        "vpTokenPresent": !value.is_null(),
                        "vpTokenShape": value_shape(&value),
                        "redacted": true,
                    })),
                )
                .await;
            Err("plaintext direct_post response rejected".to_string())
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
        &st.dcql_query,
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

fn redacted_response_detail(mode: &str, body: &str, response: &AuthorizationResponse) -> Value {
    let mut fields = url::form_urlencoded::parse(body.as_bytes())
        .map(|(key, _)| key.into_owned())
        .collect::<Vec<_>>();
    fields.sort();
    fields.dedup();
    let response_value = match response {
        AuthorizationResponse::Jwt(jwt) => compact_jwe_summary(&jwt.response),
        AuthorizationResponse::Unencoded(_) => json!({
            "present": false,
            "plaintext": true,
            "redacted": true,
        }),
    };
    let state = url::form_urlencoded::parse(body.as_bytes())
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned());
    json!({
        "mode": mode,
        "bodyLen": body.len(),
        "bodySha256": sha256_hex(body.as_bytes()),
        "fields": fields,
        "state": state,
        "response": response_value,
        "redacted": true,
        "redaction": "direct_post body and wallet tokens are not exposed by the unauthenticated trace API"
    })
}

fn compact_jwe_summary(response: &str) -> Value {
    let parts = response.split('.').collect::<Vec<_>>();
    json!({
        "present": true,
        "len": response.len(),
        "sha256": sha256_hex(response.as_bytes()),
        "partCount": parts.len(),
        "compactJwe": parts.len() == 5,
        "protectedHeaderB64Len": parts.first().map(|part| part.len()).unwrap_or(0),
        "redacted": true,
    })
}

fn redacted_decrypted_detail(value: &Value) -> Value {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    let body = value
        .get("authorization_response")
        .or_else(|| value.get("auth_response"))
        .or_else(|| value.get("body"))
        .and_then(Value::as_object)
        .or_else(|| value.as_object());
    let mut fields = body
        .map(|body| body.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    fields.sort();
    let vp_token = body
        .and_then(|body| body.get("vp_token"))
        .unwrap_or(&Value::Null);
    json!({
        "bodyLen": bytes.len(),
        "bodySha256": sha256_hex(&bytes),
        "fields": fields,
        "state": body.and_then(|body| body.get("state")).and_then(Value::as_str),
        "vpTokenPresent": !vp_token.is_null(),
        "vpTokenShape": value_shape(vp_token),
        "redacted": true,
        "redaction": "decrypted authorization response and wallet tokens are not exposed by the unauthenticated trace API"
    })
}

fn value_shape(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
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
    let session_id = Uuid::new_v4();
    let now = unix_timestamp()
        .map_err(|e| AppError::internal(format!("failed to read system time: {e}")))?;
    let key_id = format!("enc-{session_id}");
    let (private_jwk, public_jwk) = generate_encryption_key(&key_id)
        .map_err(|e| AppError::internal(format!("failed to create response key: {e}")))?;
    let client_metadata = build_client_metadata(&public_jwk);
    let url = state
        .verifier
        .build_authorization_request()
        .with_dcql_query(state.dcql_query.clone())
        .with_request_parameter(Nonce::from(nonce.clone()))
        .with_request_parameter(AuthorizationState(session_id.to_string()))
        .with_request_parameter(RequestUriMethod::Get)
        .with_request_parameter(IssuedAt(now))
        .with_request_parameter(ExpiresAt(now + REQUEST_OBJECT_TTL_SECS))
        .with_request_parameter(client_metadata)
        .build_with_session_id(session_id, state.wallet_metadata.clone())
        .await
        .map_err(|e| AppError::internal(format!("failed to build request: {e}")))?;
    let auth_url = url.to_string();
    state
        .encryption_keys
        .lock()
        .await
        .insert(session_id, private_jwk);

    state
        .trace
        .record(
            session_id,
            TraceKind::SessionCreated,
            "new presentation session created",
            None,
        )
        .await;
    if let Some(root) = state.unsafe_debug_artifacts.as_ref() {
        let private_jwk = {
            let keys = state.encryption_keys.lock().await;
            keys.get(&session_id).cloned()
        }
        .ok_or_else(|| AppError::internal("missing generated response encryption key"))?;
        let private_jwk = serde_json::to_value(&private_jwk)
            .map_err(|e| AppError::internal(format!("serialize session encryption JWK: {e}")))?;
        let artifact = match crate::serve::artifacts::write_json(
            root,
            session_id,
            "session-enc-key.jwk",
            "session response encryption private JWK",
            &private_jwk,
        ) {
            Ok(artifact) => artifact,
            Err(e) => {
                state.encryption_keys.lock().await.remove(&session_id);
                return Err(AppError::internal(format!(
                    "write unsafe debug session key: {e}"
                )));
            }
        };
        state
            .trace
            .record(
                session_id,
                TraceKind::ArtifactSaved,
                "saved unsafe debug session encryption private JWK artifact",
                Some(artifact.trace_detail()),
            )
            .await;
    }
    state
        .trace
        .record(
            session_id,
            TraceKind::RequestBuilt,
            format!(
                "built the authorization request ({})",
                state.request_profile
            ),
            Some(json!({
                "authorizationRequest": auth_url,
                "nonce": nonce,
                "state": session_id.to_string(),
                "requestProfile": state.request_profile,
                "clientId": state.client_id,
                "responseEncryptionKeyId": key_id,
            })),
        )
        .await;
    Ok((session_id, auth_url))
}

fn unix_timestamp() -> Result<i64, std::time::SystemTimeError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64)
}

#[derive(Clone, Debug)]
struct IssuedAt(i64);

impl TypedParameter for IssuedAt {
    const KEY: &'static str = "iat";
}

impl TryFrom<Value> for IssuedAt {
    type Error = anyhow::Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<IssuedAt> for Value {
    fn from(value: IssuedAt) -> Self {
        json!(value.0)
    }
}

#[derive(Clone, Debug)]
struct ExpiresAt(i64);

impl TypedParameter for ExpiresAt {
    const KEY: &'static str = "exp";
}

impl TryFrom<Value> for ExpiresAt {
    type Error = anyhow::Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<ExpiresAt> for Value {
    fn from(value: ExpiresAt) -> Self {
        json!(value.0)
    }
}

#[derive(Debug)]
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
    use std::fs;
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
            Url::parse("http://127.0.0.1:0/").unwrap(),
            CertSource::Ephemeral,
            "event_checkin",
            Some(trust_anchors),
            true,
            Some(anchor_pem),
            None,
            false,
        )
        .await
        .expect("build offline app state");
        st.status_fetcher = StatusFetcher::Recording(counter);
        st
    }

    async fn state_for_response_tests(
        unsafe_debug_artifacts: Option<std::path::PathBuf>,
    ) -> Arc<AppState> {
        Arc::new(
            AppState::new(
                Url::parse("http://127.0.0.1:0/").unwrap(),
                Url::parse("http://127.0.0.1:0/").unwrap(),
                CertSource::Ephemeral,
                "event_checkin",
                None,
                false,
                None,
                unsafe_debug_artifacts,
                false,
            )
            .await
            .expect("build app state"),
        )
    }

    fn plaintext_body() -> String {
        "vp_token=%7B%22pid%22%3A%5B%22secret-claim%22%5D%7D&state=abc".to_string()
    }

    #[tokio::test]
    async fn create_request_uses_distinct_session_encryption_keys() {
        let state = state_for_response_tests(None).await;
        let (sid1, _) = create_request(&state).await.expect("first request");
        let (sid2, _) = create_request(&state).await.expect("second request");

        let jar1 = state
            .verifier
            .retrieve_authorization_request(sid1)
            .await
            .expect("first jar");
        let jar2 = state
            .verifier
            .retrieve_authorization_request(sid2)
            .await
            .expect("second jar");
        let payload1 = crate::jose::decode_compact(&jar1)
            .expect("decode first jar")
            .payload;
        let payload2 = crate::jose::decode_compact(&jar2)
            .expect("decode second jar")
            .payload;
        let key1 = &payload1["client_metadata"]["jwks"]["keys"][0];
        let key2 = &payload2["client_metadata"]["jwks"]["keys"][0];

        assert_eq!(key1["kid"], format!("enc-{sid1}"));
        assert_eq!(key2["kid"], format!("enc-{sid2}"));
        assert_ne!(key1["x"], key2["x"]);
        assert_ne!(key1["y"], key2["y"]);

        let keys = state.encryption_keys.lock().await;
        assert!(keys.contains_key(&sid1));
        assert!(keys.contains_key(&sid2));
    }

    #[test]
    fn redaction_helpers_omit_raw_body_and_claim_values() {
        let raw_body =
            "response=a.b.c.d.e&state=abc&vp_token=secret-claim&presentation=other-secret";
        let response =
            AuthorizationResponse::from_x_www_form_urlencoded(raw_body.as_bytes()).unwrap();
        let received = redacted_response_detail("direct_post.jwt (encrypted)", raw_body, &response);
        let received_text = received.to_string();
        assert_eq!(received["bodyLen"], raw_body.len());
        assert_eq!(received["bodySha256"].as_str().unwrap().len(), 64);
        assert!(received_text.contains("response"));
        assert!(!received_text.contains("secret-claim"));
        assert!(!received_text.contains("other-secret"));
        assert!(!received_text.contains(raw_body));
        assert!(received.get("rawBody").is_none());

        let decrypted = json!({
            "vp_token": {
                "pid": ["secret-claim"]
            },
            "state": "abc",
        });
        let decrypted_detail = redacted_decrypted_detail(&decrypted);
        let decrypted_text = decrypted_detail.to_string();
        assert_eq!(decrypted_detail["vpTokenPresent"], true);
        assert_eq!(decrypted_detail["vpTokenShape"], "object");
        assert!(decrypted_text.contains("vp_token"));
        assert!(!decrypted_text.contains("secret-claim"));
    }

    #[tokio::test]
    async fn plaintext_direct_post_rejects_and_removes_session_key() {
        let state = state_for_response_tests(None).await;
        let (sid, _) = create_request(&state).await.expect("request");
        assert!(state.encryption_keys.lock().await.contains_key(&sid));

        let (status, Json(value)) = receive_response(
            State(state.clone()),
            Path(sid.to_string()),
            plaintext_body(),
        )
        .await
        .expect("plaintext rejection response");

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(value["status"], "rejected");
        assert!(value["reason"]
            .as_str()
            .unwrap()
            .contains("direct_post.jwt"));
        assert!(!state.encryption_keys.lock().await.contains_key(&sid));

        let trace = state.trace.get(sid).await.expect("trace");
        let trace_value = serde_json::to_value(&trace).expect("trace json");
        let trace_text = trace_value.to_string();
        let codes: Vec<&str> = trace.events.iter().map(|event| event.code).collect();
        assert!(codes.contains(&"RESPONSE_RECEIVED"), "codes: {codes:?}");
        assert!(codes.contains(&"REJECTED"), "codes: {codes:?}");
        assert!(!trace_text.contains("rawBody"));
        assert!(!trace_text.contains("secret-claim"));
    }

    #[tokio::test]
    async fn malformed_authorization_response_removes_session_key() {
        let state = state_for_response_tests(None).await;
        let (sid, _) = create_request(&state).await.expect("request");
        assert!(state.encryption_keys.lock().await.contains_key(&sid));

        let err = receive_response(
            State(state.clone()),
            Path(sid.to_string()),
            "vp_token=%7B%22pid%22%3A%5B".to_string(),
        )
        .await
        .expect_err("malformed response rejects");

        assert!(matches!(err, AppError::Bad(_)));
        assert!(!state.encryption_keys.lock().await.contains_key(&sid));
    }

    #[tokio::test]
    async fn unsafe_debug_artifacts_write_locally_but_trace_stays_redacted() {
        let root = std::env::temp_dir().join(format!("augenmass-serve-{}", Uuid::new_v4()));
        let state = state_for_response_tests(Some(root.clone())).await;
        let (sid, _) = create_request(&state).await.expect("request");
        let _ = get_request_object(State(state.clone()), Path(sid.to_string()))
            .await
            .expect("request object");

        let (status, _) = receive_response(
            State(state.clone()),
            Path(sid.to_string()),
            plaintext_body(),
        )
        .await
        .expect("plaintext rejection response");
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let dir = root.join(sid.to_string());
        assert!(dir.join("session-enc-key.jwk").exists());
        assert!(dir.join("request.jwt").exists());
        assert!(dir.join("request.payload.json").exists());
        assert!(dir.join("direct-post.body").exists());
        assert!(fs::read_to_string(dir.join("direct-post.body"))
            .unwrap()
            .contains("secret-claim"));

        let manifest: Value = serde_json::from_str(
            &fs::read_to_string(dir.join("debug-manifest.json")).expect("read manifest"),
        )
        .expect("manifest json");
        assert_eq!(manifest["sensitive"], true);

        let trace = state.trace.get(sid).await.expect("trace");
        let trace_value = serde_json::to_value(&trace).expect("trace json");
        let trace_text = trace_value.to_string();
        assert!(trace
            .events
            .iter()
            .any(|event| event.code == "ARTIFACT_SAVED"));
        assert!(!trace_text.contains("secret-claim"));
        assert!(!trace_text.contains(&root.display().to_string()));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let dir_mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            let file_mode = fs::metadata(dir.join("direct-post.body"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700);
            assert_eq!(file_mode, 0o600);
        }

        let _ = fs::remove_dir_all(root);
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
