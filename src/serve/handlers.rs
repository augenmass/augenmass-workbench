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
    RequestBinding, StatusInput, TrustOptions, VerifiedPid, DEFAULT_FUTURE_SKEW_SECS,
    DEFAULT_MAX_AGE_SECS, PID_VCT,
};

use crate::serve::artifacts::sha256_hex;
use crate::serve::state::{
    build_client_metadata, generate_encryption_key, AppState, SessionResult,
};
use crate::serve::trace::{TraceKind, TraceLevel};
use crate::serve::view;

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
                "futureSkewSecs": DEFAULT_FUTURE_SKEW_SECS,
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
            if let Some(sref) = verified.status_ref.as_ref() {
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
                let Some(signer) = st.status_signer.as_ref() else {
                    let reason =
                        "live status is enabled but no status signer is configured".to_string();
                    st.trace
                        .record_at(
                            sid,
                            TraceKind::Error,
                            TraceLevel::Bad,
                            &reason,
                            Some(json!({ "error": reason })),
                        )
                        .await;
                    return Err(reason);
                };
                let status = match check_status_list_token(&jws, signer, sref) {
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
            } else {
                let reason =
                    "live status is enabled but the credential has no token-status-list reference"
                        .to_string();
                st.trace
                    .record_at(
                        sid,
                        TraceKind::Rejected,
                        TraceLevel::Bad,
                        &reason,
                        Some(json!({ "reason": reason })),
                    )
                    .await;
                return Err(reason);
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
    let over_ask = report.has_over_ask();
    let over_disclosed_count = report.over_disclosed.len();
    let has_issue = over_ask || over_disclosed_count > 0;
    let level = if has_issue {
        TraceLevel::Warn
    } else {
        TraceLevel::Good
    };
    let summary = if !over_ask && over_disclosed_count > 0 {
        format!("Wallet over-disclosed {over_disclosed_count} claim(s) not requested")
    } else {
        report.verdict_line.clone()
    };
    st.trace
        .record_at(
            sid,
            TraceKind::OverAskAnalyzed,
            level,
            summary,
            Some(json!({
                "verdict": report.verdict_line,
                "overAsk": over_ask,
                "overDisclosed": report.over_disclosed,
                "overDisclosedCount": over_disclosed_count,
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
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use base64::prelude::*;
    use p256::elliptic_curve::ecdh::diffie_hellman;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::pkcs8::DecodePrivateKey;
    use rand::RngCore;
    use serde::{Deserialize, Serialize};
    use sha2::Digest;
    use ssi::claims::jws::JwsPayload;
    use ssi::claims::jwt::ClaimSet;
    use ssi::claims::sd_jwt::{ConcealJwtClaims, KbJwtPayload, SdAlg};
    use ssi::claims::{JWTClaims, ValidateClaims};
    use ssi::json_pointer;
    use ssi::jwk::{Algorithm, JWK};
    use url::Url;

    use super::*;
    use crate::commands::evidence::{ExportArgs, VerifyArgs};
    use crate::output::OutputFormat;
    use crate::serve::state::{CertSource, StatusFetcher};
    use augenmass_core::crypto::encrypt_jwe;
    use augenmass_core::TrustAnchors;

    const NOW: i64 = 1780435200;
    const NONCE: &str = "b4ba2623-76a2-486b-a1f6-f1656025d07b";
    const AUD: &str = "https://self-issued.me/v2";

    #[derive(Clone, Copy)]
    enum RuntimeJweShape {
        LocalHarness,
        WalletA128GcmWithPartyInfo,
    }

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

    async fn age_only_state_for_runtime_proof(root: PathBuf) -> Arc<AppState> {
        let state = AppState::new(
            Url::parse("http://127.0.0.1:0/").unwrap(),
            Url::parse("http://127.0.0.1:0/").unwrap(),
            CertSource::Ephemeral,
            "age_gate_18",
            None,
            false,
            None,
            None,
            Some(root),
            false,
        )
        .await
        .expect("build app state")
        .with_request_query(
            "age-only German PID query (age_equal_or_over.18)",
            pid::pid_query(&[&["age_equal_or_over", "18"]]),
        );
        Arc::new(state)
    }

    async fn age_only_state_for_trust_status_runtime_proof(
        root: PathBuf,
        anchor_pem: String,
        counter: Arc<AtomicUsize>,
        status_token: &'static str,
    ) -> Arc<AppState> {
        let trust_anchors =
            TrustAnchors::from_pem(&anchor_pem).expect("parse runtime trust anchor");
        let status_signer_pem = fixture("status/status-list-verify-key.pub.pem");
        let status_signer =
            crate::x509util::signer_jwk_from_pem(&status_signer_pem).expect("status signer JWK");
        let mut state = AppState::new(
            Url::parse("http://127.0.0.1:0/").unwrap(),
            Url::parse("http://127.0.0.1:0/").unwrap(),
            CertSource::Ephemeral,
            "age_gate_18",
            Some(trust_anchors),
            true,
            Some(anchor_pem),
            Some(status_signer),
            Some(root),
            false,
        )
        .await
        .expect("build trust/status app state")
        .with_request_query(
            "age-only German PID query (age_equal_or_over.18)",
            pid::pid_query(&[&["age_equal_or_over", "18"]]),
        );
        state.status_fetcher = StatusFetcher::RecordingToken(counter, status_token);
        Arc::new(state)
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct RuntimePidClaims {
        vct: String,
        cnf: Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        status: Option<Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        given_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        family_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        age_equal_or_over: Option<BTreeMap<String, bool>>,
    }

    impl ClaimSet for RuntimePidClaims {}
    impl<E, P> ValidateClaims<E, P> for RuntimePidClaims {}

    fn runtime_issuer_jwk_signed_by_anchor() -> (JWK, String) {
        let ca_key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("generate anchor key");
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "augenmass runtime test PID root");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params
            .self_signed(&ca_key_pair)
            .expect("self-sign runtime anchor");
        let anchor_pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            BASE64_STANDARD.encode(ca_cert.der().as_ref())
        );

        let leaf_key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("generate issuer key");
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            "augenmass runtime test PID issuer",
        );
        let cert = params
            .signed_by(&leaf_key_pair, &ca_cert, &ca_key_pair)
            .expect("sign runtime issuer leaf");
        let secret_key = p256::SecretKey::from_pkcs8_der(&leaf_key_pair.serialize_der())
            .expect("issuer private key from PKCS#8");
        let mut jwk: JWK = serde_json::from_str(&secret_key.to_jwk_string()).expect("issuer JWK");
        jwk.public_key_use = Some("sig".to_string());
        jwk.key_id = Some("augenmass-runtime-test-issuer".to_string());
        jwk.algorithm = Some(Algorithm::ES256);
        jwk.x509_certificate_chain = Some(vec![BASE64_STANDARD.encode(cert.der().as_ref())]);
        (jwk, anchor_pem)
    }

    async fn synthetic_runtime_presentation(
        nonce: &str,
        aud: &str,
        issuer_jwk: &JWK,
        status: Option<Value>,
    ) -> String {
        let mut holder_jwk = JWK::generate_p256();
        holder_jwk.public_key_use = Some("sig".to_string());
        holder_jwk.key_id = Some("augenmass-runtime-test-holder".to_string());
        holder_jwk.algorithm = Some(Algorithm::ES256);

        let now = now_unix();
        let claims = JWTClaims::builder()
            .iss("https://issuer.example.test")
            .sub("runtime-no-phone-proof")
            .iat(now)
            .exp(now + 3600)
            .with_private_claims(RuntimePidClaims {
                vct: PID_VCT.to_string(),
                cnf: json!({ "jwk": holder_jwk.to_public() }),
                status,
                given_name: Some("Runtime Secret Given".to_string()),
                family_name: Some("Runtime Secret Family".to_string()),
                age_equal_or_over: Some(BTreeMap::from([
                    ("12".to_string(), true),
                    ("14".to_string(), true),
                    ("16".to_string(), true),
                    ("18".to_string(), true),
                    ("21".to_string(), false),
                    ("65".to_string(), false),
                ])),
            })
            .expect("build runtime PID claims");

        let concealed = claims
            .conceal_and_sign(
                SdAlg::Sha256,
                &[
                    json_pointer!("/given_name"),
                    json_pointer!("/family_name"),
                    json_pointer!("/age_equal_or_over"),
                ],
                issuer_jwk,
            )
            .await
            .expect("sign runtime SD-JWT");
        let revealed = concealed
            .decode_reveal::<RuntimePidClaims>()
            .expect("decode runtime SD-JWT");
        let mut sd_jwt = revealed
            .retaining(&[json_pointer!("/age_equal_or_over")])
            .into_encoded();
        let kb_jwt = KbJwtPayload::new(aud.to_string(), nonce.to_string(), SdAlg::Sha256, &sd_jwt)
            .sign(&holder_jwk)
            .await
            .expect("sign runtime KB-JWT");
        sd_jwt.set_kb(&kb_jwt);
        sd_jwt.into_string()
    }

    async fn encrypted_runtime_direct_post_body(
        state: &Arc<AppState>,
        sid: Uuid,
        issuer_jwk: &JWK,
        status: Option<Value>,
    ) -> (String, String) {
        encrypted_runtime_direct_post_body_with_shape(
            state,
            sid,
            issuer_jwk,
            status,
            RuntimeJweShape::LocalHarness,
        )
        .await
    }

    async fn encrypted_runtime_direct_post_body_with_shape(
        state: &Arc<AppState>,
        sid: Uuid,
        issuer_jwk: &JWK,
        status: Option<Value>,
        shape: RuntimeJweShape,
    ) -> (String, String) {
        let jar = state
            .verifier
            .retrieve_authorization_request(sid)
            .await
            .expect("request jar");
        let payload = crate::jose::decode_compact(&jar)
            .expect("decode request jar")
            .payload;
        let nonce = payload["nonce"].as_str().expect("request nonce");
        let aud = payload["client_id"].as_str().expect("request client_id");
        let enc_jwk_value = payload["client_metadata"]["jwks"]["keys"][0].clone();
        let presentation = synthetic_runtime_presentation(nonce, aud, issuer_jwk, status).await;
        let response_payload = json!({
            "vp_token": presentation,
            "state": sid.to_string(),
        });
        let encrypted = match shape {
            RuntimeJweShape::LocalHarness => {
                let mut enc_jwk_value = enc_jwk_value;
                if let Value::Object(map) = &mut enc_jwk_value {
                    // The wallet-facing JWK advertises JWE alg metadata (`ECDH-ES`),
                    // but ssi::JWK's alg enum is JWS-oriented. The key material is what
                    // the local no-phone encrypter needs.
                    map.remove("alg");
                }
                let enc_jwk: JWK =
                    serde_json::from_value(enc_jwk_value).expect("response encryption public JWK");
                encrypt_jwe(&response_payload, &enc_jwk).expect("encrypt direct_post.jwt response")
            }
            RuntimeJweShape::WalletA128GcmWithPartyInfo => {
                wallet_jwe_a128gcm_with_party_info(&response_payload, &enc_jwk_value, sid)
            }
        };
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("response", &encrypted)
            .append_pair("state", &sid.to_string())
            .finish();
        (body, encrypted)
    }

    fn wallet_jwe_a128gcm_with_party_info(
        payload: &Value,
        recipient_jwk: &Value,
        sid: Uuid,
    ) -> String {
        let recipient_public = p256_public_key_from_jwk(recipient_jwk);
        let ephemeral_secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let ephemeral_public = ephemeral_secret.public_key();
        let apu = b"wallet-runtime-test";
        let apv = sid.to_string();
        let kid = recipient_jwk["kid"].as_str().expect("recipient key id");
        let header = json!({
            "alg": "ECDH-ES",
            "enc": "A128GCM",
            "typ": "JWT",
            "kid": kid,
            "apu": BASE64_URL_SAFE_NO_PAD.encode(apu),
            "apv": BASE64_URL_SAFE_NO_PAD.encode(apv.as_bytes()),
            "epk": public_jwk_value(&ephemeral_public),
        });
        let protected = BASE64_URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).expect("serialize protected JWE header"));
        let shared_secret = diffie_hellman(
            ephemeral_secret.to_nonzero_scalar(),
            recipient_public.as_affine(),
        );
        let cek = concat_kdf(
            "A128GCM",
            16,
            shared_secret.raw_secret_bytes().as_ref(),
            Some(apu),
            Some(apv.as_bytes()),
        );
        let mut iv = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut iv);
        let plaintext = serde_json::to_vec(payload).expect("serialize JWE payload");
        let (ciphertext, tag) = aes_128_gcm_encrypt(&cek, &iv, protected.as_bytes(), &plaintext);

        format!(
            "{}..{}.{}.{}",
            protected,
            BASE64_URL_SAFE_NO_PAD.encode(iv),
            BASE64_URL_SAFE_NO_PAD.encode(ciphertext),
            BASE64_URL_SAFE_NO_PAD.encode(tag)
        )
    }

    fn p256_public_key_from_jwk(jwk: &Value) -> p256::PublicKey {
        let x = BASE64_URL_SAFE_NO_PAD
            .decode(jwk["x"].as_str().expect("JWK x coordinate"))
            .expect("decode JWK x coordinate");
        let y = BASE64_URL_SAFE_NO_PAD
            .decode(jwk["y"].as_str().expect("JWK y coordinate"))
            .expect("decode JWK y coordinate");
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(&x);
        sec1[33..65].copy_from_slice(&y);
        p256::PublicKey::from_sec1_bytes(&sec1).expect("parse P-256 public key")
    }

    fn public_jwk_value(public_key: &p256::PublicKey) -> Value {
        let point = public_key.to_encoded_point(false);
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": BASE64_URL_SAFE_NO_PAD.encode(point.x().expect("public key x coordinate")),
            "y": BASE64_URL_SAFE_NO_PAD.encode(point.y().expect("public key y coordinate")),
        })
    }

    fn concat_kdf(
        alg: &str,
        shared_key_len: usize,
        derived_key: &[u8],
        apu: Option<&[u8]>,
        apv: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut shared_key = Vec::new();
        let count = shared_key_len.div_ceil(32);
        for i in 0..count {
            let mut hasher = sha2::Sha256::new();
            hasher.update(((i + 1) as u32).to_be_bytes());
            hasher.update(derived_key);
            hasher.update((alg.len() as u32).to_be_bytes());
            hasher.update(alg.as_bytes());
            hasher.update((apu.map_or(0, <[u8]>::len) as u32).to_be_bytes());
            if let Some(value) = apu {
                hasher.update(value);
            }
            hasher.update((apv.map_or(0, <[u8]>::len) as u32).to_be_bytes());
            if let Some(value) = apv {
                hasher.update(value);
            }
            hasher.update(((shared_key_len * 8) as u32).to_be_bytes());
            shared_key.extend(hasher.finalize());
        }
        shared_key.truncate(shared_key_len);
        shared_key
    }

    fn aes_128_gcm_encrypt(
        key: &[u8],
        iv: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> (Vec<u8>, [u8; 16]) {
        let round_keys = aes_128_expand_key(key);
        let hash_subkey = aes_128_encrypt_block(&[0u8; 16], &round_keys);
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(iv);
        j0[15] = 1;

        let mut counter = j0;
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        for chunk in plaintext.chunks(16) {
            increment_gcm_counter(&mut counter);
            let stream = aes_128_encrypt_block(&counter, &round_keys);
            ciphertext.extend(chunk.iter().zip(stream.iter()).map(|(a, b)| a ^ b));
        }

        let ghash = ghash(&hash_subkey, aad, &ciphertext);
        let tag_mask = aes_128_encrypt_block(&j0, &round_keys);
        let mut tag = [0u8; 16];
        for i in 0..16 {
            tag[i] = tag_mask[i] ^ ghash[i];
        }
        (ciphertext, tag)
    }

    fn increment_gcm_counter(counter: &mut [u8; 16]) {
        let value = u32::from_be_bytes(counter[12..16].try_into().unwrap()).wrapping_add(1);
        counter[12..16].copy_from_slice(&value.to_be_bytes());
    }

    fn ghash(hash_subkey: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
        let h = u128::from_be_bytes(*hash_subkey);
        let mut y = 0u128;
        for block in ghash_blocks(aad)
            .into_iter()
            .chain(ghash_blocks(ciphertext).into_iter())
        {
            y = ghash_multiply(y ^ u128::from_be_bytes(block), h);
        }
        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
        lengths[8..].copy_from_slice(&((ciphertext.len() as u64) * 8).to_be_bytes());
        y = ghash_multiply(y ^ u128::from_be_bytes(lengths), h);
        y.to_be_bytes()
    }

    fn ghash_blocks(input: &[u8]) -> Vec<[u8; 16]> {
        input
            .chunks(16)
            .map(|chunk| {
                let mut block = [0u8; 16];
                block[..chunk.len()].copy_from_slice(chunk);
                block
            })
            .collect()
    }

    fn ghash_multiply(mut x: u128, mut y: u128) -> u128 {
        let reduction = 0xe1000000000000000000000000000000u128;
        let mut z = 0u128;
        for _ in 0..128 {
            if x & (1 << 127) != 0 {
                z ^= y;
            }
            if y & 1 == 0 {
                y >>= 1;
            } else {
                y = (y >> 1) ^ reduction;
            }
            x <<= 1;
        }
        z
    }

    fn aes_128_expand_key(key: &[u8]) -> [u8; 176] {
        assert_eq!(key.len(), 16);
        let mut expanded = [0u8; 176];
        expanded[..16].copy_from_slice(key);
        let mut generated = 16;
        let mut rcon_index = 1;
        let mut temp = [0u8; 4];

        while generated < expanded.len() {
            temp.copy_from_slice(&expanded[generated - 4..generated]);
            if generated % 16 == 0 {
                temp.rotate_left(1);
                for byte in &mut temp {
                    *byte = AES_SBOX[*byte as usize];
                }
                temp[0] ^= AES_RCON[rcon_index];
                rcon_index += 1;
            }
            for byte in temp {
                expanded[generated] = expanded[generated - 16] ^ byte;
                generated += 1;
            }
        }

        expanded
    }

    fn aes_128_encrypt_block(block: &[u8; 16], round_keys: &[u8; 176]) -> [u8; 16] {
        let mut state = *block;
        aes_add_round_key(&mut state, &round_keys[0..16]);
        for round in 1..10 {
            aes_sub_bytes(&mut state);
            aes_shift_rows(&mut state);
            aes_mix_columns(&mut state);
            aes_add_round_key(&mut state, &round_keys[round * 16..(round + 1) * 16]);
        }
        aes_sub_bytes(&mut state);
        aes_shift_rows(&mut state);
        aes_add_round_key(&mut state, &round_keys[160..176]);
        state
    }

    fn aes_add_round_key(state: &mut [u8; 16], round_key: &[u8]) {
        for i in 0..16 {
            state[i] ^= round_key[i];
        }
    }

    fn aes_sub_bytes(state: &mut [u8; 16]) {
        for byte in state {
            *byte = AES_SBOX[*byte as usize];
        }
    }

    fn aes_shift_rows(state: &mut [u8; 16]) {
        let original = *state;
        state[1] = original[5];
        state[5] = original[9];
        state[9] = original[13];
        state[13] = original[1];
        state[2] = original[10];
        state[6] = original[14];
        state[10] = original[2];
        state[14] = original[6];
        state[3] = original[15];
        state[7] = original[3];
        state[11] = original[7];
        state[15] = original[11];
    }

    fn aes_mix_columns(state: &mut [u8; 16]) {
        for column in state.chunks_exact_mut(4) {
            let a0 = column[0];
            let a1 = column[1];
            let a2 = column[2];
            let a3 = column[3];
            column[0] = aes_xtime(a0) ^ (aes_xtime(a1) ^ a1) ^ a2 ^ a3;
            column[1] = a0 ^ aes_xtime(a1) ^ (aes_xtime(a2) ^ a2) ^ a3;
            column[2] = a0 ^ a1 ^ aes_xtime(a2) ^ (aes_xtime(a3) ^ a3);
            column[3] = (aes_xtime(a0) ^ a0) ^ a1 ^ a2 ^ aes_xtime(a3);
        }
    }

    fn aes_xtime(byte: u8) -> u8 {
        if byte & 0x80 == 0 {
            byte << 1
        } else {
            (byte << 1) ^ 0x1b
        }
    }

    const AES_RCON: [u8; 11] = [
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    ];

    const AES_SBOX: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16,
    ];

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
    async fn encrypted_direct_post_runtime_exports_strict_live_evidence() {
        let root = std::env::temp_dir().join(format!("augenmass-runtime-{}", Uuid::new_v4()));
        let state = age_only_state_for_runtime_proof(root.clone()).await;
        let (sid, _) = create_request(&state).await.expect("request");
        let _ = get_request_object(State(state.clone()), Path(sid.to_string()))
            .await
            .expect("request object");
        let (issuer_jwk, _) = runtime_issuer_jwk_signed_by_anchor();
        let (body, encrypted) =
            encrypted_runtime_direct_post_body(&state, sid, &issuer_jwk, None).await;

        let (status, Json(value)) =
            receive_response(State(state.clone()), Path(sid.to_string()), body)
                .await
                .expect("encrypted response accepted");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["status"], "verified");
        assert!(!state.encryption_keys.lock().await.contains_key(&sid));

        let trace = state.trace.get(sid).await.expect("trace");
        let codes: Vec<&str> = trace.events.iter().map(|event| event.code).collect();
        for expected in [
            "REQUEST_OBJECT_FETCHED",
            "RESPONSE_RECEIVED",
            "RESPONSE_DECRYPTED",
            "VERIFIED",
            "OVER_ASK_ANALYZED",
        ] {
            assert!(codes.contains(&expected), "codes: {codes:?}");
        }
        let trace_text = serde_json::to_string(&trace).expect("trace JSON");
        assert!(!trace_text.contains("Runtime Secret"));
        assert!(!trace_text.contains(&encrypted));

        let session_dir = root.join(sid.to_string());
        for filename in [
            "session-enc-key.jwk",
            "request.jwt",
            "request.payload.json",
            "direct-post.body",
            "verification-context.json",
            "auth-response.json",
            "debug-manifest.json",
        ] {
            assert!(session_dir.join(filename).exists(), "missing {filename}");
        }

        let bundle = root.join(format!("{sid}.bundle.json"));
        crate::commands::evidence::export(
            ExportArgs {
                session_dir: session_dir.clone(),
                out: bundle.clone(),
                signing_key: None,
            },
            OutputFormat::Text,
        )
        .expect("export runtime evidence bundle");
        let bundle_json: Value = serde_json::from_str(
            &fs::read_to_string(&bundle).expect("read runtime evidence bundle"),
        )
        .expect("runtime evidence bundle JSON");
        let replay_events = bundle_json["payload"]["replayTrace"]["events"]
            .as_array()
            .expect("replay events");
        let evidence_over_ask = replay_events
            .iter()
            .find(|event| event["code"] == "OVER_ASK_ANALYZED")
            .expect("evidence replay over-disclosure analysis");
        assert_eq!(evidence_over_ask["level"], "warn");
        assert_eq!(evidence_over_ask["detail"]["overDisclosedCount"], 5);
        assert_eq!(evidence_over_ask["detail"]["requestedCount"], 1);
        assert!(evidence_over_ask["summary"]
            .as_str()
            .expect("summary")
            .contains("over-disclosed 5"));

        let proven = crate::commands::evidence::assert_live(
            VerifyArgs {
                bundle,
                verify_key: None,
            },
            OutputFormat::Text,
        )
        .expect("assert strict live evidence");
        assert!(proven);

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn encrypted_direct_post_runtime_accepts_wallet_jwe_a128gcm_with_party_info() {
        let root = std::env::temp_dir().join(format!("augenmass-runtime-{}", Uuid::new_v4()));
        let state = age_only_state_for_runtime_proof(root.clone()).await;
        let (sid, _) = create_request(&state).await.expect("request");
        let _ = get_request_object(State(state.clone()), Path(sid.to_string()))
            .await
            .expect("request object");
        let (issuer_jwk, _) = runtime_issuer_jwk_signed_by_anchor();
        let (body, encrypted) = encrypted_runtime_direct_post_body_with_shape(
            &state,
            sid,
            &issuer_jwk,
            None,
            RuntimeJweShape::WalletA128GcmWithPartyInfo,
        )
        .await;
        let protected = encrypted.split('.').next().expect("protected JWE header");
        let header: Value = serde_json::from_slice(
            &BASE64_URL_SAFE_NO_PAD
                .decode(protected)
                .expect("decode protected JWE header"),
        )
        .expect("protected JWE header JSON");
        assert_eq!(header["alg"], "ECDH-ES");
        assert_eq!(header["enc"], "A128GCM");
        assert!(header["apu"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        assert!(header["apv"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));

        let (status, Json(value)) =
            receive_response(State(state.clone()), Path(sid.to_string()), body)
                .await
                .expect("wallet-shaped encrypted response accepted");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["status"], "verified");
        assert!(!state.encryption_keys.lock().await.contains_key(&sid));
        let trace = state.trace.get(sid).await.expect("trace");
        let codes: Vec<&str> = trace.events.iter().map(|event| event.code).collect();
        assert!(codes.contains(&"RESPONSE_DECRYPTED"), "codes: {codes:?}");
        assert!(codes.contains(&"VERIFIED"), "codes: {codes:?}");
        let trace_text = serde_json::to_string(&trace).expect("trace JSON");
        assert!(!trace_text.contains("Runtime Secret"));
        assert!(!trace_text.contains(&encrypted));

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn encrypted_direct_post_runtime_enforces_trust_and_live_status() {
        let root = std::env::temp_dir().join(format!("augenmass-runtime-{}", Uuid::new_v4()));
        let (issuer_jwk, anchor_pem) = runtime_issuer_jwk_signed_by_anchor();
        let counter = Arc::new(AtomicUsize::new(0));
        let state = age_only_state_for_trust_status_runtime_proof(
            root.clone(),
            anchor_pem,
            counter.clone(),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/fixtures/status/status-list-CLEAR.jwt"
            )),
        )
        .await;
        let (sid, _) = create_request(&state).await.expect("request");
        let _ = get_request_object(State(state.clone()), Path(sid.to_string()))
            .await
            .expect("request object");
        let (body, encrypted) = encrypted_runtime_direct_post_body(
            &state,
            sid,
            &issuer_jwk,
            Some(json!({
                "status_list": {
                    "idx": 42,
                    "uri": "https://status.example.test/list.jwt"
                }
            })),
        )
        .await;

        let (status, Json(value)) =
            receive_response(State(state.clone()), Path(sid.to_string()), body)
                .await
                .expect("trusted live-status response accepted");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["status"], "verified");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert!(!state.encryption_keys.lock().await.contains_key(&sid));

        let trace = state.trace.get(sid).await.expect("trace");
        let codes: Vec<&str> = trace.events.iter().map(|event| event.code).collect();
        for expected in [
            "RESPONSE_DECRYPTED",
            "VERIFIED",
            "STATUS_CHECKED",
            "OVER_ASK_ANALYZED",
        ] {
            assert!(codes.contains(&expected), "codes: {codes:?}");
        }
        let trace_text = serde_json::to_string(&trace).expect("trace JSON");
        assert!(trace_text.contains("status-list entry 42 is VALID"));
        assert!(!trace_text.contains("Runtime Secret"));
        assert!(!trace_text.contains(&encrypted));
        let over_ask = trace
            .events
            .iter()
            .find(|event| event.code == "OVER_ASK_ANALYZED")
            .expect("over-ask event");
        assert_eq!(over_ask.level, TraceLevel::Warn);
        assert!(over_ask.summary.contains("over-disclosed 5"));
        let detail = over_ask.detail.as_ref().expect("over-ask detail");
        assert_eq!(detail["overAsk"], false);
        assert_eq!(detail["overDisclosedCount"], 5);
        assert_eq!(detail["beyondPurpose"], 0);

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn encrypted_direct_post_runtime_rejects_revoked_live_status() {
        let root = std::env::temp_dir().join(format!("augenmass-runtime-{}", Uuid::new_v4()));
        let (issuer_jwk, anchor_pem) = runtime_issuer_jwk_signed_by_anchor();
        let counter = Arc::new(AtomicUsize::new(0));
        let state = age_only_state_for_trust_status_runtime_proof(
            root.clone(),
            anchor_pem,
            counter.clone(),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/fixtures/status/status-list-REVOKED.jwt"
            )),
        )
        .await;
        let (sid, _) = create_request(&state).await.expect("request");
        let _ = get_request_object(State(state.clone()), Path(sid.to_string()))
            .await
            .expect("request object");
        let (body, encrypted) = encrypted_runtime_direct_post_body(
            &state,
            sid,
            &issuer_jwk,
            Some(json!({
                "status_list": {
                    "idx": 42,
                    "uri": "https://status.example.test/list.jwt"
                }
            })),
        )
        .await;

        let (status, Json(value)) =
            receive_response(State(state.clone()), Path(sid.to_string()), body)
                .await
                .expect("revoked response rejected cleanly");

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(value["status"], "rejected");
        assert!(value["reason"]
            .as_str()
            .unwrap()
            .contains("credential is revoked"));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert!(!state.encryption_keys.lock().await.contains_key(&sid));

        let trace = state.trace.get(sid).await.expect("trace");
        let codes: Vec<&str> = trace.events.iter().map(|event| event.code).collect();
        for expected in [
            "RESPONSE_DECRYPTED",
            "VERIFIED",
            "STATUS_CHECKED",
            "REJECTED",
        ] {
            assert!(codes.contains(&expected), "codes: {codes:?}");
        }
        let status_event = trace
            .events
            .iter()
            .find(|event| event.code == "STATUS_CHECKED")
            .expect("status event");
        assert_eq!(status_event.level, TraceLevel::Bad);
        assert!(status_event.summary.contains("revoked"));
        let trace_text = serde_json::to_string(&trace).expect("trace JSON");
        assert!(!trace_text.contains("Runtime Secret"));
        assert!(!trace_text.contains(&encrypted));

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn encrypted_direct_post_runtime_rejects_missing_live_status_ref() {
        let root = std::env::temp_dir().join(format!("augenmass-runtime-{}", Uuid::new_v4()));
        let (issuer_jwk, anchor_pem) = runtime_issuer_jwk_signed_by_anchor();
        let counter = Arc::new(AtomicUsize::new(0));
        let state = age_only_state_for_trust_status_runtime_proof(
            root.clone(),
            anchor_pem,
            counter.clone(),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/fixtures/status/status-list-CLEAR.jwt"
            )),
        )
        .await;
        let (sid, _) = create_request(&state).await.expect("request");
        let _ = get_request_object(State(state.clone()), Path(sid.to_string()))
            .await
            .expect("request object");
        let (body, _) = encrypted_runtime_direct_post_body(&state, sid, &issuer_jwk, None).await;

        let (status, Json(value)) =
            receive_response(State(state.clone()), Path(sid.to_string()), body)
                .await
                .expect("missing status ref rejected cleanly");

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(value["status"], "rejected");
        assert!(value["reason"]
            .as_str()
            .unwrap()
            .contains("no token-status-list reference"));
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        let trace = state.trace.get(sid).await.expect("trace");
        let rejected = trace
            .events
            .iter()
            .find(|event| event.code == "REJECTED")
            .expect("rejected event");
        assert!(rejected.summary.contains("no token-status-list reference"));

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

    #[tokio::test]
    async fn live_status_can_use_dedicated_status_signer() {
        let sid = Uuid::new_v4();
        let vp = fixture("presentations/synthetic-pid-with-status.sdjwt");
        let decrypted = json!({ "vp_token": vp });
        let anchor_pem = fixture("certs/synthetic-pid-anchor.pem");
        let trust_anchors =
            TrustAnchors::from_pem(&anchor_pem).expect("parse PID issuer trust anchor");
        let status_signer_pem = fixture("status/status-list-verify-key.pub.pem");
        let status_signer =
            crate::x509util::signer_jwk_from_pem(&status_signer_pem).expect("parse status signer");
        let counter = Arc::new(AtomicUsize::new(0));
        let mut st = AppState::new(
            Url::parse("http://127.0.0.1:0/").unwrap(),
            Url::parse("http://127.0.0.1:0/").unwrap(),
            CertSource::Ephemeral,
            "event_checkin",
            Some(trust_anchors),
            true,
            Some(anchor_pem),
            Some(status_signer),
            None,
            false,
        )
        .await
        .expect("build offline app state");
        st.status_fetcher = StatusFetcher::Recording(counter.clone());

        let verified = verify_vp_token(&st, sid, &decrypted, &binding(NONCE), NOW)
            .await
            .expect("dedicated status signer accepts clear status-list");

        assert!(verified.holder_bound);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }
}
