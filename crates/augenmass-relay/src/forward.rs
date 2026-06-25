use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use augenmass_relay_proto::{
    decode_body, encode_body, is_allowed_request_header, is_allowed_response_header, HeaderPair,
    HttpErrorKind, HttpRequestFrame, ServerFrame,
};
use axum::body::{Body, Bytes, HttpBody};
use axum::extract::connect_info::ConnectInfo;
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode};
use axum::response::IntoResponse;
use tokio::time::timeout;

use crate::id::short_run_id;
use crate::ratelimit::RateBucket;
use crate::registry::{ForwardReply, RunLookup};
use crate::routes::RelayState;

struct ForwardInput {
    run_id: String,
    session: String,
    query: Option<String>,
    headers: HeaderMap,
    body: Bytes,
    client_ip: IpAddr,
    method: Method,
    route_label: &'static str,
}

pub async fn forward_request(
    State(state): State<Arc<RelayState>>,
    Path((run_id, session)): Path<(String, String)>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    body: Bytes,
) -> Response<Body> {
    forward_wallet_route(
        state,
        ForwardInput {
            run_id,
            session,
            query,
            headers,
            body,
            client_ip: peer.ip(),
            method: Method::GET,
            route_label: "request",
        },
    )
    .await
}

pub async fn forward_response(
    State(state): State<Arc<RelayState>>,
    Path((run_id, session)): Path<(String, String)>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    body: Bytes,
) -> Response<Body> {
    forward_wallet_route(
        state,
        ForwardInput {
            run_id,
            session,
            query,
            headers,
            body,
            client_ip: peer.ip(),
            method: Method::POST,
            route_label: "response",
        },
    )
    .await
}

async fn forward_wallet_route(state: Arc<RelayState>, input: ForwardInput) -> Response<Body> {
    let started = Instant::now();
    let req_bytes = input.body.len();
    let run_id = input.run_id.clone();
    let method = input.method.clone();
    let route_label = input.route_label;
    let result = forward_wallet_route_inner(state.clone(), input).await;
    let status = result.status().as_u16();
    let resp_bytes = result.body().size_hint().lower();
    tracing::info!(
        method = %method,
        route = route_label,
        run = %short_run_id(&run_id),
        status,
        req_bytes,
        resp_bytes,
        latency_ms = started.elapsed().as_millis(),
        "relay forward"
    );
    result
}

async fn forward_wallet_route_inner(state: Arc<RelayState>, input: ForwardInput) -> Response<Body> {
    if !state
        .rate_limiter
        .allow(
            input.client_ip,
            RateBucket::WalletForward,
            state.config.max_forward_requests_per_window,
        )
        .await
    {
        return simple(StatusCode::TOO_MANY_REQUESTS, "too many requests");
    }
    if !valid_session_segment(&input.session) {
        return simple(StatusCode::BAD_REQUEST, "invalid session segment");
    }
    if input
        .query
        .as_ref()
        .is_some_and(|query| query.len() > state.config.max_query_bytes)
    {
        return simple(StatusCode::URI_TOO_LONG, "query string too large");
    }
    if input.body.len() > state.config.max_body_bytes {
        return simple(StatusCode::PAYLOAD_TOO_LARGE, "body too large");
    }
    let run = match state.registry.lookup(&input.run_id).await {
        RunLookup::Active(run) => run,
        RunLookup::Tombstoned => return simple(StatusCode::GONE, "run expired"),
        RunLookup::Missing => return simple(StatusCode::NOT_FOUND, "run not found"),
    };
    let Some(_guard) = run.try_acquire(state.config.max_inflight) else {
        return simple(StatusCode::TOO_MANY_REQUESTS, "too many in-flight requests");
    };
    let headers = match allowed_headers(&input.headers, state.config.max_header_bytes) {
        Ok(headers) => headers,
        Err(status) => return simple(status, "header too large or invalid"),
    };
    let req_id = run.next_req_id();
    let path = format!("/{}/{}", input.route_label, input.session);
    let frame = ServerFrame::HttpRequest(HttpRequestFrame {
        req_id,
        method: input.method.as_str().to_string(),
        path,
        query: input.query,
        headers,
        body_b64: encode_body(&input.body),
        body_truncated: false,
    });
    let rx = run.register_pending(req_id).await;
    if run.tx.send(frame).await.is_err() {
        run.remove_pending(req_id).await;
        return simple(StatusCode::BAD_GATEWAY, "tunnel is closed");
    }
    let reply = match timeout(state.config.req_timeout, rx).await {
        Ok(Ok(reply)) => reply,
        Ok(Err(_)) => return simple(StatusCode::BAD_GATEWAY, "tunnel closed"),
        Err(_) => {
            run.remove_pending(req_id).await;
            return simple(StatusCode::GATEWAY_TIMEOUT, "local serve timeout");
        }
    };
    render_reply(reply, state.config.max_body_bytes).await
}

async fn render_reply(reply: ForwardReply, max_body_bytes: usize) -> Response<Body> {
    match reply {
        ForwardReply::Error(kind) => map_error(kind),
        ForwardReply::Response(response) => {
            let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY);
            let body = match decode_body(&response.body_b64) {
                Ok(body) if body.len() <= max_body_bytes => body,
                _ => return simple(StatusCode::BAD_GATEWAY, "invalid local response body"),
            };
            let mut builder = Response::builder().status(status);
            for (name, value) in response.headers {
                if !is_allowed_response_header(&name) {
                    continue;
                }
                let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
                    continue;
                };
                let Ok(value) = HeaderValue::from_str(&value) else {
                    continue;
                };
                builder = builder.header(name, value);
            }
            builder
                .body(Body::from(body))
                .unwrap_or_else(|_| simple(StatusCode::BAD_GATEWAY, "invalid local response"))
        }
    }
}

fn allowed_headers(
    headers: &HeaderMap,
    max_header_bytes: usize,
) -> Result<Vec<HeaderPair>, StatusCode> {
    let mut out = Vec::new();
    let mut bytes = 0usize;
    for (name, value) in headers {
        let name_str = name.as_str();
        if !is_allowed_request_header(name_str) {
            continue;
        }
        let value = value.to_str().map_err(|_| StatusCode::BAD_REQUEST)?;
        bytes = bytes
            .saturating_add(name_str.len())
            .saturating_add(value.len());
        if bytes > max_header_bytes {
            return Err(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
        }
        out.push((name_str.to_ascii_lowercase(), value.to_string()));
    }
    Ok(out)
}

fn valid_session_segment(session: &str) -> bool {
    !session.is_empty()
        && session.len() <= 128
        && !session.contains('/')
        && !session.contains("..")
        && session
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn map_error(kind: HttpErrorKind) -> Response<Body> {
    match kind {
        HttpErrorKind::LocalTimeout => simple(StatusCode::GATEWAY_TIMEOUT, "local serve timeout"),
        _ => simple(StatusCode::BAD_GATEWAY, "local serve unavailable"),
    }
}

fn simple(status: StatusCode, msg: &'static str) -> Response<Body> {
    (status, msg).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_session_segment() {
        assert!(valid_session_segment(
            "550e8400-e29b-41d4-a716-446655440000"
        ));
        assert!(!valid_session_segment(""));
        assert!(!valid_session_segment("../trace"));
        assert!(!valid_session_segment("trace/abc"));
    }

    #[test]
    fn strips_and_caps_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        headers.insert("authorization", HeaderValue::from_static("secret"));
        let allowed = allowed_headers(&headers, 1024).unwrap();
        assert_eq!(
            allowed,
            vec![(
                "content-type".to_string(),
                "application/x-www-form-urlencoded".to_string()
            )]
        );
        assert_eq!(
            allowed_headers(&headers, 4).unwrap_err(),
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );
    }
}
