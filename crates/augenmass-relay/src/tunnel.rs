use std::sync::Arc;
use std::time::Duration;

use augenmass_relay_proto::{
    ws_message_limit, ClientFrame, CloseCode, HttpErrorKind, Limits, ServerFrame, PROTOCOL_V,
};
use axum::extract::connect_info::ConnectInfo;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;

use crate::id::short_run_id;
use crate::ratelimit::RateBucket;
use crate::registry::{ForwardReply, Run};
use crate::routes::RelayState;

pub async fn tunnel(
    ws: WebSocketUpgrade,
    State(state): State<Arc<RelayState>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !state
        .rate_limiter
        .allow(
            peer.ip(),
            RateBucket::TunnelCreate,
            state.config.max_tunnel_creates_per_window,
        )
        .await
    {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    if !authorized(&headers, &state.config.auth_tokens) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    ws.max_message_size(ws_message_limit(state.config.max_body_bytes))
        .on_upgrade(move |socket| handle_socket(socket, state))
}

fn authorized(headers: &HeaderMap, tokens: &[String]) -> bool {
    if tokens.is_empty() {
        return true;
    }
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim);
    bearer.is_some_and(|actual| tokens.iter().any(|expected| expected == actual))
}

async fn handle_socket(mut socket: WebSocket, state: Arc<RelayState>) {
    let Some(Ok(Message::Text(text))) = socket.recv().await else {
        let _ = socket
            .send(Message::Text(close_json(
                CloseCode::ProtocolError,
                "first frame must be hello",
            )))
            .await;
        return;
    };
    let hello = serde_json::from_str::<ClientFrame>(&text);
    let (run_ttl_secs, client_info) = match hello {
        Ok(ClientFrame::Hello {
            v,
            run_ttl_secs,
            client_info,
        }) if v == PROTOCOL_V => (run_ttl_secs, client_info),
        _ => {
            let _ = socket
                .send(Message::Text(close_json(
                    CloseCode::ProtocolError,
                    "invalid hello",
                )))
                .await;
            return;
        }
    };

    let ttl = state.config.clamp_requested_ttl(run_ttl_secs);
    let Some((run, rx)) = state.registry.mint(ttl).await else {
        let _ = socket
            .send(Message::Text(close_json(
                CloseCode::ServerShutdown,
                "relay is at capacity",
            )))
            .await;
        return;
    };
    let public_url = format!("{}/r/{}/", state.public_base, run.id);
    let welcome = ServerFrame::Welcome {
        v: PROTOCOL_V,
        run_id: run.id.clone(),
        public_url,
        ttl_secs: ttl.as_secs(),
        limits: Limits {
            max_body_bytes: state.config.max_body_bytes,
            max_inflight: state.config.max_inflight,
            req_timeout_secs: state.config.req_timeout.as_secs(),
        },
    };
    if socket
        .send(Message::Text(serde_json::to_string(&welcome).unwrap()))
        .await
        .is_err()
    {
        state
            .registry
            .remove(&run.id, CloseCode::ProtocolError, "welcome send failed")
            .await;
        return;
    }
    tracing::info!(
        route = "tunnel",
        run = %short_run_id(&run.id),
        client = client_info.as_deref().unwrap_or("unknown"),
        ttl_secs = ttl.as_secs(),
        "relay run started"
    );

    let run_id = run.id.clone();
    let (sink, stream) = socket.split();
    let writer = tokio::spawn(writer_loop(sink, rx, run.clone()));
    let reader = tokio::spawn(reader_loop(stream, run.clone(), state.clone()));
    tokio::select! {
        _ = writer => {}
        _ = reader => {}
    }
    state
        .registry
        .remove(&run_id, CloseCode::ServerShutdown, "tunnel closed")
        .await;
    tracing::info!(
        route = "tunnel",
        run = %short_run_id(&run_id),
        "relay run ended"
    );
}

async fn writer_loop(
    mut sink: futures_util::stream::SplitSink<WebSocket, Message>,
    mut rx: mpsc::Receiver<ServerFrame>,
    run: Arc<Run>,
) {
    let mut ping = tokio::time::interval(Duration::from_secs(10));
    loop {
        tokio::select! {
            Some(frame) = rx.recv() => {
                let Ok(text) = serde_json::to_string(&frame) else {
                    break;
                };
                if sink.send(Message::Text(text)).await.is_err() {
                    break;
                }
                if matches!(frame, ServerFrame::Close { .. }) {
                    break;
                }
            }
            _ = ping.tick() => {
                if run.age_since_pong().await > Duration::from_secs(35) {
                    let _ = sink.send(Message::Text(close_json(CloseCode::ProtocolError, "pong timeout"))).await;
                    break;
                }
                let nonce = format!("{}-{}", short_run_id(&run.id), run.next_req_id());
                let frame = ServerFrame::Ping { nonce };
                let Ok(text) = serde_json::to_string(&frame) else {
                    break;
                };
                if sink.send(Message::Text(text)).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn reader_loop(
    mut stream: futures_util::stream::SplitStream<WebSocket>,
    run: Arc<Run>,
    state: Arc<RelayState>,
) {
    while let Some(message) = stream.next().await {
        let Ok(message) = message else {
            break;
        };
        let text = match message {
            Message::Text(text) => text,
            Message::Ping(_) | Message::Pong(_) | Message::Binary(_) => continue,
            Message::Close(_) => break,
        };
        let frame = match serde_json::from_str::<ClientFrame>(&text) {
            Ok(frame) => frame,
            Err(_) => break,
        };
        match frame {
            ClientFrame::HttpResponse(response) => {
                if response.body_b64.len() > ws_message_limit(state.config.max_body_bytes) {
                    let _ = run.tx.try_send(ServerFrame::Close {
                        code: CloseCode::FrameTooLarge,
                        reason: "response frame too large".to_string(),
                    });
                    break;
                }
                run.resolve_pending(response.req_id, ForwardReply::Response(response))
                    .await;
            }
            ClientFrame::HttpError { req_id, kind } => {
                run.resolve_pending(req_id, ForwardReply::Error(kind)).await;
            }
            ClientFrame::Pong { .. } => {
                run.note_pong().await;
            }
            ClientFrame::Bye => break,
            ClientFrame::Hello { .. } => {
                run.resolve_pending(0, ForwardReply::Error(HttpErrorKind::ProtocolError))
                    .await;
                break;
            }
        }
    }
}

fn close_json(code: CloseCode, reason: &str) -> String {
    serde_json::to_string(&ServerFrame::Close {
        code,
        reason: reason.to_string(),
    })
    .unwrap()
}
