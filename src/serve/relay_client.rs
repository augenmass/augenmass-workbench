use anyhow::{Context, Result};
use augenmass_relay_proto::{
    decode_body, encode_body, is_allowed_request_header, is_allowed_response_header, ClientFrame,
    CloseCode, HeaderPair, HttpErrorKind, HttpResponseFrame, Limits, ServerFrame, PROTOCOL_V,
    WS_MESSAGE_HARD_CAP,
};
use futures_util::{SinkExt, StreamExt};
use reqwest::redirect::Policy;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use url::Url;

pub const HOSTED_RELAY_ALIAS: &str = "augenmass";
pub const HOSTED_RELAY_CONTROL_URL: &str = "wss://wallet.augenmass.tech/_relay/tunnel";

type RelayStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub struct RelayConnection {
    pub public_url: Url,
    pub run_id: String,
    pub ttl_secs: u64,
    pub limits: Limits,
    stream: RelayStream,
}

pub fn resolve_relay_url(input: &str) -> Result<Url> {
    let target = if input == HOSTED_RELAY_ALIAS {
        std::env::var("AUGENMASS_RELAY_URL")
            .unwrap_or_else(|_| HOSTED_RELAY_CONTROL_URL.to_string())
    } else {
        input.to_string()
    };
    let target = if let Some(rest) = target.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = target.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        target
    };
    let url = Url::parse(&target).with_context(|| format!("parse relay URL {target}"))?;
    match url.scheme() {
        "ws" | "wss" => Ok(url),
        scheme => anyhow::bail!("relay URL must use ws or wss, got {scheme}"),
    }
}

pub async fn connect(relay_url: &Url, token: &str, ttl: Option<u64>) -> Result<RelayConnection> {
    let mut request = relay_url
        .as_str()
        .into_client_request()
        .with_context(|| format!("build relay websocket request {relay_url}"))?;
    if !token.trim().is_empty() {
        request.headers_mut().insert(
            http::header::AUTHORIZATION,
            format!("Bearer {}", token.trim())
                .parse()
                .context("build relay authorization header")?,
        );
    }
    let (mut stream, _) = connect_async(request)
        .await
        .with_context(|| format!("connect to relay {relay_url}"))?;
    let hello = ClientFrame::Hello {
        v: PROTOCOL_V,
        run_ttl_secs: ttl,
        client_info: Some(format!("augenmass/{}", env!("CARGO_PKG_VERSION"))),
    };
    stream
        .send(Message::Text(serde_json::to_string(&hello)?))
        .await
        .context("send relay hello")?;
    let welcome = match stream.next().await {
        Some(Ok(Message::Text(text))) => {
            serde_json::from_str::<ServerFrame>(&text).context("parse relay welcome frame")?
        }
        Some(Ok(_)) => anyhow::bail!("relay sent non-text welcome frame"),
        Some(Err(e)) => return Err(e).context("read relay welcome"),
        None => anyhow::bail!("relay closed before welcome"),
    };
    match welcome {
        ServerFrame::Welcome {
            v,
            run_id,
            public_url,
            ttl_secs,
            limits,
        } if v == PROTOCOL_V => Ok(RelayConnection {
            public_url: Url::parse(&public_url).context("parse relay public URL")?,
            run_id,
            ttl_secs,
            limits,
            stream,
        }),
        ServerFrame::Close { code, reason } => {
            anyhow::bail!("relay refused run ({code:?}): {reason}")
        }
        _ => anyhow::bail!("relay returned invalid welcome frame"),
    }
}

pub async fn run_tunnel(conn: RelayConnection, local_base: Url) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(
            conn.limits.req_timeout_secs.max(1),
        ))
        .redirect(Policy::none())
        .build()
        .context("build relay loopback http client")?;
    let mut stream = conn.stream;
    while let Some(message) = stream.next().await {
        let message = message.context("read relay frame")?;
        let Message::Text(text) = message else {
            continue;
        };
        let frame: ServerFrame = serde_json::from_str(&text).context("parse relay frame")?;
        match frame {
            ServerFrame::HttpRequest(request) => {
                let req_id = request.req_id;
                let reply = handle_request(&client, &local_base, &conn.limits, request).await;
                let frame = match reply {
                    Ok(response) => ClientFrame::HttpResponse(response),
                    Err(kind) => ClientFrame::HttpError { req_id, kind },
                };
                stream
                    .send(Message::Text(serde_json::to_string(&frame)?))
                    .await
                    .context("send relay response")?;
            }
            ServerFrame::Ping { nonce } => {
                stream
                    .send(Message::Text(serde_json::to_string(&ClientFrame::Pong {
                        nonce,
                    })?))
                    .await
                    .context("send relay pong")?;
            }
            ServerFrame::Close { code, reason } => {
                if !matches!(code, CloseCode::Expired | CloseCode::ServerShutdown) {
                    anyhow::bail!("relay closed run ({code:?}): {reason}");
                }
                return Ok(());
            }
            ServerFrame::Welcome { .. } => anyhow::bail!("relay sent duplicate welcome"),
        }
    }
    Ok(())
}

async fn handle_request(
    client: &reqwest::Client,
    local_base: &Url,
    limits: &Limits,
    request: augenmass_relay_proto::HttpRequestFrame,
) -> std::result::Result<HttpResponseFrame, HttpErrorKind> {
    let req_id = request.req_id;
    let body = decode_body(&request.body_b64).map_err(|_| HttpErrorKind::ProtocolError)?;
    if body.len() > limits.max_body_bytes {
        return Err(HttpErrorKind::BodyTooLarge);
    }
    if !method_matches_path(&request.method, &request.path) {
        return Err(HttpErrorKind::ProtocolError);
    }
    let local_url = local_url(local_base, &request.path, request.query.as_deref())
        .map_err(|_| HttpErrorKind::ProtocolError)?;
    let method = request
        .method
        .parse::<reqwest::Method>()
        .map_err(|_| HttpErrorKind::ProtocolError)?;
    let mut builder = client.request(method, local_url);
    for (name, value) in request.headers {
        if is_allowed_request_header(&name) {
            builder = builder.header(name, value);
        }
    }
    let response = builder
        .body(body)
        .send()
        .await
        .map_err(|_| HttpErrorKind::LocalUnavailable)?;
    let status = response.status().as_u16();
    let headers = response_headers(response.headers());
    let body = response
        .bytes()
        .await
        .map_err(|_| HttpErrorKind::BadLocalResponse)?;
    if body.len() > limits.max_body_bytes {
        return Err(HttpErrorKind::BodyTooLarge);
    }
    Ok(HttpResponseFrame {
        req_id,
        status,
        headers,
        body_b64: encode_body(&body),
        body_truncated: false,
    })
}

fn local_url(local_base: &Url, path: &str, query: Option<&str>) -> Result<Url> {
    validate_wallet_path(path)?;
    let mut url = local_base
        .join(path.trim_start_matches('/'))
        .context("join relay local path")?;
    url.set_query(query);
    Ok(url)
}

fn method_matches_path(method: &str, path: &str) -> bool {
    match path.split('/').nth(1) {
        Some("request") => method == "GET",
        Some("response") => method == "POST",
        _ => false,
    }
}

fn validate_wallet_path(path: &str) -> Result<()> {
    let parts = path.split('/').collect::<Vec<_>>();
    let route = parts.get(1).copied();
    let session = parts.get(2).copied();
    if parts.len() != 3 || !parts[0].is_empty() || !matches!(route, Some("request" | "response")) {
        anyhow::bail!("relay requested disallowed local path");
    }
    let Some(session) = session else {
        anyhow::bail!("relay requested missing session");
    };
    if !valid_session_segment(session) {
        anyhow::bail!("relay requested invalid session");
    }
    Ok(())
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

fn response_headers(headers: &http::HeaderMap) -> Vec<HeaderPair> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            if !is_allowed_response_header(name.as_str()) {
                return None;
            }
            let value = value.to_str().ok()?;
            Some((name.as_str().to_ascii_lowercase(), value.to_string()))
        })
        .collect()
}

pub fn warn_if_message_may_exceed_transport(body_len: usize) -> bool {
    body_len.saturating_mul(4).div_ceil(3) > WS_MESSAGE_HARD_CAP
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_url_accepts_only_wallet_paths() {
        let base = Url::parse("http://127.0.0.1:8080/").unwrap();
        assert_eq!(
            local_url(&base, "/request/550e8400-e29b-41d4-a716-446655440000", None)
                .unwrap()
                .as_str(),
            "http://127.0.0.1:8080/request/550e8400-e29b-41d4-a716-446655440000"
        );
        assert!(local_url(&base, "/request/../../trace", None).is_err());
        assert!(local_url(&base, "/trace/550e8400-e29b-41d4-a716-446655440000", None).is_err());
        assert!(local_url(&base, "/response/session/extra", None).is_err());
    }

    #[test]
    fn method_must_match_wallet_path() {
        assert!(method_matches_path("GET", "/request/abc"));
        assert!(method_matches_path("POST", "/response/abc"));
        assert!(!method_matches_path("POST", "/request/abc"));
        assert!(!method_matches_path("GET", "/response/abc"));
        assert!(!method_matches_path("GET", "/trace/abc"));
    }
}
