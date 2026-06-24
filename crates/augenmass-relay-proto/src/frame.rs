use base64::prelude::*;
use serde::{Deserialize, Serialize};

pub use crate::limits::{max_body_for_ws_cap, ws_message_limit, WS_MESSAGE_HARD_CAP};

pub const PROTOCOL_V: u32 = 1;

pub type ReqId = u64;
pub type HeaderPair = (String, String);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CloseCode {
    Expired,
    FrameTooLarge,
    ProtocolError,
    DuplicateClient,
    ServerShutdown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum HttpErrorKind {
    LocalUnavailable,
    LocalTimeout,
    BadLocalResponse,
    BodyTooLarge,
    ProtocolError,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    pub max_body_bytes: usize,
    pub max_inflight: usize,
    pub req_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HttpRequestFrame {
    pub req_id: ReqId,
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub headers: Vec<HeaderPair>,
    pub body_b64: String,
    #[serde(default)]
    pub body_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HttpResponseFrame {
    pub req_id: ReqId,
    pub status: u16,
    #[serde(default)]
    pub headers: Vec<HeaderPair>,
    pub body_b64: String,
    #[serde(default)]
    pub body_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ClientFrame {
    Hello {
        v: u32,
        #[serde(default)]
        run_ttl_secs: Option<u64>,
        #[serde(default)]
        client_info: Option<String>,
    },
    HttpResponse(HttpResponseFrame),
    HttpError {
        req_id: ReqId,
        kind: HttpErrorKind,
    },
    Pong {
        nonce: String,
    },
    Bye,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ServerFrame {
    Welcome {
        v: u32,
        run_id: String,
        public_url: String,
        ttl_secs: u64,
        limits: Limits,
    },
    HttpRequest(HttpRequestFrame),
    Ping {
        nonce: String,
    },
    Close {
        code: CloseCode,
        reason: String,
    },
}

pub fn encode_body(body: &[u8]) -> String {
    BASE64_STANDARD.encode(body)
}

pub fn decode_body(body_b64: &str) -> Result<Vec<u8>, base64::DecodeError> {
    BASE64_STANDARD.decode(body_b64)
}

pub fn is_allowed_request_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "content-type" | "accept"
    )
}

pub fn is_allowed_response_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "content-type" | "cache-control"
    )
}

pub fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_base64_round_trips_with_standard_padding() {
        let encoded = encode_body(b"hello relay");
        assert!(encoded.ends_with('='));
        assert_eq!(decode_body(&encoded).unwrap(), b"hello relay");
    }

    #[test]
    fn frame_round_trips() {
        let frame = ServerFrame::Welcome {
            v: PROTOCOL_V,
            run_id: "abc".to_string(),
            public_url: "https://wallet.example/r/abc/".to_string(),
            ttl_secs: 600,
            limits: Limits {
                max_body_bytes: 1024,
                max_inflight: 4,
                req_timeout_secs: 10,
            },
        };
        let json = serde_json::to_string(&frame).unwrap();
        assert!(json.contains("\"type\":\"welcome\""));
        assert_eq!(serde_json::from_str::<ServerFrame>(&json).unwrap(), frame);
    }

    #[test]
    fn header_allowlists_are_narrow() {
        assert!(is_allowed_request_header("content-type"));
        assert!(is_allowed_request_header("ACCEPT"));
        assert!(!is_allowed_request_header("authorization"));
        assert!(!is_allowed_request_header("cookie"));
        assert!(is_allowed_response_header("cache-control"));
        assert!(!is_allowed_response_header("set-cookie"));
        assert!(is_hop_by_hop("transfer-encoding"));
    }
}
