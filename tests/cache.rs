//! Integration tests for the cached-sandbox loopback server.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use augenmass_workbench::cache_server::{router, AppState};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Clone)]
struct UpstreamState {
    schema_hits: Arc<AtomicUsize>,
    registration_hits: Arc<AtomicUsize>,
    fail_registrations: Arc<AtomicBool>,
}

#[derive(Debug, Deserialize)]
struct RegistrationQuery {
    rp: String,
}

fn test_db(prefix: &str) -> String {
    std::env::temp_dir()
        .join(format!("{prefix}-{}.sqlite", uuid::Uuid::new_v4()))
        .display()
        .to_string()
}

async fn spawn_upstream(state: UpstreamState) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/api/schema-metadata", get(schema_metadata))
        .route("/api/registration-certificates", get(registrations))
        .with_state(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}/api")
}

async fn spawn_cache(upstream: &str, ttl_secs: u64) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind cache");
    let addr = listener.local_addr().unwrap();
    let state =
        AppState::new(&test_db("augenmass-cache-test"), upstream, ttl_secs).expect("cache state");
    let app = router(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}/api")
}

async fn schema_metadata(State(state): State<UpstreamState>) -> Json<Value> {
    state.schema_hits.fetch_add(1, Ordering::SeqCst);
    Json(json!([
        {
            "id": "pid",
            "type": "schema",
            "source": "stub"
        }
    ]))
}

async fn registrations(
    State(state): State<UpstreamState>,
    Query(query): Query<RegistrationQuery>,
) -> Response {
    state.registration_hits.fetch_add(1, Ordering::SeqCst);
    if state.fail_registrations.load(Ordering::SeqCst) {
        return (StatusCode::BAD_GATEWAY, "sandbox unavailable").into_response();
    }
    Json(json!([
        {
            "id": "reg-1",
            "jwt": "eyJhbGciOiJub25lIn0.eyJycElkIjoicnAtMSJ9.fixture",
            "relyingPartyId": query.rp,
            "source": "stub-upstream"
        }
    ]))
    .into_response()
}

fn cache_header(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .expect("header exists")
        .to_str()
        .expect("header is utf8")
        .to_string()
}

#[tokio::test]
async fn schema_metadata_is_cached_with_provenance_headers() {
    let upstream_state = UpstreamState {
        schema_hits: Arc::new(AtomicUsize::new(0)),
        registration_hits: Arc::new(AtomicUsize::new(0)),
        fail_registrations: Arc::new(AtomicBool::new(false)),
    };
    let upstream = spawn_upstream(upstream_state.clone()).await;
    let cache = spawn_cache(&upstream, 3600).await;
    let client = reqwest::Client::new();

    let first = client
        .get(format!("{cache}/schema-metadata"))
        .send()
        .await
        .expect("first cache request");
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(cache_header(first.headers(), "x-augenmass-cache"), "MISS");
    assert!(first.headers().contains_key("x-augenmass-cache-fetched-at"));
    assert!(first.headers().contains_key("x-augenmass-cache-sha256"));

    let second = client
        .get(format!("{cache}/schema-metadata"))
        .send()
        .await
        .expect("second cache request");
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(cache_header(second.headers(), "x-augenmass-cache"), "HIT");
    let body: Value = second.json().await.expect("cached schema json");
    assert_eq!(body[0]["id"], "pid");
    assert_eq!(upstream_state.schema_hits.load(Ordering::SeqCst), 1);

    let status: Value = client
        .get(format!("{cache}/cache/status"))
        .send()
        .await
        .expect("cache status")
        .json()
        .await
        .expect("status json");
    assert_eq!(status["entries"][0]["key"], "schema-metadata");
}

#[tokio::test]
async fn registration_list_falls_back_to_stale_cache_on_upstream_failure() {
    let upstream_state = UpstreamState {
        schema_hits: Arc::new(AtomicUsize::new(0)),
        registration_hits: Arc::new(AtomicUsize::new(0)),
        fail_registrations: Arc::new(AtomicBool::new(false)),
    };
    let upstream = spawn_upstream(upstream_state.clone()).await;
    let cache = spawn_cache(&upstream, 3600).await;
    let client = reqwest::Client::new();

    let first = client
        .get(format!("{cache}/registration-certificates?rp=rp-1"))
        .send()
        .await
        .expect("first list");
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(cache_header(first.headers(), "x-augenmass-cache"), "MISS");

    upstream_state
        .fail_registrations
        .store(true, Ordering::SeqCst);

    let stale = client
        .post(format!(
            "{cache}/cache/refresh?route=registration-certificates&rp=rp-1"
        ))
        .send()
        .await
        .expect("forced refresh");
    assert_eq!(stale.status(), StatusCode::OK);
    assert_eq!(cache_header(stale.headers(), "x-augenmass-cache"), "STALE");
    let body: Value = stale.json().await.expect("stale list json");
    assert_eq!(body[0]["id"], "reg-1");
    assert_eq!(body[0]["relyingPartyId"], "rp-1");
    assert_eq!(upstream_state.registration_hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn registration_refresh_requires_rp() {
    let upstream_state = UpstreamState {
        schema_hits: Arc::new(AtomicUsize::new(0)),
        registration_hits: Arc::new(AtomicUsize::new(0)),
        fail_registrations: Arc::new(AtomicBool::new(false)),
    };
    let upstream = spawn_upstream(upstream_state).await;
    let cache = spawn_cache(&upstream, 3600).await;
    let response = reqwest::Client::new()
        .post(format!(
            "{cache}/cache/refresh?route=registration-certificates"
        ))
        .send()
        .await
        .expect("refresh without rp");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
