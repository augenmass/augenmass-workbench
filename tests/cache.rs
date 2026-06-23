//! Integration tests for the cached-sandbox loopback server.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use assert_cmd::Command;
use augenmass_workbench::cache_server::{router, AppState};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

fn upstream_state() -> UpstreamState {
    UpstreamState {
        schema_hits: Arc::new(AtomicUsize::new(0)),
        registration_hits: Arc::new(AtomicUsize::new(0)),
        fail_registrations: Arc::new(AtomicBool::new(false)),
    }
}

async fn spawn_upstream(state: UpstreamState) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/api/schema-metadata", get(schema_metadata))
        .route(
            "/api/schema-metadata/vocabularies",
            get(schema_vocabularies),
        )
        .route("/api/registration-certificates", get(registrations))
        .with_state(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}/api")
}

async fn spawn_chunked_oversize_upstream() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind chunked upstream");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept chunked upstream");
        let mut buffer = [0_u8; 1024];
        let _ = stream.read(&mut buffer).await;
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n",
            )
            .await
            .expect("write headers");
        let chunk = vec![b'a'; 64 * 1024];
        let header = format!("{:x}\r\n", chunk.len());
        for _ in 0..82 {
            stream
                .write_all(header.as_bytes())
                .await
                .expect("write chunk header");
            stream.write_all(&chunk).await.expect("write chunk");
            stream.write_all(b"\r\n").await.expect("write chunk break");
        }
        stream.flush().await.expect("flush chunks");
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    format!("http://{addr}/api")
}

async fn spawn_cache(upstream: &str, ttl_secs: u64) -> String {
    spawn_cache_with_admin(upstream, ttl_secs, None).await
}

async fn spawn_cache_with_admin(
    upstream: &str,
    ttl_secs: u64,
    admin_token: Option<String>,
) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind cache");
    let addr = listener.local_addr().unwrap();
    let state = AppState::new_with_options(
        &test_db("augenmass-cache-test"),
        upstream,
        ttl_secs,
        10,
        admin_token,
    )
    .expect("cache state");
    let app = router(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}/api")
}

async fn schema_metadata(State(state): State<UpstreamState>) -> Response {
    state.schema_hits.fetch_add(1, Ordering::SeqCst);
    Json(json!([
        {
            "id": "pid",
            "type": "schema",
            "source": "stub"
        }
    ]))
    .into_response()
}

async fn schema_vocabularies(State(state): State<UpstreamState>) -> Json<Value> {
    state.schema_hits.fetch_add(1, Ordering::SeqCst);
    Json(json!([
        {
            "id": "eu.europa.ec.eudi.pid.1",
            "type": "vocabulary",
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
    let upstream_state = upstream_state();
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
async fn schema_metadata_refuses_body_above_cache_cap_without_storing() {
    let upstream = spawn_chunked_oversize_upstream().await;
    let cache = spawn_cache(&upstream, 3600).await;
    let client = reqwest::Client::new();

    let response = tokio::time::timeout(
        Duration::from_secs(5),
        client.get(format!("{cache}/schema-metadata")).send(),
    )
    .await
    .expect("cache fails before oversized upstream finishes")
    .expect("oversized cache request");
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let text = response.text().await.expect("oversized error text");
    assert!(text.contains("above the cache body cap"));

    let status: Value = client
        .get(format!("{cache}/cache/status"))
        .send()
        .await
        .expect("cache status")
        .json()
        .await
        .expect("status json");
    assert_eq!(
        status["entries"].as_array().expect("entries array").len(),
        0
    );
}

#[tokio::test]
async fn registration_list_falls_back_to_stale_cache_on_upstream_failure() {
    let upstream_state = upstream_state();
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
    let upstream_state = upstream_state();
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

#[tokio::test]
async fn registration_list_rejects_malformed_rp_before_upstream() {
    let upstream_state = upstream_state();
    let upstream = spawn_upstream(upstream_state.clone()).await;
    let cache = spawn_cache(&upstream, 3600).await;
    let response = reqwest::Client::new()
        .get(format!("{cache}/registration-certificates?rp=bad%20rp"))
        .send()
        .await
        .expect("list with malformed rp");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(upstream_state.registration_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cache_warm_cli_refreshes_demo_routes() {
    let upstream_state = upstream_state();
    let upstream = spawn_upstream(upstream_state.clone()).await;
    let cache = spawn_cache_with_admin(&upstream, 3600, Some("secret".to_string())).await;

    let output = tokio::task::spawn_blocking(move || {
        Command::cargo_bin("augenmass")
            .expect("binary builds")
            .args([
                "cache",
                "warm",
                "--api-base",
                cache.as_str(),
                "--admin-token",
                "secret",
                "--rp",
                "rp-1",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone()
    })
    .await
    .expect("warm command task");
    let stdout = String::from_utf8(output).expect("stdout is utf8");
    assert!(stdout.contains("Cache warm complete"));
    assert!(stdout.contains("schema-metadata"));
    assert!(stdout.contains("schema-metadata/vocabularies"));
    assert!(stdout.contains("registration-certificates?rp=rp-1"));
    assert!(stdout.contains("1 item(s)"));
    assert_eq!(upstream_state.schema_hits.load(Ordering::SeqCst), 2);
    assert_eq!(upstream_state.registration_hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn health_stays_public_when_admin_token_is_configured() {
    let upstream_state = upstream_state();
    let upstream = spawn_upstream(upstream_state).await;
    let cache = spawn_cache_with_admin(&upstream, 3600, Some("secret".to_string())).await;
    let health: Value = reqwest::Client::new()
        .get(format!("{cache}/health"))
        .send()
        .await
        .expect("health")
        .json()
        .await
        .expect("health json");
    assert_eq!(health["status"], "ok");
    assert_eq!(health["service"], "augenmass cache");
}

#[tokio::test]
async fn admin_token_protects_cache_status_and_refresh() {
    let upstream_state = upstream_state();
    let upstream = spawn_upstream(upstream_state.clone()).await;
    let cache = spawn_cache_with_admin(&upstream, 3600, Some("secret".to_string())).await;
    let client = reqwest::Client::new();

    let status_without_token = client
        .get(format!("{cache}/cache/status"))
        .send()
        .await
        .expect("status without token");
    assert_eq!(status_without_token.status(), StatusCode::UNAUTHORIZED);

    let refresh_without_token = client
        .post(format!("{cache}/cache/refresh?route=schema-metadata"))
        .send()
        .await
        .expect("refresh without token");
    assert_eq!(refresh_without_token.status(), StatusCode::UNAUTHORIZED);

    let refreshed = client
        .post(format!("{cache}/cache/refresh?route=schema-metadata"))
        .bearer_auth("secret")
        .send()
        .await
        .expect("refresh with token");
    assert_eq!(refreshed.status(), StatusCode::OK);
    assert_eq!(
        cache_header(refreshed.headers(), "x-augenmass-cache"),
        "MISS"
    );
    assert_eq!(upstream_state.schema_hits.load(Ordering::SeqCst), 1);

    let status: Value = client
        .get(format!("{cache}/cache/status"))
        .header("x-augenmass-cache-admin", "secret")
        .send()
        .await
        .expect("status with token")
        .json()
        .await
        .expect("status json");
    assert_eq!(status["entries"][0]["key"], "schema-metadata");
}
