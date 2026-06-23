//! Read-through cache for public sandbox reads.
//!
//! This is intentionally distinct from the mutable local clone. The clone is a
//! demo registrar for writes; this cache mirrors successful sandbox GET
//! responses with provenance so demos and audits can keep running when the
//! sandbox drifts or is temporarily unreachable.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use reqwest::Client;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::config::trim_base;

const USER_AGENT: &str = concat!("augenmass-cache/", env!("CARGO_PKG_VERSION"));
const MAX_CACHE_BODY_BYTES: usize = 5 * 1024 * 1024;
const MAX_RP_LEN: usize = 256;
pub const DEFAULT_CACHE_DB: &str = "./augenmass-cache.sqlite";
pub const DEFAULT_CACHE_HOST: &str = "127.0.0.1";
pub const DEFAULT_CACHE_PORT: u16 = 8081;
pub const DEFAULT_CACHE_TTL_SECS: u64 = 3600;
pub const DEFAULT_CACHE_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Clone)]
pub struct ServeConfig {
    pub db_path: String,
    pub host: String,
    pub port: u16,
    pub upstream: String,
    pub ttl_secs: u64,
    pub timeout_secs: u64,
    pub admin_token: Option<String>,
}

#[derive(Clone)]
pub struct AppState {
    db: Arc<Mutex<Connection>>,
    client: Client,
    upstream: String,
    ttl: Duration,
    admin_token: Option<String>,
}

#[derive(Debug, Clone, Copy)]
enum Endpoint {
    SchemaMetadata,
    SchemaVocabularies,
    RegistrationCertificates,
}

#[derive(Debug, Deserialize)]
struct RegistrationQuery {
    rp: String,
}

#[derive(Debug, Deserialize)]
struct RefreshQuery {
    route: String,
    rp: Option<String>,
}

#[derive(Debug, Clone)]
struct CacheRequest {
    key: String,
    upstream_url: String,
}

#[derive(Debug)]
struct CachedResponse {
    key: String,
    upstream_url: String,
    status: u16,
    content_type: String,
    body: Vec<u8>,
    fetched_at: DateTime<Utc>,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct CacheRow {
    key: String,
    upstream_url: String,
    status: u16,
    content_type: String,
    bytes: usize,
    fetched_at: String,
    sha256: String,
}

#[derive(Debug, Clone, Copy)]
enum CacheDisposition {
    Hit,
    Miss,
    Refreshed,
    Stale,
}

impl CacheDisposition {
    fn as_str(self) -> &'static str {
        match self {
            CacheDisposition::Hit => "HIT",
            CacheDisposition::Miss => "MISS",
            CacheDisposition::Refreshed => "REFRESHED",
            CacheDisposition::Stale => "STALE",
        }
    }
}

pub async fn serve(config: ServeConfig) -> Result<()> {
    let conn = Connection::open(&config.db_path)
        .with_context(|| format!("open SQLite db {}", config.db_path))?;
    init_db(&conn)?;
    let timeout = Duration::from_secs(config.timeout_secs);
    let state = AppState {
        db: Arc::new(Mutex::new(conn)),
        client: Client::builder()
            .user_agent(USER_AGENT)
            .timeout(timeout)
            .build()?,
        upstream: trim_base(&config.upstream),
        ttl: Duration::from_secs(config.ttl_secs),
        admin_token: normalize_token(config.admin_token.clone()),
    };

    let app = router(state);
    let addr = resolve_bind_addr(&config.host, config.port)?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    println!("cached-sandbox target listening on http://{addr}/api");
    println!("upstream: {}", trim_base(&config.upstream));
    println!("ttl: {}s", config.ttl_secs);
    println!("upstream timeout: {}s", config.timeout_secs);
    println!(
        "admin endpoints: {}",
        if config
            .admin_token
            .as_deref()
            .is_some_and(|token| !token.trim().is_empty())
        {
            "protected by token"
        } else {
            "open on this listener"
        }
    );
    axum::serve(listener, app)
        .await
        .context("serve cached sandbox target")
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/schema-metadata", get(schema_metadata))
        .route("/api/schema-metadata", get(schema_metadata))
        .route("/schema-metadata/vocabularies", get(schema_vocabularies))
        .route(
            "/api/schema-metadata/vocabularies",
            get(schema_vocabularies),
        )
        .route("/registration-certificates", get(registration_certificates))
        .route(
            "/api/registration-certificates",
            get(registration_certificates),
        )
        .route("/health", get(health))
        .route("/api/health", get(health))
        .route("/api/cache/status", get(cache_status))
        .route("/api/cache/refresh", post(cache_refresh))
        .with_state(state)
}

impl AppState {
    pub fn new(db_path: &str, upstream: &str, ttl_secs: u64) -> Result<Self> {
        Self::new_with_options(
            db_path,
            upstream,
            ttl_secs,
            DEFAULT_CACHE_TIMEOUT_SECS,
            None,
        )
    }

    pub fn new_with_options(
        db_path: &str,
        upstream: &str,
        ttl_secs: u64,
        timeout_secs: u64,
        admin_token: Option<String>,
    ) -> Result<Self> {
        let conn =
            Connection::open(db_path).with_context(|| format!("open SQLite db {db_path}"))?;
        init_db(&conn)?;
        Ok(Self {
            db: Arc::new(Mutex::new(conn)),
            client: Client::builder()
                .user_agent(USER_AGENT)
                .timeout(Duration::from_secs(timeout_secs))
                .build()?,
            upstream: trim_base(upstream),
            ttl: Duration::from_secs(ttl_secs),
            admin_token: normalize_token(admin_token),
        })
    }
}

async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "service": "augenmass cache",
        "upstream": state.upstream,
        "ttlSecs": state.ttl.as_secs(),
    }))
}

async fn schema_metadata(State(state): State<AppState>) -> Response {
    let request = match request_for(state.upstream.as_str(), Endpoint::SchemaMetadata, None) {
        Ok(request) => request,
        Err(error) => return server_error(error).into_response(),
    };
    cached_or_fetch(&state, request, false)
        .await
        .into_response()
}

async fn schema_vocabularies(State(state): State<AppState>) -> Response {
    let request = match request_for(state.upstream.as_str(), Endpoint::SchemaVocabularies, None) {
        Ok(request) => request,
        Err(error) => return server_error(error).into_response(),
    };
    cached_or_fetch(&state, request, false)
        .await
        .into_response()
}

async fn registration_certificates(
    State(state): State<AppState>,
    Query(query): Query<RegistrationQuery>,
) -> Response {
    let request = match request_for(
        state.upstream.as_str(),
        Endpoint::RegistrationCertificates,
        Some(query.rp.as_str()),
    ) {
        Ok(request) => request,
        Err(error) => return server_error(error).into_response(),
    };
    cached_or_fetch(&state, request, false)
        .await
        .into_response()
}

async fn cache_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, Response> {
    if let Some(response) = require_admin(&state, &headers) {
        return Err(response);
    }
    let rows = cache_rows(&state).map_err(server_error)?;
    Ok(Json(json!({
        "kind": "augenmass-cache-status",
        "upstream": state.upstream,
        "ttlSecs": state.ttl.as_secs(),
        "entries": rows,
    })))
}

async fn cache_refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<RefreshQuery>,
) -> Response {
    if let Some(response) = require_admin(&state, &headers) {
        return response;
    }
    let endpoint = match parse_route(&query.route) {
        Ok(endpoint) => endpoint,
        Err(error) => return bad_request(error).into_response(),
    };
    let request = match request_for(state.upstream.as_str(), endpoint, query.rp.as_deref()) {
        Ok(request) => request,
        Err(error) => return bad_request(error).into_response(),
    };
    cached_or_fetch(&state, request, true).await.into_response()
}

async fn cached_or_fetch(state: &AppState, request: CacheRequest, force: bool) -> Response {
    let cached = match load_cached(state, &request.key) {
        Ok(cached) => cached,
        Err(error) => return server_error(error).into_response(),
    };

    if let Some(hit) = cached.as_ref() {
        if !force && is_fresh(hit, state.ttl) {
            return response_from_cache(hit, CacheDisposition::Hit);
        }
    }

    match fetch_and_store(state, &request).await {
        Ok(fetched) => {
            let disposition = if cached.is_some() {
                CacheDisposition::Refreshed
            } else {
                CacheDisposition::Miss
            };
            response_from_cache(&fetched, disposition)
        }
        Err(error) => {
            if let Some(stale) = cached {
                response_from_cache(&stale, CacheDisposition::Stale)
            } else {
                (
                    StatusCode::BAD_GATEWAY,
                    format!(
                        "upstream fetch failed for {}: {error}",
                        request.upstream_url
                    ),
                )
                    .into_response()
            }
        }
    }
}

async fn fetch_and_store(state: &AppState, request: &CacheRequest) -> Result<CachedResponse> {
    let response = state
        .client
        .get(&request.upstream_url)
        .send()
        .await
        .with_context(|| format!("GET {}", request.upstream_url))?;
    let status = response.status();
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/json")
        .to_string();
    let body = response
        .bytes()
        .await
        .with_context(|| format!("read GET {} response", request.upstream_url))?
        .to_vec();
    if body.len() > MAX_CACHE_BODY_BYTES {
        anyhow::bail!(
            "GET {} returned {} bytes, above the cache body cap of {} bytes",
            request.upstream_url,
            body.len(),
            MAX_CACHE_BODY_BYTES
        );
    }

    if !status.is_success() {
        anyhow::bail!(
            "GET {} returned {}: {}",
            request.upstream_url,
            status,
            String::from_utf8_lossy(&body)
        );
    }

    let fetched_at = Utc::now();
    let cached = CachedResponse {
        key: request.key.clone(),
        upstream_url: request.upstream_url.clone(),
        status: status.as_u16(),
        content_type,
        sha256: sha256_hex(&body),
        body,
        fetched_at,
    };
    store_cached(state, &cached)?;
    Ok(cached)
}

fn init_db(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        create table if not exists cached_responses (
            key text primary key,
            upstream_url text not null,
            status integer not null,
            content_type text not null,
            body blob not null,
            fetched_at text not null,
            sha256 text not null
        );
        "#,
    )
    .context("initialize cache schema")
}

fn load_cached(state: &AppState, key: &str) -> Result<Option<CachedResponse>> {
    let db = state.db.lock().expect("cache db mutex poisoned");
    let mut stmt = db
        .prepare(
            "select key, upstream_url, status, content_type, body, fetched_at, sha256 \
             from cached_responses where key = ?1",
        )
        .context("prepare cache lookup")?;
    let mut rows = stmt.query([key]).context("query cached response")?;
    let Some(row) = rows.next().context("read cached response row")? else {
        return Ok(None);
    };
    Ok(Some(CachedResponse {
        key: row.get(0)?,
        upstream_url: row.get(1)?,
        status: row.get::<_, i64>(2)? as u16,
        content_type: row.get(3)?,
        body: row.get(4)?,
        fetched_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(5)?)
            .context("parse cached fetched_at")?
            .with_timezone(&Utc),
        sha256: row.get(6)?,
    }))
}

fn store_cached(state: &AppState, cached: &CachedResponse) -> Result<()> {
    let db = state.db.lock().expect("cache db mutex poisoned");
    db.execute(
        "insert into cached_responses \
         (key, upstream_url, status, content_type, body, fetched_at, sha256) \
         values (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
         on conflict(key) do update set \
         upstream_url = excluded.upstream_url, \
         status = excluded.status, \
         content_type = excluded.content_type, \
         body = excluded.body, \
         fetched_at = excluded.fetched_at, \
         sha256 = excluded.sha256",
        params![
            &cached.key,
            &cached.upstream_url,
            cached.status,
            &cached.content_type,
            &cached.body,
            cached.fetched_at.to_rfc3339(),
            &cached.sha256
        ],
    )
    .context("store cached response")?;
    Ok(())
}

fn cache_rows(state: &AppState) -> Result<Vec<CacheRow>> {
    let db = state.db.lock().expect("cache db mutex poisoned");
    let mut stmt = db
        .prepare(
            "select key, upstream_url, status, content_type, length(body), fetched_at, sha256 \
             from cached_responses order by fetched_at desc, key asc",
        )
        .context("prepare cache status")?;
    let rows = stmt
        .query_map([], |row| {
            Ok(CacheRow {
                key: row.get(0)?,
                upstream_url: row.get(1)?,
                status: row.get::<_, i64>(2)? as u16,
                content_type: row.get(3)?,
                bytes: row.get::<_, i64>(4)? as usize,
                fetched_at: row.get(5)?,
                sha256: row.get(6)?,
            })
        })
        .context("query cache status")?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.context("read cache status row")?);
    }
    Ok(out)
}

fn request_for(upstream: &str, endpoint: Endpoint, rp: Option<&str>) -> Result<CacheRequest> {
    let relative = match endpoint {
        Endpoint::SchemaMetadata => "schema-metadata",
        Endpoint::SchemaVocabularies => "schema-metadata/vocabularies",
        Endpoint::RegistrationCertificates => "registration-certificates",
    };
    let mut url = reqwest::Url::parse(&format!("{}/{}", trim_base(upstream), relative))
        .with_context(|| format!("invalid upstream base URL {upstream}"))?;
    let key = match endpoint {
        Endpoint::RegistrationCertificates => {
            let rp = rp.context("rp is required for registration-certificates cache refresh")?;
            validate_rp(rp)?;
            url.query_pairs_mut().append_pair("rp", rp);
            format!("registration-certificates?rp={rp}")
        }
        Endpoint::SchemaMetadata => "schema-metadata".to_string(),
        Endpoint::SchemaVocabularies => "schema-metadata/vocabularies".to_string(),
    };
    Ok(CacheRequest {
        key,
        upstream_url: url.to_string(),
    })
}

fn parse_route(route: &str) -> Result<Endpoint> {
    match route {
        "schema-metadata" => Ok(Endpoint::SchemaMetadata),
        "schema-metadata/vocabularies" | "vocabularies" => Ok(Endpoint::SchemaVocabularies),
        "registration-certificates" => Ok(Endpoint::RegistrationCertificates),
        other => anyhow::bail!(
            "unsupported cache route {other}; expected schema-metadata, schema-metadata/vocabularies, or registration-certificates"
        ),
    }
}

fn validate_rp(rp: &str) -> Result<()> {
    if rp.is_empty() {
        anyhow::bail!("rp must not be empty");
    }
    if rp.len() > MAX_RP_LEN {
        anyhow::bail!("rp is too long: {} bytes, maximum {MAX_RP_LEN}", rp.len());
    }
    if !rp
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        anyhow::bail!("rp contains unsupported characters");
    }
    Ok(())
}

fn is_fresh(cached: &CachedResponse, ttl: Duration) -> bool {
    let age = Utc::now()
        .signed_duration_since(cached.fetched_at)
        .to_std()
        .unwrap_or_default();
    age <= ttl
}

fn response_from_cache(cached: &CachedResponse, disposition: CacheDisposition) -> Response {
    let status = StatusCode::from_u16(cached.status).unwrap_or(StatusCode::OK);
    let mut response = Response::builder()
        .status(status)
        .header(CONTENT_TYPE, cached.content_type.as_str())
        .body(Body::from(cached.body.clone()))
        .unwrap_or_else(|_| Response::new(Body::from(cached.body.clone())));

    let headers = response.headers_mut();
    insert_header(headers, "x-augenmass-cache", disposition.as_str());
    insert_header(headers, "x-augenmass-cache-key", &cached.key);
    insert_header(
        headers,
        "x-augenmass-cache-fetched-at",
        &cached.fetched_at.to_rfc3339(),
    );
    insert_header(headers, "x-augenmass-cache-sha256", &cached.sha256);
    insert_header(headers, "x-augenmass-cache-upstream", &cached.upstream_url);
    response
}

fn insert_header(headers: &mut axum::http::HeaderMap, name: &'static str, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

fn bad_request(error: anyhow::Error) -> Response {
    (StatusCode::BAD_REQUEST, error.to_string()).into_response()
}

fn server_error(error: anyhow::Error) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
}

fn require_admin(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    let expected = state.admin_token.as_deref()?;
    if token_matches(headers, expected) {
        None
    } else {
        Some(
            (
                StatusCode::UNAUTHORIZED,
                "cache admin token required; send Authorization: Bearer <token>",
            )
                .into_response(),
        )
    }
}

fn token_matches(headers: &HeaderMap, expected: &str) -> bool {
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim);
    if bearer == Some(expected) {
        return true;
    }

    headers
        .get("x-augenmass-cache-admin")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        == Some(expected)
}

fn normalize_token(token: Option<String>) -> Option<String> {
    token
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty())
}

fn resolve_bind_addr(host: &str, port: u16) -> Result<SocketAddr> {
    (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolve bind host {host}:{port}"))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("bind host {host}:{port} did not resolve"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_canonical_registration_request() {
        let request = request_for(
            "https://sandbox.eudi-wallet.org/api/",
            Endpoint::RegistrationCertificates,
            Some("rp-1"),
        )
        .expect("request");
        assert_eq!(request.key, "registration-certificates?rp=rp-1");
        assert_eq!(
            request.upstream_url,
            "https://sandbox.eudi-wallet.org/api/registration-certificates?rp=rp-1"
        );
    }

    #[test]
    fn rejects_registration_refresh_without_rp() {
        assert!(request_for(
            "https://sandbox.eudi-wallet.org/api",
            Endpoint::RegistrationCertificates,
            None,
        )
        .is_err());
    }

    #[test]
    fn rejects_empty_or_oversized_rp() {
        assert!(validate_rp("").is_err());
        assert!(validate_rp(&"a".repeat(MAX_RP_LEN + 1)).is_err());
        assert!(validate_rp("2af138a8-59ea-4a84-aea3-666cafdb1369").is_ok());
    }
}
