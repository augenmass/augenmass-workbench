//! Read-through cache for public sandbox reads.
//!
//! This is intentionally distinct from the mutable local clone. The clone is a
//! demo registrar for writes; this cache mirrors successful sandbox GET
//! responses with provenance so demos and audits can keep running when the
//! sandbox drifts or is temporarily unreachable.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
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
pub const DEFAULT_CACHE_MAX_ENTRIES: usize = 512;

#[derive(Debug, Clone)]
pub struct ServeConfig {
    pub db_path: String,
    pub host: String,
    pub port: u16,
    pub upstream: String,
    pub ttl_secs: u64,
    pub timeout_secs: u64,
    pub max_entries: usize,
    pub admin_token: Option<String>,
    pub allowed_rps: Vec<String>,
    pub allow_any_rp: bool,
    pub unsafe_upstream: bool,
}

#[derive(Clone)]
pub struct AppState {
    db: Arc<Mutex<Connection>>,
    client: Client,
    upstream: String,
    ttl: Duration,
    max_entries: usize,
    admin_token: Option<String>,
    allowed_rps: BTreeSet<String>,
    allow_any_rp: bool,
    inflight: Arc<Mutex<BTreeSet<String>>>,
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
    endpoint: Endpoint,
    rp: Option<String>,
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
    let addr = resolve_bind_addr(&config.host, config.port)?;
    let admin_token = normalize_token(config.admin_token.clone());
    require_admin_token_for_public_bind(addr, admin_token.as_deref())?;
    require_safe_upstream_for_public_bind(addr, &config.upstream, config.unsafe_upstream)?;
    validate_max_entries(config.max_entries)?;
    let allowed_rps = normalize_allowed_rps(config.allowed_rps)?;
    require_rp_allowlist_for_public_bind(addr, &allowed_rps, config.allow_any_rp)?;

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
        max_entries: config.max_entries,
        admin_token: admin_token.clone(),
        allowed_rps: allowed_rps.clone(),
        allow_any_rp: config.allow_any_rp,
        inflight: Arc::new(Mutex::new(BTreeSet::new())),
    };

    let app = router(state);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    println!("cached-sandbox target listening on http://{addr}/api");
    println!("upstream: {}", trim_base(&config.upstream));
    println!("ttl: {}s", config.ttl_secs);
    println!("upstream timeout: {}s", config.timeout_secs);
    println!("max entries: {}", config.max_entries);
    println!(
        "registration RP read-through: {}",
        if allowed_rps.is_empty() && config.allow_any_rp {
            "any syntactically valid RP".to_string()
        } else if allowed_rps.is_empty() {
            "none configured".to_string()
        } else {
            allowed_rps.iter().cloned().collect::<Vec<_>>().join(", ")
        }
    );
    println!(
        "admin endpoints: {}",
        if admin_token.is_some() {
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
        Self::new_with_limits(
            db_path,
            upstream,
            ttl_secs,
            timeout_secs,
            admin_token,
            DEFAULT_CACHE_MAX_ENTRIES,
        )
    }

    pub fn new_with_limits(
        db_path: &str,
        upstream: &str,
        ttl_secs: u64,
        timeout_secs: u64,
        admin_token: Option<String>,
        max_entries: usize,
    ) -> Result<Self> {
        Self::new_with_limits_and_allowed_rps(
            db_path,
            upstream,
            ttl_secs,
            timeout_secs,
            admin_token,
            max_entries,
            Vec::new(),
        )
    }

    pub fn new_with_limits_and_allowed_rps(
        db_path: &str,
        upstream: &str,
        ttl_secs: u64,
        timeout_secs: u64,
        admin_token: Option<String>,
        max_entries: usize,
        allowed_rps: Vec<String>,
    ) -> Result<Self> {
        let allow_any_rp = allowed_rps.is_empty();
        validate_max_entries(max_entries)?;
        let allowed_rps = normalize_allowed_rps(allowed_rps)?;
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
            max_entries,
            admin_token: normalize_token(admin_token),
            allowed_rps,
            allow_any_rp,
            inflight: Arc::new(Mutex::new(BTreeSet::new())),
        })
    }
}

async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "service": "augenmass cache",
        "ttlSecs": state.ttl.as_secs(),
        "maxEntries": state.max_entries,
        "allowedRpCount": state.allowed_rps.len(),
        "allowAnyRp": state.allow_any_rp,
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
        Err(error) => return bad_request(error).into_response(),
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
        "maxEntries": state.max_entries,
        "allowedRps": state.allowed_rps.iter().collect::<Vec<_>>(),
        "allowAnyRp": state.allow_any_rp,
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
    if let Err(error) = enforce_allowed_rp(state, &request) {
        return forbidden(error).into_response();
    }

    let cached = match load_cached(state, &request.key) {
        Ok(cached) => cached,
        Err(error) => return server_error(error).into_response(),
    };

    if let Some(hit) = cached.as_ref() {
        if !force && is_fresh(hit, state.ttl) {
            return response_from_cache(hit, CacheDisposition::Hit);
        }
    }

    let Some(_guard) = InflightGuard::try_start(state, &request.key) else {
        if let Some(stale) = cached {
            return response_from_cache(&stale, CacheDisposition::Stale);
        }
        return match wait_for_inflight_cache(state, &request.key).await {
            Ok(Some(fetched)) => response_from_cache(&fetched, CacheDisposition::Hit),
            Ok(None) => (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("cache refresh already in flight for {}", request.key),
            )
                .into_response(),
            Err(error) => server_error(error).into_response(),
        };
    };

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
                eprintln!(
                    "cache upstream fetch failed for {} ({}): {error:#}",
                    request.key, request.upstream_url
                );
                (
                    StatusCode::BAD_GATEWAY,
                    format!("upstream fetch failed for {}", request.key),
                )
                    .into_response()
            }
        }
    }
}

struct InflightGuard {
    inflight: Arc<Mutex<BTreeSet<String>>>,
    key: String,
}

impl InflightGuard {
    fn try_start(state: &AppState, key: &str) -> Option<Self> {
        let mut inflight = state
            .inflight
            .lock()
            .expect("cache inflight mutex poisoned");
        if inflight.contains(key) {
            return None;
        }
        inflight.insert(key.to_string());
        Some(Self {
            inflight: Arc::clone(&state.inflight),
            key: key.to_string(),
        })
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        let mut inflight = self.inflight.lock().expect("cache inflight mutex poisoned");
        inflight.remove(&self.key);
    }
}

async fn wait_for_inflight_cache(state: &AppState, key: &str) -> Result<Option<CachedResponse>> {
    for _ in 0..80 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if !is_inflight(state, key) {
            return load_cached(state, key);
        }
    }
    Ok(None)
}

fn is_inflight(state: &AppState, key: &str) -> bool {
    state
        .inflight
        .lock()
        .expect("cache inflight mutex poisoned")
        .contains(key)
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
    let body = read_response_body_with_cap(response, &request.upstream_url).await?;

    if !status.is_success() {
        anyhow::bail!(
            "GET {} returned {}: {}",
            request.upstream_url,
            status,
            String::from_utf8_lossy(&body)
        );
    }
    validate_upstream_body(request.endpoint, &body)
        .with_context(|| format!("validate JSON body from {}", request.upstream_url))?;

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

async fn read_response_body_with_cap(
    mut response: reqwest::Response,
    upstream_url: &str,
) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("read GET {upstream_url} response"))?
    {
        let next_len = body
            .len()
            .checked_add(chunk.len())
            .context("cache response body length overflow")?;
        if next_len > MAX_CACHE_BODY_BYTES {
            anyhow::bail!(
                "GET {upstream_url} returned more than {MAX_CACHE_BODY_BYTES} bytes, above the cache body cap"
            );
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn validate_upstream_body(endpoint: Endpoint, body: &[u8]) -> Result<()> {
    let value: serde_json::Value = serde_json::from_slice(body).context("parse JSON")?;
    if matches!(endpoint, Endpoint::RegistrationCertificates) {
        let registrations = value
            .as_array()
            .context("registration-certificates response must be a JSON array")?;
        for (index, item) in registrations.iter().enumerate() {
            let jwt = item
                .get("jwt")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|jwt| !jwt.is_empty());
            if jwt.is_none() {
                anyhow::bail!("registration-certificates response item {index} has no jwt");
            }
        }
    }
    Ok(())
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
    evict_oldest_entries(&db, state.max_entries)?;
    Ok(())
}

fn evict_oldest_entries(db: &Connection, max_entries: usize) -> Result<()> {
    validate_max_entries(max_entries)?;
    let count: i64 = db
        .query_row("select count(*) from cached_responses", [], |row| {
            row.get(0)
        })
        .context("count cached responses")?;
    let overflow = count.saturating_sub(max_entries as i64);
    if overflow > 0 {
        db.execute(
            "delete from cached_responses \
             where key in ( \
               select key from cached_responses \
               order by fetched_at asc, key asc \
               limit ?1 \
             )",
            params![overflow],
        )
        .context("evict oldest cached responses")?;
    }
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
        endpoint,
        rp: rp.map(ToString::to_string),
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

fn normalize_allowed_rps(values: Vec<String>) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for value in values {
        for rp in value.split(',').map(str::trim).filter(|rp| !rp.is_empty()) {
            validate_rp(rp).with_context(|| format!("invalid allowed RP {rp}"))?;
            out.insert(rp.to_string());
        }
    }
    Ok(out)
}

fn enforce_allowed_rp(state: &AppState, request: &CacheRequest) -> Result<()> {
    if !matches!(request.endpoint, Endpoint::RegistrationCertificates) || state.allow_any_rp {
        return Ok(());
    }
    let rp = request
        .rp
        .as_deref()
        .context("rp is required for registration-certificates cache access")?;
    if !state.allowed_rps.contains(rp) {
        anyhow::bail!(
            "rp {rp} is not enabled on this cache; ask the operator to prewarm and allow it"
        );
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

fn forbidden(error: anyhow::Error) -> Response {
    (StatusCode::FORBIDDEN, error.to_string()).into_response()
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

fn require_admin_token_for_public_bind(addr: SocketAddr, admin_token: Option<&str>) -> Result<()> {
    if !addr.ip().is_loopback() && admin_token.is_none() {
        anyhow::bail!(
            "AUGENMASS_CACHE_ADMIN_TOKEN is required when cache serve binds to non-loopback {addr}; set --admin-token or AUGENMASS_CACHE_ADMIN_TOKEN, or bind --host 127.0.0.1 for local-only use"
        );
    }
    Ok(())
}

fn require_rp_allowlist_for_public_bind(
    addr: SocketAddr,
    allowed_rps: &BTreeSet<String>,
    allow_any_rp: bool,
) -> Result<()> {
    if !addr.ip().is_loopback() && allowed_rps.is_empty() && !allow_any_rp {
        anyhow::bail!(
            "AUGENMASS_CACHE_ALLOWED_RPS must include at least one RP when cache serve binds to non-loopback {addr}; set --allowed-rp or AUGENMASS_CACHE_ALLOWED_RPS, or explicitly set --allow-any-rp"
        );
    }
    Ok(())
}

fn require_safe_upstream_for_public_bind(
    addr: SocketAddr,
    upstream: &str,
    allow_unsafe: bool,
) -> Result<()> {
    if addr.ip().is_loopback() || allow_unsafe {
        return Ok(());
    }
    let url = reqwest::Url::parse(&trim_base(upstream))
        .with_context(|| format!("invalid cache upstream URL {upstream}"))?;
    if url.scheme() != "https" {
        anyhow::bail!(
            "AUGENMASS_CACHE_UPSTREAM must use https for non-loopback cache binds; set --unsafe-upstream only for isolated development"
        );
    }
    if !url.username().is_empty() || url.password().is_some() {
        anyhow::bail!("AUGENMASS_CACHE_UPSTREAM must not contain URL userinfo");
    }
    if url.query().is_some() || url.fragment().is_some() {
        anyhow::bail!("AUGENMASS_CACHE_UPSTREAM must not contain a query string or fragment");
    }
    if let Some(host) = url.host_str() {
        if host.eq_ignore_ascii_case("localhost") {
            anyhow::bail!("AUGENMASS_CACHE_UPSTREAM must not point at localhost on public binds");
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            if is_non_public_ip(ip) {
                anyhow::bail!(
                    "AUGENMASS_CACHE_UPSTREAM must not point at loopback, private, link-local, documentation, multicast, or metadata IP ranges on public binds"
                );
            }
        }
    }
    Ok(())
}

fn is_non_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_non_public_ipv4(ip),
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_non_public_ipv4(mapped);
            }
            let segments = ip.segments();
            ip.is_loopback()
                || ip.is_unspecified()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                || segments[0] == 0xff00
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}

fn is_non_public_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    match octets {
        [0, _, _, _]
        | [10, _, _, _]
        | [127, _, _, _]
        | [169, 254, _, _]
        | [192, 168, _, _]
        | [192, 0, 0, _]
        | [192, 0, 2, _]
        | [198, 18 | 19, _, _]
        | [198, 51, 100, _]
        | [203, 0, 113, _]
        | [255, 255, 255, 255] => true,
        [100, second, _, _] if (64..=127).contains(&second) => true,
        [172, second, _, _] if (16..=31).contains(&second) => true,
        [first, _, _, _] if first >= 224 => true,
        _ => false,
    }
}

fn validate_max_entries(max_entries: usize) -> Result<()> {
    if max_entries == 0 {
        anyhow::bail!("cache max entries must be at least 1");
    }
    Ok(())
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

    #[test]
    fn normalizes_allowed_rps_from_repeated_or_comma_values() {
        let allowed = normalize_allowed_rps(vec![
            "rp-2,rp-1".to_string(),
            " rp-1 ".to_string(),
            "".to_string(),
        ])
        .expect("allowed rps");
        assert_eq!(
            allowed.into_iter().collect::<Vec<_>>(),
            vec!["rp-1".to_string(), "rp-2".to_string()]
        );
        assert!(normalize_allowed_rps(vec!["bad rp".to_string()]).is_err());
    }

    #[test]
    fn validates_upstream_json_shape_before_cache_store() {
        assert!(validate_upstream_body(Endpoint::SchemaMetadata, br#"{"ok":true}"#).is_ok());
        assert!(validate_upstream_body(Endpoint::SchemaVocabularies, br#"[{"id":"v"}]"#).is_ok());
        assert!(validate_upstream_body(
            Endpoint::RegistrationCertificates,
            br#"[{"jwt":"a.b.c"}]"#
        )
        .is_ok());
        assert!(validate_upstream_body(Endpoint::SchemaMetadata, b"<html>").is_err());
        assert!(
            validate_upstream_body(Endpoint::RegistrationCertificates, br#"{"id":"r"}"#).is_err()
        );
        assert!(
            validate_upstream_body(Endpoint::RegistrationCertificates, br#"[{"id":"r"}]"#).is_err()
        );
    }

    #[test]
    fn public_bind_requires_admin_token() {
        let loopback: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        let unspecified_v4: SocketAddr = "0.0.0.0:8081".parse().unwrap();
        let unspecified_v6: SocketAddr = "[::]:8081".parse().unwrap();

        assert!(require_admin_token_for_public_bind(loopback, None).is_ok());
        assert!(require_admin_token_for_public_bind(unspecified_v4, None).is_err());
        assert!(require_admin_token_for_public_bind(unspecified_v6, None).is_err());
        assert!(
            require_admin_token_for_public_bind(unspecified_v4, Some("local-smoke-token")).is_ok()
        );
    }

    #[test]
    fn public_bind_requires_safe_upstream_unless_explicitly_unsafe() {
        let public: SocketAddr = "0.0.0.0:8081".parse().unwrap();
        let loopback: SocketAddr = "127.0.0.1:8081".parse().unwrap();

        assert!(require_safe_upstream_for_public_bind(
            public,
            "https://sandbox.eudi-wallet.org/api",
            false
        )
        .is_ok());
        assert!(
            require_safe_upstream_for_public_bind(public, "http://127.0.0.1:8080/api", false)
                .is_err()
        );
        assert!(require_safe_upstream_for_public_bind(
            public,
            "https://169.254.169.254/api",
            false
        )
        .is_err());
        assert!(require_safe_upstream_for_public_bind(
            public,
            "https://user@example.test/api",
            false
        )
        .is_err());
        assert!(
            require_safe_upstream_for_public_bind(public, "http://127.0.0.1:8080/api", true)
                .is_ok()
        );
        assert!(require_safe_upstream_for_public_bind(
            loopback,
            "http://127.0.0.1:8080/api",
            false
        )
        .is_ok());
    }

    #[test]
    fn public_bind_requires_explicit_rp_allowlist_or_opt_in() {
        let public: SocketAddr = "0.0.0.0:8081".parse().unwrap();
        let loopback: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        let empty = BTreeSet::new();
        let allowed = BTreeSet::from(["rp-1".to_string()]);

        assert!(require_rp_allowlist_for_public_bind(public, &empty, false).is_err());
        assert!(require_rp_allowlist_for_public_bind(public, &empty, true).is_ok());
        assert!(require_rp_allowlist_for_public_bind(public, &allowed, false).is_ok());
        assert!(require_rp_allowlist_for_public_bind(loopback, &empty, false).is_ok());
    }
}
