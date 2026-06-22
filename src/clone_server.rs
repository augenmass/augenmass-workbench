//! The local clone: a registrar-compatible demo store. A tiny axum + SQLite
//! server that mirrors the registrar's request/response shape but does not sign,
//! does not enforce auth, and does not issue x5c. It stores payload-only JWTs
//! (`header.payload.fixture`), which is sound because every read path in this
//! toolkit (and the audit site) decodes the registration certificate
//! payload-only, with no client-side crypto.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use base64::prelude::*;
use chrono::Utc;
use rusqlite::{params, Connection};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    db: Arc<Mutex<Connection>>,
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    rp: String,
}

pub async fn serve(db_path: &str, port: u16) -> Result<()> {
    let conn = Connection::open(db_path).with_context(|| format!("open SQLite db {db_path}"))?;
    init_db(&conn)?;
    let state = AppState {
        db: Arc::new(Mutex::new(conn)),
    };

    let app = Router::new()
        .route("/registration-certificates", get(list).post(create))
        .route("/api/registration-certificates", get(list).post(create))
        .with_state(state);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    println!("clone target listening on http://{addr}/api");
    axum::serve(listener, app)
        .await
        .context("serve clone target")
}

fn init_db(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        create table if not exists registrations (
            id text primary key,
            rp_id text not null,
            entity text not null,
            created_at text not null
        );
        create index if not exists registrations_rp_id on registrations(rp_id);
        "#,
    )
    .context("initialize clone schema")
}

async fn create(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
    create_inner(&state, body).map(Json).map_err(bad_request)
}

fn create_inner(state: &AppState, body: Value) -> Result<Value> {
    let rp_id = body
        .get("rpId")
        .and_then(Value::as_str)
        .context("rpId is required")?
        .to_string();
    let id = Uuid::new_v4().to_string();
    let created_at = Utc::now().to_rfc3339();
    let jwt = compact_jwt(&body)?;
    let entity = json!({
        "id": id,
        "jwt": jwt,
        "cwt": "fixture",
        "intendedUse": {
            "purpose": body.get("purpose").cloned().unwrap_or(Value::Null)
        },
        "relyingPartyId": rp_id,
        "createdAt": created_at,
        "revoked": null
    });

    let db = state.db.lock().expect("clone db mutex poisoned");
    db.execute(
        "insert into registrations (id, rp_id, entity, created_at) values (?1, ?2, ?3, ?4)",
        params![id, rp_id, serde_json::to_string(&entity)?, created_at],
    )
    .context("store registration")?;

    Ok(entity)
}

async fn list(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    list_inner(&state, &query.rp).map(Json).map_err(bad_request)
}

fn list_inner(state: &AppState, rp_id: &str) -> Result<Value> {
    let db = state.db.lock().expect("clone db mutex poisoned");
    let mut stmt = db
        .prepare("select entity from registrations where rp_id = ?1 order by created_at asc")
        .context("prepare list query")?;
    let rows = stmt
        .query_map([rp_id], |row| row.get::<_, String>(0))
        .context("query registrations")?;

    let mut entities = Vec::new();
    for row in rows {
        let entity: Value = serde_json::from_str(&row.context("read registration row")?)
            .context("decode stored registration")?;
        entities.push(entity);
    }

    Ok(Value::Array(entities))
}

/// Encode a payload-only JWT: `base64url(header).base64url(payload).fixture`,
/// header `{"typ":"rc-wrp+jwt","alg":"none"}`. Decodes back through
/// `regcert::decode_registration_jwt` exactly like a real cert's payload.
pub fn compact_jwt(payload: &Value) -> Result<String> {
    let header = json!({
        "typ": "rc-wrp+jwt",
        "alg": "none"
    });
    let header = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let payload = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload)?);
    Ok(format!("{header}.{payload}.fixture"))
}

fn bad_request(error: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::{age_check_body, GenerateOptions};

    #[test]
    fn compact_jwt_payload_decodes_with_engine() {
        let body = age_check_body(&GenerateOptions::default());
        let jwt = compact_jwt(&body).expect("compact jwt");
        let scope = augenmass_core::regcert::decode_registration_jwt(&jwt).expect("decode scope");
        assert_eq!(scope.all_claim_keys(), vec!["age_equal_or_over.18"]);
    }
}
