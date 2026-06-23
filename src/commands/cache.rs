//! `cache`: serve a read-through mirror for sandbox GET routes.

use anyhow::Result;

use crate::cache_server::{self, ServeConfig};

pub struct ServeArgs {
    pub db: String,
    pub host: String,
    pub port: u16,
    pub upstream: String,
    pub ttl_secs: u64,
    pub timeout_secs: u64,
    pub admin_token: Option<String>,
}

pub async fn serve(args: ServeArgs) -> Result<()> {
    cache_server::serve(ServeConfig {
        db_path: args.db,
        host: args.host,
        port: args.port,
        upstream: args.upstream,
        ttl_secs: args.ttl_secs,
        timeout_secs: args.timeout_secs,
        admin_token: args.admin_token,
    })
    .await
}
