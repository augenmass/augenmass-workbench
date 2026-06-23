//! `cache`: serve a loopback read-through mirror for sandbox GET routes.

use anyhow::Result;

use crate::cache_server;

pub async fn serve(db: &str, port: u16, upstream: &str, ttl_secs: u64) -> Result<()> {
    cache_server::serve(db, port, upstream, ttl_secs).await
}
