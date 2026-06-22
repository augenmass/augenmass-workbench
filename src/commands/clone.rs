//! `clone serve`: run the registrar-compatible local demo store.

use anyhow::Result;

use crate::clone_server;

pub async fn serve(db: &str, port: u16) -> Result<()> {
    clone_server::serve(db, port).await
}
