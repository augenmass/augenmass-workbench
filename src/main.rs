// See `src/lib.rs`: every write to standard output and standard error goes
// through `augenmass_workbench::output`.
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]

use anyhow::Result;
use augenmass_workbench::cli;

#[tokio::main]
async fn main() -> Result<()> {
    install_rustls_crypto_provider();
    dotenvy::dotenv().ok();
    cli::run().await
}

fn install_rustls_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
