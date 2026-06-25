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
