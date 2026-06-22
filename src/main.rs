use anyhow::Result;
use augenmass_workbench::cli;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    cli::run().await
}
