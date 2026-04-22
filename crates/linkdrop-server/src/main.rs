use anyhow::Result;
use clap::Parser;
use linkdrop_server::{ServerArgs, run};

#[tokio::main]
async fn main() -> Result<()> {
    run(ServerArgs::parse()).await
}
