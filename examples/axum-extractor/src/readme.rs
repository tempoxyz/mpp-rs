//! The README's Tempo server quick start, built by CI so it keeps compiling.
//! `tests/readme.rs` checks that README.md shows this file's code verbatim.
//!
//! Run it with `MPP_SECRET_KEY=$(openssl rand -base64 32) cargo run --bin axum-readme`.

use std::sync::Arc;

use axum::{routing::get, Router};
use mpp::server::axum::{ChargeChallenger, ChargeConfig, MppCharge, WithReceipt};
use mpp::server::{tempo, Mpp, TempoConfig};

struct OneCent;

impl ChargeConfig for OneCent {
    fn amount() -> &'static str {
        "0.01"
    }
}

// WithReceipt adds the Payment-Receipt header to the paid response.
async fn paid(charge: MppCharge<OneCent>) -> WithReceipt<String> {
    WithReceipt {
        body: format!("paid: {}", charge.receipt.reference),
        receipt: charge.receipt,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Reads the challenge-binding secret from MPP_SECRET_KEY (at least 32 bytes).
    let mpp = Mpp::create(
        tempo(TempoConfig {
            recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        })
        .rpc_url("https://rpc.moderato.tempo.xyz"),
    )?;

    let app = Router::new()
        .route("/paid", get(paid))
        .with_state(Arc::new(mpp) as Arc<dyn ChargeChallenger>);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
