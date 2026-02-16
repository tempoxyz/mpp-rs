//! # Axum Extractor Example — Server
//!
//! Demonstrates payment-gated endpoints using mpp's axum extractors.
//!
//! - `/api/health` — Free health check
//! - `/api/fortune` — $0.01 (default `MppCharge`)
//! - `/api/premium` — $1.00 (custom `MppChargeFor<OneDollar>`)
//!
//! ## Running
//!
//! ```bash
//! cargo run --bin axum-server
//! ```
//!
//! The server listens on `http://localhost:3000`.

use axum::{routing::get, Json, Router};
use alloy::primitives::B256;
use alloy::providers::{Provider, ProviderBuilder};
use mpp::server::axum::{ChargeAmount, ChargeChallenger, MppCharge, MppChargeFor, WithReceipt};
use mpp::server::{tempo, Mpp, TempoConfig};
use mpp::PrivateKeySigner;
use rand::seq::IndexedRandom;
use std::sync::Arc;
use tempo_alloy::TempoNetwork;

const PATH_USD: &str = "0x20c0000000000000000000000000000000000000";

const FORTUNES: &[&str] = &[
    "A beautiful, smart, and loving person will come into your life.",
    "A dubious friend may be an enemy in camouflage.",
    "A faithful friend is a strong defense.",
    "A fresh start will put you on your way.",
    "A golden egg of opportunity falls into your lap this month.",
    "A good time to finish up old tasks.",
    "A hunch is creativity trying to tell you something.",
    "A lifetime of happiness lies ahead of you.",
    "A light heart carries you through all the hard times.",
    "A new perspective will come with the new year.",
];

const PREMIUM_FORTUNES: &[&str] = &[
    "The cosmos has aligned in your favor — expect an extraordinary opportunity this week.",
    "A partnership forged in trust will yield ten-fold returns.",
    "Your code will compile on the first try. Today is your day.",
    "An unexpected windfall arrives before the next full moon.",
    "The answer you seek is already within you. Trust your instincts.",
];

// -- Per-route pricing via ChargeAmount trait --

struct OneDollar;

impl ChargeAmount for OneDollar {
    fn amount() -> &'static str {
        "1.00"
    }
}

#[tokio::main]
async fn main() {
    let signer = PrivateKeySigner::random();
    let recipient = format!("{}", signer.address());
    println!("Server recipient: {recipient}");

    let rpc_url = std::env::var("RPC_URL")
        .unwrap_or_else(|_| "https://rpc.moderato.tempo.xyz".to_string());

    // Fund the server account via testnet faucet.
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect_http(rpc_url.parse().unwrap());
    let _: Vec<B256> = provider
        .raw_request("tempo_fundAddress".into(), (signer.address(),))
        .await
        .expect("faucet funding failed");
    println!("Server account funded");

    let mpp = Mpp::create(
        tempo(TempoConfig {
            currency: PATH_USD,
            recipient: &recipient,
        })
        .rpc_url(&rpc_url)
        .fee_payer(true)
        .fee_payer_signer(signer),
    )
    .expect("failed to create payment handler");

    // Cast to Arc<dyn ChargeChallenger> for the axum extractors.
    let state: Arc<dyn ChargeChallenger> = Arc::new(mpp);

    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/fortune", get(fortune))
        .route("/api/premium", get(premium_fortune))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("failed to bind");

    println!("Axum Extractor Example listening on http://localhost:3000");
    println!("  GET /api/health   — free");
    println!("  GET /api/fortune  — $0.01 (MppCharge)");
    println!("  GET /api/premium  — $1.00 (MppChargeFor<OneDollar>)");
    axum::serve(listener, app).await.expect("server error");
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

/// $0.01 fortune — uses the default `MppCharge` extractor.
///
/// The extractor handles the full 402 flow automatically:
/// no credential → 402 with challenge, valid credential → receipt.
async fn fortune(charge: MppCharge) -> WithReceipt<Json<serde_json::Value>> {
    let fortune = FORTUNES
        .choose(&mut rand::rng())
        .unwrap_or(&"No fortune today.");

    WithReceipt {
        receipt: charge.receipt,
        body: Json(serde_json::json!({ "fortune": fortune })),
    }
}

/// $1.00 premium fortune — uses `MppChargeFor<OneDollar>`.
async fn premium_fortune(
    charge: MppChargeFor<OneDollar>,
) -> WithReceipt<Json<serde_json::Value>> {
    let fortune = PREMIUM_FORTUNES
        .choose(&mut rand::rng())
        .unwrap_or(&"The stars are silent.");

    WithReceipt {
        receipt: charge.receipt,
        body: Json(serde_json::json!({
            "fortune": fortune,
            "tier": "premium",
        })),
    }
}
