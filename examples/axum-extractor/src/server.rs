//! # Axum Extractor Example — Server
//!
//! Demonstrates payment-gated endpoints using mpp's axum extractors.
//!
//! - `/api/health` — Free health check
//! - `/api/fortune` — $0.01 (`MppCharge<OneCent>`)
//! - `/api/premium` — $1.00 (`MppCharge<OneDollar>`)
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
use mpp::server::axum::{ChargeChallenger, ChargeConfig, MppCharge, WithReceipt};
use mpp::server::{tempo, Mpp, TempoConfig};
use mpp::PrivateKeySigner;
use rand::seq::IndexedRandom;
use std::sync::Arc;
use tempo_alloy::TempoNetwork;

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

struct OneCent;

impl ChargeConfig for OneCent {
    fn amount() -> &'static str {
        "0.01"
    }
}

struct OneDollar;

impl ChargeConfig for OneDollar {
    fn amount() -> &'static str {
        "1.00"
    }
    fn description() -> Option<&'static str> {
        Some("Premium fortune reading")
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
            recipient: &recipient,
        })
        .rpc_url(&rpc_url)
        .fee_payer(true)
        .fee_payer_signer(signer),
    )
    .expect("failed to create payment handler");

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
    println!("  GET /api/fortune  — $0.01");
    println!("  GET /api/premium  — $1.00");
    axum::serve(listener, app).await.expect("server error");
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn fortune(charge: MppCharge<OneCent>) -> WithReceipt<Json<serde_json::Value>> {
    let fortune = FORTUNES
        .choose(&mut rand::rng())
        .unwrap_or(&"No fortune today.");

    WithReceipt {
        receipt: charge.receipt,
        body: Json(serde_json::json!({ "fortune": fortune })),
    }
}

async fn premium_fortune(
    charge: MppCharge<OneDollar>,
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
