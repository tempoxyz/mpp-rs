//! # Axum Extractor Example — Client
//!
//! Fetches fortunes from the axum-extractor server, demonstrating
//! automatic 402 payment handling at two price points.
//!
//! ## Running
//!
//! ```bash
//! # First start the server:
//! cargo run --bin axum-server
//!
//! # Then in another terminal:
//! cargo run --bin axum-client
//! ```

use alloy::primitives::B256;
use alloy::providers::{Provider, ProviderBuilder};
use mpp::client::{Fetch, TempoProvider};
use mpp::{parse_receipt, PrivateKeySigner};
use reqwest::Client;
use tempo_alloy::TempoNetwork;

#[tokio::main]
async fn main() {
    let signer = match std::env::var("PRIVATE_KEY") {
        Ok(key) => {
            let bytes = hex::decode(key.strip_prefix("0x").unwrap_or(&key))
                .expect("invalid PRIVATE_KEY hex");
            PrivateKeySigner::from_slice(&bytes).expect("invalid private key")
        }
        Err(_) => {
            let signer = PrivateKeySigner::random();
            println!("Generated wallet: {}", signer.address());
            signer
        }
    };

    let rpc_url =
        std::env::var("RPC_URL").unwrap_or_else(|_| "https://rpc.moderato.tempo.xyz".to_string());

    // Fund via testnet faucet.
    println!("Funding account via faucet...");
    let rpc_provider =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(rpc_url.parse().unwrap());
    let _: Vec<B256> = rpc_provider
        .raw_request("tempo_fundAddress".into(), (signer.address(),))
        .await
        .expect("faucet funding failed");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let provider = TempoProvider::new(signer, &rpc_url).expect("failed to create payment provider");

    let base_url =
        std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let client = Client::new();

    // 1. Cheap fortune ($0.01)
    println!("\n--- Fetching $0.01 fortune ---");
    fetch_fortune(&client, &provider, &format!("{base_url}/api/fortune")).await;

    // 2. Premium fortune ($1.00)
    println!("\n--- Fetching $1.00 premium fortune ---");
    fetch_fortune(&client, &provider, &format!("{base_url}/api/premium")).await;
}

async fn fetch_fortune(client: &Client, provider: &TempoProvider, url: &str) {
    println!("GET {url}");

    let resp = client
        .get(url)
        .send_with_payment(provider)
        .await
        .expect("request failed");

    println!("Status: {}", resp.status());

    if let Some(receipt_hdr) = resp.headers().get("payment-receipt") {
        if let Ok(receipt_str) = receipt_hdr.to_str() {
            if let Ok(receipt) = parse_receipt(receipt_str) {
                println!(
                    "Payment tx: https://explore.moderato.tempo.xyz/tx/{}",
                    receipt.reference
                );
            }
        }
    }

    let body: serde_json::Value = resp.json().await.expect("failed to parse response");

    if let Some(fortune) = body.get("fortune").and_then(|v| v.as_str()) {
        println!("Fortune: {fortune}");
    } else {
        println!("Response: {body}");
    }
}
