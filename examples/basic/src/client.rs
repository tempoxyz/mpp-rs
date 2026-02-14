//! # Fortune Teller CLI Client
//!
//! A CLI client that fetches a fortune from the payment-gated Fortune Teller API
//! with automatic payment handling.
//!
//! ## Running
//!
//! ```bash
//! # First start the server:
//! cargo run --bin basic-server
//!
//! # Then in another terminal:
//! cargo run --bin basic-client
//!
//! # Optional: provide your own private key
//! export PRIVATE_KEY=0x...
//! cargo run --bin basic-client
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

    let rpc_url = std::env::var("RPC_URL")
        .unwrap_or_else(|_| "https://rpc.moderato.tempo.xyz".to_string());

    // Fund the client account via testnet faucet.
    println!("Funding account via faucet...");
    let rpc_provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect_http(rpc_url.parse().unwrap());
    let _: Vec<B256> = rpc_provider
        .raw_request("tempo_fundAddress".into(), (signer.address(),))
        .await
        .expect("faucet funding failed");
    // Wait briefly for faucet transactions to confirm.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let provider =
        TempoProvider::new(signer, &rpc_url).expect("failed to create payment provider");

    let base_url = std::env::var("BASE_URL")
        .unwrap_or_else(|_| "http://localhost:3000".to_string());

    let client = Client::new();

    let url = format!("{base_url}/api/fortune");
    println!("Fetching fortune from {url} ...");

    let resp = client
        .get(&url)
        .send_with_payment(&provider)
        .await
        .expect("request failed");

    println!("Status: {}", resp.status());

    if let Some(receipt_hdr) = resp.headers().get("payment-receipt") {
        if let Ok(receipt_str) = receipt_hdr.to_str() {
            if let Ok(receipt) = parse_receipt(receipt_str) {
                println!("Payment tx: https://explore.moderato.tempo.xyz/tx/{}", receipt.reference);
            }
        }
    }

    let body: serde_json::Value = resp.json().await.expect("failed to parse response");

    if let Some(fortune) = body.get("fortune").and_then(|v| v.as_str()) {
        println!("\nFortune: {fortune}");
    } else {
        println!("\nResponse: {body}");
    }
}
