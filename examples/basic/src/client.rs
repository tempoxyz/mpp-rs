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
//! # Or target any external server:
//! cargo run --bin basic-client -- https://mpp.dev/api/ping/paid
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

    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut url = "http://localhost:3000/api/fortune".to_string();
    let mut extra_headers = reqwest::header::HeaderMap::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-H" => {
                i += 1;
                if let Some((key, val)) = args.get(i).and_then(|h| h.split_once(':')) {
                    extra_headers.insert(
                        reqwest::header::HeaderName::from_bytes(key.trim().as_bytes())
                            .expect("invalid header name"),
                        val.trim().parse().expect("invalid header value"),
                    );
                }
            }
            _ => url = args[i].clone(),
        }
        i += 1;
    }

    let client = Client::builder()
        .default_headers(extra_headers)
        .build()
        .expect("failed to build client");

    println!("Fetching {url} ...");

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

    let body = resp.text().await.expect("failed to read response body");

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
        if let Some(fortune) = json.get("fortune").and_then(|v| v.as_str()) {
            println!("\nFortune: {fortune}");
        } else {
            println!("\nResponse: {json}");
        }
    } else {
        println!("\nResponse: {body}");
    }
}
