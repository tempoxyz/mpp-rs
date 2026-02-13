//! Minimal example of fetching a URL with automatic 402 payment handling.
//!
//! Run with:
//!   TEMPO_PRIVATE_KEY=0x... cargo run --example fetch_client --features "tempo,client" -- <URL>
//!
//! Or set the URL via environment variable:
//!   TEMPO_PRIVATE_KEY=0x... URL=https://example.com cargo run --example fetch_client --features "tempo,client"

use mpay::client::{Fetch, TempoProvider};
use mpay::PrivateKeySigner;
use reqwest::Client;
use std::env;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let key = match env::var("TEMPO_PRIVATE_KEY") {
        Ok(k) => k,
        Err(_) => {
            eprintln!("Error: TEMPO_PRIVATE_KEY environment variable required");
            return ExitCode::from(2);
        }
    };

    let rpc_url =
        env::var("TEMPO_RPC_URL").unwrap_or_else(|_| "https://rpc.moderato.tempo.xyz".into());

    let url = env::args()
        .nth(1)
        .or_else(|| env::var("URL").ok())
        .unwrap_or_else(|| {
            eprintln!("Usage: fetch_client <URL> or set URL env var");
            std::process::exit(2);
        });

    let key_hex = key.strip_prefix("0x").unwrap_or(&key);
    let key_bytes = match hex::decode(key_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: invalid private key: {e}");
            return ExitCode::from(2);
        }
    };

    let signer = match PrivateKeySigner::from_slice(&key_bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: failed to create signer: {e}");
            return ExitCode::from(2);
        }
    };

    let provider = match TempoProvider::new(signer, &rpc_url) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: failed to create provider: {e}");
            return ExitCode::from(2);
        }
    };

    let client = Client::new();

    match client.get(&url).send_with_payment(&provider).await {
        Ok(response) => {
            let status = response.status();
            match response.text().await {
                Ok(body) => {
                    if status.is_client_error() || status.is_server_error() {
                        eprintln!("{body}");
                        ExitCode::from(1)
                    } else {
                        println!("{body}");
                        ExitCode::SUCCESS
                    }
                }
                Err(e) => {
                    eprintln!("Error reading response: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::from(1)
        }
    }
}
