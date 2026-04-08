//! Session multi-fetch client example.
//!
//! Demonstrates making multiple paid requests over a single payment channel.
//! Mirrors the TypeScript `session/multi-fetch` client.
//!
//! # Running
//!
//! ```bash
//! # Start the server first, then:
//! cargo run --bin session-client
//! ```

use alloy::primitives::{Address, B256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::sol;
use mpp::client::{Fetch, TempoSessionProvider};
use mpp::{parse_receipt, PrivateKeySigner};
use reqwest::Client;
use tempo_alloy::TempoNetwork;

sol! {
    #[sol(rpc)]
    interface IERC20 {
        function balanceOf(address account) external view returns (uint256);
    }
}

const RPC_URL: &str = "https://rpc.moderato.tempo.xyz";
const CURRENCY: &str = "0x20c0000000000000000000000000000000000000";
const PAGE_COUNT: usize = 9;
/// 1 pathUSD in base units (6 decimals) — max deposit for the channel.
const MAX_DEPOSIT: u128 = 1_000_000;

#[tokio::main]
async fn main() {
    let base_url =
        std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());

    // Use PRIVATE_KEY env var or generate a random one for the demo.
    let signer = match std::env::var("PRIVATE_KEY") {
        Ok(key) => {
            let key = key.strip_prefix("0x").unwrap_or(&key);
            let bytes = hex::decode(key).expect("invalid hex in PRIVATE_KEY");
            PrivateKeySigner::from_slice(&bytes).expect("invalid private key")
        }
        Err(_) => PrivateKeySigner::random(),
    };

    let signer_address = signer.address();
    println!("Client account: {signer_address:#x}");

    // Fund the client account via testnet faucet.
    println!("Funding account via faucet...");
    let faucet_provider =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(RPC_URL.parse().unwrap());
    let _: Vec<B256> = faucet_provider
        .raw_request("tempo_fundAddress".into(), (signer_address,))
        .await
        .expect("faucet funding failed");

    let currency_addr: Address = CURRENCY.parse().unwrap();
    let erc20 = IERC20::new(currency_addr, &faucet_provider);

    // Wait for faucet transactions to confirm.
    let mut balance_before = erc20.balanceOf(signer_address).call().await.unwrap();
    for _ in 0..30 {
        if balance_before.to::<u128>() > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        balance_before = erc20.balanceOf(signer_address).call().await.unwrap();
    }
    let balance_before_f64 = balance_before.to::<u128>() as f64 / 1e6;
    println!("Balance: {balance_before_f64} pathUSD");

    // Create a session provider that manages channel lifecycle automatically.
    // - First request: opens a payment channel on-chain (approve + open escrow)
    // - Subsequent requests: sends incrementing off-chain vouchers (no gas!)
    let session = TempoSessionProvider::new(signer, RPC_URL)
        .expect("failed to create session provider")
        .with_max_deposit(MAX_DEPOSIT);

    let client = Client::new();

    println!("\n--- Channel ---");
    println!(
        "Max deposit: {} pathUSD (locked into payment channel on first request)",
        MAX_DEPOSIT as f64 / 1e6
    );

    println!("\n--- Scraping {PAGE_COUNT} pages @ 0.01 pathUSD each ---");

    for i in 1..=PAGE_COUNT {
        let url = format!("https://example.com/page/{i}");
        let request_url = format!("{base_url}/api/scrape?url={}", urlencoding(&url));

        let response = client.get(&request_url).send_with_payment(&session).await;

        match response {
            Ok(resp) => {
                if !resp.status().is_success() {
                    eprintln!(
                        "Error: {} — {}",
                        resp.status(),
                        resp.text().await.unwrap_or_default()
                    );
                    return;
                }
                if i == 1 {
                    if let Some(r) = resp
                        .headers()
                        .get("payment-receipt")
                        .and_then(|h| h.to_str().ok())
                        .and_then(|s| parse_receipt(s).ok())
                    {
                        println!(
                            "  Open channel tx: https://explore.moderato.tempo.xyz/tx/{}",
                            r.reference
                        );
                    }
                }
                let _body: serde_json::Value = resp.json().await.unwrap_or_default();
                let cumulative = session.cumulative() as f64 / 1e6;
                println!("  {url} → OK (voucher cumulative: {cumulative:.2} pathUSD)");
            }
            Err(e) => {
                eprintln!("Request failed: {e}");
                return;
            }
        }
    }

    let cumulative = session.cumulative() as f64 / 1e6;
    println!("\nVoucher cumulative: {cumulative:.2} pathUSD ({PAGE_COUNT} × 0.01)");

    // Close the channel and settle on-chain.
    // The server submits the highest cumulative voucher to the escrow contract,
    // transferring the owed amount to the server and refunding the remainder.
    println!("\n--- Settlement ---");
    let close_url = format!("{base_url}/api/scrape");
    match session.close(&client, &close_url).await {
        Ok(Some(receipt)) => {
            println!(
                "  Channel settled: https://explore.moderato.tempo.xyz/tx/{}",
                receipt.reference
            );
        }
        Ok(None) => {
            println!("  No active channel to close");
        }
        Err(e) => {
            eprintln!("  Close failed: {e}");
        }
    }

    // Wait for settlement transaction to confirm.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let balance_after = erc20.balanceOf(signer_address).call().await.unwrap();
    let balance_after_f64 = balance_after.to::<u128>() as f64 / 1e6;
    let total_spent = balance_before
        .to::<u128>()
        .saturating_sub(balance_after.to::<u128>()) as f64
        / 1e6;
    println!("\n--- Summary ---");
    println!("  Pages scraped:   {PAGE_COUNT}");
    println!("  Voucher total:   {cumulative:.2} pathUSD");
    println!("  Channel deposit: {} pathUSD", MAX_DEPOSIT as f64 / 1e6);
    println!("  Balance before:  {balance_before_f64} pathUSD");
    println!("  Balance after:   {balance_after_f64} pathUSD");
    println!("  Total spent:     {total_spent} pathUSD (deposit - refund + gas)");
}

/// Minimal percent-encoding for URL query parameters.
fn urlencoding(s: &str) -> String {
    s.replace('%', "%25")
        .replace(' ', "%20")
        .replace(':', "%3A")
        .replace('/', "%2F")
        .replace('?', "%3F")
        .replace('#', "%23")
        .replace('&', "%26")
        .replace('=', "%3D")
}
