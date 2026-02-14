//! SSE streaming payment client example.
//!
//! Connects to the SSE server, opens a payment channel, and streams tokens
//! with automatic per-token payment via vouchers.
//!
//! # Running
//!
//! ```bash
//! # Start the server first, then:
//! cargo run --bin sse-client
//! ```

use alloy::primitives::{Address, B256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::sol;
use futures::StreamExt;
use mpp::client::{Fetch, TempoSessionProvider};
use mpp::server::sse::{parse_event, SseEvent};
use mpp::{parse_receipt, PrivateKeySigner};
use reqwest::Client;
use tempo_alloy::TempoNetwork;

const RPC_URL: &str = "https://rpc.moderato.tempo.xyz";
const CURRENCY: &str = "0x20c0000000000000000000000000000000000000";

sol! {
    #[sol(rpc)]
    interface IERC20 {
        function balanceOf(address account) external view returns (uint256);
    }
}

#[tokio::main]
async fn main() {
    let base_url =
        std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let signer = match std::env::var("PRIVATE_KEY") {
        Ok(key) => {
            let key = key.strip_prefix("0x").unwrap_or(&key);
            let bytes = hex::decode(key).expect("invalid hex in PRIVATE_KEY");
            PrivateKeySigner::from_slice(&bytes).expect("invalid private key")
        }
        Err(_) => PrivateKeySigner::random(),
    };

    let signer_address = signer.address();
    println!("Client account: {:#x}", signer_address);

    // Fund the client account via testnet faucet.
    println!("Funding account via faucet...");
    let faucet_provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect_http(RPC_URL.parse().unwrap());
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
    println!("Balance: {} pathUSD", balance_before.to::<u128>() as f64 / 1e6);

    // Create a session provider with max deposit of 1 pathUSD (1_000_000 base units).
    let provider = TempoSessionProvider::new(signer, RPC_URL)
        .expect("failed to create session provider")
        .with_max_deposit(1_000_000)
        .with_on_channel_update(|entry| {
            eprintln!(
                "[channel] id={:#x} cumulative={}",
                entry.channel_id, entry.cumulative_amount
            );
        });

    let prompt = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "Tell me something interesting".to_string());

    println!("\n--- Channel ---");
    println!("Max deposit: 1 pathUSD (locked into payment channel on first request)");
    println!("Price per token: 0.000075 pathUSD");

    let url = format!(
        "{}/api/chat?prompt={}",
        base_url,
        urlencoding::encode(&prompt)
    );
    let voucher_url = format!("{}/api/chat", base_url);

    println!("\n--- Streaming (prompt: \"{}\") ---", prompt);

    let client = Client::new();

    // Step 1: send_with_payment handles the 402 → open channel flow.
    // The server returns a management JSON response (not SSE) for the channel open.
    let open_resp = match client.get(&url).send_with_payment(&provider).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    if let Some(r) = open_resp.headers().get("payment-receipt")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| parse_receipt(s).ok())
    {
        println!("Open channel tx: https://explore.moderato.tempo.xyz/tx/{}", r.reference);
    }
    let open_status = open_resp.status();
    if !open_status.is_success() {
        let body = open_resp.text().await.unwrap_or_default();
        eprintln!("Server returned {}: {}", open_status, body);
        std::process::exit(1);
    }
    // Consume the management response body.
    let _ = open_resp.text().await;

    // Step 2: Send a second request with a voucher to start the actual SSE stream.
    let response = match client.get(&url).send_with_payment(&provider).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error starting stream: {}", e);
            std::process::exit(1);
        }
    };

    let stream_status = response.status();
    if !stream_status.is_success() {
        let body = response.text().await.unwrap_or_default();
        eprintln!("Server returned {}: {}", stream_status, body);
        std::process::exit(1);
    }

    // Stream and parse SSE events.
    let mut stream = response.bytes_stream();
    let mut buffer = String::new();
    let mut token_count = 0u64;

    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            Err(e) => {
                eprintln!("\nStream error: {}", e);
                break;
            }
        };
        buffer.push_str(&String::from_utf8_lossy(&chunk));

        while let Some(pos) = buffer.find("\n\n") {
            let event_str = buffer[..pos + 2].to_string();
            buffer = buffer[pos + 2..].to_string();

            if let Some(event) = parse_event(&event_str) {
                match event {
                    SseEvent::Message(token) => {
                        token_count += 1;
                        print!("{}", token);
                    }
                    SseEvent::PaymentReceipt(receipt) => {
                        println!("\n\n--- Receipt ---");
                        println!("  Channel:    {}", receipt.channel_id);
                        println!("  Accepted:   {}", receipt.accepted_cumulative);
                        println!("  Spent:      {}", receipt.spent);
                        if let Some(units) = receipt.units {
                            println!("  Units:      {}", units);
                        }
                        if let Some(ref tx) = receipt.tx_hash {
                            println!("  Tx hash:    {}", tx);
                        }
                    }
                    SseEvent::PaymentNeedVoucher(nv) => {
                        let required: u128 = nv.required_cumulative.parse().unwrap_or(0);
                        eprintln!(
                            "\n[voucher: channel={} required={}]",
                            nv.channel_id, required
                        );
                        if let Err(e) = provider
                            .send_voucher(&client, &voucher_url, &nv.channel_id, required)
                            .await
                        {
                            eprintln!("[voucher failed: {}]", e);
                        }
                    }
                }
            }
        }
    }

    let cumulative = provider.cumulative() as f64 / 1e6;
    println!("\n\nTokens: {token_count}");
    println!("Voucher cumulative: {cumulative:.6} pathUSD ({token_count} × 0.000075)");

    // Close the channel and settle on-chain.
    println!("\n--- Settlement ---");
    let close_url = format!("{}/api/chat", base_url);
    match provider.close(&client, &close_url).await {
        Ok(Some(receipt)) => {
            println!("  Channel settled: https://explore.moderato.tempo.xyz/tx/{}", receipt.reference);
        }
        Ok(None) => {
            println!("  Close sent (no receipt returned)");
        }
        Err(e) => {
            eprintln!("  Close failed: {e}");
        }
    }

    // Wait for settlement transaction to confirm.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let balance_after = erc20.balanceOf(signer_address).call().await.unwrap();
    let balance_before_f64 = balance_before.to::<u128>() as f64 / 1e6;
    let balance_after_f64 = balance_after.to::<u128>() as f64 / 1e6;
    let total_spent =
        balance_before.to::<u128>().saturating_sub(balance_after.to::<u128>()) as f64 / 1e6;
    println!("\n--- Summary ---");
    println!("  Tokens streamed: {token_count}");
    println!("  Voucher total:   {cumulative:.6} pathUSD");
    println!("  Channel deposit: 1 pathUSD");
    println!("  Balance before:  {balance_before_f64} pathUSD");
    println!("  Balance after:   {balance_after_f64} pathUSD");
    println!("  Total spent:     {total_spent} pathUSD (deposit - refund + gas)");
}
