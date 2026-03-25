//! # Stripe Fortune Teller CLI Client
//!
//! A CLI client that fetches a fortune from the payment-gated Fortune Teller API
//! using Stripe's Shared Payment Token (SPT) flow.
//!
//! Uses a test card (`pm_card_visa`) for headless operation — no browser needed.
//!
//! ## Running
//!
//! ```bash
//! # First start the server:
//! STRIPE_SECRET_KEY=sk_test_... cargo run --bin stripe-server
//!
//! # Then in another terminal:
//! cargo run --bin stripe-client
//!
//! # Or target a different server:
//! cargo run --bin stripe-client -- --server http://localhost:8000
//! ```

use mpp::client::{Fetch, StripeProvider};
use mpp::protocol::methods::stripe::CreateTokenResult;
use mpp::{parse_receipt, MppError};
use reqwest::Client;

#[tokio::main]
async fn main() {
    let server_url = std::env::args()
        .skip_while(|a| a != "--server")
        .nth(1)
        .unwrap_or_else(|| "http://localhost:3000".to_string());

    let server_base = server_url.trim_end_matches('/').to_string();
    let spt_url = format!("{server_base}/api/create-spt");

    let provider = StripeProvider::new(move |params| {
        let spt_url = spt_url.clone();
        Box::pin(async move {
            let resp = Client::new()
                .post(&spt_url)
                .json(&serde_json::json!({
                    "paymentMethod": "pm_card_visa",
                    "amount": params.amount,
                    "currency": params.currency,
                    "expiresAt": params.expires_at,
                }))
                .send()
                .await
                .map_err(|e| MppError::Http(e.to_string()))?;

            if !resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(MppError::Http(format!("SPT creation failed: {body}")));
            }

            let json: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| MppError::Http(e.to_string()))?;

            let spt = json["spt"]
                .as_str()
                .ok_or_else(|| MppError::Http("missing spt in response".to_string()))?
                .to_string();

            Ok(CreateTokenResult::from(spt))
        })
    });

    let fortune_url = format!("{server_base}/api/fortune");
    println!("Fetching {fortune_url} ...");

    let resp = Client::new()
        .get(&fortune_url)
        .send_with_payment(&provider)
        .await
        .expect("request failed");

    println!("Status: {}", resp.status());

    if let Some(receipt_hdr) = resp.headers().get("payment-receipt") {
        if let Ok(receipt_str) = receipt_hdr.to_str() {
            if let Ok(receipt) = parse_receipt(receipt_str) {
                println!("Payment receipt: {}", receipt.reference);
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
