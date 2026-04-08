//! Session multi-fetch server example.
//!
//! Demonstrates a payment-channel-gated `/scrape` endpoint that costs 0.01 pathUSD
//! per request. Mirrors the TypeScript `session/multi-fetch` example.
//!
//! # Running
//!
//! ```bash
//! cargo run --bin session-server
//! ```

use alloy::primitives::B256;
use alloy::providers::{Provider, ProviderBuilder};
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use mpp::client::channel_ops::default_escrow_contract;
use mpp::server::{
    tempo, Mpp, SessionChallengeOptions, SessionChannelStore, SessionMethodConfig,
    TempoChargeMethod, TempoConfig, TempoSessionMethod,
};
use mpp::{parse_authorization, PaymentCredential, PrivateKeySigner};
use std::sync::Arc;
use tempo_alloy::TempoNetwork;

const RPC_URL: &str = "https://rpc.moderato.tempo.xyz";
const CHAIN_ID: u64 = 42431;
const CURRENCY: &str = "0x20c0000000000000000000000000000000000000";
/// 0.01 pathUSD in base units (6 decimals).
const AMOUNT_PER_REQUEST: &str = "10000";

type PaymentHandler = Mpp<
    TempoChargeMethod<mpp::server::TempoProvider>,
    TempoSessionMethod<mpp::server::TempoProvider>,
>;

#[derive(serde::Deserialize)]
struct ScrapeQuery {
    url: Option<String>,
}

#[tokio::main]
async fn main() {
    let signer = PrivateKeySigner::random();
    let recipient = format!("{:#x}", signer.address());
    println!("Server recipient: {recipient}");

    // Fund the server account via testnet faucet.
    let faucet_provider =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(RPC_URL.parse().unwrap());
    let _: Vec<B256> = faucet_provider
        .raw_request("tempo_fundAddress".into(), (signer.address(),))
        .await
        .expect("faucet funding failed");
    println!("Server account funded");

    // Create the base payment handler (charge method).
    let base_payment = Mpp::create(
        tempo(TempoConfig {
            recipient: &recipient,
        })
        .rpc_url(RPC_URL)
        .fee_payer(true),
    )
    .expect("failed to create payment handler");

    // Create the session method with an in-memory channel store.
    let rpc_provider = mpp::server::tempo_provider(RPC_URL).expect("failed to create provider");
    let store = Arc::new(SessionChannelStore::new());
    let session_method = TempoSessionMethod::new(
        rpc_provider,
        store,
        SessionMethodConfig {
            escrow_contract: default_escrow_contract(CHAIN_ID).unwrap(),
            chain_id: CHAIN_ID,
            min_voucher_delta: 0,
        },
    )
    .with_close_signer(signer);

    // Add session method to the payment handler.
    let payment = base_payment.with_session_method(session_method);

    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/scrape", get(scrape).post(scrape))
        .with_state(Arc::new(payment));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listening on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn health() -> impl IntoResponse {
    axum::Json(serde_json::json!({ "status": "ok" }))
}

async fn scrape(
    State(payment): State<Arc<PaymentHandler>>,
    headers: HeaderMap,
    Query(query): Query<ScrapeQuery>,
) -> impl IntoResponse {
    let page_url = query.url.as_deref().unwrap_or("https://example.com");

    // Check for a payment credential in the Authorization header.
    if let Some(credential) = parse_credential(&headers) {
        match payment.verify_session(&credential).await {
            Ok(result) => {
                // If the session method returned a management response (open/close/topUp),
                // return it directly instead of the scraped content.
                // Include the payment-receipt header so the client can read tx hashes.
                if let Some(mgmt) = result.management_response {
                    let receipt_header = result.receipt.to_header().unwrap_or_default();
                    return (
                        StatusCode::OK,
                        [("payment-receipt", receipt_header)],
                        axum::Json(mgmt),
                    )
                        .into_response();
                }

                // Payment verified — return the scraped content with a receipt.
                let content = scrape_page(page_url);
                let receipt_header = result.receipt.to_header().unwrap_or_default();
                return (
                    StatusCode::OK,
                    [("payment-receipt", receipt_header)],
                    axum::Json(serde_json::json!({
                        "content": content,
                        "url": page_url,
                    })),
                )
                    .into_response();
            }
            Err(e) => {
                eprintln!("Session verification failed: {e}");
            }
        }
    }

    // No valid credential — return 402 with a session challenge.
    let currency = payment.currency().unwrap();
    let recipient = payment.recipient().unwrap();
    let challenge = payment
        .session_challenge_with_details(
            AMOUNT_PER_REQUEST,
            currency,
            recipient,
            SessionChallengeOptions {
                unit_type: Some("page"),
                suggested_deposit: Some("1000000"),
                ..Default::default()
            },
        )
        .expect("failed to create session challenge");

    (
        StatusCode::PAYMENT_REQUIRED,
        [(header::WWW_AUTHENTICATE, challenge.to_header().unwrap())],
        "Payment required",
    )
        .into_response()
}

fn parse_credential(headers: &HeaderMap) -> Option<PaymentCredential> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| parse_authorization(s).ok())
}

fn scrape_page(url: &str) -> String {
    format!("<h1>{url}</h1><p>Scraped content from {url}</p>")
}
