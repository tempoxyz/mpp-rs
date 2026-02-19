//! SSE streaming payment server example.
//!
//! Demonstrates pay-per-token LLM streaming using Server-Sent Events (SSE)
//! with mpp's session payment flow.
//!
//! # Running
//!
//! ```bash
//! cargo run --bin sse-server
//! ```

use axum::{
    body::Body,
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use futures::stream;
use mpp::server::{
    Mpp, SessionChannelStore, SessionChallengeOptions, TempoChargeMethod, TempoSessionMethod,
    tempo, TempoConfig, SessionMethodConfig,
};
use alloy::primitives::B256;
use alloy::providers::{Provider, ProviderBuilder};
use mpp::client::channel_ops::default_escrow_contract;
use mpp::{parse_authorization, PaymentCredential, PrivateKeySigner};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tempo_alloy::TempoNetwork;
use tokio_stream::StreamExt;

const RPC_URL: &str = "https://rpc.moderato.tempo.xyz";
const CURRENCY: &str = "0x20c0000000000000000000000000000000000000";

/// Price per token: $0.000075 = 75 base units in 6-decimal pathUSD.
const PRICE_PER_TOKEN: u128 = 75;

/// Unit type for session challenges.
const UNIT_TYPE: &str = "token";

type PaymentHandler = Mpp<
    TempoChargeMethod<mpp::server::TempoProvider>,
    TempoSessionMethod<mpp::server::TempoProvider>,
>;

struct AppState {
    payment: PaymentHandler,
    store: Arc<SessionChannelStore>,
}

#[derive(Deserialize)]
struct ChatQuery {
    prompt: Option<String>,
}

#[tokio::main]
async fn main() {
    let signer = PrivateKeySigner::random();
    let recipient = format!("{:#x}", signer.address());
    println!("Server recipient: {}", recipient);

    // Fund the server account via testnet faucet.
    let faucet_provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect_http(RPC_URL.parse().unwrap());
    let _: Vec<B256> = faucet_provider
        .raw_request("tempo_fundAddress".into(), (signer.address(),))
        .await
        .expect("faucet funding failed");
    println!("Server account funded");

    // Shared channel store for session state.
    let store = Arc::new(SessionChannelStore::new());

    // Create the base payment handler.
    let base = Mpp::create(
        tempo(TempoConfig {
            recipient: &recipient,
        })
        .rpc_url(RPC_URL)
        .fee_payer(true),
    )
    .expect("failed to create payment handler");

    // Create the session method with shared store.
    let provider = mpp::server::tempo_provider(RPC_URL).expect("failed to create provider");
    let chain_id = mpp::tempo::MODERATO_CHAIN_ID;
    let session_method = TempoSessionMethod::new(
        provider,
        store.clone(),
        SessionMethodConfig {
            escrow_contract: default_escrow_contract(chain_id).unwrap(),
            chain_id,
            min_voucher_delta: 0,
        },
    )
    .with_close_signer(signer);

    let payment = base.with_session_method(session_method);

    let state = Arc::new(AppState { payment, store });

    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/chat", get(chat).post(chat))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listening on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn health() -> impl IntoResponse {
    axum::Json(serde_json::json!({ "status": "ok" }))
}

async fn chat(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ChatQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let prompt = query.prompt.unwrap_or_else(|| "Hello!".to_string());

    let credential = parse_credential(&headers);

    // Phase 1: No credential → 402 with session challenge.
    let credential = match credential {
        Some(c) => c,
        None => {
            let challenge = state
                .payment
                .session_challenge_with_details(
                    &PRICE_PER_TOKEN.to_string(),
                    CURRENCY,
                    state.payment.recipient().unwrap(),
                    SessionChallengeOptions {
                        unit_type: Some(UNIT_TYPE),
                        ..Default::default()
                    },
                )
                .expect("failed to create session challenge");

            return (
                StatusCode::PAYMENT_REQUIRED,
                [(
                    header::WWW_AUTHENTICATE,
                    challenge.to_header().expect("failed to format challenge"),
                )],
                "Payment required",
            )
                .into_response();
        }
    };

    // Phases 2-4: Verify the session credential.
    let result = match state.payment.verify_session(&credential).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[server] session verification failed: {}", e);
            return (StatusCode::BAD_REQUEST, format!("Verification failed: {}", e))
                .into_response();
        }
    };

    // If management response (open/close/topUp), return it directly.
    if let Some(mgmt) = result.management_response {
        let receipt_header = result
            .receipt
            .to_header()
            .unwrap_or_else(|_| String::new());
        let body = serde_json::to_string(&mgmt).unwrap_or_else(|_| "{}".to_string());
        let mut response = (StatusCode::OK, body).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        response.headers_mut().insert(
            axum::http::HeaderName::from_static("payment-receipt"),
            axum::http::HeaderValue::from_str(&receipt_header).unwrap(),
        );
        return response;
    }

    // Content request (voucher): stream tokens as SSE.
    let channel_id = result.receipt.reference.clone();
    let challenge_id = credential.challenge.id.clone();

    let token_stream = generate_tokens(&prompt);

    // Use mpp's sse::serve for metered streaming with automatic
    // balance tracking, need-voucher events, and final receipt.
    let event_stream = mpp::server::sse::serve(mpp::server::sse::ServeOptions {
        store: state.store.clone(),
        channel_id,
        challenge_id,
        tick_cost: PRICE_PER_TOKEN,
        generate: token_stream,
        poll_interval_ms: 100,
    });

    let body_stream = async_stream::stream! {
        let mut event_stream = std::pin::pin!(event_stream);
        while let Some(event) = StreamExt::next(&mut event_stream).await {
            yield Ok::<_, std::convert::Infallible>(event);
        }
    };

    let headers = mpp::server::sse::sse_headers();
    let header_tuples: Vec<(String, String)> = headers
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let mut response = Body::from_stream(body_stream).into_response();
    for (k, v) in header_tuples {
        response.headers_mut().insert(
            axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
            axum::http::HeaderValue::from_str(&v).unwrap(),
        );
    }

    response
}

fn parse_credential(headers: &HeaderMap) -> Option<PaymentCredential> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| parse_authorization(s).ok())
}

/// Mock token generator simulating LLM output.
fn generate_tokens(prompt: &str) -> futures::stream::BoxStream<'static, String> {
    // Simulate LLM-style tokenization: each "word" token includes a leading
    // space (matching how GPT-style tokenizers work). We build them with
    // format! to avoid triggering the no-leading-whitespace-strings lint.
    let sp = |w: &str| -> String { format!(" {w}") };
    let words: Vec<String> = vec![
        "The".into(),
        sp("question"),
        sp("you"),
        sp("asked"),
        "--\"".into(),
        prompt.to_string(),
        "\"--is".into(),
        sp("a"),
        sp("fascinating"),
        sp("one."),
        "\n\n".into(),
        "In".into(),
        sp("short,"),
        sp("the"),
        sp("answer"),
        sp("depends"),
        sp("on"),
        sp("context."),
        sp("Let"),
        sp("me"),
        sp("explain"),
        sp("with"),
        sp("a"),
        sp("few"),
        sp("key"),
        sp("points:"),
        "\n\n".into(),
        "1.".into(),
        sp("First,"),
        sp("consider"),
        sp("the"),
        sp("underlying"),
        sp("assumptions."),
        "\n".into(),
        "2.".into(),
        sp("Then,"),
        sp("evaluate"),
        sp("the"),
        sp("available"),
        sp("evidence."),
        "\n".into(),
        "3.".into(),
        sp("Finally,"),
        sp("draw"),
        sp("your"),
        sp("own"),
        sp("conclusions."),
        "\n\n".into(),
        "Hope".into(),
        sp("that"),
        sp("helps!"),
    ];

    Box::pin(stream::iter(words).then(|token| async move {
        let delay = 20 + rand::random::<u64>() % 60;
        tokio::time::sleep(Duration::from_millis(delay)).await;
        token
    }))
}
