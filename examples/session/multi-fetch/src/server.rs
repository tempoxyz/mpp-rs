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
    deduct_from_channel, tempo, Mpp, SessionChallengeOptions, SessionChannelStore,
    SessionMethodConfig, TempoChargeMethod, TempoConfig, TempoSessionMethod,
};
use mpp::tempo::SessionCredentialPayload;
use mpp::{parse_authorization, PaymentCredential, PrivateKeySigner, Receipt};
use std::sync::Arc;
use tempo_alloy::TempoNetwork;

const RPC_URL: &str = "https://rpc.moderato.tempo.xyz";
const CHAIN_ID: u64 = 42431;
/// 0.01 pathUSD in base units (6 decimals).
const AMOUNT_PER_REQUEST: u128 = 10_000;

type PaymentHandler = Mpp<
    TempoChargeMethod<mpp::server::TempoProvider>,
    TempoSessionMethod<mpp::server::TempoProvider>,
>;

struct AppState {
    payment: PaymentHandler,
    store: Arc<SessionChannelStore>,
}

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
        store.clone(),
        SessionMethodConfig {
            escrow_contract: default_escrow_contract(CHAIN_ID).unwrap(),
            chain_id: CHAIN_ID,
            min_voucher_delta: 0,
        },
    )
    .with_close_signer(signer);

    // Add session method to the payment handler.
    let payment = base_payment.with_session_method(session_method);
    let state = Arc::new(AppState { payment, store });

    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/scrape", get(scrape).post(scrape))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listening on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn health() -> impl IntoResponse {
    axum::Json(serde_json::json!({ "status": "ok" }))
}

async fn scrape(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ScrapeQuery>,
) -> impl IntoResponse {
    let page_url = query.url.as_deref().unwrap_or("https://example.com");

    // Check for a payment credential in the Authorization header.
    if let Some(credential) = parse_credential(&headers) {
        let payload = credential.payload_as::<SessionCredentialPayload>().ok();
        match state.payment.verify_session(&credential).await {
            Ok(result) => {
                // If the session method returned a management response (open/close/topUp),
                // return it directly instead of the scraped content.
                // Include the payment-receipt header so the client can read tx hashes.
                if let Some(mgmt) = result.management_response.as_ref() {
                    if !matches!(
                        payload.as_ref(),
                        Some(SessionCredentialPayload::Open { .. })
                    ) {
                        let receipt_header = result.receipt.to_header().unwrap_or_default();
                        return (
                            StatusCode::OK,
                            [("payment-receipt", receipt_header)],
                            axum::Json(mgmt.clone()),
                        )
                            .into_response();
                    }
                }

                let Some(channel_id) = payload
                    .as_ref()
                    .and_then(|payload| content_channel_id(payload, &result.receipt.reference))
                else {
                    return payment_required(&state.payment, Some(&result.receipt));
                };

                if let Err(e) = charge_request(&state.store, channel_id).await {
                    eprintln!("Session charge failed: {e}");
                    return payment_required(&state.payment, Some(&result.receipt));
                }

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
    payment_required(&state.payment, None)
}

fn content_channel_id<'a>(
    payload: &'a SessionCredentialPayload,
    receipt_reference: &'a str,
) -> Option<&'a str> {
    match payload {
        SessionCredentialPayload::Open { channel_id, .. } => Some(channel_id),
        SessionCredentialPayload::Voucher { .. } => Some(receipt_reference),
        SessionCredentialPayload::TopUp { .. } | SessionCredentialPayload::Close { .. } => None,
    }
}

async fn charge_request(
    store: &SessionChannelStore,
    channel_id: &str,
) -> Result<(), mpp::server::VerificationError> {
    deduct_from_channel(store, channel_id, AMOUNT_PER_REQUEST)
        .await
        .map(|_| ())
}

fn payment_required(
    payment: &PaymentHandler,
    receipt: Option<&Receipt>,
) -> axum::response::Response {
    let currency = payment.currency().unwrap();
    let recipient = payment.recipient().unwrap();
    let challenge = payment
        .session_challenge_with_details(
            &AMOUNT_PER_REQUEST.to_string(),
            currency,
            recipient,
            SessionChallengeOptions {
                unit_type: Some("page"),
                suggested_deposit: Some("1000000"),
                ..Default::default()
            },
        )
        .expect("failed to create session challenge");

    let mut response = (
        StatusCode::PAYMENT_REQUIRED,
        [(header::WWW_AUTHENTICATE, challenge.to_header().unwrap())],
        "Payment required",
    )
        .into_response();
    if let Some(receipt) = receipt {
        insert_payment_receipt(&mut response, receipt);
    }
    response
}

fn insert_payment_receipt(response: &mut axum::response::Response, receipt: &Receipt) {
    let receipt = receipt
        .to_header()
        .expect("failed to format payment receipt");
    response.headers_mut().insert(
        axum::http::HeaderName::from_static("payment-receipt"),
        axum::http::HeaderValue::from_str(&receipt).expect("invalid payment receipt header"),
    );
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::Address;
    use mpp::tempo::ChannelState;

    fn channel_state(channel_id: &str, authorized: u128, spent: u128) -> ChannelState {
        ChannelState {
            channel_id: channel_id.to_string(),
            chain_id: CHAIN_ID,
            escrow_contract: Address::ZERO,
            payer: Address::ZERO,
            payee: Address::ZERO,
            token: Address::ZERO,
            settlement_route: None,
            authorized_signer: Address::ZERO,
            deposit: authorized,
            settled_on_chain: 0,
            highest_voucher_amount: authorized,
            highest_voucher_signature: None,
            spent,
            units: 0,
            finalized: false,
            closing: false,
            close_requested_at: 0,
            created_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn opening_and_voucher_credentials_purchase_content() {
        let cases = [
            (
                serde_json::json!({
                    "action": "open",
                    "type": "transaction",
                    "channelId": "channel-open",
                    "transaction": "0x01",
                    "cumulativeAmount": "10000",
                    "signature": "0x02"
                }),
                Some("channel-open"),
            ),
            (
                serde_json::json!({
                    "action": "voucher",
                    "channelId": "channel-voucher",
                    "cumulativeAmount": "20000",
                    "signature": "0x03"
                }),
                Some("receipt-channel"),
            ),
            (
                serde_json::json!({
                    "action": "topUp",
                    "type": "transaction",
                    "channelId": "channel-top-up",
                    "transaction": "0x04",
                    "additionalDeposit": "10000"
                }),
                None,
            ),
            (
                serde_json::json!({
                    "action": "close",
                    "channelId": "channel-close",
                    "cumulativeAmount": "20000",
                    "signature": "0x05"
                }),
                None,
            ),
        ];

        for (payload, expected) in cases {
            let payload: SessionCredentialPayload = serde_json::from_value(payload).unwrap();
            assert_eq!(content_channel_id(&payload, "receipt-channel"), expected);
        }
    }

    #[test]
    fn payment_required_can_acknowledge_an_accepted_voucher() {
        let receipt = Receipt::success("tempo", "channel-1");
        let mut response = StatusCode::PAYMENT_REQUIRED.into_response();

        insert_payment_receipt(&mut response, &receipt);

        let encoded = response.headers().get("payment-receipt").unwrap();
        let parsed = mpp::parse_receipt(encoded.to_str().unwrap()).unwrap();
        assert_eq!(parsed.reference, "channel-1");
    }

    #[tokio::test]
    async fn request_charge_requires_full_price_and_preserves_failed_state() {
        struct Case {
            name: &'static str,
            authorized: u128,
            spent: u128,
            succeeds: bool,
            expected_spent: u128,
        }

        let cases = [
            Case {
                name: "one-unit voucher",
                authorized: 10_001,
                spent: 10_000,
                succeeds: false,
                expected_spent: 10_000,
            },
            Case {
                name: "partial balance",
                authorized: 19_999,
                spent: 10_000,
                succeeds: false,
                expected_spent: 10_000,
            },
            Case {
                name: "exact balance",
                authorized: 20_000,
                spent: 10_000,
                succeeds: true,
                expected_spent: 20_000,
            },
            Case {
                name: "prepaid balance",
                authorized: 30_000,
                spent: 10_000,
                succeeds: true,
                expected_spent: 20_000,
            },
        ];

        for (index, case) in cases.into_iter().enumerate() {
            let channel_id = format!("channel-{index}");
            let store = SessionChannelStore::new();
            store.insert(
                &channel_id,
                channel_state(&channel_id, case.authorized, case.spent),
            );

            let result = charge_request(&store, &channel_id).await;
            assert_eq!(result.is_ok(), case.succeeds, "{}", case.name);

            let state = store.get_channel_sync(&channel_id).unwrap();
            assert_eq!(state.spent, case.expected_spent, "{}", case.name);
            assert_eq!(state.units, u64::from(case.succeeds), "{}", case.name);
        }
    }
}
