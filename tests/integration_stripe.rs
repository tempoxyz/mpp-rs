//! Integration tests for the MPP Stripe charge flow.
//!
//! Unlike Tempo integration tests which require a live blockchain, Stripe tests
//! use a mock Stripe API server. The mock validates that the server sends the
//! correct PaymentIntent creation request (SPT, amount, currency, confirm=true)
//! and returns a succeeded PaymentIntent.
//!
//! # Running
//!
//! ```bash
//! cargo test --features integration-stripe --test integration_stripe
//! ```

#![cfg(feature = "integration-stripe")]

use std::sync::Arc;

use axum::extract::Form;
use axum::{routing::get, Json, Router};
use mpp::client::{Fetch, StripeProvider};
use mpp::protocol::core::PaymentCredential;
use mpp::protocol::methods::stripe::{CreateTokenResult, StripeCredentialPayload};
use mpp::server::axum::{ChargeChallenger, ChargeConfig, MppCharge};
use mpp::server::{stripe, Mpp, StripeChargeOptions, StripeConfig};
use reqwest::Client;

// ==================== Mock Stripe API ====================

/// Start a mock Stripe API server that accepts `POST /v1/payment_intents`
/// and returns a succeeded PaymentIntent.
async fn start_mock_stripe() -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/v1/payment_intents",
        axum::routing::post(mock_create_payment_intent),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind mock stripe");
    let addr = listener.local_addr().unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("mock stripe error");
    });

    (url, handle)
}

/// Mock Stripe PaymentIntent creation handler.
///
/// Validates the request has required fields and returns a succeeded PI.
async fn mock_create_payment_intent(
    Form(params): Form<std::collections::HashMap<String, String>>,
) -> Json<serde_json::Value> {
    // Validate required fields match the mppx server implementation
    assert!(
        params.contains_key("shared_payment_granted_token"),
        "missing shared_payment_granted_token"
    );
    assert!(params.contains_key("amount"), "missing amount");
    assert!(params.contains_key("currency"), "missing currency");
    assert_eq!(
        params.get("confirm").map(|s| s.as_str()),
        Some("true"),
        "confirm must be true"
    );
    assert_eq!(
        params
            .get("automatic_payment_methods[enabled]")
            .map(|s| s.as_str()),
        Some("true"),
        "automatic_payment_methods must be enabled"
    );

    Json(serde_json::json!({
        "id": format!("pi_mock_{}", params.get("shared_payment_granted_token").unwrap()),
        "status": "succeeded",
        "amount": params["amount"],
        "currency": params["currency"],
    }))
}

/// Mock Stripe API that returns `requires_action` (simulates 3DS).
async fn start_mock_stripe_requires_action() -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/v1/payment_intents",
        axum::routing::post(|| async {
            Json(serde_json::json!({
                "id": "pi_requires_action",
                "status": "requires_action",
            }))
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind");
    let addr = listener.local_addr().unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (url, handle)
}

// ==================== MPP Server Helpers ====================

/// Start an axum server with a Stripe-backed Mpp instance.
async fn start_server(
    mpp: Arc<Mpp<mpp::protocol::methods::stripe::method::ChargeMethod>>,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/health", get(health))
        .route("/paid", get(paid))
        .route("/paid-premium", get(paid_premium))
        .with_state(mpp);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind");
    let addr = listener.local_addr().unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("server error");
    });

    (url, handle)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

/// Mock Stripe API that returns a 400 error response.
async fn start_mock_stripe_error() -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/v1/payment_intents",
        axum::routing::post(|| async {
            (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": {
                        "message": "Invalid payment token",
                        "type": "invalid_request_error",
                        "code": "resource_missing"
                    }
                })),
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind");
    let addr = listener.local_addr().unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, handle)
}

/// Paid endpoint: issues a Stripe charge challenge and verifies credentials.
///
/// Uses the raw Mpp API since the axum `MppCharge` extractor is Tempo-specific.
async fn paid(
    axum::extract::State(mpp): axum::extract::State<
        Arc<Mpp<mpp::protocol::methods::stripe::method::ChargeMethod>>,
    >,
    req: axum::extract::Request,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let issue_challenge = || {
        let challenge = mpp.stripe_charge("0.10").expect("challenge creation");
        let www_auth = challenge.to_header().expect("format challenge");
        let mut resp = axum::http::StatusCode::PAYMENT_REQUIRED.into_response();
        resp.headers_mut().insert(
            "www-authenticate",
            www_auth.parse().expect("www-auth header value"),
        );
        resp
    };

    match auth_header {
        Some(auth) => {
            let credential = match mpp::parse_authorization(&auth) {
                Ok(c) => c,
                Err(_) => return issue_challenge(),
            };

            match mpp.verify_credential(&credential).await {
                Ok(receipt) => {
                    let body = serde_json::json!({ "message": "paid content" });
                    let mut resp = axum::response::Json(body).into_response();
                    let receipt_hdr = receipt.to_header().expect("format receipt");
                    resp.headers_mut().insert(
                        "payment-receipt",
                        receipt_hdr.parse().expect("receipt header value"),
                    );
                    resp
                }
                Err(_) => issue_challenge(),
            }
        }
        None => issue_challenge(),
    }
}

/// Premium paid endpoint: uses `stripe_charge_with_options` with description.
async fn paid_premium(
    axum::extract::State(mpp): axum::extract::State<
        Arc<Mpp<mpp::protocol::methods::stripe::method::ChargeMethod>>,
    >,
    req: axum::extract::Request,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let issue_challenge = || {
        let challenge = mpp
            .stripe_charge_with_options(
                "1.00",
                StripeChargeOptions {
                    description: Some("Premium content"),
                    external_id: Some("premium-001"),
                    ..Default::default()
                },
            )
            .expect("challenge creation");
        let www_auth = challenge.to_header().expect("format challenge");
        let mut resp = axum::http::StatusCode::PAYMENT_REQUIRED.into_response();
        resp.headers_mut().insert(
            "www-authenticate",
            www_auth.parse().expect("www-auth header value"),
        );
        resp
    };

    match auth_header {
        Some(auth) => match mpp::parse_authorization(&auth) {
            Ok(credential) => match mpp.verify_credential(&credential).await {
                Ok(receipt) => {
                    let body = serde_json::json!({ "message": "premium content" });
                    let mut resp = axum::response::Json(body).into_response();
                    let receipt_hdr = receipt.to_header().expect("format receipt");
                    resp.headers_mut().insert(
                        "payment-receipt",
                        receipt_hdr.parse().expect("receipt header value"),
                    );
                    resp
                }
                Err(_) => issue_challenge(),
            },
            Err(_) => issue_challenge(),
        },
        None => issue_challenge(),
    }
}

struct TenCents;
impl ChargeConfig for TenCents {
    fn amount() -> &'static str {
        "0.10"
    }
}

async fn paid_extractor(charge: MppCharge<TenCents>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "message": "paid via extractor",
        "method": charge.receipt.method.as_str(),
    }))
}

/// Start an axum server with a Stripe-backed Mpp instance using the MppCharge extractor.
async fn start_server_with_extractor(
    mpp: Arc<Mpp<mpp::protocol::methods::stripe::method::ChargeMethod>>,
) -> (String, tokio::task::JoinHandle<()>) {
    let challenger: Arc<dyn ChargeChallenger> = mpp;
    let app = Router::new()
        .route("/paid-extractor", get(paid_extractor))
        .with_state(challenger);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind");
    let addr = listener.local_addr().unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("server error");
    });

    (url, handle)
}

// ==================== Tests ====================

/// Full e2e: client hits paid endpoint → gets 402 with method=stripe →
/// creates SPT via callback → sends credential with SPT → server verifies
/// by calling (mock) Stripe API → returns 200 + Payment-Receipt.
#[tokio::test]
async fn test_e2e_stripe_charge() {
    let (stripe_url, stripe_handle) = start_mock_stripe().await;

    let mpp = Mpp::create_stripe(
        stripe(StripeConfig {
            secret_key: "sk_test_mock_key",
            network_id: "internal",
            payment_method_types: &["card"],
            currency: "usd",
            decimals: 2,
        })
        .stripe_api_base(&stripe_url)
        .secret_key("test-hmac-secret"),
    )
    .expect("failed to create Mpp");

    let mpp = Arc::new(mpp);
    let (url, handle) = start_server(mpp).await;

    // Create client provider with a mock createToken callback
    let provider = StripeProvider::new(|_params| {
        Box::pin(async move {
            Ok(CreateTokenResult::from(
                "spt_mock_test_token_123".to_string(),
            ))
        })
    });

    let resp = Client::new()
        .get(format!("{url}/paid"))
        .send_with_payment(&provider)
        .await
        .expect("stripe payment failed");

    assert_eq!(resp.status(), 200);

    // Verify receipt header
    let receipt_hdr = resp
        .headers()
        .get("payment-receipt")
        .expect("missing Payment-Receipt header")
        .to_str()
        .unwrap();
    let receipt = mpp::parse_receipt(receipt_hdr).expect("failed to parse receipt");
    assert_eq!(receipt.method.as_str(), "stripe");
    assert_eq!(receipt.status, mpp::ReceiptStatus::Success);
    assert!(
        receipt.reference.starts_with("pi_mock_"),
        "receipt reference should be a mock PI id, got: {}",
        receipt.reference
    );

    // Verify response body
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"], "paid content");

    handle.abort();
    stripe_handle.abort();
}

/// 402 challenge should advertise method=stripe with correct fields.
#[tokio::test]
async fn test_stripe_402_challenge_format() {
    let (stripe_url, stripe_handle) = start_mock_stripe().await;

    let mpp = Mpp::create_stripe(
        stripe(StripeConfig {
            secret_key: "sk_test_mock",
            network_id: "test-network",
            payment_method_types: &["card"],
            currency: "usd",
            decimals: 2,
        })
        .stripe_api_base(&stripe_url)
        .secret_key("test-secret"),
    )
    .expect("failed to create Mpp");

    let mpp = Arc::new(mpp);
    let (url, handle) = start_server(mpp).await;

    // Hit without auth → expect 402
    let resp = Client::new()
        .get(format!("{url}/paid"))
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 402);

    let www_auth = resp
        .headers()
        .get("www-authenticate")
        .expect("missing WWW-Authenticate header")
        .to_str()
        .unwrap();
    assert!(
        www_auth.starts_with("Payment "),
        "WWW-Authenticate should start with 'Payment ', got: {www_auth}"
    );

    let challenge = mpp::parse_www_authenticate(www_auth).expect("failed to parse challenge");
    assert_eq!(challenge.method.as_str(), "stripe");
    assert_eq!(challenge.intent.as_str(), "charge");

    // Verify request fields match the Stripe schema
    let request: serde_json::Value = challenge
        .request
        .decode_value()
        .expect("failed to decode request");
    assert!(request["amount"].is_string(), "amount should be a string");
    assert_eq!(request["currency"], "usd");

    handle.abort();
    stripe_handle.abort();
}

/// Health endpoint works without payment.
#[tokio::test]
async fn test_stripe_health_no_payment() {
    let (stripe_url, stripe_handle) = start_mock_stripe().await;

    let mpp = Mpp::create_stripe(
        stripe(StripeConfig {
            secret_key: "sk_test_mock",
            network_id: "internal",
            payment_method_types: &["card"],
            currency: "usd",
            decimals: 2,
        })
        .stripe_api_base(&stripe_url)
        .secret_key("test-secret"),
    )
    .expect("failed to create Mpp");

    let mpp = Arc::new(mpp);
    let (url, handle) = start_server(mpp).await;

    let resp = Client::new()
        .get(format!("{url}/health"))
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");

    handle.abort();
    stripe_handle.abort();
}

/// Stripe API returning `requires_action` should fail verification.
#[tokio::test]
async fn test_stripe_requires_action_rejected() {
    let (stripe_url, stripe_handle) = start_mock_stripe_requires_action().await;

    let mpp = Mpp::create_stripe(
        stripe(StripeConfig {
            secret_key: "sk_test_mock",
            network_id: "internal",
            payment_method_types: &["card"],
            currency: "usd",
            decimals: 2,
        })
        .stripe_api_base(&stripe_url)
        .secret_key("test-secret"),
    )
    .expect("failed to create Mpp");

    let mpp = Arc::new(mpp);
    let (url, handle) = start_server(mpp).await;

    let provider = StripeProvider::new(|_params| {
        Box::pin(async move {
            Ok(CreateTokenResult::from(
                "spt_will_require_action".to_string(),
            ))
        })
    });

    // The client will get a 402, create a credential, but the server
    // verification will fail because Stripe returns requires_action.
    // The middleware retries once and then returns the 402.
    let resp = Client::new()
        .get(format!("{url}/paid"))
        .send_with_payment(&provider)
        .await;

    if let Ok(r) = resp {
        assert_eq!(
            r.status(),
            402,
            "should get 402 when Stripe requires action"
        );
    }

    handle.abort();
    stripe_handle.abort();
}

/// 402 challenge should include `methodDetails` with `networkId` and `paymentMethodTypes`.
#[tokio::test]
async fn test_stripe_challenge_contains_method_details() {
    let (stripe_url, stripe_handle) = start_mock_stripe().await;

    let mpp = Mpp::create_stripe(
        stripe(StripeConfig {
            secret_key: "sk_test_mock",
            network_id: "test-network-id",
            payment_method_types: &["card"],
            currency: "usd",
            decimals: 2,
        })
        .stripe_api_base(&stripe_url)
        .secret_key("test-secret"),
    )
    .expect("failed to create Mpp");

    let mpp = Arc::new(mpp);
    let (url, handle) = start_server(mpp).await;

    let resp = Client::new()
        .get(format!("{url}/paid"))
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 402);

    let www_auth = resp
        .headers()
        .get("www-authenticate")
        .expect("missing WWW-Authenticate header")
        .to_str()
        .unwrap();

    let challenge = mpp::parse_www_authenticate(www_auth).expect("failed to parse challenge");
    let request: serde_json::Value = challenge
        .request
        .decode_value()
        .expect("failed to decode request");

    assert_eq!(
        request["methodDetails"]["networkId"], "test-network-id",
        "methodDetails.networkId should match configured network_id"
    );
    assert_eq!(
        request["methodDetails"]["paymentMethodTypes"],
        serde_json::json!(["card"]),
        "methodDetails.paymentMethodTypes should be [\"card\"]"
    );

    handle.abort();
    stripe_handle.abort();
}

/// e2e test for `stripe_charge_with_options` with description and external_id.
#[tokio::test]
async fn test_e2e_stripe_charge_with_description() {
    let (stripe_url, stripe_handle) = start_mock_stripe().await;

    let mpp = Mpp::create_stripe(
        stripe(StripeConfig {
            secret_key: "sk_test_mock",
            network_id: "test-net",
            payment_method_types: &["card"],
            currency: "usd",
            decimals: 2,
        })
        .stripe_api_base(&stripe_url)
        .secret_key("test-secret"),
    )
    .expect("failed to create Mpp");

    let mpp = Arc::new(mpp);
    let (url, handle) = start_server(mpp).await;

    // Check 402 has description
    let resp = Client::new()
        .get(format!("{url}/paid-premium"))
        .send()
        .await
        .expect("request failed");
    assert_eq!(resp.status(), 402);

    let www_auth = resp
        .headers()
        .get("www-authenticate")
        .expect("missing header")
        .to_str()
        .unwrap();
    assert!(
        www_auth.contains("description="),
        "challenge should contain description"
    );

    let challenge = mpp::parse_www_authenticate(www_auth).expect("failed to parse");
    assert_eq!(challenge.description.as_deref(), Some("Premium content"));

    let request: serde_json::Value = challenge
        .request
        .decode_value()
        .expect("failed to decode request");
    assert_eq!(request["description"], "Premium content");
    assert_eq!(request["externalId"], "premium-001");

    // Also verify full e2e with payment
    let provider = StripeProvider::new(|_params| {
        Box::pin(async move { Ok(CreateTokenResult::from("spt_premium_token".to_string())) })
    });

    let resp = Client::new()
        .get(format!("{url}/paid-premium"))
        .send_with_payment(&provider)
        .await
        .expect("payment failed");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"], "premium content");

    handle.abort();
    stripe_handle.abort();
}

/// Stripe API returning an error body should result in failed verification.
#[tokio::test]
async fn test_stripe_error_body_parsing() {
    let (stripe_url, stripe_handle) = start_mock_stripe_error().await;

    let mpp = Mpp::create_stripe(
        stripe(StripeConfig {
            secret_key: "sk_test_mock",
            network_id: "internal",
            payment_method_types: &["card"],
            currency: "usd",
            decimals: 2,
        })
        .stripe_api_base(&stripe_url)
        .secret_key("test-secret"),
    )
    .expect("create mpp");

    let mpp = Arc::new(mpp);
    let (url, handle) = start_server(mpp).await;

    let provider = StripeProvider::new(|_| {
        Box::pin(async move { Ok(CreateTokenResult::from("spt_bad_token".to_string())) })
    });

    let resp = Client::new()
        .get(format!("{url}/paid"))
        .send_with_payment(&provider)
        .await;

    // Should get 402 back (server verification failed, re-issues challenge)
    if let Ok(r) = resp {
        assert_eq!(r.status(), 402, "should get 402 when Stripe returns error");
    }

    handle.abort();
    stripe_handle.abort();
}

/// The `MppCharge` extractor works with Stripe's `ChargeChallenger` impl.
#[tokio::test]
async fn test_stripe_charge_via_mpp_charge_extractor() {
    let (stripe_url, stripe_handle) = start_mock_stripe().await;

    let mpp = Mpp::create_stripe(
        stripe(StripeConfig {
            secret_key: "sk_test_mock",
            network_id: "extractor-net",
            payment_method_types: &["card"],
            currency: "usd",
            decimals: 2,
        })
        .stripe_api_base(&stripe_url)
        .secret_key("test-secret"),
    )
    .expect("failed to create Mpp");

    let mpp = Arc::new(mpp);
    let (url, handle) = start_server_with_extractor(mpp).await;

    // Without auth → expect 402 challenge
    let resp = Client::new()
        .get(format!("{url}/paid-extractor"))
        .send()
        .await
        .expect("request failed");
    assert_eq!(resp.status(), 402);

    let www_auth = resp
        .headers()
        .get("www-authenticate")
        .expect("missing WWW-Authenticate header")
        .to_str()
        .unwrap();
    let challenge = mpp::parse_www_authenticate(www_auth).expect("failed to parse challenge");
    assert_eq!(challenge.method.as_str(), "stripe");
    assert_eq!(challenge.intent.as_str(), "charge");

    // With payment → expect 200
    let provider = StripeProvider::new(|_params| {
        Box::pin(async move { Ok(CreateTokenResult::from("spt_extractor_token".to_string())) })
    });

    let resp = Client::new()
        .get(format!("{url}/paid-extractor"))
        .send_with_payment(&provider)
        .await
        .expect("payment failed");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"], "paid via extractor");
    assert_eq!(body["method"], "stripe");

    handle.abort();
    stripe_handle.abort();
}

// ==================== Live Stripe API Tests ====================
//
// These tests call the real Stripe test-mode API. Skipped at runtime
// when STRIPE_SECRET_KEY is not set (same pattern as mppx).

fn stripe_secret_key() -> Option<String> {
    std::env::var("STRIPE_SECRET_KEY")
        .ok()
        .filter(|s| !s.is_empty())
}

/// Create a test SPT via Stripe's test helper endpoint.
async fn create_test_spt(
    secret_key: &str,
    amount: &str,
    currency: &str,
    network_id: Option<&str>,
    expires_at: u64,
) -> Result<String, String> {
    let base_params = vec![
        ("payment_method".to_string(), "pm_card_visa".to_string()),
        ("usage_limits[currency]".to_string(), currency.to_string()),
        ("usage_limits[max_amount]".to_string(), amount.to_string()),
        (
            "usage_limits[expires_at]".to_string(),
            expires_at.to_string(),
        ),
    ];

    let mut params = base_params.clone();
    if let Some(nid) = network_id {
        params.push(("seller_details[network_id]".to_string(), nid.to_string()));
    }

    let auth = format!(
        "Basic {}",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{secret_key}:")
        )
    );

    let client = Client::new();
    let url = "https://api.stripe.com/v1/test_helpers/shared_payment/granted_tokens";

    let response = client
        .post(url)
        .header("Authorization", &auth)
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    // Fallback: retry without seller_details if Stripe rejects it
    // (matches mppx's fallback in Charge.integration.test.ts).
    let response = if !response.status().is_success() && network_id.is_some() {
        let body = response.text().await.unwrap_or_default();
        if body.contains("Received unknown parameter") {
            client
                .post(url)
                .header("Authorization", &auth)
                .form(&base_params)
                .send()
                .await
                .map_err(|e| format!("fallback request failed: {e}"))?
        } else {
            return Err(format!("Stripe SPT creation failed: {body}"));
        }
    } else {
        response
    };

    if !response.status().is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Stripe SPT creation failed: {body}"));
    }

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("parse error: {e}"))?;

    body["id"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "missing id in SPT response".to_string())
}

fn create_live_mpp(secret_key: &str) -> Mpp<mpp::protocol::methods::stripe::method::ChargeMethod> {
    Mpp::create_stripe(
        stripe(StripeConfig {
            secret_key,
            network_id: "internal",
            payment_method_types: &["card"],
            currency: "usd",
            decimals: 2,
        })
        .secret_key("live-test-hmac-secret"),
    )
    .expect("failed to create Mpp")
}

/// Live: create a real SPT, build credential, verify against Stripe.
#[tokio::test]
async fn test_live_stripe_charge_success() {
    let Some(sk) = stripe_secret_key() else {
        eprintln!("STRIPE_SECRET_KEY not set, skipping");
        return;
    };

    let mpp = create_live_mpp(&sk);
    let challenge = mpp.stripe_charge("0.50").expect("challenge creation");

    let request: serde_json::Value = challenge.request.decode_value().expect("decode request");
    let amount = request["amount"].as_str().expect("amount");
    assert_eq!(amount, "50");

    let expires_at = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs())
        + 3600;

    let spt = create_test_spt(&sk, amount, "usd", Some("internal"), expires_at)
        .await
        .expect("SPT creation failed");
    assert!(spt.starts_with("spt_"), "got: {spt}");

    let credential = PaymentCredential::new(
        challenge.to_echo(),
        StripeCredentialPayload {
            spt,
            external_id: None,
        },
    );

    let receipt = mpp
        .verify_credential(&credential)
        .await
        .expect("verification failed");
    assert!(receipt.is_success());
    assert_eq!(receipt.method.as_str(), "stripe");
    assert!(receipt.reference.starts_with("pi_"));
}

/// Live: invalid SPT should be rejected by Stripe.
#[tokio::test]
async fn test_live_stripe_invalid_spt_rejected() {
    let Some(sk) = stripe_secret_key() else {
        eprintln!("STRIPE_SECRET_KEY not set, skipping");
        return;
    };

    let mpp = create_live_mpp(&sk);
    let challenge = mpp.stripe_charge("0.10").expect("challenge creation");

    let credential = PaymentCredential::new(
        challenge.to_echo(),
        StripeCredentialPayload {
            spt: "spt_invalid_does_not_exist".to_string(),
            external_id: None,
        },
    );

    let result = mpp.verify_credential(&credential).await;
    assert!(result.is_err(), "invalid SPT should fail verification");
}
