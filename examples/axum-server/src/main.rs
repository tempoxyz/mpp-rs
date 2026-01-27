//! Axum server example demonstrating mpay payment gating.
//!
//! Run with: `cargo run`
//! Then test with:
//!   curl http://localhost:3000/free
//!   curl http://localhost:3000/paid
//!   curl http://localhost:3000/resource/abc123

use axum::{
    async_trait,
    extract::{FromRequestParts, Path},
    http::{header, request::Parts, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use mpay::{
    Challenge::PaymentChallenge,
    Credential::PaymentCredential,
    Receipt::{format_receipt, PaymentReceipt, ReceiptStatus},
    Schema::{Base64UrlJson, PAYMENT_RECEIPT_HEADER},
};

const REALM: &str = "api.example.com";
const USDC_ADDRESS: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const MERCHANT_ADDRESS: &str = "0x1234567890123456789012345678901234567890";

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/free", get(free_endpoint))
        .route("/paid", get(paid_endpoint))
        .route("/resource/{id}", get(dynamic_pricing_endpoint))
        .route("/clean", get(clean_endpoint));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listening on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn free_endpoint() -> &'static str {
    "Free content - no payment required!"
}

async fn paid_endpoint(headers: HeaderMap) -> impl IntoResponse {
    if let Some(auth) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth.to_str() {
            if let Ok(credential) = parse_credential(auth_str) {
                if verify_payment(&credential).await.is_ok() {
                    let receipt = PaymentReceipt {
                        status: ReceiptStatus::Success,
                        method: credential.challenge.method.clone(),
                        timestamp: chrono_now(),
                        reference: credential.payload.signature.clone(),
                        block_number: None,
                        error: None,
                    };

                    return (
                        StatusCode::OK,
                        [(
                            header::HeaderName::from_static(PAYMENT_RECEIPT_HEADER),
                            format_receipt(&receipt).unwrap(),
                        )],
                        "Here's your paid content!",
                    )
                        .into_response();
                }
            }
        }
    }

    let challenge = create_challenge(1_000_000, None);
    let header = format_www_authenticate(&challenge);

    (
        StatusCode::PAYMENT_REQUIRED,
        [(header::WWW_AUTHENTICATE, header)],
        "Payment required",
    )
        .into_response()
}

async fn dynamic_pricing_endpoint(
    headers: HeaderMap,
    Path(resource_id): Path<String>,
) -> impl IntoResponse {
    if let Some(auth) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth.to_str() {
            if let Ok(credential) = parse_credential(auth_str) {
                if verify_payment(&credential).await.is_ok() {
                    let receipt = PaymentReceipt {
                        status: ReceiptStatus::Success,
                        method: credential.challenge.method.clone(),
                        timestamp: chrono_now(),
                        reference: credential.payload.signature.clone(),
                        block_number: None,
                        error: None,
                    };

                    return (
                        StatusCode::OK,
                        [(
                            header::HeaderName::from_static(PAYMENT_RECEIPT_HEADER),
                            format_receipt(&receipt).unwrap(),
                        )],
                        format!("Content for resource: {}", resource_id),
                    )
                        .into_response();
                }
            }
        }
    }

    let price = get_resource_price(&resource_id);
    let challenge = create_challenge(price, Some(&resource_id));
    let header = format_www_authenticate(&challenge);

    (
        StatusCode::PAYMENT_REQUIRED,
        [(header::WWW_AUTHENTICATE, header)],
        "Payment required",
    )
        .into_response()
}

async fn clean_endpoint(RequirePayment(credential): RequirePayment) -> impl IntoResponse {
    let receipt = PaymentReceipt {
        status: ReceiptStatus::Success,
        method: credential.challenge.method.clone(),
        timestamp: chrono_now(),
        reference: credential.payload.signature.clone(),
        block_number: None,
        error: None,
    };

    (
        StatusCode::OK,
        [(
            header::HeaderName::from_static(PAYMENT_RECEIPT_HEADER),
            format_receipt(&receipt).unwrap(),
        )],
        format!("Paid by: {:?}", credential.source),
    )
}

struct RequirePayment(PaymentCredential);

#[async_trait]
impl<S> FromRequestParts<S> for RequirePayment
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, [(header::HeaderName, String); 1], &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok());

        if let Some(auth_str) = auth {
            if let Ok(credential) = parse_credential(auth_str) {
                if verify_payment(&credential).await.is_ok() {
                    return Ok(RequirePayment(credential));
                }
            }
        }

        let challenge = create_challenge(1_000_000, None);
        let header = format_www_authenticate(&challenge);

        Err((
            StatusCode::PAYMENT_REQUIRED,
            [(header::WWW_AUTHENTICATE, header)],
            "Payment required",
        ))
    }
}

fn create_challenge(amount: u64, memo: Option<&str>) -> PaymentChallenge {
    let mut request = serde_json::json!({
        "amount": amount.to_string(),
        "asset": USDC_ADDRESS,
        "destination": MERCHANT_ADDRESS,
    });

    if let Some(m) = memo {
        request["memo"] = serde_json::Value::String(m.to_string());
    }

    PaymentChallenge {
        id: uuid::Uuid::new_v4().to_string(),
        realm: REALM.to_string(),
        method: "tempo".into(),
        intent: "charge".into(),
        request: Base64UrlJson::from_value(&request).unwrap(),
        digest: None,
        expires: None,
        description: None,
    }
}

fn format_www_authenticate(challenge: &PaymentChallenge) -> String {
    mpay::protocol::core::format_www_authenticate(challenge).unwrap()
}

fn parse_credential(auth: &str) -> Result<PaymentCredential, mpay::MppError> {
    mpay::protocol::core::parse_authorization(auth)
}

async fn verify_payment(_credential: &PaymentCredential) -> Result<(), &'static str> {
    Ok(())
}

fn get_resource_price(resource_id: &str) -> u64 {
    match resource_id.len() {
        0..=5 => 500_000,
        6..=10 => 1_000_000,
        _ => 2_000_000,
    }
}

fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    format!("{}Z", duration.as_secs())
}
