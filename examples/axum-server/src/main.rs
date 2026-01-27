//! axum server example demonstrating payment-gated endpoints with mpay.
//!
//! Run with: `MERCHANT_ADDRESS=0x... cargo run`
//!
//! Then test:
//! - GET http://localhost:3000/free → 200 OK (no payment)
//! - GET http://localhost:3000/paid → 402 Payment Required (needs credential)

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{header, request::Parts, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use mpay::{Challenge, Credential, Receipt, Schema};
use std::sync::LazyLock;

const REALM: &str = "api.example.com";
const ALPHA_USD: &str = "0x20c0000000000000000000000000000000000001";

static MERCHANT_ADDRESS: LazyLock<String> = LazyLock::new(|| {
    std::env::var("MERCHANT_ADDRESS")
        .expect("MERCHANT_ADDRESS environment variable must be set")
});

#[tokio::main]
async fn main() {
    LazyLock::force(&MERCHANT_ADDRESS);

    let app = Router::new()
        .route("/free", get(free_endpoint))
        .route("/paid", get(paid_endpoint));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listening on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn free_endpoint() -> impl IntoResponse {
    "Free content - no payment required"
}

async fn paid_endpoint(headers: HeaderMap) -> impl IntoResponse {
    if let Some(auth) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth.to_str() {
            if let Ok(credential) = Credential::parse_authorization(auth_str) {
                if verify_payment(&credential).await.is_ok() {
                    let receipt = Receipt::Receipt::success("tempo", "0x...");

                    if let Ok(receipt_header) = Receipt::format_receipt(&receipt) {
                        return (
                            StatusCode::OK,
                            [(
                                header::HeaderName::from_static("payment-receipt"),
                                receipt_header,
                            )],
                            "Here's your paid content!",
                        )
                            .into_response();
                    }
                }
            }
        }
    }

    let challenge = Challenge::PaymentChallenge {
        id: uuid::Uuid::new_v4().to_string(),
        realm: REALM.to_string(),
        method: "tempo".into(),
        intent: "charge".into(),
        request: Schema::Base64UrlJson::from_value(&serde_json::json!({
            "amount": "1000000",
            "currency": ALPHA_USD,
            "recipient": &*MERCHANT_ADDRESS
        }))
        .unwrap(),
        expires: None,
        description: None,
    };

    match Challenge::format_www_authenticate(&challenge) {
        Ok(www_auth) => (
            StatusCode::PAYMENT_REQUIRED,
            [(header::WWW_AUTHENTICATE, www_auth)],
            "Payment required",
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

struct RequirePayment(Credential::PaymentCredential);

#[async_trait]
impl<S> FromRequestParts<S> for RequirePayment
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or((StatusCode::PAYMENT_REQUIRED, "Missing authorization".into()))?;

        let credential = Credential::parse_authorization(auth)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

        Ok(RequirePayment(credential))
    }
}

#[allow(dead_code)]
async fn handler_with_extractor(RequirePayment(credential): RequirePayment) -> impl IntoResponse {
    format!("Paid by: {:?}", credential.source)
}

async fn verify_payment(_credential: &Credential::PaymentCredential) -> Result<(), ()> {
    Ok(())
}
