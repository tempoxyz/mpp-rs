//! Tower payment layers mounted on an axum router through the public API only,
//! the way a downstream crate uses them.

#![cfg(all(feature = "tower", feature = "tempo"))]

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, Response, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use mpp::server::middleware::{PaymentBodyLayer, PaymentLayer};
use mpp::server::Mpp;
use mpp::{
    format_authorization, parse_www_authenticate, ChargeMethod, ChargeRequest, PaymentCredential,
    PaymentPayload, Receipt, VerificationError, PAYMENT_RECEIPT_HEADER, WWW_AUTHENTICATE_HEADER,
};
use tower::ServiceExt;

#[derive(Clone)]
struct MockMethod;

impl ChargeMethod for MockMethod {
    fn method(&self) -> &str {
        "tempo"
    }

    async fn verify(
        &self,
        _credential: &PaymentCredential,
        _request: &ChargeRequest,
    ) -> Result<Receipt, VerificationError> {
        Ok(Receipt::success("tempo", "0xabc123"))
    }
}

fn mpp() -> Mpp<MockMethod> {
    Mpp::new_with_config(
        MockMethod,
        "test-realm",
        "test-secret",
        "0x20c0000000000000000000000000000000000000",
        "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
    )
}

fn request(
    method: &str,
    uri: &str,
    authorization: Option<&str>,
    body: &'static str,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(authorization) = authorization {
        builder = builder.header(header::AUTHORIZATION, authorization);
    }
    builder.body(Body::from(body)).unwrap()
}

/// Answers the 402 challenge in `response` with a credential for it.
fn pay(response: &Response<Body>) -> String {
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    let challenge = response.headers()[WWW_AUTHENTICATE_HEADER]
        .to_str()
        .unwrap();
    let challenge = parse_www_authenticate(challenge).unwrap();
    let credential =
        PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xdeadbeef"));
    format_authorization(&credential).unwrap()
}

#[tokio::test]
async fn payment_layer_gates_axum_route() {
    let app = Router::new()
        .route("/premium", get(|| async { "paid" }))
        .route_layer(PaymentLayer::charge(&mpp(), "0.10").unwrap());

    let response = app
        .clone()
        .oneshot(request("GET", "/premium", None, ""))
        .await
        .unwrap();
    let authorization = pay(&response);

    let response = app
        .clone()
        .oneshot(request("GET", "/premium", Some(&authorization), ""))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key(PAYMENT_RECEIPT_HEADER));

    // `route_layer` only gates matched routes.
    let response = app
        .oneshot(request("GET", "/missing", None, ""))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn payment_layer_gates_whole_axum_router() {
    let app = Router::new()
        .route("/premium", get(|| async { "paid" }))
        .layer(PaymentLayer::charge(&mpp(), "0.10").unwrap());

    let response = app
        .clone()
        .oneshot(request("GET", "/premium", None, ""))
        .await
        .unwrap();
    let authorization = pay(&response);

    let response = app
        .oneshot(request("GET", "/premium", Some(&authorization), ""))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn payment_body_layer_gates_axum_route() {
    let app = Router::new()
        .route("/search", post(|body: String| async move { body }))
        .route_layer(PaymentBodyLayer::charge(&mpp(), "0.10").unwrap());

    let response = app
        .clone()
        .oneshot(request("POST", "/search", None, "query"))
        .await
        .unwrap();
    let authorization = pay(&response);

    let response = app
        .clone()
        .oneshot(request("POST", "/search", Some(&authorization), "query"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], b"query");

    // The credential is bound to the body it was issued for.
    let response = app
        .oneshot(request("POST", "/search", Some(&authorization), "other"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
}
