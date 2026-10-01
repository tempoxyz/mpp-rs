//! Rejected credentials as answered by the axum extractor and the tower
//! layer, through the public API only.

#![cfg(all(feature = "axum", feature = "tower", feature = "tempo"))]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use axum::routing::get;
use axum::Router;
use mpp::server::axum::{ChallengeOptions, ChargeChallenger, ChargeConfig, MppCharge};
use mpp::server::middleware::PaymentLayer;
use mpp::server::{ChargeOptions, Mpp};
use mpp::{
    compute_challenge_id, format_authorization, parse_authorization, parse_www_authenticate,
    ChargeMethod, ChargeRequest, MppError, PaymentChallenge, PaymentCredential, PaymentPayload,
    Receipt, VerificationError, WWW_AUTHENTICATE_HEADER,
};
use tower::ServiceExt;

const SECRET: &str = "test-secret-key-at-least-32-bytes";

struct TenCents;
impl ChargeConfig for TenCents {
    fn amount() -> &'static str {
        "0.10"
    }
}

/// Fails verification with the configured error, if any.
#[derive(Clone)]
struct MockMethod(Option<VerificationError>);

impl ChargeMethod for MockMethod {
    fn method(&self) -> &str {
        "tempo"
    }

    async fn verify(
        &self,
        _credential: &PaymentCredential,
        _request: &ChargeRequest,
    ) -> Result<Receipt, VerificationError> {
        match self.0.clone() {
            Some(error) => Err(error),
            None => Ok(Receipt::success("tempo", "0xabc123")),
        }
    }
}

fn mpp(method_error: Option<VerificationError>) -> Mpp<MockMethod> {
    Mpp::new_with_config(
        MockMethod(method_error),
        "test-realm",
        SECRET,
        "0x20c0000000000000000000000000000000000000",
        "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
    )
}

struct Challenger(Mpp<MockMethod>);

impl ChargeChallenger for Challenger {
    fn challenge(
        &self,
        amount: &str,
        options: ChallengeOptions,
    ) -> Result<PaymentChallenge, String> {
        self.0
            .charge_with_options(
                amount,
                ChargeOptions {
                    description: options.description,
                    mppx_scope: options.mppx_scope.as_ref(),
                    ..Default::default()
                },
            )
            .map(|mut offers| offers.remove(0))
            .map_err(|e| e.to_string())
    }

    fn verify_payment(
        &self,
        _credential: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Receipt, String>> + Send>> {
        unreachable!("the extractor verifies through verify_payment_for_route")
    }

    fn verify_payment_for_route(
        &self,
        credential: &str,
        amount: &str,
        mppx_scope: Option<serde_json::Value>,
        _body: Option<&[u8]>,
    ) -> Pin<Box<dyn Future<Output = Result<Receipt, MppError>> + Send>> {
        let prepared = parse_authorization(credential).and_then(|credential| {
            let options = ChargeOptions {
                mppx_scope: mppx_scope.as_ref(),
                ..Default::default()
            };
            let expected = self.0.charge_with_options(amount, options)?.remove(0);
            let expected: ChargeRequest = expected.request.decode()?;
            Ok((credential, expected))
        });
        let mpp = self.0.clone();
        Box::pin(async move {
            let (credential, expected) = prepared?;
            Ok(mpp
                .verify_credential_with_expected_request(&credential, &expected)
                .await?)
        })
    }
}

fn axum_extractor(mpp: Mpp<MockMethod>) -> Router {
    async fn paid(_charge: MppCharge<TenCents>) -> &'static str {
        "paid"
    }
    Router::new()
        .route("/paid", get(paid))
        .with_state(Arc::new(Challenger(mpp)) as Arc<dyn ChargeChallenger>)
}

fn tower_layer(mpp: Mpp<MockMethod>) -> Router {
    Router::new()
        .route("/paid", get(|| async { "paid" }))
        .route_layer(PaymentLayer::charge(&mpp, TenCents::amount()).unwrap())
}

fn request(authorization: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().uri("/paid");
    if let Some(authorization) = authorization {
        builder = builder.header(header::AUTHORIZATION, authorization);
    }
    builder.body(Body::empty()).unwrap()
}

fn valid(challenge: PaymentChallenge) -> String {
    let credential =
        PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xdeadbeef"));
    format_authorization(&credential).unwrap()
}

/// Re-issues the challenge with a past expiry, as this server would have.
fn expired(mut challenge: PaymentChallenge) -> String {
    let expires = "2020-01-01T00:00:00Z";
    challenge.id = compute_challenge_id(
        SECRET,
        &challenge.realm,
        challenge.method.as_str(),
        challenge.intent.as_str(),
        challenge.request.raw(),
        Some(expires),
        challenge.digest.as_deref(),
        challenge.opaque.as_ref().map(|opaque| opaque.raw()),
    );
    challenge.expires = Some(expires.to_string());
    valid(challenge)
}

fn tampered(mut challenge: PaymentChallenge) -> String {
    challenge.id = "forged".to_string();
    valid(challenge)
}

fn malformed(_challenge: PaymentChallenge) -> String {
    "Payment !!!".to_string()
}

struct Case {
    name: &'static str,
    /// Error the payment method fails verification with.
    method_error: Option<VerificationError>,
    /// Builds the submitted credential from a fresh challenge.
    credential: fn(PaymentChallenge) -> String,
    status: StatusCode,
    problem: &'static str,
}

#[tokio::test]
async fn rejected_credentials_are_answered_per_spec() {
    let cases = [
        Case {
            name: "expired",
            method_error: None,
            credential: expired,
            status: StatusCode::PAYMENT_REQUIRED,
            problem: "payment-expired",
        },
        Case {
            name: "tampered challenge",
            method_error: None,
            credential: tampered,
            status: StatusCode::PAYMENT_REQUIRED,
            problem: "invalid-challenge",
        },
        Case {
            name: "malformed credential",
            method_error: None,
            credential: malformed,
            status: StatusCode::PAYMENT_REQUIRED,
            problem: "malformed-credential",
        },
        Case {
            name: "verification failed",
            method_error: Some(VerificationError::new("transfer not found")),
            credential: valid,
            status: StatusCode::PAYMENT_REQUIRED,
            problem: "verification-failed",
        },
        Case {
            name: "rpc failure",
            method_error: Some(VerificationError::network_error("rpc unreachable")),
            credential: valid,
            status: StatusCode::INTERNAL_SERVER_ERROR,
            problem: "internal-payment-error",
        },
        Case {
            name: "store failure",
            method_error: Some(VerificationError::internal("store unavailable")),
            credential: valid,
            status: StatusCode::INTERNAL_SERVER_ERROR,
            problem: "internal-payment-error",
        },
    ];

    type Adapter = (&'static str, fn(Mpp<MockMethod>) -> Router, bool);
    // The tower layer is generic over the response body and cannot write one.
    let adapters: [Adapter; 2] = [
        ("axum extractor", axum_extractor, true),
        ("tower layer", tower_layer, false),
    ];

    for case in &cases {
        for (adapter, app, has_body) in adapters {
            let label = format!("{adapter}: {}", case.name);
            let app = app(mpp(case.method_error.clone()));

            let unpaid = app.clone().oneshot(request(None)).await.unwrap();
            assert_eq!(unpaid.status(), StatusCode::PAYMENT_REQUIRED, "{label}");
            let challenge = unpaid.headers()[WWW_AUTHENTICATE_HEADER].to_str().unwrap();
            let challenge = parse_www_authenticate(challenge).unwrap();

            let authorization = (case.credential)(challenge);
            let response = app.oneshot(request(Some(&authorization))).await.unwrap();

            assert_eq!(response.status(), case.status, "{label}");
            assert_eq!(
                response.headers()[header::CACHE_CONTROL],
                "no-store",
                "{label}"
            );
            // A fresh challenge asks the client to pay again, so it must not
            // accompany a failure that is the server's own.
            let fresh_challenge = response
                .headers()
                .get(WWW_AUTHENTICATE_HEADER)
                .map(|value| parse_www_authenticate(value.to_str().unwrap()).unwrap());
            assert_eq!(
                fresh_challenge.is_some(),
                case.status == StatusCode::PAYMENT_REQUIRED,
                "{label}"
            );

            if !has_body {
                continue;
            }
            assert_eq!(
                response.headers()[header::CONTENT_TYPE],
                "application/problem+json",
                "{label}"
            );
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let problem: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                problem["type"],
                format!("https://paymentauth.org/problems/{}", case.problem),
                "{label}"
            );
            assert_eq!(problem["status"], case.status.as_u16(), "{label}");
            assert_eq!(
                problem["challengeId"].as_str(),
                fresh_challenge
                    .as_ref()
                    .map(|challenge| challenge.id.as_str()),
                "{label}"
            );
            if case.status == StatusCode::INTERNAL_SERVER_ERROR {
                assert_eq!(
                    problem["detail"], "An internal payment error occurred.",
                    "{label}"
                );
            }
        }
    }
}
