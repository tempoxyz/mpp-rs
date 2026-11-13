//! Interop tests for email OTP identity against a real issuer and, optionally,
//! an mppx server.
//!
//! Skipped unless `MPP_IDENTITY_ISSUER` is set. Run Tempo's issuer
//! (tempoxyz/tempo-apps `apps/mpp-identity`) locally with `DEV_LOG_OTP=true`,
//! which logs `OTP for <id>: <code>` instead of emailing it, and point
//! `MPP_IDENTITY_OTP_LOG` at its log:
//!
//! ```bash
//! pnpm keygen && pnpm dev > /tmp/mpp-identity.log 2>&1 &   # in apps/mpp-identity
//! MPP_IDENTITY_ISSUER=http://localhost:8787 MPP_IDENTITY_OTP_LOG=/tmp/mpp-identity.log \
//!   cargo test --features identity-email-otp,client,axum --test identity_issuer -- --nocapture
//! ```
//!
//! - `MPP_IDENTITY_ATTESTATION_OUT`: write the attestation the Rust server
//!   accepted, and its audience, as JSON, for another SDK to verify.
//! - `MPP_IDENTITY_MPPX_URL`: a URL on an mppx server that requires
//!   `EmailOtp` from the same issuer; the Rust client must get a 200 from it.

#![cfg(all(feature = "identity-email-otp", feature = "client", feature = "axum"))]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::get;
use mpp::client::{ChargeClient, PaymentProvider};
use mpp::identity::client::{IdentityClient, Prover};
use mpp::identity::ext::attestation::HEADER;
use mpp::identity::ext::email_otp::{CodeContext, EmailOtpProver, EmailOtpVerifier};
use mpp::protocol::core::{PaymentChallenge, PaymentCredential};
use mpp::MppError;

const EMAIL: &str = "Interop@Example.com";

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// Reads the code the issuer logged for `ctx.id`, waiting up to 30 seconds.
async fn logged_code(ctx: CodeContext) -> Option<String> {
    let log = env("MPP_IDENTITY_OTP_LOG")?;
    let needle = format!("OTP for {}: ", ctx.id);
    for _ in 0..300 {
        if let Ok(text) = std::fs::read_to_string(&log) {
            if let Some(rest) = text.split(needle.as_str()).nth(1) {
                let code: String = rest.chars().take_while(char::is_ascii_digit).collect();
                if !code.is_empty() {
                    return Some(code);
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

/// A client that proves with an email OTP prover for `origin`.
fn client(issuer: &str, origin: &str) -> ChargeClient {
    let prover = EmailOtpProver::new(EMAIL, [issuer], [origin], logged_code)
        .build()
        .expect("prover");
    let provers: Vec<Arc<dyn Prover>> = vec![Arc::new(prover)];
    ChargeClient::new(reqwest::Client::builder())
        .expect("client")
        .with_identity(IdentityClient::new(provers).expect("identity client"))
}

/// A provider for routes that never ask for payment.
#[derive(Clone)]
struct NoPayment;

impl PaymentProvider for NoPayment {
    fn supports(&self, _method: &str, _intent: &str) -> bool {
        false
    }

    async fn pay(&self, _challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
        Err(MppError::Internal("this route is free".into()))
    }
}

async fn get_url(client: &ChargeClient, url: &str) -> reqwest::Response {
    client
        .send_with_payment(client.request(reqwest::Method::GET, url), &NoPayment)
        .await
        .expect("request")
}

#[tokio::test]
async fn rust_client_and_verifier_against_issuer() {
    let Some(issuer) = env("MPP_IDENTITY_ISSUER") else {
        eprintln!("MPP_IDENTITY_ISSUER not set, skipping");
        return;
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let verifier = EmailOtpVerifier::new(origin.clone(), issuer.clone()).unwrap();
    let accepted: Arc<Mutex<Option<String>>> = Arc::default();
    let seen = accepted.clone();
    let app = axum::Router::new().route(
        "/hello",
        get(move |headers: HeaderMap| {
            let (verifier, seen) = (verifier.clone(), seen.clone());
            async move {
                match verifier.verify_headers(&headers).await {
                    Ok(verified) => {
                        *seen.lock().unwrap() = headers
                            .get(HEADER)
                            .and_then(|value| value.to_str().ok())
                            .map(String::from);
                        format!("hello {}", verified.email).into_response()
                    }
                    Err(rejection) => {
                        let mut response =
                            (rejection.status.code(), rejection.reason).into_response();
                        response.headers_mut().extend(rejection.headers);
                        response
                    }
                }
            }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let client = client(&issuer, &origin);
    let url = format!("{origin}/hello");
    let response = get_url(&client, &url).await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "hello interop@example.com");

    // The cached attestation is sent first; no new code is needed.
    let first = accepted.lock().unwrap().clone().expect("attestation");
    let response = get_url(&client, &url).await;
    assert_eq!(response.status(), 200);
    assert_eq!(accepted.lock().unwrap().as_deref(), Some(first.as_str()));

    // An attestation for this origin is refused by a server at another origin.
    let elsewhere = EmailOtpVerifier::new("http://localhost:1", issuer.clone()).unwrap();
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(HEADER, first.parse().unwrap());
    let rejection = elsewhere.verify_headers(&headers).await.unwrap_err();
    assert_eq!(rejection.reason, "The attestation is for another audience.");

    if let Some(out) = env("MPP_IDENTITY_ATTESTATION_OUT") {
        let body =
            serde_json::json!({ "attestation": first, "audience": origin, "issuer": issuer });
        std::fs::write(out, body.to_string()).unwrap();
    }
}

#[tokio::test]
async fn rust_client_against_mppx_server() {
    let (Some(issuer), Some(url)) = (env("MPP_IDENTITY_ISSUER"), env("MPP_IDENTITY_MPPX_URL"))
    else {
        eprintln!("MPP_IDENTITY_ISSUER or MPP_IDENTITY_MPPX_URL not set, skipping");
        return;
    };
    let origin = reqwest::Url::parse(&url)
        .unwrap()
        .origin()
        .ascii_serialization();
    let response = get_url(&client(&issuer, &origin), &url).await;
    let status = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(status, 200, "{body}");
    eprintln!("mppx answered: {body}");
}
