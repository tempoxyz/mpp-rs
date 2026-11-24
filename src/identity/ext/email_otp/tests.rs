//! End-to-end tests: a fake email OTP issuer, a route whose
//! [`RouteIdentity`] requires a verified email, and a
//! [`ChargeClient`](crate::client::ChargeClient) proving with an [`EmailOtpProver`].

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::http::StatusCode as AxumStatus;
use axum::response::{IntoResponse, Response as AxumResponse};
use axum::routing::{get, post};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};

use super::{EmailOtpProver, EmailOtpVerifier, VerifiedEmail};
use crate::client::{ChargeClient, PaymentProvider};
use crate::error::MppError;
use crate::identity::client::{IdentityClient, Prover};
use crate::identity::ext::attestation::token::tests::{signing_key, KID};
use crate::identity::ext::attestation::{sign, AttestationProver, HEADER};
use crate::identity::{Handle, IdentityContext, IdentityRequest, RouteIdentity};
use crate::protocol::core::{PaymentChallenge, PaymentCredential};

/// A fake issuer: emails code `123456` for any address and signs 15-minute
/// attestations for the requested audience.
async fn issuer(codes_sent: Arc<AtomicUsize>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let iss = base.clone();
    let pending: Arc<std::sync::Mutex<Option<(String, String)>>> = Arc::default();
    let pending_otp = pending.clone();
    let app = axum::Router::new()
        .route(
            "/.well-known/jwks.json",
            get(|| async {
                axum::Json(json!({ "keys": [{
                    "kty": "OKP", "crv": "Ed25519", "kid": KID, "alg": "EdDSA", "use": "sig",
                    "x": URL_SAFE_NO_PAD.encode(signing_key().verifying_key().as_bytes()),
                }]}))
            }),
        )
        .route(
            "/email/otp",
            post(move |axum::Json(body): axum::Json<Value>| {
                let (pending, codes_sent) = (pending_otp.clone(), codes_sent.clone());
                async move {
                    codes_sent.fetch_add(1, Ordering::SeqCst);
                    *pending.lock().unwrap() = Some((
                        body["email"].as_str().unwrap().to_string(),
                        body["audience"].as_str().unwrap().to_string(),
                    ));
                    axum::Json(json!({ "id": "otp_1", "expires_at": "2030-01-01T00:00:00Z" }))
                }
            }),
        )
        .route(
            "/email/verify",
            post(move |axum::Json(body): axum::Json<Value>| {
                let (pending, iss) = (pending.clone(), iss.clone());
                async move {
                    let Some((email, audience)) = pending.lock().unwrap().clone() else {
                        return (
                            AxumStatus::BAD_REQUEST,
                            axum::Json(json!({"error": "No code."})),
                        );
                    };
                    if body["code"] != "123456" {
                        return (
                            AxumStatus::BAD_REQUEST,
                            axum::Json(json!({"error": "Invalid code."})),
                        );
                    }
                    let now = crate::identity::ext::attestation::now();
                    let attestation = sign(
                        &json!({
                            "iss": iss, "aud": audience, "sub": email, "type": "email",
                            "iat": now, "exp": now + 900, "jti": format!("att_{now}"),
                        }),
                        &signing_key(),
                        KID,
                    )
                    .unwrap();
                    (
                        AxumStatus::OK,
                        axum::Json(
                            json!({ "attestation": attestation, "expires_at": "2030-01-01T00:15:00Z" }),
                        ),
                    )
                }
            }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    base
}

/// A server whose `/hello` route requires a verified email through its
/// [`RouteIdentity`], counting rejections.
async fn server(issuer: String, rejections: Arc<AtomicUsize>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let email = Handle::new(EmailOtpVerifier::new(base.clone(), issuer).unwrap());
    let route = RouteIdentity::new().verifier(&email);
    let app = axum::Router::new().route(
        "/hello",
        get(move |parts: axum::http::request::Parts| {
            let (route, email, rejections) = (route.clone(), email.clone(), rejections.clone());
            async move {
                let context = IdentityContext::new(IdentityRequest::from_parts(&parts));
                match route.verify_request(&context).await {
                    Ok(call) => {
                        let results = call.results();
                        let verified: &VerifiedEmail = results.get(&email).unwrap();
                        format!("hello {}", verified.email).into_response()
                    }
                    Err(rejection) => {
                        rejections.fetch_add(1, Ordering::SeqCst);
                        let (head, body) = rejection.into_response().into_parts();
                        AxumResponse::from_parts(head, axum::body::Body::from(body))
                    }
                }
            }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    base
}

/// A provider for routes that never ask for payment.
#[derive(Clone)]
struct NoPayment;

impl PaymentProvider for NoPayment {
    fn supports(&self, _method: &str, _intent: &str) -> bool {
        false
    }

    async fn pay(&self, _challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
        Err(MppError::Internal("these routes are free".into()))
    }
}

struct Setup {
    api: String,
    issuer: String,
    prover: AttestationProver,
    client: ChargeClient,
    codes_sent: Arc<AtomicUsize>,
    prompts: Arc<AtomicUsize>,
    rejections: Arc<AtomicUsize>,
}

fn charge_client(prover: &AttestationProver) -> ChargeClient {
    let provers: Vec<Arc<dyn Prover>> = vec![Arc::new(prover.clone())];
    ChargeClient::new(reqwest::Client::builder())
        .unwrap()
        .with_identity(IdentityClient::new(provers).unwrap())
}

async fn setup() -> Setup {
    let codes_sent = Arc::new(AtomicUsize::new(0));
    let rejections = Arc::new(AtomicUsize::new(0));
    let prompts = Arc::new(AtomicUsize::new(0));
    let issuer = issuer(codes_sent.clone()).await;
    let api = server(issuer.clone(), rejections.clone()).await;
    let counter = prompts.clone();
    let prover = EmailOtpProver::new(
        "Me@Example.com",
        [issuer.clone()],
        [api.clone()],
        move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            async { Some("123456".to_string()) }
        },
    )
    .build()
    .unwrap();
    Setup {
        client: charge_client(&prover),
        api,
        issuer,
        prover,
        codes_sent,
        prompts,
        rejections,
    }
}

async fn get_hello(client: &ChargeClient, api: &str) -> reqwest::Response {
    client
        .send_with_payment(
            client.request(Method::GET, format!("{api}/hello")),
            &NoPayment,
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn obtains_an_attestation_then_reuses_it() {
    let s = setup().await;
    let response = get_hello(&s.client, &s.api).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "hello me@example.com");
    assert_eq!(s.rejections.load(Ordering::SeqCst), 1);
    assert_eq!(s.codes_sent.load(Ordering::SeqCst), 1);
    assert_eq!(s.prompts.load(Ordering::SeqCst), 1);

    // The cached attestation goes on the first try.
    let response = get_hello(&s.client, &s.api).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(s.rejections.load(Ordering::SeqCst), 1);
    assert_eq!(s.codes_sent.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn concurrent_retries_share_one_acquisition() {
    let s = setup().await;
    let (a, b) = tokio::join!(get_hello(&s.client, &s.api), get_hello(&s.client, &s.api));
    assert_eq!(a.status(), StatusCode::OK);
    assert_eq!(b.status(), StatusCode::OK);
    assert_eq!(s.codes_sent.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn out_of_scope_requests_are_left_alone() {
    let s = setup().await;
    let prompts = s.prompts.clone();
    let elsewhere = EmailOtpProver::new(
        "me@example.com",
        ["http://127.0.0.1:1"],
        ["https://elsewhere.example"],
        move |_| {
            prompts.fetch_add(1, Ordering::SeqCst);
            async { Some("123456".to_string()) }
        },
    )
    .build()
    .unwrap();
    let response = get_hello(&charge_client(&elsewhere), &s.api).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers()["identity-attestation-required"]
            .to_str()
            .unwrap(),
        format!("email;issuer=\"{}\"", s.issuer),
    );
    assert_eq!(s.prompts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_attestation_is_never_sent_to_another_audience() {
    let s = setup().await;
    let now = crate::identity::ext::attestation::now();
    let foreign = sign(
        &json!({"iss": "https://issuer.example", "aud": "https://other.example",
                "sub": "x@example.com", "type": "email", "iat": now, "exp": now + 900}),
        &signing_key(),
        KID,
    )
    .unwrap();
    s.prover.insert(&foreign).unwrap();
    let mut request =
        reqwest::Request::new(Method::GET, format!("{}/hello", s.api).parse().unwrap());
    s.prover.present(&mut request, false);
    assert!(request.headers().get(HEADER).is_none());
}
