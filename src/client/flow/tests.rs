//! Behaviour that `Fetch` and `PaymentMiddleware` must share.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::header::WWW_AUTHENTICATE;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use reqwest::header::{HeaderMap, HeaderValue, HOST};
use reqwest_middleware::ClientBuilder;
use tokio::net::TcpListener;

use crate::client::flow::{send_with_exchange, Exchange};
use crate::client::{
    AcceptPaymentPolicy, ClientEvents, Fetch, HttpError, PaymentContext, PaymentFailureReason,
    PaymentMiddleware, PaymentProvider,
};
use crate::error::MppError;
use crate::protocol::core::{
    format_www_authenticate, Base64UrlJson, PaymentChallenge, PaymentCredential, PaymentPayload,
};

const ACCEPT_PAYMENT: &str = "tempo/charge, tempo/session";

/// The two entry points into the payment flow.
#[derive(Clone, Copy, Debug)]
enum Via {
    Fetch,
    Middleware,
}

const BOTH: [Via; 2] = [Via::Fetch, Via::Middleware];

#[test]
fn caller_host_header_binds_proof_realm() {
    let challenge = PaymentChallenge::new(
        "proof-id",
        "api.example.com",
        "tempo",
        "charge",
        Base64UrlJson::from_value(&serde_json::json!({
            "amount": "0",
            "currency": "0x3333333333333333333333333333333333333333"
        }))
        .unwrap(),
    );
    let url = reqwest::Url::parse("http://127.0.0.1:8080/paid").unwrap();
    assert!(super::is_cross_realm_proof(
        &challenge,
        &url,
        &HeaderMap::new()
    ));

    let mut headers = HeaderMap::new();
    headers.insert(HOST, HeaderValue::from_static("api.example.com"));
    assert!(!super::is_cross_realm_proof(&challenge, &url, &headers));
    assert!(!super::is_cross_realm_proof_with_trust(
        &challenge,
        &url,
        &HeaderMap::new(),
        Some("api.example.com")
    ));
    assert!(super::is_cross_realm_proof_with_trust(
        &challenge,
        &url,
        &HeaderMap::new(),
        Some("API.example.com")
    ));
}

#[test]
fn websocket_urls_bind_their_host() {
    let socket = reqwest::Url::parse("ws://target.example:8546/rpc").unwrap();
    let secure = reqwest::Url::parse("wss://target.example/rpc").unwrap();
    for (intent, amount) in [("session", "100"), ("charge", "0")] {
        let challenge = PaymentChallenge::new(
            "ws-id",
            "target.example",
            "tempo",
            intent,
            Base64UrlJson::from_value(&serde_json::json!({
                "amount": amount,
                "currency": "0x3333333333333333333333333333333333333333"
            }))
            .unwrap(),
        );
        for url in [&socket, &secure] {
            assert!(
                !super::is_cross_realm_proof(&challenge, url, &HeaderMap::new()),
                "{intent} {url}"
            );
        }
        let other = reqwest::Url::parse("wss://relay.example/rpc").unwrap();
        assert!(super::is_cross_realm_proof(
            &challenge,
            &other,
            &HeaderMap::new()
        ));
    }
}

#[test]
fn session_challenges_bind_their_realm() {
    let relay = reqwest::Url::parse("https://relay.example/data").unwrap();
    let target = reqwest::Url::parse("https://target.example/data").unwrap();
    // A transport without an HTTP origin, such as an MCP resource.
    let opaque = reqwest::Url::parse("mcp://target.example/tool").unwrap();
    for amount in ["0", "100"] {
        let challenge = PaymentChallenge::new(
            "session-id",
            "target.example",
            "tempo",
            "session",
            Base64UrlJson::from_value(&serde_json::json!({ "amount": amount })).unwrap(),
        );
        assert!(super::is_cross_realm_proof(
            &challenge,
            &relay,
            &HeaderMap::new()
        ));
        assert!(!super::is_cross_realm_proof(
            &challenge,
            &target,
            &HeaderMap::new()
        ));
        assert!(!super::is_cross_realm_proof_with_trust(
            &challenge,
            &relay,
            &HeaderMap::new(),
            Some("target.example")
        ));
        assert!(super::is_cross_realm_proof(
            &challenge,
            &opaque,
            &HeaderMap::new()
        ));
        assert!(!super::is_cross_realm_proof_with_trust(
            &challenge,
            &opaque,
            &HeaderMap::new(),
            Some("target.example")
        ));
    }
    let subscription = PaymentChallenge::new(
        "subscription-id",
        "target.example",
        "tempo",
        "subscription",
        Base64UrlJson::from_value(&serde_json::json!({ "amount": "0" })).unwrap(),
    );
    assert!(!super::is_cross_realm_proof(
        &subscription,
        &relay,
        &HeaderMap::new()
    ));
}

#[tokio::test]
async fn foreign_session_realm_is_refused_before_signing() {
    for via in BOTH {
        let requests = Arc::new(AtomicU32::new(0));
        let app = Router::new().route(
            "/paid",
            get({
                let requests = requests.clone();
                move || async move {
                    requests.fetch_add(1, Ordering::SeqCst);
                    let request =
                        Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
                    let challenge = PaymentChallenge::new(
                        "foreign",
                        "target.example",
                        "tempo",
                        "session",
                        request,
                    );
                    (
                        StatusCode::PAYMENT_REQUIRED,
                        [(
                            WWW_AUTHENTICATE,
                            format_www_authenticate(&challenge).unwrap(),
                        )],
                    )
                        .into_response()
                }
            }),
        );
        let url = spawn_server(app).await;
        let provider = TestProvider::default();

        let request = reqwest::Client::new().get(format!("{url}/paid"));
        let err = via
            .send(request, &provider, ClientEvents::default())
            .await
            .unwrap_err();

        assert!(matches!(err, HttpError::CrossRealmProof), "{via:?}: {err}");
        assert!(
            err.to_string().contains("session payment"),
            "{via:?}: {err}"
        );
        assert!(provider.paid().is_empty(), "{via:?}");
        assert_eq!(requests.load(Ordering::SeqCst), 1, "{via:?}");
    }
}

impl Via {
    async fn send(
        self,
        request: reqwest::RequestBuilder,
        provider: &TestProvider,
        events: ClientEvents,
    ) -> Result<reqwest::Response, HttpError> {
        match self {
            Self::Fetch => {
                request
                    .send_with_payment_options(provider, &AcceptPaymentPolicy::Always, events)
                    .await
            }
            Self::Middleware => {
                let (client, request) = request.build_split();
                ClientBuilder::new(client.clone())
                    .with(
                        PaymentMiddleware::new(provider.clone())
                            .with_accept_payment_policy(AcceptPaymentPolicy::Always)
                            .with_http_client(client)
                            .with_events(events),
                    )
                    .build()
                    .execute(request.unwrap())
                    .await
                    .map_err(|err| match err {
                        reqwest_middleware::Error::Middleware(err) => err.downcast().unwrap(),
                        reqwest_middleware::Error::Reqwest(err) => HttpError::Request(err),
                    })
            }
        }
    }
}

#[derive(Clone, Default)]
struct TestProvider {
    /// Ask for a fresh challenge the first time one is prepared.
    refresh_first_challenge: bool,
    check_management_client: bool,
    prepared: Arc<AtomicU32>,
    paid: Arc<Mutex<Vec<String>>>,
    committed: Arc<AtomicU32>,
    rolled_back: Arc<AtomicU32>,
    invalidated: Arc<AtomicU32>,
    abandoned: Arc<AtomicU32>,
    /// Send a session voucher before the server asks for payment.
    prepaid: bool,
    /// The realm of the prepaid voucher's cached Challenge, when not the request's host.
    prepaid_realm: Option<&'static str>,
    /// The realm this caller pins for every origin.
    trusted_realm: Option<&'static str>,
    /// Payments that fail as a Zone withdrawal still settling before one succeeds.
    settling: Arc<AtomicU32>,
    /// Pay charges with a `zone` Credential instead of a hash.
    zone: bool,
}

impl TestProvider {
    fn paid(&self) -> Vec<String> {
        self.paid.lock().unwrap().clone()
    }
}

impl PaymentProvider for TestProvider {
    fn supports(&self, method: &str, _intent: &str) -> bool {
        method == "tempo"
    }

    fn trusted_tempo_proof_realm(&self, _url: &reqwest::Url) -> Option<&str> {
        self.trusted_realm
    }

    async fn prepare_http_payment_challenge(
        &self,
        challenge: &PaymentChallenge,
        _context: PaymentContext,
    ) -> Result<Option<PaymentChallenge>, MppError> {
        let first = self.prepared.fetch_add(1, Ordering::SeqCst) == 0;
        Ok((!(first && self.refresh_first_challenge)).then(|| challenge.clone()))
    }

    async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
        self.paid.lock().unwrap().push(challenge.id.clone());
        if self.settling.load(Ordering::SeqCst) > 0 {
            self.settling.fetch_sub(1, Ordering::SeqCst);
            return Err(MppError::ZoneSettlementPending {
                challenge: Box::new(challenge.clone()),
                challenge_id: challenge.id.clone(),
                sender_tag: String::new(),
                sender_tags: Vec::new(),
                zone_id: 3,
            });
        }
        if challenge.intent.as_str() == "session" {
            return Ok(PaymentCredential::new(
                challenge.to_echo(),
                serde_json::json!({"type": "voucher", "channelId": "0xsession", "cumulativeAmount": "1000"}),
            ));
        }
        if self.zone {
            return Ok(PaymentCredential::new(
                challenge.to_echo(),
                PaymentPayload::zone(
                    format!("0x{}", "ab".repeat(32)),
                    format!("0x{}", "a1".repeat(32)),
                    3,
                ),
            ));
        }
        Ok(PaymentCredential::new(
            challenge.to_echo(),
            PaymentPayload::hash("0xproof"),
        ))
    }

    async fn pay_with_context(
        &self,
        challenge: &PaymentChallenge,
        context: PaymentContext,
    ) -> Result<PaymentCredential, MppError> {
        if self.check_management_client {
            let response = context
                .http_client
                .expect("configured client")
                .get(context.url.join("/management").unwrap())
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        }
        self.pay(challenge).await
    }

    async fn commit_payment(
        &self,
        _: &PaymentChallenge,
        _: &PaymentCredential,
    ) -> Result<(), MppError> {
        self.committed.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn rollback_payment(
        &self,
        _: &PaymentChallenge,
        _: &PaymentCredential,
    ) -> Result<(), MppError> {
        self.rolled_back.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn invalidate_payment(
        &self,
        _: &PaymentChallenge,
        _: &PaymentCredential,
    ) -> Result<(), MppError> {
        self.invalidated.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn abandon_payment(&self, _: &PaymentChallenge, _: &PaymentCredential) {
        self.abandoned.fetch_add(1, Ordering::SeqCst);
    }

    async fn prepaid_credential(
        &self,
        _context: PaymentContext,
    ) -> Option<(PaymentChallenge, PaymentCredential)> {
        if !self.prepaid {
            return None;
        }
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
        let realm = self.prepaid_realm.unwrap_or("127.0.0.1");
        let challenge = PaymentChallenge::new("prepaid-1", realm, "tempo", "session", request);
        let credential = PaymentCredential::new(
            challenge.to_echo(),
            serde_json::json!({"type": "voucher", "channelId": "0xsession", "cumulativeAmount": "1000"}),
        );
        Some((challenge, credential))
    }

    fn accept_payment_header(&self) -> Option<String> {
        Some(ACCEPT_PAYMENT.to_owned())
    }
}

fn www_authenticate(id: &str, method: &str, intent: &str) -> String {
    let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
    let challenge = PaymentChallenge::new(id, "127.0.0.1", method, intent, request);
    format_www_authenticate(&challenge).unwrap()
}

fn payment_required(id: &str, intent: &str) -> axum::response::Response {
    (
        StatusCode::PAYMENT_REQUIRED,
        [(WWW_AUTHENTICATE, www_authenticate(id, "tempo", intent))],
    )
        .into_response()
}

fn is_paid(request: &Request<Body>) -> bool {
    request.headers().contains_key("authorization")
}

async fn spawn_server(app: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

/// A body that cannot be cloned for a retry.
fn streaming_body(content: &'static str) -> reqwest::Body {
    reqwest::Response::from(http_types::Response::new(content)).into()
}

#[tokio::test]
async fn custom_header_offer_falls_back_to_safe_challenge() {
    let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
    let unsafe_challenge =
        PaymentChallenge::new("unsafe", "flow.example.com", "tempo", "charge", request)
            .with_header("Payment-Authorization");
    let combined = format!(
        "{}, {}",
        format_www_authenticate(&unsafe_challenge).unwrap(),
        www_authenticate("safe", "tempo", "charge"),
    );
    let app = Router::new().route(
        "/paid",
        get(move |request: Request<Body>| {
            let combined = combined.clone();
            async move {
                if is_paid(&request) {
                    StatusCode::OK.into_response()
                } else {
                    (StatusCode::PAYMENT_REQUIRED, [(WWW_AUTHENTICATE, combined)]).into_response()
                }
            }
        }),
    );
    let url = spawn_server(app).await;

    for via in BOTH {
        let provider = TestProvider::default();
        let request = reqwest::Client::new().get(format!("{url}/paid"));
        let response = via
            .send(request, &provider, ClientEvents::default())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{via:?}");
        assert_eq!(provider.paid(), ["safe"], "{via:?}");
    }
}

/// Serves a 402 with `challenges` until a request carries a credential.
async fn spawn_challenging_server(challenges: String) -> String {
    let app = Router::new().route(
        "/paid",
        get(move |request: Request<Body>| {
            let challenges = challenges.clone();
            async move {
                if is_paid(&request) {
                    StatusCode::OK.into_response()
                } else {
                    (
                        StatusCode::PAYMENT_REQUIRED,
                        [(WWW_AUTHENTICATE, challenges)],
                    )
                        .into_response()
                }
            }
        }),
    );
    spawn_server(app).await
}

/// A challenge whose raw `header` auth-param selects `name`.
fn www_authenticate_with_header(id: &str, name: &str) -> String {
    format!(
        r#"{}, header="{name}""#,
        www_authenticate(id, "tempo", "charge")
    )
}

#[tokio::test]
async fn unsupported_credential_header_offer_is_skipped_for_valid_challenge() {
    for name in ["Authorization", "X-Payment"] {
        let url = spawn_challenging_server(format!(
            "{}, {}",
            www_authenticate_with_header("unsupported", name),
            www_authenticate("valid", "tempo", "charge"),
        ))
        .await;
        for via in BOTH {
            let provider = TestProvider::default();
            let request = reqwest::Client::new().get(format!("{url}/paid"));
            let response = via
                .send(request, &provider, ClientEvents::default())
                .await
                .unwrap_or_else(|err| panic!("{name} {via:?}: {err}"));
            assert_eq!(response.status(), StatusCode::OK, "{name} {via:?}");
            assert_eq!(provider.paid(), ["valid"], "{name} {via:?}");
        }
    }
}

#[tokio::test]
async fn only_unsupported_credential_header_offer_is_never_paid() {
    for name in ["Authorization", "X-Payment"] {
        let url = spawn_challenging_server(www_authenticate_with_header("unsupported", name)).await;
        for via in BOTH {
            let provider = TestProvider::default();
            let request = reqwest::Client::new().get(format!("{url}/paid"));
            let result = via.send(request, &provider, ClientEvents::default()).await;
            assert!(
                matches!(result, Err(HttpError::NoSupportedChallenge(_))),
                "{name} {via:?}: {result:?}"
            );
            assert!(provider.paid().is_empty(), "{name} {via:?}");
        }
    }
}

#[tokio::test]
async fn unchallenged_402_after_payment_is_returned() {
    let app = Router::new().route(
        "/paid",
        get(|request: Request<Body>| async move {
            if is_paid(&request) {
                (StatusCode::PAYMENT_REQUIRED, "insufficient-balance").into_response()
            } else {
                payment_required("charge-1", "charge")
            }
        }),
    );
    let url = spawn_server(app).await;

    for via in BOTH {
        let provider = TestProvider::default();
        let request = reqwest::Client::new().get(format!("{url}/paid"));
        let response = via
            .send(request, &provider, ClientEvents::default())
            .await
            .unwrap_or_else(|err| panic!("{via:?}: {err}"));

        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED, "{via:?}");
        assert_eq!(response.text().await.unwrap(), "insufficient-balance");
        assert_eq!(provider.paid(), ["charge-1"], "{via:?}");
        assert_eq!(provider.rolled_back.load(Ordering::SeqCst), 1, "{via:?}");
        assert_eq!(provider.committed.load(Ordering::SeqCst), 0, "{via:?}");
    }
}

#[tokio::test]
async fn unpayable_402_after_payment_is_returned() {
    let app = Router::new().route(
        "/paid",
        get(|request: Request<Body>| async move {
            if is_paid(&request) {
                (
                    StatusCode::PAYMENT_REQUIRED,
                    [(
                        WWW_AUTHENTICATE,
                        www_authenticate("stripe-1", "stripe", "charge"),
                    )],
                    "method-unsupported",
                )
                    .into_response()
            } else {
                payment_required("charge-1", "charge")
            }
        }),
    );
    let url = spawn_server(app).await;

    for via in BOTH {
        let provider = TestProvider::default();
        let request = reqwest::Client::new().get(format!("{url}/paid"));
        let response = via
            .send(request, &provider, ClientEvents::default())
            .await
            .unwrap_or_else(|err| panic!("{via:?}: {err}"));

        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED, "{via:?}");
        assert_eq!(response.text().await.unwrap(), "method-unsupported");
        assert_eq!(provider.paid(), ["charge-1"], "{via:?}");
        assert_eq!(provider.rolled_back.load(Ordering::SeqCst), 1, "{via:?}");
    }
}

#[tokio::test]
async fn provider_can_ask_for_a_fresh_challenge() {
    for via in BOTH {
        let requests = Arc::new(AtomicU32::new(0));
        let app = Router::new().route(
            "/paid",
            get({
                let requests = requests.clone();
                move |request: Request<Body>| async move {
                    let count = requests.fetch_add(1, Ordering::SeqCst);
                    if is_paid(&request) {
                        StatusCode::OK.into_response()
                    } else if count == 0 {
                        payment_required("before-setup", "charge")
                    } else {
                        payment_required("after-setup", "charge")
                    }
                }
            }),
        );
        let url = spawn_server(app).await;
        let provider = TestProvider {
            refresh_first_challenge: true,
            ..Default::default()
        };

        let request = reqwest::Client::new().get(format!("{url}/paid"));
        let response = via
            .send(request, &provider, ClientEvents::default())
            .await
            .unwrap_or_else(|err| panic!("{via:?}: {err}"));

        assert_eq!(response.status(), StatusCode::OK, "{via:?}");
        assert_eq!(requests.load(Ordering::SeqCst), 3, "{via:?}");
        assert_eq!(provider.paid(), ["after-setup"], "{via:?}");
    }
}

#[tokio::test]
async fn stale_session_is_reopened_once() {
    for via in BOTH {
        let requests = Arc::new(AtomicU32::new(0));
        let app = Router::new().route(
            "/paid",
            get({
                let requests = requests.clone();
                move |request: Request<Body>| async move {
                    match (requests.fetch_add(1, Ordering::SeqCst), is_paid(&request)) {
                        (0 | 2, false) => payment_required("session-1", "session"),
                        (1, true) => StatusCode::GONE.into_response(),
                        (3, true) => StatusCode::OK.into_response(),
                        _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                    }
                }
            }),
        );
        let url = spawn_server(app).await;
        let provider = TestProvider::default();

        let request = reqwest::Client::new().get(format!("{url}/paid"));
        let response = via
            .send(request, &provider, ClientEvents::default())
            .await
            .unwrap_or_else(|err| panic!("{via:?}: {err}"));

        assert_eq!(response.status(), StatusCode::OK, "{via:?}");
        assert_eq!(requests.load(Ordering::SeqCst), 4, "{via:?}");
        assert_eq!(provider.paid().len(), 2, "{via:?}");
        assert_eq!(provider.invalidated.load(Ordering::SeqCst), 1, "{via:?}");
        assert_eq!(provider.committed.load(Ordering::SeqCst), 0, "{via:?}");
        assert_eq!(provider.rolled_back.load(Ordering::SeqCst), 0, "{via:?}");
    }
}

#[tokio::test]
async fn session_responses_redirected_to_another_origin_are_rejected() {
    let foreign = spawn_server(
        Router::new().route("/landing", get(|| async { StatusCode::OK.into_response() })),
    )
    .await;
    for prepaid in [false, true] {
        let app = Router::new().route(
            "/paid",
            get({
                let foreign = foreign.clone();
                move |request: Request<Body>| async move {
                    if is_paid(&request) {
                        axum::response::Redirect::temporary(&format!("{foreign}/landing"))
                            .into_response()
                    } else {
                        payment_required("session-1", "session")
                    }
                }
            }),
        );
        let url = spawn_server(app).await;
        for via in BOTH {
            let provider = TestProvider {
                prepaid,
                ..TestProvider::default()
            };
            // The caller's client follows redirects.
            let request = reqwest::Client::new().get(format!("{url}/paid"));
            let error = via
                .send(request, &provider, ClientEvents::default())
                .await
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("session response origin mismatch"),
                "{via:?} prepaid={prepaid}: {error}"
            );
            assert_eq!(provider.committed.load(Ordering::SeqCst), 0, "{via:?}");
        }
    }
}

#[tokio::test]
async fn session_that_stays_gone_is_returned() {
    let app = Router::new().route(
        "/paid",
        get(|request: Request<Body>| async move {
            if is_paid(&request) {
                StatusCode::GONE.into_response()
            } else {
                payment_required("session-1", "session")
            }
        }),
    );
    let url = spawn_server(app).await;

    for via in BOTH {
        let provider = TestProvider::default();
        let request = reqwest::Client::new().get(format!("{url}/paid"));
        let response = via
            .send(request, &provider, ClientEvents::default())
            .await
            .unwrap_or_else(|err| panic!("{via:?}: {err}"));

        assert_eq!(response.status(), StatusCode::GONE, "{via:?}");
        assert_eq!(provider.paid().len(), 2, "{via:?}");
        assert_eq!(provider.invalidated.load(Ordering::SeqCst), 2, "{via:?}");
        assert_eq!(provider.rolled_back.load(Ordering::SeqCst), 0, "{via:?}");
    }
}

#[tokio::test]
async fn retries_repeat_accept_payment() {
    for via in BOTH {
        let advertised = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new().route(
            "/paid",
            get({
                let advertised = advertised.clone();
                move |request: Request<Body>| async move {
                    advertised.lock().unwrap().push(
                        request
                            .headers()
                            .get("accept-payment")
                            .map(|value| value.to_str().unwrap().to_owned()),
                    );
                    if is_paid(&request) {
                        StatusCode::OK.into_response()
                    } else {
                        payment_required("charge-1", "charge")
                    }
                }
            }),
        );
        let url = spawn_server(app).await;
        let provider = TestProvider::default();

        let request = reqwest::Client::new().get(format!("{url}/paid"));
        let response = via
            .send(request, &provider, ClientEvents::default())
            .await
            .unwrap_or_else(|err| panic!("{via:?}: {err}"));

        assert_eq!(response.status(), StatusCode::OK, "{via:?}");
        assert_eq!(
            *advertised.lock().unwrap(),
            [
                Some(ACCEPT_PAYMENT.to_owned()),
                Some(ACCEPT_PAYMENT.to_owned())
            ],
            "{via:?}"
        );
    }
}

#[tokio::test]
async fn request_that_cannot_be_cloned_fails_only_when_challenged() {
    let app = Router::new()
        .route("/free", post(|body: String| async move { body }))
        .route(
            "/paid",
            post(|| async { payment_required("charge-1", "charge") }),
        );
    let url = spawn_server(app).await;

    for via in BOTH {
        let provider = TestProvider::default();
        let request = reqwest::Client::new()
            .post(format!("{url}/free"))
            .body(streaming_body("payload"));
        let response = via
            .send(request, &provider, ClientEvents::default())
            .await
            .unwrap_or_else(|err| panic!("{via:?}: {err}"));
        assert_eq!(response.text().await.unwrap(), "payload", "{via:?}");

        let events = ClientEvents::default();
        let failed = Arc::new(AtomicU32::new(0));
        let _subscription = events.on_payment_failed({
            let failed = failed.clone();
            move |_| {
                failed.fetch_add(1, Ordering::SeqCst);
                async {}
            }
        });
        let request = reqwest::Client::new()
            .post(format!("{url}/paid"))
            .body(streaming_body("payload"));
        let err = via.send(request, &provider, events).await.unwrap_err();

        assert!(matches!(err, HttpError::CloneFailed), "{via:?}: {err}");
        assert_eq!(failed.load(Ordering::SeqCst), 1, "{via:?}");
        assert!(provider.paid().is_empty(), "{via:?}");
    }
}

#[tokio::test]
async fn management_context_uses_the_callers_redirect_policy() {
    for via in BOTH {
        let challenge = www_authenticate("context", "tempo", "charge");
        let app = Router::new()
            .route(
                "/management",
                get(|| async {
                    (
                        StatusCode::TEMPORARY_REDIRECT,
                        [("location", "/destination")],
                    )
                }),
            )
            .route("/destination", get(|| async { StatusCode::OK }))
            .route(
                "/paid",
                get(move |headers: axum::http::HeaderMap| {
                    let challenge = challenge.clone();
                    async move {
                        if headers.contains_key("authorization") {
                            StatusCode::OK.into_response()
                        } else {
                            (
                                StatusCode::PAYMENT_REQUIRED,
                                [("www-authenticate", challenge)],
                            )
                                .into_response()
                        }
                    }
                }),
            );
        let url = spawn_server(app).await;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let provider = TestProvider {
            check_management_client: true,
            ..Default::default()
        };
        assert_eq!(
            via.send(
                client.get(format!("{url}/paid")),
                &provider,
                ClientEvents::default()
            )
            .await
            .unwrap()
            .status(),
            StatusCode::OK
        );
    }
}

#[tokio::test]
async fn opaque_client_defaults_cannot_authorize_payment() {
    for via in BOTH {
        for default in ["tempo/charge;q=0", "tempo/charge"] {
            for preference in [
                None,
                Some("tempo/charge;q=0"),
                Some("tempo/charge"),
                Some("garbage"),
                Some("tempo/charge;q=invalid"),
            ] {
                let app = Router::new().route(
                    "/",
                    get(|request: Request<Body>| async move {
                        if request.headers().contains_key("authorization") {
                            StatusCode::OK.into_response()
                        } else {
                            payment_required("default-header", "charge")
                        }
                    }),
                );
                let url = spawn_server(app).await;
                let mut defaults = reqwest::header::HeaderMap::new();
                defaults.insert("Accept-Payment", default.parse().unwrap());
                let client = reqwest::Client::builder()
                    .default_headers(defaults)
                    .build()
                    .unwrap();
                let mut request = client.get(&url);
                if let Some(preference) = preference {
                    request = request.header("Accept-Payment", preference);
                }
                let provider = TestProvider::default();
                let result = match via {
                    Via::Fetch => request
                        .send_with_payment(&provider)
                        .await
                        .map(|r| r.status())
                        .map_err(|e| e.to_string()),
                    Via::Middleware => ClientBuilder::new(client)
                        .with(PaymentMiddleware::new(provider.clone()))
                        .build()
                        .execute(request.build().unwrap())
                        .await
                        .map(|r| r.status())
                        .map_err(|e| e.to_string()),
                };
                let permitted = preference == Some("tempo/charge");
                assert_eq!(
                    provider.paid().len(),
                    usize::from(permitted),
                    "{via:?}, {default}, {preference:?}: {result:?}"
                );
                if permitted {
                    assert_eq!(result.unwrap(), StatusCode::OK);
                }
            }
        }
    }
}

#[tokio::test]
async fn session_commit_requires_a_matching_receipt() {
    for via in BOTH {
        for variant in ["missing", "malformed", "wrong-challenge", "valid"] {
            let app = Router::new().route(
                "/",
                get(move |request: Request<Body>| async move {
                    if !is_paid(&request) {
                        return payment_required("receipt-check", "session");
                    }
                    if variant == "missing" {
                        return StatusCode::OK.into_response();
                    }
                    let mut receipt = crate::protocol::core::Receipt::success("tempo", "0xsession");
                    receipt.extensions.insert(
                        "challengeId".into(),
                        serde_json::json!(if variant == "wrong-challenge" {
                            "other"
                        } else {
                            "receipt-check"
                        }),
                    );
                    let header = if variant == "malformed" {
                        "bad".to_owned()
                    } else {
                        receipt.to_header().unwrap()
                    };
                    (StatusCode::OK, [("payment-receipt", header)]).into_response()
                }),
            );
            let url = spawn_server(app).await;
            let provider = TestProvider::default();
            via.send(
                reqwest::Client::new().get(&url),
                &provider,
                ClientEvents::default(),
            )
            .await
            .unwrap();
            assert_eq!(
                provider.committed.load(Ordering::SeqCst),
                u32::from(variant == "valid"),
                "{via:?}: {variant}"
            );
        }
    }
}

#[tokio::test]
async fn paid_server_error_reports_unknown_outcome() {
    let app = Router::new().route(
        "/paid/{status}",
        get(
            |axum::extract::Path(status): axum::extract::Path<u16>,
             request: Request<Body>| async move {
                if is_paid(&request) {
                    (StatusCode::from_u16(status).unwrap(), "answer").into_response()
                } else {
                    payment_required("charge-1", "charge")
                }
            },
        ),
    );
    let url = spawn_server(app).await;

    for via in BOTH {
        for status in [500u16, 503, 400, 200] {
            let provider = TestProvider::default();
            let events = ClientEvents::default();
            let failed = Arc::new(Mutex::new(Vec::new()));
            let _subscription = events.on_payment_failed({
                let failed = failed.clone();
                move |ctx| {
                    failed.lock().unwrap().push(ctx);
                    async {}
                }
            });
            let request = reqwest::Client::new().get(format!("{url}/paid/{status}"));
            let response = via
                .send(request, &provider, events)
                .await
                .unwrap_or_else(|err| panic!("{via:?} {status}: {err}"));

            assert_eq!(response.status().as_u16(), status, "{via:?}");
            assert_eq!(response.text().await.unwrap(), "answer", "{via:?}");
            assert_eq!(provider.paid(), ["charge-1"], "{via:?} {status}");
            // An unknown outcome keeps optimistic state, like a lost response.
            assert_eq!(
                provider.rolled_back.load(Ordering::SeqCst),
                u32::from(status == 400),
                "{via:?} {status}"
            );
            let failed = failed.lock().unwrap().clone();
            if status < 500 {
                assert!(failed.is_empty(), "{via:?} {status}: {failed:?}");
                continue;
            }
            assert_eq!(failed.len(), 1, "{via:?} {status}");
            assert_eq!(failed[0].challenge.as_ref().unwrap().id, "charge-1");
            let Some(PaymentFailureReason::OutcomeUnknown {
                status: reported,
                credential,
                transaction_hash,
            }) = &failed[0].reason
            else {
                panic!("{via:?} {status}: {:?}", failed[0].reason);
            };
            assert_eq!(*reported, Some(status), "{via:?}");
            assert!(credential.starts_with("Payment "), "{via:?}: {credential}");
            assert_eq!(transaction_hash.as_deref(), Some("0xproof"), "{via:?}");
        }
    }
}

#[tokio::test]
async fn prepaid_server_error_reports_unknown_outcome() {
    let app = Router::new().route(
        "/paid",
        get(|request: Request<Body>| async move {
            if is_paid(&request) {
                (StatusCode::SERVICE_UNAVAILABLE, "answer").into_response()
            } else {
                payment_required("charge-1", "charge")
            }
        }),
    );
    let url = spawn_server(app).await;

    for via in BOTH {
        let provider = TestProvider {
            prepaid: true,
            ..TestProvider::default()
        };
        let events = ClientEvents::default();
        let failed = Arc::new(Mutex::new(Vec::new()));
        let _subscription = events.on_payment_failed({
            let failed = failed.clone();
            move |ctx| {
                failed.lock().unwrap().push(ctx);
                async {}
            }
        });
        let request = reqwest::Client::new().get(format!("{url}/paid"));
        let response = via
            .send(request, &provider, events)
            .await
            .unwrap_or_else(|err| panic!("{via:?}: {err}"));

        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{via:?}"
        );
        assert!(provider.paid().is_empty(), "{via:?}");
        let failed = failed.lock().unwrap().clone();
        assert_eq!(failed.len(), 1, "{via:?}");
        assert_eq!(failed[0].challenge.as_ref().unwrap().id, "prepaid-1");
        let Some(PaymentFailureReason::OutcomeUnknown {
            status,
            transaction_hash,
            ..
        }) = &failed[0].reason
        else {
            panic!("{via:?}: {:?}", failed[0].reason);
        };
        assert_eq!(*status, Some(503), "{via:?}");
        assert_eq!(*transaction_hash, None, "{via:?}");
    }
}

#[tokio::test]
async fn prepaid_credentials_respect_request_preferences() {
    let app = Router::new().route(
        "/paid",
        get(|request: Request<Body>| async move {
            if is_paid(&request) {
                StatusCode::OK.into_response()
            } else {
                payment_required("session-1", "session")
            }
        }),
    );
    let url = spawn_server(app).await;
    for via in BOTH {
        for warm in [false, true] {
            for (preference, allowed) in [
                ("tempo/session;q=0", false),
                ("tempo/charge", false),
                ("tempo/charge, tempo/session;q=0", false),
                ("tempo/session", true),
                ("tempo/*", true),
            ] {
                let provider = TestProvider {
                    prepaid: warm,
                    ..TestProvider::default()
                };
                let response = via
                    .send(
                        reqwest::Client::new()
                            .get(format!("{url}/paid"))
                            .header("Accept-Payment", preference),
                        &provider,
                        ClientEvents::default(),
                    )
                    .await;
                assert_eq!(
                    response.is_ok(),
                    allowed,
                    "{via:?} warm={warm} {preference}: {response:?}"
                );
                if let Ok(response) = response {
                    assert_eq!(response.status(), StatusCode::OK);
                }
                if !allowed {
                    assert!(provider.paid().is_empty());
                    assert_eq!(provider.abandoned.load(Ordering::SeqCst), u32::from(warm));
                }
            }
        }
    }
}

/// A cached Challenge for another realm is sent prepaid only to a caller
/// that pins that realm; any other caller pays a fresh Challenge instead.
#[tokio::test]
async fn prepaid_credentials_respect_the_callers_realm_pins() {
    let app = Router::new().route(
        "/paid",
        get(|request: Request<Body>| async move {
            if is_paid(&request) {
                StatusCode::OK.into_response()
            } else {
                payment_required("session-1", "session")
            }
        }),
    );
    let url = spawn_server(app).await;
    for via in BOTH {
        for trusted_realm in [None, Some("realm.example")] {
            let provider = TestProvider {
                prepaid: true,
                prepaid_realm: Some("realm.example"),
                trusted_realm,
                ..TestProvider::default()
            };
            let response = via
                .send(
                    reqwest::Client::new().get(format!("{url}/paid")),
                    &provider,
                    ClientEvents::default(),
                )
                .await
                .unwrap_or_else(|err| panic!("{via:?} {trusted_realm:?}: {err}"));
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "{via:?} {trusted_realm:?}"
            );
            // Had the unpinned caller sent the cached voucher, the server would
            // have accepted it without asking for the fresh Challenge.
            let fresh: &[&str] = if trusted_realm.is_some() {
                &[]
            } else {
                &["session-1"]
            };
            assert_eq!(provider.paid(), fresh, "{via:?} {trusted_realm:?}");
        }
    }
}

#[tokio::test]
async fn excluded_prepaid_session_falls_back_to_allowed_charge() {
    let app = Router::new().route(
        "/paid",
        get(|request: Request<Body>| async move {
            if is_paid(&request) {
                StatusCode::OK.into_response()
            } else {
                payment_required("charge-1", "charge")
            }
        }),
    );
    let url = spawn_server(app).await;
    for via in BOTH {
        let provider = TestProvider {
            prepaid: true,
            ..TestProvider::default()
        };
        let response = via
            .send(
                reqwest::Client::new()
                    .get(format!("{url}/paid"))
                    .header("Accept-Payment", "tempo/charge, tempo/session;q=0"),
                &provider,
                ClientEvents::default(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(provider.paid(), vec!["charge-1"]);
        assert_eq!(provider.abandoned.load(Ordering::SeqCst), 1);
    }
}

/// A hash credential's transfer is already on chain: a 402 answering it is
/// final, and the client never pays a fresh challenge for the same request.
#[tokio::test]
async fn refused_hash_credential_is_not_paid_again() {
    for via in BOTH {
        let calls = Arc::new(AtomicU32::new(0));
        let app = Router::new().route(
            "/paid",
            get({
                let calls = calls.clone();
                move || async move {
                    let n = calls.fetch_add(1, Ordering::SeqCst);
                    payment_required(&format!("charge-{n}"), "charge")
                }
            }),
        );
        let url = spawn_server(app).await;
        let provider = TestProvider::default();

        let request = reqwest::Client::new().get(format!("{url}/paid"));
        let response = via
            .send(request, &provider, ClientEvents::default())
            .await
            .unwrap_or_else(|err| panic!("{via:?}: {err}"));

        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED, "{via:?}");
        assert_eq!(provider.paid(), ["charge-0"], "{via:?}");
    }
}

#[test]
fn session_receipt_spending_is_bounded_by_the_sent_voucher() {
    let challenge = PaymentChallenge::new(
        "test",
        "api.example.com",
        "tempo",
        "session",
        Base64UrlJson::from_value(&serde_json::json!({})).unwrap(),
    );
    let credential = PaymentCredential {
        challenge: challenge.to_echo(),
        payload: serde_json::json!({"channelId": "channel", "cumulativeAmount": "1000"}),
        source: None,
    };
    for (spent, accepted, valid) in [
        ("500", "1000", true),
        ("1001", "1001", false),
        ("500", "1001", false),
        ("500", "499", false),
        ("invalid", "1000", false),
    ] {
        let mut receipt = crate::protocol::core::Receipt::success("tempo", "channel");
        receipt
            .extensions
            .insert("spent".into(), serde_json::json!(spent));
        receipt
            .extensions
            .insert("acceptedCumulative".into(), serde_json::json!(accepted));
        assert_eq!(
            super::session_receipt_within_authorization(&receipt, &credential),
            valid
        );
    }
}

/// Refuses every paid attempt before it leaves, as an identity prover can.
struct RefusesPaid {
    client: reqwest::Client,
    unsent: bool,
}

impl Exchange for RefusesPaid {
    type Error = HttpError;

    fn unsent(&self) -> bool {
        self.unsent
    }

    async fn send(&mut self, request: reqwest::Request) -> Result<reqwest::Response, HttpError> {
        self.unsent = request
            .headers()
            .contains_key(reqwest::header::AUTHORIZATION);
        if self.unsent {
            return Err(HttpError::Payment(MppError::InvalidConfig(
                "refused".into(),
            )));
        }
        self.client
            .execute(request)
            .await
            .map_err(HttpError::request)
    }
}

/// An unsent voucher is released, but an unsent hash Credential's transfer is
/// already on chain: it is kept and reported with an unknown outcome.
#[tokio::test]
async fn unsent_paid_attempt_releases_only_unsettled_credentials() {
    for intent in ["session", "charge"] {
        let app = Router::new().route(
            "/paid",
            get(move || async move { payment_required("challenge-1", intent) }),
        );
        let url = spawn_server(app).await;
        let provider = TestProvider::default();
        let events = ClientEvents::default();
        let failed = Arc::new(Mutex::new(Vec::new()));
        let _subscription = events.on_payment_failed({
            let failed = failed.clone();
            move |ctx| {
                failed.lock().unwrap().push(ctx);
                async {}
            }
        });
        let client = reqwest::Client::new();
        let request = client.get(format!("{url}/paid")).build().unwrap();
        let mut exchange = RefusesPaid {
            client,
            unsent: false,
        };

        let result = send_with_exchange(
            &mut exchange,
            request,
            &provider,
            &AcceptPaymentPolicy::Always,
            &events,
            1,
        )
        .await;

        assert!(result.is_err(), "{intent}");
        assert_eq!(provider.paid(), ["challenge-1"], "{intent}");
        let settled = intent == "charge";
        assert_eq!(
            provider.rolled_back.load(Ordering::SeqCst),
            u32::from(!settled),
            "{intent}"
        );
        let failed = failed.lock().unwrap().clone();
        assert_eq!(failed.len(), 1, "{intent}");
        match &failed[0].reason {
            Some(PaymentFailureReason::OutcomeUnknown {
                transaction_hash, ..
            }) => {
                assert!(settled, "{intent}");
                assert_eq!(transaction_hash.as_deref(), Some("0xproof"));
            }
            None => assert!(!settled, "{intent}"),
            other => panic!("{intent}: {other:?}"),
        }
    }
}

/// An unsent Zone Credential's withdrawal is already on chain too: it is kept
/// and reported with an unknown outcome, so a retry does not withdraw again.
#[tokio::test]
async fn unsent_zone_credential_is_not_released() {
    let app = Router::new().route(
        "/paid",
        get(|| async { payment_required("challenge-1", "charge") }),
    );
    let url = spawn_server(app).await;
    let provider = TestProvider {
        zone: true,
        ..Default::default()
    };
    let events = ClientEvents::default();
    let failed = Arc::new(Mutex::new(Vec::new()));
    let _subscription = events.on_payment_failed({
        let failed = failed.clone();
        move |ctx| {
            failed.lock().unwrap().push(ctx);
            async {}
        }
    });
    let client = reqwest::Client::new();
    let request = client.get(format!("{url}/paid")).build().unwrap();
    let mut exchange = RefusesPaid {
        client,
        unsent: false,
    };

    let result = send_with_exchange(
        &mut exchange,
        request,
        &provider,
        &AcceptPaymentPolicy::Always,
        &events,
        1,
    )
    .await;

    assert!(result.is_err());
    assert_eq!(provider.paid(), ["challenge-1"]);
    assert_eq!(provider.rolled_back.load(Ordering::SeqCst), 0);
    let failed = failed.lock().unwrap().clone();
    assert_eq!(failed.len(), 1);
    match &failed[0].reason {
        Some(PaymentFailureReason::OutcomeUnknown {
            transaction_hash, ..
        }) => assert_eq!(transaction_hash, &None),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn settling_zone_withdrawal_is_resumed_for_the_same_challenge() {
    let challenged = Arc::new(AtomicU32::new(0));
    let app = Router::new().route(
        "/paid",
        get({
            let challenged = challenged.clone();
            move |request: Request<Body>| async move {
                if is_paid(&request) {
                    StatusCode::OK.into_response()
                } else {
                    challenged.fetch_add(1, Ordering::SeqCst);
                    payment_required("charge-1", "charge")
                }
            }
        }),
    );
    let url = spawn_server(app).await;

    for via in BOTH {
        challenged.store(0, Ordering::SeqCst);
        // Settles on the third attempt, within the retry limit, without
        // asking the server for a new challenge.
        let provider = TestProvider {
            settling: Arc::new(AtomicU32::new(2)),
            ..Default::default()
        };
        let request = reqwest::Client::new().get(format!("{url}/paid"));
        let response = via
            .send(request, &provider, ClientEvents::default())
            .await
            .unwrap_or_else(|err| panic!("{via:?}: {err}"));
        assert_eq!(response.status(), StatusCode::OK, "{via:?}");
        assert_eq!(provider.paid(), ["charge-1"; 3], "{via:?}");
        assert_eq!(challenged.load(Ordering::SeqCst), 1, "{via:?}");

        // Past the limit, the error is returned.
        challenged.store(0, Ordering::SeqCst);
        let provider = TestProvider {
            settling: Arc::new(AtomicU32::new(10)),
            ..Default::default()
        };
        let request = reqwest::Client::new().get(format!("{url}/paid"));
        let error = via
            .send(request, &provider, ClientEvents::default())
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("has not settled"),
            "{via:?}: {error}"
        );
        assert_eq!(provider.paid(), ["charge-1"; 3], "{via:?}");
        assert_eq!(challenged.load(Ordering::SeqCst), 1, "{via:?}");
    }
}

/// A zero-amount Tempo proof refused with a `credit_insufficient` 402 that
/// offers only the real charge starts a new challenge round, as mppx's client
/// does. These use the real [`TempoProvider`](crate::client::TempoProvider) to
/// sign proofs and apply its spending policy.
#[cfg(feature = "tempo")]
mod new_challenge_rounds {
    use axum::http::header::CONTENT_TYPE;
    use axum::routing::any;

    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::client::{TempoProvider, DEFAULT_MAX_PAYMENT_RETRIES};
    use crate::protocol::core::parse_authorization;

    const CURRENCY: &str = "0x20c0000000000000000000000000000000000000";
    const RECIPIENT: &str = "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2";
    const CHAIN_ID: u64 = 42431;
    const REALM: &str = "127.0.0.1";

    /// Signs zero-amount proofs with a real `TempoProvider` and its policy,
    /// and pays any other charge with a pull-mode transaction credential (no
    /// RPC), recording every challenge it creates a credential for.
    #[derive(Clone)]
    struct CreditProvider {
        tempo: TempoProvider,
        paid: Arc<Mutex<Vec<String>>>,
        /// Pays charges with a hash credential, settled on chain, instead.
        hash: bool,
        commits: Arc<AtomicUsize>,
        rollbacks: Arc<AtomicUsize>,
    }

    impl CreditProvider {
        /// Charges are capped at 10000 base units of `CURRENCY`.
        fn new() -> Self {
            let signer = alloy::signers::local::PrivateKeySigner::random();
            let tempo = TempoProvider::new(signer, "https://rpc.example.com")
                .unwrap()
                .with_expected_chain_id(CHAIN_ID)
                .with_currencies([CURRENCY])
                .with_max_atomic_amount(alloy::primitives::U256::from(10_000));
            Self {
                tempo,
                paid: Arc::default(),
                hash: false,
                commits: Arc::default(),
                rollbacks: Arc::default(),
            }
        }

        fn paid(&self) -> Vec<String> {
            self.paid.lock().unwrap().clone()
        }

        fn settled(&self) -> (usize, usize) {
            (
                self.commits.load(Ordering::SeqCst),
                self.rollbacks.load(Ordering::SeqCst),
            )
        }
    }

    impl PaymentProvider for CreditProvider {
        fn supports(&self, method: &str, intent: &str) -> bool {
            self.tempo.supports(method, intent)
        }

        fn select_challenge<'a>(
            &self,
            challenges: &[&'a PaymentChallenge],
        ) -> Option<&'a PaymentChallenge> {
            self.tempo.select_challenge(challenges)
        }

        fn trusted_tempo_proof_realm(&self, url: &reqwest::Url) -> Option<&str> {
            self.tempo.trusted_tempo_proof_realm(url)
        }

        fn accept_payment_header(&self) -> Option<String> {
            self.tempo.accept_payment_header()
        }

        async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
            self.paid.lock().unwrap().push(challenge.id.clone());
            let request: crate::protocol::intents::ChargeRequest = challenge.request.decode()?;
            if request.amount == "0" {
                return self.tempo.pay(challenge).await;
            }
            let payload = if self.hash {
                PaymentPayload::hash("0xsettled")
            } else {
                PaymentPayload::transaction("0x76signed")
            };
            Ok(PaymentCredential::new(challenge.to_echo(), payload))
        }

        async fn commit_payment(
            &self,
            _: &PaymentChallenge,
            _: &PaymentCredential,
        ) -> Result<(), MppError> {
            self.commits.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn rollback_payment(
            &self,
            _: &PaymentChallenge,
            _: &PaymentCredential,
        ) -> Result<(), MppError> {
            self.rollbacks.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn charge_in(id: &str, realm: &str, amount: &str) -> PaymentChallenge {
        let request = Base64UrlJson::from_value(&serde_json::json!({
            "amount": amount,
            "currency": CURRENCY,
            "recipient": RECIPIENT,
            "methodDetails": { "chainId": CHAIN_ID }
        }))
        .unwrap();
        PaymentChallenge::new(id, realm, "tempo", "charge", request)
    }

    fn charge(id: &str, amount: &str) -> PaymentChallenge {
        charge_in(id, REALM, amount)
    }

    /// The server's offer before payment: a zero-amount proof, then the real charge.
    fn proof_then_charge() -> axum::response::Response {
        challenged(&[charge("proof-1", "0"), charge("charge-1", "10000")], None)
    }

    fn challenged(
        challenges: &[PaymentChallenge],
        reason: Option<&str>,
    ) -> axum::response::Response {
        let body = reason.map_or_else(String::new, |reason| {
            serde_json::json!({
                "type": format!("https://paymentauth.org/problems/{reason}"),
                "title": "Payment Required",
                "status": 402,
            })
            .to_string()
        });
        let mut response = (
            StatusCode::PAYMENT_REQUIRED,
            [(CONTENT_TYPE, "application/problem+json")],
            body,
        )
            .into_response();
        for challenge in challenges {
            response.headers_mut().append(
                WWW_AUTHENTICATE,
                format_www_authenticate(challenge).unwrap().parse().unwrap(),
            );
        }
        response
    }

    #[derive(Clone, Debug)]
    struct Seen {
        method: String,
        body: String,
        marker: Option<String>,
        credential: Option<PaymentCredential>,
    }

    /// Serves `respond` for every request, recording each one.
    async fn spawn_credit_server<F>(respond: F) -> (String, Arc<Mutex<Vec<Seen>>>)
    where
        F: Fn(Option<&PaymentCredential>) -> axum::response::Response
            + Clone
            + Send
            + Sync
            + 'static,
    {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new().route(
            "/paid",
            any({
                let seen = seen.clone();
                move |request: Request<Body>| async move {
                    let (parts, body) = request.into_parts();
                    let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
                    let credential = parts
                        .headers
                        .get("authorization")
                        .map(|value| parse_authorization(value.to_str().unwrap()).unwrap());
                    let response = respond(credential.as_ref());
                    seen.lock().unwrap().push(Seen {
                        method: parts.method.to_string(),
                        body: String::from_utf8(body.to_vec()).unwrap(),
                        marker: parts
                            .headers
                            .get("x-marker")
                            .map(|value| value.to_str().unwrap().to_owned()),
                        credential,
                    });
                    response
                }
            }),
        );
        (spawn_server(app).await, seen)
    }

    fn paid_id(credential: Option<&PaymentCredential>) -> Option<String> {
        credential.map(|credential| credential.challenge.id.clone())
    }

    fn credential_ids(seen: &Mutex<Vec<Seen>>) -> Vec<String> {
        seen.lock()
            .unwrap()
            .iter()
            .filter_map(|seen| paid_id(seen.credential.as_ref()))
            .collect()
    }

    async fn send(
        via: Via,
        request: reqwest::RequestBuilder,
        provider: &CreditProvider,
    ) -> Result<reqwest::Response, HttpError> {
        match via {
            Via::Fetch => {
                request
                    .send_with_payment_options(
                        provider,
                        &AcceptPaymentPolicy::Always,
                        ClientEvents::default(),
                    )
                    .await
            }
            Via::Middleware => {
                let (client, request) = request.build_split();
                ClientBuilder::new(client.clone())
                    .with(
                        PaymentMiddleware::new(provider.clone())
                            .with_accept_payment_policy(AcceptPaymentPolicy::Always),
                    )
                    .build()
                    .execute(request.unwrap())
                    .await
                    .map_err(|err| match err {
                        reqwest_middleware::Error::Middleware(err) => err.downcast().unwrap(),
                        reqwest_middleware::Error::Reqwest(err) => HttpError::Request(err),
                    })
            }
        }
    }

    async fn get(
        via: Via,
        url: &str,
        provider: &CreditProvider,
    ) -> Result<reqwest::Response, HttpError> {
        send(
            via,
            reqwest::Client::new().get(format!("{url}/paid")),
            provider,
        )
        .await
    }

    #[tokio::test]
    async fn refused_proof_then_real_charge_is_paid() {
        let (url, seen) = spawn_credit_server(|credential| match paid_id(credential).as_deref() {
            None => proof_then_charge(),
            Some("proof-1") => {
                challenged(&[charge("charge-2", "10000")], Some("credit_insufficient"))
            }
            Some("charge-2") => (StatusCode::OK, "paid").into_response(),
            Some(other) => panic!("unexpected credential for {other}"),
        })
        .await;

        for via in BOTH {
            seen.lock().unwrap().clear();
            let provider = CreditProvider::new();
            let request = reqwest::Client::new()
                .post(format!("{url}/paid"))
                .header("x-marker", "kept")
                .body("request-body");
            let response = send(via, request, &provider)
                .await
                .unwrap_or_else(|err| panic!("{via:?}: {err}"));

            assert_eq!(response.status(), StatusCode::OK, "{via:?}");
            assert_eq!(response.text().await.unwrap(), "paid", "{via:?}");
            assert_eq!(provider.paid(), ["proof-1", "charge-2"], "{via:?}");
            let seen = seen.lock().unwrap().clone();
            assert_eq!(seen.len(), 3, "{via:?}");
            // Exactly two credentials: the proof, then the new real charge.
            let credentials: Vec<_> = seen.iter().filter_map(|s| s.credential.clone()).collect();
            assert_eq!(credentials.len(), 2, "{via:?}");
            assert_eq!(credentials[0].challenge.id, "proof-1", "{via:?}");
            assert!(
                credentials[0].charge_payload().unwrap().is_proof(),
                "{via:?}"
            );
            assert_eq!(credentials[1].challenge.id, "charge-2", "{via:?}");
            assert!(
                !credentials[1].charge_payload().unwrap().is_proof(),
                "{via:?}"
            );
            // Every retry repeats the original method, body and headers.
            for request in &seen {
                assert_eq!(request.method, "POST", "{via:?}");
                assert_eq!(request.body, "request-body", "{via:?}");
                assert_eq!(request.marker.as_deref(), Some("kept"), "{via:?}");
            }
        }
    }

    #[tokio::test]
    async fn accepted_proof_never_pays_the_real_charge() {
        let (url, seen) = spawn_credit_server(|credential| match paid_id(credential).as_deref() {
            None => proof_then_charge(),
            Some("proof-1") => (StatusCode::OK, "credit").into_response(),
            Some(other) => panic!("unexpected credential for {other}"),
        })
        .await;

        for via in BOTH {
            seen.lock().unwrap().clear();
            let provider = CreditProvider::new();
            let response = get(via, &url, &provider)
                .await
                .unwrap_or_else(|err| panic!("{via:?}: {err}"));

            assert_eq!(response.status(), StatusCode::OK, "{via:?}");
            assert_eq!(provider.paid(), ["proof-1"], "{via:?}");
            assert_eq!(credential_ids(&seen), ["proof-1"], "{via:?}");
        }
    }

    /// Every Credential sent, as JSON so resent ones compare equal.
    fn credentials(seen: &Mutex<Vec<Seen>>) -> Vec<serde_json::Value> {
        seen.lock()
            .unwrap()
            .iter()
            .filter_map(|seen| seen.credential.as_ref())
            .map(|credential| serde_json::to_value(credential).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn reoffered_challenge_resends_the_same_credential() {
        for reoffered in [charge("proof-1", "0"), charge("charge-1", "10000")] {
            let id = reoffered.id.clone();
            let (url, seen) = spawn_credit_server(move |credential| match credential {
                None => challenged(std::slice::from_ref(&reoffered), None),
                // The same Challenge is identified by its id, not by display
                // fields such as its description.
                Some(_) => challenged(
                    &[reoffered.clone().with_description("try again")],
                    Some("verification-failed"),
                ),
            })
            .await;

            for via in BOTH {
                seen.lock().unwrap().clear();
                let provider = CreditProvider::new();
                let response = get(via, &url, &provider)
                    .await
                    .unwrap_or_else(|err| panic!("{via:?}: {err}"));

                // The last 402 is the final answer.
                assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED, "{via:?}");
                // Signed once, then that Credential resent each round, at most
                // DEFAULT_MAX_PAYMENT_RETRIES times in all.
                assert_eq!(provider.paid(), std::slice::from_ref(&id), "{via:?}");
                let credentials = credentials(&seen);
                assert_eq!(credentials.len(), DEFAULT_MAX_PAYMENT_RETRIES, "{via:?}");
                assert!(
                    credentials.iter().all(|sent| *sent == credentials[0]),
                    "{via:?}"
                );
                assert_eq!(
                    seen.lock().unwrap().len(),
                    DEFAULT_MAX_PAYMENT_RETRIES + 1,
                    "{via:?}"
                );
                assert_eq!(provider.settled(), (0, 1), "{via:?}");
            }
        }
    }

    #[tokio::test]
    async fn resent_credential_accepted_is_committed_once() {
        let answered = Arc::new(AtomicUsize::new(0));
        let (url, seen) = spawn_credit_server({
            let answered = answered.clone();
            move |credential| match credential {
                None => challenged(&[charge("charge-1", "10000")], None),
                Some(_) if answered.fetch_add(1, Ordering::SeqCst) == 0 => {
                    challenged(&[charge("charge-1", "10000")], Some("verification-failed"))
                }
                Some(_) => (StatusCode::OK, "paid").into_response(),
            }
        })
        .await;

        for via in BOTH {
            seen.lock().unwrap().clear();
            answered.store(0, Ordering::SeqCst);
            let provider = CreditProvider::new();
            let response = get(via, &url, &provider)
                .await
                .unwrap_or_else(|err| panic!("{via:?}: {err}"));

            assert_eq!(response.status(), StatusCode::OK, "{via:?}");
            assert_eq!(provider.paid(), ["charge-1"], "{via:?}");
            let credentials = credentials(&seen);
            assert_eq!(credentials.len(), 2, "{via:?}");
            assert_eq!(credentials[0], credentials[1], "{via:?}");
            assert_eq!(provider.settled(), (1, 0), "{via:?}");
        }
    }

    #[tokio::test]
    async fn settled_hash_credential_is_not_resent_or_paid_again() {
        let (url, seen) = spawn_credit_server(|credential| match credential {
            None => challenged(&[charge("charge-1", "10000")], None),
            Some(_) => challenged(&[charge("charge-1", "10000")], Some("verification-failed")),
        })
        .await;

        for via in BOTH {
            seen.lock().unwrap().clear();
            let provider = CreditProvider {
                hash: true,
                ..CreditProvider::new()
            };
            let response = get(via, &url, &provider)
                .await
                .unwrap_or_else(|err| panic!("{via:?}: {err}"));

            assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED, "{via:?}");
            assert_eq!(provider.paid(), ["charge-1"], "{via:?}");
            assert_eq!(credentials(&seen).len(), 1, "{via:?}");
            assert_eq!(seen.lock().unwrap().len(), 2, "{via:?}");
        }
    }

    #[tokio::test]
    async fn earlier_refused_challenge_offered_again_is_a_new_attempt() {
        // Only the Challenge just answered is resent: A, then B, then A again
        // gets a new Credential for A.
        let (url, seen) = spawn_credit_server(|credential| match paid_id(credential).as_deref() {
            None => challenged(&[charge("charge-a", "100")], None),
            Some("charge-a") => {
                challenged(&[charge("charge-b", "100")], Some("verification-failed"))
            }
            Some("charge-b") => {
                challenged(&[charge("charge-a", "100")], Some("verification-failed"))
            }
            Some(other) => panic!("unexpected credential for {other}"),
        })
        .await;

        for via in BOTH {
            seen.lock().unwrap().clear();
            let provider = CreditProvider::new();
            let response = get(via, &url, &provider)
                .await
                .unwrap_or_else(|err| panic!("{via:?}: {err}"));

            assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED, "{via:?}");
            assert_eq!(
                provider.paid(),
                ["charge-a", "charge-b", "charge-a"],
                "{via:?}"
            );
            assert_eq!(
                credential_ids(&seen),
                ["charge-a", "charge-b", "charge-a"],
                "{via:?}"
            );
        }
    }

    #[tokio::test]
    async fn refusal_without_payable_challenge_is_final() {
        let stripe = PaymentChallenge::new(
            "stripe-1",
            REALM,
            "stripe",
            "charge",
            Base64UrlJson::from_value(&serde_json::json!({"amount": "100"})).unwrap(),
        );
        for offers in [vec![], vec![stripe]] {
            let (url, seen) = spawn_credit_server(move |credential| match credential {
                None => proof_then_charge(),
                Some(_) => challenged(&offers, Some("credit_insufficient")),
            })
            .await;

            for via in BOTH {
                seen.lock().unwrap().clear();
                let provider = CreditProvider::new();
                let response = get(via, &url, &provider)
                    .await
                    .unwrap_or_else(|err| panic!("{via:?}: {err}"));

                assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED, "{via:?}");
                assert_eq!(provider.paid(), ["proof-1"], "{via:?}");
                assert_eq!(seen.lock().unwrap().len(), 2, "{via:?}");
            }
        }
    }

    #[tokio::test]
    async fn endless_new_challenges_stop_at_the_retry_limit() {
        let (url, seen) = spawn_credit_server(|credential| {
            let next = match paid_id(credential) {
                None => 0,
                Some(id) => id.trim_start_matches("charge-").parse::<u32>().unwrap() + 1,
            };
            challenged(
                &[charge(&format!("charge-{next}"), "100")],
                Some("credit_insufficient"),
            )
        })
        .await;

        for via in BOTH {
            seen.lock().unwrap().clear();
            let provider = CreditProvider::new();
            let response = get(via, &url, &provider)
                .await
                .unwrap_or_else(|err| panic!("{via:?}: {err}"));

            assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED, "{via:?}");
            let expected: Vec<_> = (0..DEFAULT_MAX_PAYMENT_RETRIES)
                .map(|n| format!("charge-{n}"))
                .collect();
            assert_eq!(provider.paid(), expected, "{via:?}");
            assert_eq!(credential_ids(&seen), expected, "{via:?}");
            assert_eq!(
                seen.lock().unwrap().len(),
                DEFAULT_MAX_PAYMENT_RETRIES + 1,
                "{via:?}"
            );
        }
    }

    #[tokio::test]
    async fn new_round_challenge_over_the_spending_cap_is_not_paid() {
        let (url, seen) = spawn_credit_server(|credential| match credential {
            None => proof_then_charge(),
            Some(_) => challenged(&[charge("charge-2", "20000")], Some("credit_insufficient")),
        })
        .await;

        for via in BOTH {
            seen.lock().unwrap().clear();
            let provider = CreditProvider::new();
            let response = get(via, &url, &provider)
                .await
                .unwrap_or_else(|err| panic!("{via:?}: {err}"));

            assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED, "{via:?}");
            assert_eq!(provider.paid(), ["proof-1"], "{via:?}");
            assert_eq!(credential_ids(&seen), ["proof-1"], "{via:?}");
            // The refused proof is rolled back once; nothing is committed.
            assert_eq!(provider.settled(), (0, 1), "{via:?}");
        }
    }

    #[tokio::test]
    async fn new_round_proof_for_another_realm_is_not_signed() {
        let (url, seen) = spawn_credit_server(|credential| match credential {
            None => proof_then_charge(),
            Some(_) => challenged(
                &[charge_in("proof-2", "other.example.com", "0")],
                Some("credit_insufficient"),
            ),
        })
        .await;

        for via in BOTH {
            seen.lock().unwrap().clear();
            let provider = CreditProvider::new();
            let result = get(via, &url, &provider).await;

            assert!(
                result.is_err() || result.unwrap().status() == StatusCode::PAYMENT_REQUIRED,
                "{via:?}"
            );
            assert_eq!(provider.paid(), ["proof-1"], "{via:?}");
            assert_eq!(credential_ids(&seen), ["proof-1"], "{via:?}");
            // The refused proof is rolled back once; nothing is committed.
            assert_eq!(provider.settled(), (0, 1), "{via:?}");
        }
    }

    #[tokio::test]
    async fn expired_new_round_challenge_is_not_paid() {
        let (url, seen) = spawn_credit_server(|credential| match credential {
            None => proof_then_charge(),
            Some(_) => {
                let mut expired = charge("charge-2", "10000");
                expired.expires = Some("2020-01-01T00:00:00Z".to_owned());
                challenged(&[expired], Some("credit_insufficient"))
            }
        })
        .await;

        for via in BOTH {
            seen.lock().unwrap().clear();
            let provider = CreditProvider::new();
            let result = get(via, &url, &provider).await;

            assert!(
                result.is_err() || result.unwrap().status() == StatusCode::PAYMENT_REQUIRED,
                "{via:?}"
            );
            assert_eq!(provider.paid(), ["proof-1"], "{via:?}");
            assert_eq!(credential_ids(&seen), ["proof-1"], "{via:?}");
            // The refused proof is rolled back once; nothing is committed.
            assert_eq!(provider.settled(), (0, 1), "{via:?}");
        }
    }

    /// Holds one payment lock from `pay` until the payment is settled or
    /// released, as `TempoSessionProvider` holds its payment lease until the
    /// server's answer is reconciled. Leases are keyed by Credential, so
    /// settling a replaced Credential leaves its replacement's lease held.
    #[derive(Clone, Default)]
    struct LeasingProvider {
        lock: Arc<tokio::sync::Mutex<()>>,
        leases: Arc<Mutex<HashMap<String, tokio::sync::OwnedMutexGuard<()>>>>,
        paid: Arc<Mutex<Vec<String>>>,
        commits: Arc<AtomicUsize>,
        rollbacks: Arc<AtomicUsize>,
        /// Credentials (by signature) whose rollback fails after releasing
        /// their lease.
        failing_rollbacks: Arc<Mutex<Vec<String>>>,
    }

    impl LeasingProvider {
        fn paid(&self) -> Vec<String> {
            self.paid.lock().unwrap().clone()
        }

        fn settled(&self) -> (usize, usize) {
            (
                self.commits.load(Ordering::SeqCst),
                self.rollbacks.load(Ordering::SeqCst),
            )
        }

        fn leases(&self) -> usize {
            self.leases.lock().unwrap().len()
        }

        /// Whether the Credential signed `signature` holds its lease.
        fn holds(&self, signature: &str) -> bool {
            self.leases.lock().unwrap().contains_key(signature)
        }
    }

    impl PaymentProvider for LeasingProvider {
        fn supports(&self, method: &str, _intent: &str) -> bool {
            method == "tempo"
        }

        async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
            let lease = self.lock.clone().lock_owned().await;
            let count = {
                let mut paid = self.paid.lock().unwrap();
                paid.push(challenge.id.clone());
                paid.len()
            };
            let signature = format!("0x76{count:02}");
            self.leases.lock().unwrap().insert(signature.clone(), lease);
            Ok(PaymentCredential::new(
                challenge.to_echo(),
                PaymentPayload::transaction(signature),
            ))
        }

        async fn commit_payment(
            &self,
            _: &PaymentChallenge,
            credential: &PaymentCredential,
        ) -> Result<(), MppError> {
            self.leases.lock().unwrap().remove(&lease_key(credential));
            self.commits.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn rollback_payment(
            &self,
            _: &PaymentChallenge,
            credential: &PaymentCredential,
        ) -> Result<(), MppError> {
            let key = lease_key(credential);
            self.leases.lock().unwrap().remove(&key);
            if self.failing_rollbacks.lock().unwrap().contains(&key) {
                return Err(MppError::InvalidConfig("rollback failed".into()));
            }
            self.rollbacks.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn abandon_payment(&self, _: &PaymentChallenge, credential: &PaymentCredential) {
            self.leases.lock().unwrap().remove(&lease_key(credential));
        }
    }

    fn lease_key(credential: &PaymentCredential) -> String {
        credential.payload["signature"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }

    async fn get_with_events(
        via: Via,
        url: &str,
        provider: &LeasingProvider,
        events: ClientEvents,
    ) -> Result<reqwest::Response, HttpError> {
        let request = reqwest::Client::new().get(format!("{url}/paid"));
        let send = async {
            match via {
                Via::Fetch => {
                    request
                        .send_with_payment_options(provider, &AcceptPaymentPolicy::Always, events)
                        .await
                }
                Via::Middleware => {
                    let (client, request) = request.build_split();
                    ClientBuilder::new(client.clone())
                        .with(
                            PaymentMiddleware::new(provider.clone())
                                .with_accept_payment_policy(AcceptPaymentPolicy::Always)
                                .with_events(events),
                        )
                        .build()
                        .execute(request.unwrap())
                        .await
                        .map_err(|err| match err {
                            reqwest_middleware::Error::Middleware(err) => err.downcast().unwrap(),
                            reqwest_middleware::Error::Reqwest(err) => HttpError::Request(err),
                        })
                }
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), send)
            .await
            .unwrap_or_else(|_| panic!("{via:?}: payment flow stalled"))
    }

    /// Refuses the first Credential by offering its Challenge again, then
    /// accepts the next one.
    async fn spawn_reoffering_server() -> (String, Arc<Mutex<Vec<Seen>>>, Arc<AtomicUsize>) {
        let answered = Arc::new(AtomicUsize::new(0));
        let (url, seen) = spawn_credit_server({
            let answered = answered.clone();
            move |credential| match credential {
                None => challenged(&[charge("charge-1", "10000")], None),
                Some(_) if answered.fetch_add(1, Ordering::SeqCst) == 0 => {
                    challenged(&[charge("charge-1", "10000")], Some("verification-failed"))
                }
                Some(_) => (StatusCode::OK, "paid").into_response(),
            }
        })
        .await;
        (url, seen, answered)
    }

    /// A `challenge.received` handler that pays through the provider, like
    /// mppx's `createCredential(overrideContext)`, is not left waiting on the
    /// lease of the Credential it replaces: that Credential is released
    /// before the handler runs, then rolled back once the replacement exists.
    #[tokio::test]
    async fn reoffered_challenge_override_paid_through_the_provider_completes() {
        let (url, seen, answered) = spawn_reoffering_server().await;

        for via in BOTH {
            seen.lock().unwrap().clear();
            answered.store(0, Ordering::SeqCst);
            let provider = LeasingProvider::default();
            let events = ClientEvents::default();
            let leases_seen = Arc::new(Mutex::new(Vec::new()));
            let _sub = events.on_challenge_received({
                let provider = provider.clone();
                let leases_seen = leases_seen.clone();
                move |ctx| {
                    let provider = provider.clone();
                    let leases_seen = leases_seen.clone();
                    async move {
                        leases_seen.lock().unwrap().push(provider.leases());
                        provider.pay(&ctx.challenge).await.ok()
                    }
                }
            });

            let response = get_with_events(via, &url, &provider, events)
                .await
                .unwrap_or_else(|err| panic!("{via:?}: {err}"));

            assert_eq!(response.status(), StatusCode::OK, "{via:?}");
            assert_eq!(provider.paid(), ["charge-1", "charge-1"], "{via:?}");
            // Called on the first 402 and on the re-offer, after the refused
            // Credential's lease was released.
            assert_eq!(*leases_seen.lock().unwrap(), [0, 0], "{via:?}");
            // The first 402's handler pays once (a Credential the flow sends);
            // on the re-offer the handler's replacement is sent and the
            // refused Credential is rolled back once.
            let credentials = credentials(&seen);
            assert_eq!(credentials.len(), 2, "{via:?}");
            assert_ne!(credentials[0], credentials[1], "{via:?}");
            assert_eq!(credentials[1]["payload"]["signature"], "0x7602", "{via:?}");
            assert_eq!(provider.settled(), (1, 1), "{via:?}");
            assert_eq!(provider.leases(), 0, "{via:?}");
        }
    }

    /// With no handler, or only an `on_any` observer (even one whose return
    /// type could carry a Credential), a Challenge offered again gets the same
    /// Credential resent, never a second payment.
    #[tokio::test]
    async fn reoffered_challenge_without_override_handler_resends_the_credential() {
        let (url, seen, answered) = spawn_reoffering_server().await;

        // 0: no handler; 1: `on_any` returning `()`; 2: `on_any` returning
        // `Option<PaymentCredential>`, always `None`.
        for observer in 0..3 {
            let observe = observer > 0;
            for via in BOTH {
                seen.lock().unwrap().clear();
                answered.store(0, Ordering::SeqCst);
                let provider = LeasingProvider::default();
                let events = ClientEvents::default();
                let observed = Arc::new(AtomicUsize::new(0));
                let observed_by = observed.clone();
                let _sub = match observer {
                    1 => Some(events.on_any(move |_| {
                        observed_by.fetch_add(1, Ordering::SeqCst);
                        async {}
                    })),
                    2 => Some(events.on_any(move |_| {
                        observed_by.fetch_add(1, Ordering::SeqCst);
                        async { None::<PaymentCredential> }
                    })),
                    _ => None,
                };

                let response = get_with_events(via, &url, &provider, events)
                    .await
                    .unwrap_or_else(|err| panic!("{via:?}: {err}"));

                assert_eq!(response.status(), StatusCode::OK, "{via:?}");
                assert_eq!(provider.paid(), ["charge-1"], "{via:?}");
                let credentials = credentials(&seen);
                assert_eq!(credentials.len(), 2, "{via:?}");
                assert_eq!(credentials[0], credentials[1], "{via:?}");
                assert_eq!(provider.settled(), (1, 0), "{via:?}");
                assert_eq!(provider.leases(), 0, "{via:?}");
                assert_eq!(observed.load(Ordering::SeqCst) > 0, observe, "{via:?}");
            }
        }
    }

    /// A handler that returns the Credential already sent (as a session
    /// provider replays a released open) resends it rather than voiding it.
    #[tokio::test]
    async fn reoffered_challenge_handler_returning_the_sent_credential_resends_it() {
        let (url, seen, answered) = spawn_reoffering_server().await;

        for via in BOTH {
            seen.lock().unwrap().clear();
            answered.store(0, Ordering::SeqCst);
            let provider = LeasingProvider::default();
            let events = ClientEvents::default();
            let _sub = events.on_challenge_received(|ctx| async move {
                Some(PaymentCredential::new(
                    ctx.challenge.to_echo(),
                    PaymentPayload::transaction("0x7699"),
                ))
            });

            let response = get_with_events(via, &url, &provider, events)
                .await
                .unwrap_or_else(|err| panic!("{via:?}: {err}"));

            assert_eq!(response.status(), StatusCode::OK, "{via:?}");
            assert!(provider.paid().is_empty(), "{via:?}");
            let credentials = credentials(&seen);
            assert_eq!(credentials.len(), 2, "{via:?}");
            assert_eq!(credentials[0], credentials[1], "{via:?}");
            assert_eq!(provider.settled(), (1, 0), "{via:?}");
        }
    }

    /// A handler that declines (returns `None`) on a Challenge offered again
    /// gets the same Credential resent, as mppx resends the previous
    /// Credential, rather than a second payment for the same Challenge.
    #[tokio::test]
    async fn reoffered_challenge_declined_by_handler_resends_the_credential() {
        let (url, seen, answered) = spawn_reoffering_server().await;

        for via in BOTH {
            seen.lock().unwrap().clear();
            answered.store(0, Ordering::SeqCst);
            let provider = LeasingProvider::default();
            let events = ClientEvents::default();
            let leases_seen = Arc::new(Mutex::new(Vec::new()));
            let _sub = events.on_challenge_received({
                let provider = provider.clone();
                let leases_seen = leases_seen.clone();
                move |_| {
                    leases_seen.lock().unwrap().push(provider.leases());
                    async { None }
                }
            });

            let response = get_with_events(via, &url, &provider, events)
                .await
                .unwrap_or_else(|err| panic!("{via:?}: {err}"));

            assert_eq!(response.status(), StatusCode::OK, "{via:?}");
            assert_eq!(provider.paid(), ["charge-1"], "{via:?}");
            // The handler ran on the re-offer with the lease released.
            assert_eq!(*leases_seen.lock().unwrap(), [0, 0], "{via:?}");
            let credentials = credentials(&seen);
            assert_eq!(credentials.len(), 2, "{via:?}");
            assert_eq!(credentials[0], credentials[1], "{via:?}");
            assert_eq!(provider.settled(), (1, 0), "{via:?}");
            assert_eq!(provider.leases(), 0, "{via:?}");
        }
    }

    /// Without a callback that can return a Credential, a Challenge offered
    /// again gets its Credential resent under the provider's lease, so a
    /// concurrent request on the same provider pays only once the resend is
    /// settled, as `TempoSessionProvider` keeps vouchers ordered.
    #[tokio::test]
    async fn reoffered_challenge_resend_keeps_the_lease_for_concurrent_requests() {
        // 0: no handler; 1: an `on_any` observer returning `()`.
        for observer in 0..2 {
            for via in BOTH {
                let provider = LeasingProvider::default();
                let answered = Arc::new(AtomicUsize::new(0));
                // (signature, its lease held, payments made) per Credential
                // the server receives.
                let arrivals = Arc::new(Mutex::new(Vec::new()));
                let (url, seen) = spawn_credit_server({
                    let provider = provider.clone();
                    let answered = answered.clone();
                    let arrivals = arrivals.clone();
                    move |credential| match credential {
                        None => challenged(&[charge("charge-1", "10000")], None),
                        Some(credential) => {
                            let signature = lease_key(credential);
                            arrivals.lock().unwrap().push((
                                signature.clone(),
                                provider.holds(&signature),
                                provider.paid().len(),
                            ));
                            if answered.fetch_add(1, Ordering::SeqCst) == 0 {
                                challenged(
                                    &[charge("charge-1", "10000")],
                                    Some("verification-failed"),
                                )
                            } else {
                                (StatusCode::OK, "paid").into_response()
                            }
                        }
                    }
                })
                .await;
                let events = ClientEvents::default();
                let _sub = (observer == 1).then(|| events.on_any(|_| async {}));

                let (first, second) = tokio::join!(
                    get_with_events(via, &url, &provider, events.clone()),
                    get_with_events(via, &url, &provider, events.clone()),
                );

                for response in [first, second] {
                    let response = response.unwrap_or_else(|err| panic!("{via:?}: {err}"));
                    assert_eq!(response.status(), StatusCode::OK, "{via:?}");
                }
                // The resend arrives under the first Credential's lease,
                // before the concurrent request could pay.
                assert_eq!(
                    *arrivals.lock().unwrap(),
                    [
                        ("0x7601".to_owned(), true, 1),
                        ("0x7601".to_owned(), true, 1),
                        ("0x7602".to_owned(), true, 2),
                    ],
                    "{via:?} observer {observer}"
                );
                assert_eq!(credentials(&seen).len(), 3, "{via:?}");
                assert_eq!(provider.paid(), ["charge-1", "charge-1"], "{via:?}");
                assert_eq!(provider.settled(), (2, 0), "{via:?}");
                assert_eq!(provider.leases(), 0, "{via:?}");
            }
        }
    }

    /// When the Credential a callback's replacement refuses cannot be rolled
    /// back, the flow fails without sending the replacement and leaves no
    /// provider lease held, so later payments do not wait forever.
    #[tokio::test]
    async fn failed_rollback_of_a_replaced_credential_frees_the_replacement() {
        let (url, seen, answered) = spawn_reoffering_server().await;

        for via in BOTH {
            seen.lock().unwrap().clear();
            answered.store(0, Ordering::SeqCst);
            let provider = LeasingProvider::default();
            provider
                .failing_rollbacks
                .lock()
                .unwrap()
                .push("0x7601".to_owned());
            let events = ClientEvents::default();
            let _sub = events.on_challenge_received({
                let provider = provider.clone();
                move |ctx| {
                    let provider = provider.clone();
                    async move { provider.pay(&ctx.challenge).await.ok() }
                }
            });

            let result = get_with_events(via, &url, &provider, events).await;

            assert!(
                matches!(result, Err(HttpError::Payment(_))),
                "{via:?}: {result:?}"
            );
            assert_eq!(provider.paid(), ["charge-1", "charge-1"], "{via:?}");
            // Only the refused Credential was sent; the unsent replacement is
            // rolled back and its lease freed.
            assert_eq!(credentials(&seen).len(), 1, "{via:?}");
            assert_eq!(provider.leases(), 0, "{via:?}");
            assert!(provider.lock.try_lock().is_ok(), "{via:?}");
            assert_eq!(provider.settled(), (0, 1), "{via:?}");
        }
    }
}
