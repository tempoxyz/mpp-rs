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
    /// Receipts recorded with [`PaymentProvider::record_receipt`].
    recorded: Arc<AtomicU32>,
    /// Receipts recorded with [`PaymentProvider::record_receipt_without_prepay`].
    recorded_without_prepay: Arc<AtomicU32>,
    /// Send a session voucher before the server asks for payment.
    prepaid: bool,
    /// The realm of the prepaid voucher's cached Challenge, when not the request's host.
    prepaid_realm: Option<&'static str>,
    /// The realm this caller pins for every origin.
    trusted_realm: Option<&'static str>,
    /// Pay charges with a transaction (pull) credential instead of a hash.
    transaction: bool,
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
        if challenge.intent.as_str() == "session" {
            return Ok(PaymentCredential::new(
                challenge.to_echo(),
                serde_json::json!({"type": "voucher", "channelId": "0xsession", "cumulativeAmount": "1000"}),
            ));
        }
        if self.transaction {
            return Ok(PaymentCredential::new(
                challenge.to_echo(),
                PaymentPayload::transaction("0x76f8"),
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

    fn record_receipt(
        &self,
        _: &PaymentContext,
        _: &PaymentChallenge,
        _: &crate::protocol::core::Receipt,
    ) -> Option<u128> {
        self.recorded.fetch_add(1, Ordering::SeqCst);
        None
    }

    fn record_receipt_without_prepay(
        &self,
        _: &PaymentContext,
        _: &PaymentChallenge,
        _: &crate::protocol::core::Receipt,
    ) -> Option<u128> {
        self.recorded_without_prepay.fetch_add(1, Ordering::SeqCst);
        None
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
async fn payment_authorization_offer_is_refused_before_signing() {
    let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
    let challenge = PaymentChallenge::new("pa", "127.0.0.1", "tempo", "charge", request)
        .with_header("Payment-Authorization");
    let header = format_www_authenticate(&challenge).unwrap();
    let paid_requests = Arc::new(AtomicU32::new(0));
    let app = Router::new().route(
        "/paid",
        get({
            let paid_requests = paid_requests.clone();
            move |request: Request<Body>| {
                let header = header.clone();
                let paid_requests = paid_requests.clone();
                async move {
                    if request.headers().contains_key("payment-authorization") {
                        paid_requests.fetch_add(1, Ordering::SeqCst);
                    }
                    (StatusCode::PAYMENT_REQUIRED, [(WWW_AUTHENTICATE, header)]).into_response()
                }
            }
        }),
    );
    let url = spawn_server(app).await;

    // A caller-owned client may follow redirects, which would forward
    // Payment-Authorization to another host, so nothing is signed.
    for via in BOTH {
        let provider = TestProvider::default();
        let request = reqwest::Client::new()
            .get(format!("{url}/paid"))
            .header("authorization", "Bearer api-key");
        let error = via
            .send(request, &provider, ClientEvents::default())
            .await
            .unwrap_err();
        assert!(
            matches!(error, HttpError::UnsafeCredentialHeader),
            "{via:?}: {error}"
        );
        assert!(provider.paid().is_empty(), "{via:?}");
    }
    assert_eq!(paid_requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn default_policy_pays_without_accept_payment() {
    let app = Router::new().route(
        "/paid",
        get(|request: Request<Body>| async move {
            if is_paid(&request) {
                StatusCode::OK.into_response()
            } else {
                payment_required("default", "charge")
            }
        }),
    );
    let url = spawn_server(app).await;

    let provider = TestProvider::default();
    let response = reqwest::Client::new()
        .get(format!("{url}/paid"))
        .send_with_payment(&provider)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(provider.paid(), ["default"]);

    let provider = TestProvider::default();
    let response = ClientBuilder::new(reqwest::Client::new())
        .with(PaymentMiddleware::new(provider.clone()))
        .build()
        .get(format!("{url}/paid"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(provider.paid(), ["default"]);

    // The explicit policy stays available and leaves the 402 unpaid.
    let provider = TestProvider::default();
    let response = reqwest::Client::new()
        .get(format!("{url}/paid"))
        .send_with_payment_policy(&provider, &AcceptPaymentPolicy::Explicit)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    assert!(provider.paid().is_empty());
}

fn paid_route() -> Router {
    Router::new().route(
        "/paid",
        get(|request: Request<Body>| async move {
            if is_paid(&request) {
                StatusCode::OK.into_response()
            } else {
                payment_required("hooked", "charge")
            }
        }),
    )
}

#[tokio::test]
async fn on_challenge_decline_returns_402_without_paying() {
    let url = spawn_server(paid_route()).await;
    for via in BOTH {
        let provider = TestProvider::default();
        let events = ClientEvents::default();
        let seen = Arc::new(Mutex::new(Vec::new()));
        events.set_on_challenge({
            let seen = seen.clone();
            move |context: crate::client::OnChallengeContext| {
                seen.lock().unwrap().push((
                    context.challenge.id.clone(),
                    context.method.clone(),
                    context.url.path().to_owned(),
                    context.headers.get("x-caller").cloned(),
                ));
                async { false }
            }
        });
        let credentials = Arc::new(AtomicU32::new(0));
        let _created = events.on_credential_created({
            let credentials = credentials.clone();
            move |_| {
                credentials.fetch_add(1, Ordering::SeqCst);
                async {}
            }
        });
        let request = reqwest::Client::new()
            .get(format!("{url}/paid"))
            .header("x-caller", "yes");
        let response = via.send(request, &provider, events).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED, "{via:?}");
        assert!(response.headers().contains_key(WWW_AUTHENTICATE), "{via:?}");
        assert!(provider.paid().is_empty(), "{via:?}");
        assert_eq!(credentials.load(Ordering::SeqCst), 0, "{via:?}");
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "{via:?}");
        assert_eq!(seen[0].0, "hooked");
        assert_eq!(seen[0].1, reqwest::Method::GET);
        assert_eq!(seen[0].2, "/paid");
        assert_eq!(seen[0].3.as_ref().unwrap(), "yes");
    }
}

/// A session provider's prepaid voucher is sent before any 402, so with an
/// approval hook set none is sent: a declining hook stops every payment.
#[tokio::test]
async fn on_challenge_hook_disables_prepaid_credentials() {
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
        let provider = TestProvider {
            prepaid: true,
            ..TestProvider::default()
        };
        let events = ClientEvents::default();
        events.set_on_challenge(|_| async { false });
        let credentials = Arc::new(AtomicU32::new(0));
        let _created = events.on_credential_created({
            let credentials = credentials.clone();
            move |_| {
                credentials.fetch_add(1, Ordering::SeqCst);
                async {}
            }
        });
        let request = reqwest::Client::new().get(format!("{url}/paid"));
        let response = via.send(request, &provider, events).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED, "{via:?}");
        assert!(provider.paid().is_empty(), "{via:?}");
        assert_eq!(credentials.load(Ordering::SeqCst), 0, "{via:?}");
    }
}

/// With an approval hook set, a paid session request's receipt is recorded
/// without prepaying, so the provider arms no prepaid voucher or top-up that
/// would pay the next request without the hook.
#[tokio::test]
async fn on_challenge_hook_records_receipts_without_prepay() {
    let app = Router::new().route(
        "/paid",
        get(|request: Request<Body>| async move {
            if !is_paid(&request) {
                return payment_required("session-1", "session");
            }
            let mut receipt = crate::protocol::core::Receipt::success("tempo", "0xsession");
            receipt
                .extensions
                .insert("challengeId".into(), serde_json::json!("session-1"));
            (
                StatusCode::OK,
                [("payment-receipt", receipt.to_header().unwrap())],
            )
                .into_response()
        }),
    );
    let url = spawn_server(app).await;
    for via in BOTH {
        for hooked in [false, true] {
            let provider = TestProvider::default();
            let events = ClientEvents::default();
            if hooked {
                events.set_on_challenge(|_| async { true });
            }
            let request = reqwest::Client::new().get(format!("{url}/paid"));
            let response = via.send(request, &provider, events).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{via:?}, {hooked}");
            assert_eq!(
                provider.recorded.load(Ordering::SeqCst),
                u32::from(!hooked),
                "{via:?}, {hooked}"
            );
            assert_eq!(
                provider.recorded_without_prepay.load(Ordering::SeqCst),
                u32::from(hooked),
                "{via:?}, {hooked}"
            );
        }
    }
}

#[tokio::test]
async fn on_challenge_approval_pays() {
    let url = spawn_server(paid_route()).await;
    for via in BOTH {
        let provider = TestProvider::default();
        let events = ClientEvents::default();
        let calls = Arc::new(AtomicU32::new(0));
        events.set_on_challenge({
            let calls = calls.clone();
            move |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                async { crate::client::ChallengeDecision::Pay }
            }
        });
        let request = reqwest::Client::new().get(format!("{url}/paid"));
        let response = via.send(request, &provider, events).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{via:?}");
        assert_eq!(provider.paid(), ["hooked"], "{via:?}");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "{via:?}");
    }
}

#[tokio::test]
async fn on_challenge_credential_replaces_provider_payment() {
    let url = spawn_server(paid_route()).await;
    for via in BOTH {
        let provider = TestProvider::default();
        let events = ClientEvents::default();
        events.set_on_challenge(|context: crate::client::OnChallengeContext| async move {
            Some(PaymentCredential::new(
                context.challenge.to_echo(),
                crate::protocol::core::PaymentPayload::hash("0xhook"),
            ))
        });
        let request = reqwest::Client::new().get(format!("{url}/paid"));
        let response = via.send(request, &provider, events).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{via:?}");
        assert!(provider.paid().is_empty(), "{via:?}");
    }
}

#[tokio::test]
async fn challenge_received_credential_skips_on_challenge() {
    let url = spawn_server(paid_route()).await;
    let provider = TestProvider::default();
    let events = ClientEvents::default();
    let _override = events.on_challenge_received(|context| async move {
        Some(PaymentCredential::new(
            context.challenge.to_echo(),
            crate::protocol::core::PaymentPayload::hash("0xevent"),
        ))
    });
    events.set_on_challenge(|_| async { false });
    let response = Via::Fetch
        .send(
            reqwest::Client::new().get(format!("{url}/paid")),
            &provider,
            events,
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(provider.paid().is_empty());
}

#[tokio::test]
async fn panicking_on_challenge_declines() {
    let url = spawn_server(paid_route()).await;
    let provider = TestProvider::default();
    let events = ClientEvents::default();
    events.set_on_challenge(|_| -> std::future::Ready<bool> { panic!("hook failed") });
    let response = Via::Middleware
        .send(
            reqwest::Client::new().get(format!("{url}/paid")),
            &provider,
            events.clone(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    assert!(provider.paid().is_empty());

    events.clear_on_challenge();
    let response = Via::Middleware
        .send(
            reqwest::Client::new().get(format!("{url}/paid")),
            &provider,
            events,
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
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
async fn opaque_client_defaults_cannot_authorize_explicit_payment() {
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
                        .send_with_payment_policy(&provider, &AcceptPaymentPolicy::Explicit)
                        .await
                        .map(|r| r.status())
                        .map_err(|e| e.to_string()),
                    Via::Middleware => ClientBuilder::new(client)
                        .with(
                            PaymentMiddleware::new(provider.clone())
                                .with_accept_payment_policy(AcceptPaymentPolicy::Explicit),
                        )
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

/// A 402 answering a credential with `invalid-challenge` (also the replay
/// answer) is final: paying its fresh challenge could pay twice.
#[tokio::test]
async fn invalid_challenge_after_payment_is_final() {
    let issued = Arc::new(AtomicU32::new(0));
    let app = Router::new().route(
        "/paid",
        get({
            let issued = issued.clone();
            move |request: Request<Body>| {
                let issued = issued.clone();
                async move {
                    let n = issued.fetch_add(1, Ordering::SeqCst);
                    let request_json =
                        Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
                    let challenge = PaymentChallenge::new(
                        format!("fresh-{n}"),
                        "127.0.0.1",
                        "tempo",
                        "charge",
                        request_json,
                    );
                    let header = format_www_authenticate(&challenge).unwrap();
                    let problem = if request.headers().contains_key("authorization") {
                        "https://paymentauth.org/problems/invalid-challenge"
                    } else {
                        "https://paymentauth.org/problems/payment-required"
                    };
                    (
                        StatusCode::PAYMENT_REQUIRED,
                        [
                            (WWW_AUTHENTICATE, header),
                            (
                                reqwest::header::CONTENT_TYPE,
                                "application/problem+json".to_string(),
                            ),
                        ],
                        serde_json::json!({"type": problem, "status": 402}).to_string(),
                    )
                        .into_response()
                }
            }
        }),
    );
    let url = spawn_server(app).await;
    for via in BOTH {
        // A transaction credential: a hash credential's answer is final
        // before the invalid-challenge check is reached.
        let provider = TestProvider {
            transaction: true,
            ..TestProvider::default()
        };
        let response = via
            .send(
                reqwest::Client::new().get(format!("{url}/paid")),
                &provider,
                ClientEvents::default(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED, "{via:?}");
        assert_eq!(provider.paid().len(), 1, "{via:?}");
        assert!(response.url().path().ends_with("/paid"), "{via:?}");
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(
            body["type"], "https://paymentauth.org/problems/invalid-challenge",
            "{via:?}"
        );
    }
}

/// A server whose 402 problem is not readable after a credential: answers
/// every paid request with `body` and `content_type` and a fresh challenge.
fn rejecting_route(content_type: Option<&'static str>, body: String) -> Router {
    let issued = Arc::new(AtomicU32::new(0));
    Router::new().route(
        "/paid",
        get(move |request: Request<Body>| {
            let issued = issued.clone();
            let body = body.clone();
            async move {
                let n = issued.fetch_add(1, Ordering::SeqCst);
                let challenge = www_authenticate(&format!("fresh-{n}"), "tempo", "charge");
                if !is_paid(&request) {
                    return payment_required(&format!("fresh-{n}"), "charge");
                }
                let mut response = (
                    StatusCode::PAYMENT_REQUIRED,
                    [(WWW_AUTHENTICATE, challenge)],
                    body,
                )
                    .into_response();
                if let Some(content_type) = content_type {
                    response
                        .headers_mut()
                        .insert(reqwest::header::CONTENT_TYPE, content_type.parse().unwrap());
                }
                response
            }
        }),
    )
}

/// A 402 without a problem body answering a credential (as the Tower layer
/// answers a replay) is final too: its cause is unknown, so it is not paid
/// again.
#[tokio::test]
async fn bare_402_after_payment_is_final() {
    let url = spawn_server(rejecting_route(None, String::new())).await;
    for via in BOTH {
        let provider = TestProvider {
            transaction: true,
            ..TestProvider::default()
        };
        let response = via
            .send(
                reqwest::Client::new().get(format!("{url}/paid")),
                &provider,
                ClientEvents::default(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED, "{via:?}");
        assert_eq!(provider.paid().len(), 1, "{via:?}");
    }
}

/// A problem body past the read limit is not buffered whole to learn its
/// type: the type is unknown, so the 402 is final, and the caller still gets
/// the whole body.
#[tokio::test]
async fn oversized_problem_body_is_final_and_bounded() {
    let mut body = String::from(
        r#"{"type":"https://paymentauth.org/problems/verification-failed","detail":""#,
    );
    body.push_str(&"x".repeat(super::MAX_PROBLEM_BODY_BYTES * 2));
    body.push_str(r#""}"#);
    let body_len = body.len();
    let url = spawn_server(rejecting_route(Some("application/problem+json"), body)).await;
    for via in BOTH {
        let provider = TestProvider {
            transaction: true,
            ..TestProvider::default()
        };
        let response = via
            .send(
                reqwest::Client::new().get(format!("{url}/paid")),
                &provider,
                ClientEvents::default(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED, "{via:?}");
        assert_eq!(provider.paid().len(), 1, "{via:?}");
        let returned = response.bytes().await.unwrap();
        assert_eq!(returned.len(), body_len, "{via:?}");
    }
}

/// An empty 402 answering a credential is final even without a
/// `Content-Length` header, as a chunked or HTTP/2 response sends it.
#[tokio::test]
async fn streamed_empty_402_after_payment_is_final() {
    let issued = Arc::new(AtomicU32::new(0));
    let router = Router::new().route(
        "/paid",
        get(move |request: Request<Body>| {
            let issued = issued.clone();
            async move {
                let n = issued.fetch_add(1, Ordering::SeqCst);
                if !is_paid(&request) {
                    return payment_required(&format!("fresh-{n}"), "charge");
                }
                let challenge = www_authenticate(&format!("fresh-{n}"), "tempo", "charge");
                let body = Body::from_stream(futures_util::stream::empty::<
                    Result<bytes::Bytes, std::io::Error>,
                >());
                let response = (
                    StatusCode::PAYMENT_REQUIRED,
                    [(WWW_AUTHENTICATE, challenge)],
                    body,
                )
                    .into_response();
                assert!(response
                    .headers()
                    .get(reqwest::header::CONTENT_LENGTH)
                    .is_none());
                response
            }
        }),
    );
    let url = spawn_server(router).await;
    for via in BOTH {
        let provider = TestProvider {
            transaction: true,
            ..TestProvider::default()
        };
        let response = via
            .send(
                reqwest::Client::new().get(format!("{url}/paid")),
                &provider,
                ClientEvents::default(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED, "{via:?}");
        assert_eq!(provider.paid().len(), 1, "{via:?}");
    }
}

/// A problem naming another failure, such as verification-failed, still lets
/// the client pay the fresh challenge.
#[tokio::test]
async fn verification_failed_after_payment_pays_fresh_challenge() {
    let body = serde_json::json!({"type": "https://paymentauth.org/problems/verification-failed"})
        .to_string();
    let url = spawn_server(rejecting_route(Some("application/problem+json"), body)).await;
    for via in BOTH {
        let provider = TestProvider {
            transaction: true,
            ..TestProvider::default()
        };
        let response = via
            .send(
                reqwest::Client::new().get(format!("{url}/paid")),
                &provider,
                ClientEvents::default(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED, "{via:?}");
        assert!(provider.paid().len() > 1, "{via:?}: {:?}", provider.paid());
    }
}

/// A server that answers any request carrying a Payment credential with a
/// 402 of `content_type` and `body` and a fresh challenge, and asks for
/// payment otherwise.
fn caller_credential_route(content_type: Option<&'static str>, body: String) -> Router {
    let issued = Arc::new(AtomicU32::new(0));
    Router::new().route(
        "/paid",
        get(move |request: Request<Body>| {
            let issued = issued.clone();
            let body = body.clone();
            async move {
                let n = issued.fetch_add(1, Ordering::SeqCst);
                if !super::carries_payment_credential(request.headers()) {
                    return payment_required(&format!("fresh-{n}"), "charge");
                }
                let challenge = www_authenticate(&format!("fresh-{n}"), "tempo", "charge");
                let mut response = (
                    StatusCode::PAYMENT_REQUIRED,
                    [(WWW_AUTHENTICATE, challenge)],
                    body,
                )
                    .into_response();
                if let Some(content_type) = content_type {
                    response
                        .headers_mut()
                        .insert(reqwest::header::CONTENT_TYPE, content_type.parse().unwrap());
                }
                response
            }
        }),
    )
}

/// A credential the caller set on the request is answered under the same
/// final rules as one the flow sent: `invalid-challenge` (the replay answer)
/// or an empty 402 is returned without paying the fresh challenge, as mppx
/// does after `initialCredentialSent`.
#[tokio::test]
async fn refused_caller_credential_is_not_paid_again() {
    let invalid_challenge =
        serde_json::json!({"type": "https://paymentauth.org/problems/invalid-challenge"})
            .to_string();
    for (name, content_type, body) in [
        (
            "invalid-challenge",
            Some("application/problem+json"),
            invalid_challenge,
        ),
        ("empty body", None, String::new()),
    ] {
        let url = spawn_server(caller_credential_route(content_type, body)).await;
        for (header, value) in [
            ("authorization", "Payment eyJjaGFsbGVuZ2UiOnt9fQ"),
            ("payment-authorization", "eyJjaGFsbGVuZ2UiOnt9fQ"),
        ] {
            for via in BOTH {
                let provider = TestProvider::default();
                let response = via
                    .send(
                        reqwest::Client::new()
                            .get(format!("{url}/paid"))
                            .header(header, value),
                        &provider,
                        ClientEvents::default(),
                    )
                    .await
                    .unwrap_or_else(|err| panic!("{name}, {header}, {via:?}: {err}"));
                assert_eq!(
                    response.status(),
                    StatusCode::PAYMENT_REQUIRED,
                    "{name}, {header}, {via:?}"
                );
                assert!(
                    provider.paid().is_empty(),
                    "{name}, {header}, {via:?}: {:?}",
                    provider.paid()
                );
            }
        }
    }
}

/// A caller credential refused for another reason, such as
/// verification-failed, still lets the client pay the fresh challenge.
#[tokio::test]
async fn caller_credential_verification_failed_pays_fresh_challenge() {
    let body = serde_json::json!({"type": "https://paymentauth.org/problems/verification-failed"})
        .to_string();
    let url = spawn_server(caller_credential_route(
        Some("application/problem+json"),
        body,
    ))
    .await;
    for via in BOTH {
        let provider = TestProvider::default();
        let response = via
            .send(
                reqwest::Client::new()
                    .get(format!("{url}/paid"))
                    .header("authorization", "Payment eyJjaGFsbGVuZ2UiOnt9fQ"),
                &provider,
                ClientEvents::default(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED, "{via:?}");
        assert!(!provider.paid().is_empty(), "{via:?}");
    }
}

#[test]
fn carries_payment_credential_reads_both_headers() {
    let headers = |pairs: &[(&'static str, &'static str)]| {
        let mut map = reqwest::header::HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, value.parse().unwrap());
        }
        map
    };
    assert!(super::carries_payment_credential(&headers(&[(
        "authorization",
        "Payment abc"
    )])));
    assert!(super::carries_payment_credential(&headers(&[(
        "authorization",
        "payment abc"
    )])));
    assert!(super::carries_payment_credential(&headers(&[(
        "Payment-Authorization",
        "abc"
    )])));
    assert!(!super::carries_payment_credential(&headers(&[(
        "authorization",
        "Bearer abc"
    )])));
    assert!(!super::carries_payment_credential(&headers(&[(
        "authorization",
        "Paymentabc"
    )])));
    assert!(!super::carries_payment_credential(&headers(&[])));
}

/// A caller's own hash (push) credential has its transfer on chain already,
/// so any 402 answering it is final, even verification-failed, as for a hash
/// credential the flow sent.
#[tokio::test]
async fn caller_hash_credential_is_never_paid_again() {
    let challenge = crate::protocol::core::parse_www_authenticate(&www_authenticate(
        "caller", "tempo", "charge",
    ))
    .unwrap();
    let credential = PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xabc"));
    let authorization = crate::protocol::core::format_authorization(&credential).unwrap();
    let token = authorization.trim_start_matches("Payment ").to_string();
    let body = serde_json::json!({"type": "https://paymentauth.org/problems/verification-failed"})
        .to_string();
    let url = spawn_server(caller_credential_route(
        Some("application/problem+json"),
        body,
    ))
    .await;
    for (header, value) in [
        ("authorization", authorization.clone()),
        ("payment-authorization", token.clone()),
        ("payment-authorization", authorization.clone()),
    ] {
        for via in BOTH {
            let provider = TestProvider::default();
            let response = via
                .send(
                    reqwest::Client::new()
                        .get(format!("{url}/paid"))
                        .header(header, value.as_str()),
                    &provider,
                    ClientEvents::default(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::PAYMENT_REQUIRED,
                "{header}, {via:?}"
            );
            assert!(
                provider.paid().is_empty(),
                "{header}, {via:?}: {:?}",
                provider.paid()
            );
        }
    }
}

/// A paid retry replaces the caller's credential in either field, so the
/// server never sees two Payment credentials.
#[test]
fn remove_payment_credentials_clears_both_fields() {
    let mut headers = HeaderMap::new();
    headers.append("payment-authorization", HeaderValue::from_static("abc"));
    headers.append(
        reqwest::header::AUTHORIZATION,
        HeaderValue::from_static("Payment abc"),
    );
    headers.append(
        reqwest::header::AUTHORIZATION,
        HeaderValue::from_static("Bearer token"),
    );
    super::remove_payment_credentials(&mut headers);
    assert!(!headers.contains_key("payment-authorization"));
    let authorization: Vec<_> = headers
        .get_all(reqwest::header::AUTHORIZATION)
        .iter()
        .collect();
    assert_eq!(authorization, [HeaderValue::from_static("Bearer token")]);
    assert!(!super::carries_payment_credential(&headers));
}

#[test]
fn comma_joined_payment_credentials_are_found_and_removed() {
    use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
    let mut headers = HeaderMap::new();
    headers.append(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer t, Payment abc"),
    );
    assert!(super::carries_payment_credential(&headers));
    super::remove_payment_credentials(&mut headers);
    let values: Vec<_> = headers.get_all(AUTHORIZATION).iter().collect();
    assert_eq!(values, vec![HeaderValue::from_static("Bearer t")]);

    let mut headers = HeaderMap::new();
    headers.append(
        AUTHORIZATION,
        HeaderValue::from_static("Digest realm=\"a, b\", nonce=x, Payment abc, Basic dXM="),
    );
    assert!(super::carries_payment_credential(&headers));
    super::remove_payment_credentials(&mut headers);
    let values: Vec<_> = headers.get_all(AUTHORIZATION).iter().collect();
    assert_eq!(
        values,
        vec![HeaderValue::from_static(
            "Digest realm=\"a, b\", nonce=x, Basic dXM="
        )]
    );

    let mut headers = HeaderMap::new();
    headers.append(AUTHORIZATION, HeaderValue::from_static("Payment abc"));
    super::remove_payment_credentials(&mut headers);
    assert!(headers.get(AUTHORIZATION).is_none());

    let mut headers = HeaderMap::new();
    headers.append(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer payment, Basic x"),
    );
    assert!(!super::carries_payment_credential(&headers));
}

/// An auth-param written with whitespace around its `=` (RFC 9110 BWS) is
/// read as the tokenizer reads it, as a parameter of the scheme before it,
/// even when its name is `Payment`, so a paid retry keeps it and every
/// parameter after it. A token68 ending in `=` padding stays its scheme's.
#[test]
fn padded_auth_params_are_not_read_as_schemes() {
    use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};

    let remove = |value: &'static str| {
        let mut headers = HeaderMap::new();
        headers.append(AUTHORIZATION, HeaderValue::from_static(value));
        super::remove_payment_credentials(&mut headers);
        headers
            .get_all(AUTHORIZATION)
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };

    for value in [
        "Digest realm=x, Payment = \"aux\", nonce=y",
        "Digest realm=x, Payment =\"aux\", nonce=y",
        "Digest realm=x, Payment= \"aux\", nonce=y",
        "Digest realm=x, Payment\t=\taux, nonce=y",
    ] {
        let mut headers = HeaderMap::new();
        headers.append(AUTHORIZATION, HeaderValue::from_static(value));
        assert!(!super::carries_payment_credential(&headers), "{value}");
        assert_eq!(remove(value), [value], "{value}");
    }

    // A real Payment credential after the padded parameter is still removed,
    // with its own parameters, and the schemes after it stay.
    assert_eq!(
        remove("Digest realm=x, Payment = \"aux\", Payment xyz, a = b, Bearer t"),
        ["Digest realm=x, Payment = \"aux\", Bearer t"]
    );
    assert_eq!(remove("Bearer t, Payment xyz"), ["Bearer t"]);
    assert_eq!(remove("Bearer t,Payment\txyz"), ["Bearer t"]);

    // token68 credentials with `=` padding, before and as the Payment one.
    assert_eq!(
        remove("Basic dXNlcjpwYQ==, Payment eyJhIjoxfQ==, Basic dXM="),
        ["Basic dXNlcjpwYQ==, Basic dXM="]
    );
    assert_eq!(remove("Payment eyJhIjoxfQ=="), Vec::<String>::new());
    assert_eq!(remove("Payment eyJhIjoxfQ=, Bearer t"), ["Bearer t"]);
}

/// A value with bytes outside visible ASCII, such as obs-text in a quoted
/// parameter, is read as bytes: a non-Payment credential stays byte for
/// byte, and a Payment credential comma-joined with it is still removed.
#[test]
fn obs_text_authorization_values_are_kept_or_split_as_bytes() {
    use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};

    let remove = |value: &[u8]| {
        let mut headers = HeaderMap::new();
        headers.append(AUTHORIZATION, HeaderValue::from_bytes(value).unwrap());
        let carried = super::carries_payment_credential(&headers);
        super::remove_payment_credentials(&mut headers);
        let kept = headers
            .get_all(AUTHORIZATION)
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect::<Vec<_>>();
        (carried, kept)
    };

    let value = b"Digest realm=\"caf\xe9\", nonce=\"n\xff\"";
    assert!(HeaderValue::from_bytes(value).unwrap().to_str().is_err());
    assert_eq!(remove(value), (false, vec![value.to_vec()]));

    // A padded auth-param named Payment is a parameter here too.
    let value = b"Digest realm=\"caf\xe9\", Payment = \"aux\"";
    assert_eq!(remove(value), (false, vec![value.to_vec()]));

    assert_eq!(
        remove(b"Digest realm=\"caf\xe9\", Payment abc, Bearer t\xe9"),
        (
            true,
            vec![b"Digest realm=\"caf\xe9\", Bearer t\xe9".to_vec()]
        )
    );
    assert_eq!(
        remove(b"Payment abc, opaque=\"\xe9\""),
        (true, Vec::<Vec<u8>>::new())
    );
}

/// A Payment credential the flow cannot see on the request, from the
/// client's default headers or comma-joined after another scheme, is still
/// not paid again when the server answers it with invalid-challenge.
#[tokio::test]
async fn hidden_caller_credential_is_not_paid_again() {
    let body = serde_json::json!({"type": "https://paymentauth.org/problems/invalid-challenge"})
        .to_string();
    let url = spawn_server(caller_credential_route(
        Some("application/problem+json"),
        body,
    ))
    .await;
    let mut defaults = reqwest::header::HeaderMap::new();
    defaults.insert(
        reqwest::header::AUTHORIZATION,
        "Payment eyJjaGFsbGVuZ2UiOnt9fQ".parse().unwrap(),
    );
    let default_client = reqwest::Client::builder()
        .default_headers(defaults)
        .build()
        .unwrap();
    for via in BOTH {
        for (name, builder) in [
            ("default headers", default_client.get(format!("{url}/paid"))),
            (
                "comma-joined",
                reqwest::Client::new()
                    .get(format!("{url}/paid"))
                    .header("authorization", "Bearer t, Payment eyJjaGFsbGVuZ2UiOnt9fQ"),
            ),
        ] {
            let provider = TestProvider::default();
            let response = via
                .send(builder, &provider, ClientEvents::default())
                .await
                .unwrap_or_else(|err| panic!("{name}, {via:?}: {err}"));
            assert_eq!(
                response.status(),
                StatusCode::PAYMENT_REQUIRED,
                "{name}, {via:?}"
            );
            assert!(
                provider.paid().is_empty(),
                "{name}, {via:?}: {:?}",
                provider.paid()
            );
        }
    }
}
