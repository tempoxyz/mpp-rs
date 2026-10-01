//! Behaviour that `Fetch` and `PaymentMiddleware` must share.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::header::WWW_AUTHENTICATE;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use reqwest_middleware::ClientBuilder;
use tokio::net::TcpListener;

use crate::client::{
    AcceptPaymentPolicy, ClientEvents, Fetch, HttpError, PaymentContext, PaymentMiddleware,
    PaymentProvider,
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
                ClientBuilder::new(client)
                    .with(PaymentMiddleware::new(provider.clone()).with_events(events))
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
    prepared: Arc<AtomicU32>,
    paid: Arc<Mutex<Vec<String>>>,
    committed: Arc<AtomicU32>,
    rolled_back: Arc<AtomicU32>,
    invalidated: Arc<AtomicU32>,
}

impl TestProvider {
    fn paid(&self) -> Vec<String> {
        self.paid.lock().unwrap().clone()
    }
}

impl PaymentProvider for TestProvider {
    fn supports(&self, _method: &str, _intent: &str) -> bool {
        true
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
        Ok(PaymentCredential::new(
            challenge.to_echo(),
            PaymentPayload::hash("0xproof"),
        ))
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

    fn accept_payment_header(&self) -> Option<String> {
        Some(ACCEPT_PAYMENT.to_owned())
    }
}

fn www_authenticate(id: &str, intent: &str) -> String {
    let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
    let challenge = PaymentChallenge::new(id, "flow.example.com", "tempo", intent, request);
    format_www_authenticate(&challenge).unwrap()
}

fn payment_required(id: &str, intent: &str) -> axum::response::Response {
    (
        StatusCode::PAYMENT_REQUIRED,
        [(WWW_AUTHENTICATE, www_authenticate(id, intent))],
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
        assert_eq!(provider.committed.load(Ordering::SeqCst), 1, "{via:?}");
        assert_eq!(provider.rolled_back.load(Ordering::SeqCst), 0, "{via:?}");
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
