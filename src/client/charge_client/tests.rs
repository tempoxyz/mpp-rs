use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;

use crate::client::PaymentContext;
use crate::protocol::core::{
    format_www_authenticate, parse_authorization, Base64UrlJson, PaymentCredential, PaymentPayload,
};
use crate::MppError;

#[derive(Clone, Default)]
struct Provider {
    prepared: Arc<AtomicUsize>,
    paid: Arc<Mutex<Vec<String>>>,
    prepaid_calls: Arc<AtomicUsize>,
    prepaid: Option<PaymentChallenge>,
    replacement: Option<PaymentChallenge>,
    refresh_first: bool,
}

impl PaymentProvider for Provider {
    fn supports(&self, method: &str, _: &str) -> bool {
        matches!(method, "test" | "alternate")
    }

    async fn prepaid_credential(
        &self,
        _context: PaymentContext,
    ) -> Option<(PaymentChallenge, PaymentCredential)> {
        self.prepaid_calls.fetch_add(1, Ordering::SeqCst);
        self.prepaid.clone().map(|challenge| {
            let credential = PaymentCredential::new(
                challenge.to_echo(),
                PaymentPayload::hash("offline-prepaid-proof"),
            );
            (challenge, credential)
        })
    }

    async fn prepare_http_payment_challenge(
        &self,
        challenge: &PaymentChallenge,
        context: PaymentContext,
    ) -> Result<Option<PaymentChallenge>, MppError> {
        assert!(
            context.http_client.is_none(),
            "no session management client"
        );
        let first = self.prepared.fetch_add(1, Ordering::SeqCst) == 0;
        if first && self.refresh_first {
            return Ok(None);
        }
        Ok(Some(
            self.replacement
                .clone()
                .unwrap_or_else(|| challenge.clone()),
        ))
    }

    async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
        self.paid.lock().unwrap().push(challenge.id.clone());
        Ok(PaymentCredential::new(
            challenge.to_echo(),
            PaymentPayload::hash("offline-proof"),
        ))
    }
}

fn challenge(id: &str, intent: &str, header: &str) -> PaymentChallenge {
    PaymentChallenge::new(
        id,
        "local.test",
        "test",
        intent,
        Base64UrlJson::from_value(&serde_json::json!({"amount": "1"})).unwrap(),
    )
    .with_header(header)
}

fn offer(challenges: &[PaymentChallenge]) -> axum::response::Response {
    let headers = challenges.iter().map(|challenge| {
        (
            "www-authenticate",
            format_www_authenticate(challenge).unwrap(),
        )
    });
    let mut response = StatusCode::PAYMENT_REQUIRED.into_response();
    for (name, value) in headers {
        response.headers_mut().append(name, value.parse().unwrap());
    }
    response
}

async fn server(app: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{address}")
}

fn client() -> ChargeClient {
    ChargeClient::new(Client::builder().no_proxy()).unwrap()
}

#[tokio::test]
async fn never_requests_prepaid_credentials_and_still_pays_charge_challenges() {
    for intent in ["session", "charge"] {
        for header in ["Authorization", "Payment-Authorization"] {
            for paid in [false, true] {
                let observed = Arc::new(Mutex::new(Vec::new()));
                let url = server(Router::new().route(
                    "/",
                    get({
                        let observed = observed.clone();
                        move |headers: HeaderMap| {
                            let observed = observed.clone();
                            async move {
                                let credential = headers.get("payment-authorization").cloned();
                                observed.lock().unwrap().push(headers);
                                if !paid || credential.is_some() {
                                    StatusCode::OK.into_response()
                                } else {
                                    offer(&[challenge(
                                        "quoted-charge",
                                        "charge",
                                        "Payment-Authorization",
                                    )])
                                }
                            }
                        }
                    }),
                ))
                .await;
                let provider = Provider {
                    prepaid: Some(challenge("prepaid", intent, header)),
                    ..Provider::default()
                };
                let client = client();
                let response = client
                    .send_with_payment(
                        client
                            .request(Method::GET, url)
                            .bearer_auth("api-key")
                            .header(ACCEPT_PAYMENT_HEADER, "test/session, test/charge"),
                        &provider,
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(provider.prepaid_calls.load(Ordering::SeqCst), 0);
                assert_eq!(provider.prepared.load(Ordering::SeqCst), usize::from(paid));
                assert_eq!(
                    *provider.paid.lock().unwrap(),
                    if paid { vec!["quoted-charge"] } else { vec![] }
                );
                let observed = observed.lock().unwrap();
                assert_eq!(observed.len(), 1 + usize::from(paid));
                assert!(!observed[0].contains_key("payment-authorization"));
                for headers in observed.iter() {
                    assert_eq!(headers["authorization"], "Bearer api-key");
                }
                if paid {
                    let credential =
                        parse_authorization(observed[1]["payment-authorization"].to_str().unwrap())
                            .unwrap();
                    assert_eq!(credential.challenge.id, "quoted-charge");
                    assert_eq!(credential.challenge.intent.as_str(), "charge");
                }
            }
        }
    }
}

#[tokio::test]
async fn legacy_fetch_keeps_prepaid_session_support() {
    use crate::client::Fetch;

    let url = server(Router::new().route(
        "/",
        get(|headers: HeaderMap| async move {
            let credential =
                parse_authorization(headers["authorization"].to_str().unwrap()).unwrap();
            assert_eq!(credential.challenge.id, "prepaid");
            assert_eq!(credential.challenge.intent.as_str(), "session");
            assert!(!headers.contains_key("payment-authorization"));
            StatusCode::OK
        }),
    ))
    .await;
    let provider = Provider {
        prepaid: Some(challenge("prepaid", "session", "Authorization")),
        ..Provider::default()
    };
    let response = Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(url)
        .header(ACCEPT_PAYMENT_HEADER, "test/session")
        .send_with_payment(&provider)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(provider.prepaid_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.prepared.load(Ordering::SeqCst), 0);
    assert!(provider.paid.lock().unwrap().is_empty());
}

#[tokio::test]
async fn redirects_are_never_followed_before_or_after_payment() {
    for cross_origin in [false, true] {
        for initial_redirect in [false, true] {
            for status in [301, 302, 303, 307, 308] {
                let contacted = Arc::new(AtomicUsize::new(0));
                let sink = Router::new().route(
                    "/sink",
                    get({
                        let contacted = contacted.clone();
                        move || {
                            contacted.fetch_add(1, Ordering::SeqCst);
                            async { "unexpected redirect target" }
                        }
                    }),
                );
                let target = if cross_origin {
                    format!("{}/sink", server(sink.clone()).await)
                } else {
                    "/sink".to_owned()
                };
                let url = server(sink.route(
                    "/",
                    get(move |headers: HeaderMap| {
                        let target = target.clone();
                        async move {
                            if initial_redirect || headers.contains_key("payment-authorization") {
                                (
                                    StatusCode::from_u16(status).unwrap(),
                                    [("location", target)],
                                )
                                    .into_response()
                            } else {
                                offer(&[challenge("charge", "charge", "Payment-Authorization")])
                            }
                        }
                    }),
                ))
                .await;
                // A permissive builder must not weaken the retained client's policy.
                let client = ChargeClient::new(
                    Client::builder()
                        .no_proxy()
                        .redirect(reqwest::redirect::Policy::limited(10)),
                )
                .unwrap();
                let provider = Provider::default();
                // The caller's builder has its own redirect-following client.
                let request = Client::new()
                    .get(url)
                    .header(ACCEPT_PAYMENT_HEADER, "test/charge");
                let response = client.send_with_payment(request, &provider).await.unwrap();
                assert_eq!(response.status().as_u16(), status);
                assert_eq!(contacted.load(Ordering::SeqCst), 0);
                assert_eq!(
                    provider.prepared.load(Ordering::SeqCst),
                    usize::from(!initial_redirect)
                );
                assert_eq!(
                    provider.paid.lock().unwrap().len(),
                    usize::from(!initial_redirect)
                );
            }
        }
    }
}

#[tokio::test]
async fn ordinary_authorization_charge_succeeds() {
    let url = server(Router::new().route(
        "/",
        get(|headers: HeaderMap| async move {
            if let Some(credential) = headers.get("authorization") {
                assert_eq!(
                    parse_authorization(credential.to_str().unwrap())
                        .unwrap()
                        .challenge
                        .id,
                    "charge"
                );
                assert!(!headers.contains_key("payment-authorization"));
                StatusCode::OK.into_response()
            } else {
                offer(&[challenge("charge", "charge", "Authorization")])
            }
        }),
    ))
    .await;
    let client = client();
    let provider = Provider::default();
    let response = client
        .send_with_payment(
            client
                .request(Method::GET, url)
                .header(ACCEPT_PAYMENT_HEADER, "test/charge"),
            &provider,
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(*provider.paid.lock().unwrap(), ["charge"]);
}

#[tokio::test]
async fn provider_refresh_uses_owned_client_and_never_follows_redirects() {
    for redirect in [false, true] {
        let requests = Arc::new(AtomicUsize::new(0));
        let sink_requests = Arc::new(AtomicUsize::new(0));
        let url = server(
            Router::new()
                .route(
                    "/",
                    get({
                        let requests = requests.clone();
                        move |headers: HeaderMap| {
                            let index = requests.fetch_add(1, Ordering::SeqCst);
                            async move {
                                if headers.contains_key("payment-authorization") {
                                    StatusCode::OK.into_response()
                                } else if index > 0 && redirect {
                                    (StatusCode::TEMPORARY_REDIRECT, [("location", "/sink")])
                                        .into_response()
                                } else {
                                    offer(&[challenge(
                                        if index == 0 { "initial" } else { "fresh" },
                                        "charge",
                                        "Payment-Authorization",
                                    )])
                                }
                            }
                        }
                    }),
                )
                .route(
                    "/sink",
                    get({
                        let sink_requests = sink_requests.clone();
                        move || {
                            sink_requests.fetch_add(1, Ordering::SeqCst);
                            async { "unexpected" }
                        }
                    }),
                ),
        )
        .await;
        let provider = Provider {
            refresh_first: true,
            ..Provider::default()
        };
        let client = client();
        let response = client
            .send_with_payment(
                client
                    .request(Method::GET, url)
                    .header(ACCEPT_PAYMENT_HEADER, "test/charge"),
                &provider,
            )
            .await
            .unwrap();
        assert_eq!(sink_requests.load(Ordering::SeqCst), 0);
        if redirect {
            assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
            assert_eq!(requests.load(Ordering::SeqCst), 2);
            assert_eq!(provider.prepared.load(Ordering::SeqCst), 1);
            assert!(provider.paid.lock().unwrap().is_empty());
        } else {
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(requests.load(Ordering::SeqCst), 3);
            assert_eq!(provider.prepared.load(Ordering::SeqCst), 2);
            assert_eq!(*provider.paid.lock().unwrap(), ["fresh"]);
        }
    }
}

#[tokio::test]
async fn custom_header_casing_is_preserved_for_initial_and_prepared_challenges() {
    for header in ["payment-authorization", "PaYmEnT-AuThOrIzAtIoN"] {
        for replace in [false, true] {
            let offered = challenge(
                "charge",
                "charge",
                if replace { "Authorization" } else { header },
            );
            let replacement = challenge("prepared", "charge", header);
            let expected_header = header.to_owned();
            let url = server(Router::new().route(
                "/",
                get(move |headers: HeaderMap| {
                    let offered = offered.clone();
                    let expected_header = expected_header.clone();
                    async move {
                        if let Some(credential) = headers.get("payment-authorization") {
                            let credential =
                                parse_authorization(credential.to_str().unwrap()).unwrap();
                            assert_eq!(
                                credential.challenge.header.as_deref(),
                                Some(expected_header.as_str())
                            );
                            StatusCode::OK.into_response()
                        } else {
                            offer(&[offered])
                        }
                    }
                }),
            ))
            .await;
            let provider = Provider {
                replacement: replace.then_some(replacement),
                ..Provider::default()
            };
            let client = client();
            let response = client
                .send_with_payment(
                    client
                        .request(Method::GET, url)
                        .header(ACCEPT_PAYMENT_HEADER, "test/charge"),
                    &provider,
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                *provider.paid.lock().unwrap(),
                [if replace { "prepared" } else { "charge" }]
            );
        }
    }
}

#[tokio::test]
async fn preserves_api_authorization_and_replays_body() {
    let observed = Arc::new(Mutex::new(Vec::new()));
    let url = server(Router::new().route(
        "/",
        post({
            let observed = observed.clone();
            move |headers: HeaderMap, body: String| {
                let observed = observed.clone();
                async move {
                    assert_eq!(headers["authorization"], "Bearer api-key");
                    assert_eq!(body, "payload");
                    observed.lock().unwrap().push(headers.clone());
                    if let Some(credential) = headers.get("payment-authorization") {
                        assert_eq!(
                            parse_authorization(credential.to_str().unwrap())
                                .unwrap()
                                .challenge
                                .id,
                            "charge"
                        );
                        StatusCode::OK.into_response()
                    } else {
                        offer(&[challenge("charge", "charge", "Payment-Authorization")])
                    }
                }
            }
        }),
    ))
    .await;
    for default_auth in [false, true] {
        let mut defaults = HeaderMap::new();
        if default_auth {
            defaults.insert("authorization", "Bearer api-key".parse().unwrap());
        }
        let client =
            ChargeClient::new(Client::builder().no_proxy().default_headers(defaults)).unwrap();
        let mut request = client
            .request(Method::POST, &url)
            .header(ACCEPT_PAYMENT_HEADER, "test/charge")
            .body("payload");
        if !default_auth {
            request = request.bearer_auth("api-key");
        }
        let response = client
            .send_with_payment(request, &Provider::default())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    assert_eq!(observed.lock().unwrap().len(), 4);
}

#[tokio::test]
async fn filters_sessions_and_unsupported_methods_before_preparation_and_falls_back() {
    for with_charge in [false, true] {
        let url = server(Router::new().route(
            "/",
            get(move |headers: HeaderMap| async move {
                if headers.contains_key("payment-authorization") {
                    return StatusCode::OK.into_response();
                }
                let mut unsupported = challenge("unsupported", "charge", "Payment-Authorization");
                unsupported.method = "other".into();
                let mut challenges = vec![
                    challenge("session", "session", "Authorization"),
                    challenge("custom-session", "session", "Payment-Authorization"),
                    unsupported,
                ];
                if with_charge {
                    challenges.push(challenge("charge", "charge", "Payment-Authorization"));
                }
                offer(&challenges)
            }),
        ))
        .await;
        let provider = Provider::default();
        let client = client();
        let response = client
            .send_with_payment(
                client.request(Method::GET, url).header(
                    ACCEPT_PAYMENT_HEADER,
                    "test/session, other/charge, test/charge",
                ),
                &provider,
            )
            .await;
        if with_charge {
            assert_eq!(response.unwrap().status(), StatusCode::OK);
            assert_eq!(*provider.paid.lock().unwrap(), ["charge"]);
        } else {
            assert!(response.is_err());
            assert_eq!(provider.prepared.load(Ordering::SeqCst), 0);
            assert!(provider.paid.lock().unwrap().is_empty());
        }
    }
}

#[tokio::test]
async fn rechecks_prepared_challenge_before_creating_credential() {
    let mut unsupported = challenge("unsupported", "charge", "Payment-Authorization");
    unsupported.method = "other".into();
    let mut opted_out = challenge("opted-out", "charge", "Payment-Authorization");
    opted_out.method = "alternate".into();
    let expired = challenge("expired", "charge", "Payment-Authorization")
        .with_expires("2020-01-01T00:00:00Z");
    for replacement in [
        challenge("session", "session", "Authorization"),
        challenge("custom-session", "session", "Payment-Authorization"),
        unsupported,
        opted_out,
        expired,
    ] {
        let url = server(Router::new().route(
            "/",
            get(|| async { offer(&[challenge("charge", "charge", "Payment-Authorization")]) }),
        ))
        .await;
        let provider = Provider {
            replacement: Some(replacement),
            ..Provider::default()
        };
        let client = client();
        let error = client
            .send_with_payment(
                client
                    .request(Method::GET, url)
                    .header(ACCEPT_PAYMENT_HEADER, "test/*, alternate/charge;q=0"),
                &provider,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            HttpError::NoSupportedChallenge(_) | HttpError::Payment(_)
        ));
        assert_eq!(provider.prepared.load(Ordering::SeqCst), 1);
        assert!(provider.paid.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn missing_malformed_ambiguous_and_disabled_preferences_never_prepare() {
    let url = server(Router::new().route(
        "/",
        get(|| async { offer(&[challenge("charge", "charge", "Payment-Authorization")]) }),
    ))
    .await;
    let mut defaults = HeaderMap::new();
    defaults.insert(ACCEPT_PAYMENT_HEADER, "test/charge".parse().unwrap());
    let client = ChargeClient::new(Client::builder().no_proxy().default_headers(defaults)).unwrap();
    for preference in [None, Some(""), Some("invalid"), Some("test/charge;q=0")] {
        let provider = Provider::default();
        let mut request = client.request(Method::GET, &url);
        if let Some(preference) = preference {
            request = request.header(ACCEPT_PAYMENT_HEADER, preference);
        }
        let response = client.send_with_payment(request, &provider).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(provider.prepared.load(Ordering::SeqCst), 0);
    }
    for repeated in [false, true] {
        let provider = Provider::default();
        let mut request = client
            .request(Method::GET, &url)
            .header(ACCEPT_PAYMENT_HEADER, "test/charge");
        if repeated {
            request = request.header(ACCEPT_PAYMENT_HEADER, "test/charge;q=0");
        }
        let cap = if repeated { 3 } else { 0 };
        let response = client
            .send_with_payment_max_retries(request, &provider, cap)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(provider.prepared.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn method_opt_out_is_preserved_with_other_positive_preferences() {
    let url = server(Router::new().route(
        "/",
        get(|| async { offer(&[challenge("charge", "charge", "Payment-Authorization")]) }),
    ))
    .await;
    let client = client();
    let provider = Provider::default();
    let result = client
        .send_with_payment(
            client
                .request(Method::GET, url)
                .header(ACCEPT_PAYMENT_HEADER, "test/charge;q=0, other/charge"),
            &provider,
        )
        .await;
    assert!(result.is_err());
    assert_eq!(provider.prepared.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn paid_retries_stop_at_cap_and_do_not_repay_same_challenge() {
    for repeat in [false, true] {
        let requests = Arc::new(AtomicUsize::new(0));
        let url = server(Router::new().route(
            "/",
            get({
                let requests = requests.clone();
                move || {
                    let index = requests.fetch_add(1, Ordering::SeqCst);
                    async move {
                        let id = if repeat {
                            "same".to_owned()
                        } else {
                            index.to_string()
                        };
                        offer(&[challenge(&id, "charge", "Payment-Authorization")])
                    }
                }
            }),
        ))
        .await;
        let provider = Provider::default();
        let client = client();
        let response = client
            .send_with_payment_max_retries(
                client
                    .request(Method::GET, url)
                    .header(ACCEPT_PAYMENT_HEADER, "test/charge"),
                &provider,
                2,
            )
            .await
            .unwrap();
        let expected = if repeat { 1 } else { 2 };
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(provider.paid.lock().unwrap().len(), expected);
        assert_eq!(requests.load(Ordering::SeqCst), expected + 1);
    }
}

#[tokio::test]
async fn noncloneable_body_is_sent_once_and_never_paid() {
    let url = server(
        Router::new()
            .route("/free", post(|body: String| async move { body }))
            .route(
                "/paid",
                post(|| async { offer(&[challenge("charge", "charge", "Payment-Authorization")]) }),
            ),
    )
    .await;
    let client = client();
    let provider = Provider::default();
    for paid in [false, true] {
        let body: reqwest::Body =
            reqwest::Response::from(axum::http::Response::new("payload")).into();
        let request = client
            .request(
                Method::POST,
                format!("{url}/{}", if paid { "paid" } else { "free" }),
            )
            .header(ACCEPT_PAYMENT_HEADER, "test/charge")
            .body(body);
        let response = client.send_with_payment(request, &provider).await;
        if paid {
            assert!(matches!(response, Err(HttpError::CloneFailed)));
        } else {
            assert_eq!(response.unwrap().text().await.unwrap(), "payload");
        }
    }
    assert_eq!(provider.prepared.load(Ordering::SeqCst), 0);
    assert!(provider.paid.lock().unwrap().is_empty());
}
