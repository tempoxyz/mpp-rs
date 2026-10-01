use super::*;

#[derive(Clone)]
struct MockProvider;

impl PaymentProvider for MockProvider {
    fn supports(&self, _method: &str, _intent: &str) -> bool {
        true
    }

    async fn pay(
        &self,
        _challenge: &crate::protocol::core::PaymentChallenge,
    ) -> Result<crate::protocol::core::PaymentCredential, crate::error::MppError> {
        unimplemented!("mock provider")
    }
}

#[test]
fn test_middleware_new() {
    let _middleware = PaymentMiddleware::new(MockProvider);
}

#[cfg(all(feature = "client", feature = "middleware", feature = "utils"))]
mod integration {
    use super::*;
    use crate::client::{
        ClientEvent, ClientEventKind, HttpError, PaymentContext, PaymentFailureReason,
    };
    use crate::error::MppError;
    use crate::protocol::core::{
        format_www_authenticate, Base64UrlJson, PaymentChallenge, PaymentCredential, PaymentPayload,
    };

    use axum::http::header::WWW_AUTHENTICATE as WWW_AUTH_NAME;
    use axum::http::StatusCode as AxumStatusCode;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::Router;
    use reqwest_middleware::ClientBuilder;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    #[derive(Clone)]
    struct TestProvider {
        pay_count: Arc<AtomicU32>,
        commit_count: Arc<AtomicU32>,
        rollback_count: Arc<AtomicU32>,
        challenge_ids: Arc<Mutex<Vec<String>>>,
        fail: bool,
    }

    impl TestProvider {
        fn new() -> Self {
            Self {
                pay_count: Arc::new(AtomicU32::new(0)),
                commit_count: Arc::new(AtomicU32::new(0)),
                rollback_count: Arc::new(AtomicU32::new(0)),
                challenge_ids: Arc::new(Mutex::new(Vec::new())),
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                pay_count: Arc::new(AtomicU32::new(0)),
                commit_count: Arc::new(AtomicU32::new(0)),
                rollback_count: Arc::new(AtomicU32::new(0)),
                challenge_ids: Arc::new(Mutex::new(Vec::new())),
                fail: true,
            }
        }

        fn call_count(&self) -> u32 {
            self.pay_count.load(Ordering::SeqCst)
        }

        fn challenge_ids(&self) -> Vec<String> {
            self.challenge_ids.lock().unwrap().clone()
        }

        fn commit_count(&self) -> u32 {
            self.commit_count.load(Ordering::SeqCst)
        }

        fn rollback_count(&self) -> u32 {
            self.rollback_count.load(Ordering::SeqCst)
        }
    }

    impl PaymentProvider for TestProvider {
        fn supports(&self, _method: &str, _intent: &str) -> bool {
            true
        }

        async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
            self.pay_count.fetch_add(1, Ordering::SeqCst);
            self.challenge_ids
                .lock()
                .unwrap()
                .push(challenge.id.clone());
            if self.fail {
                return Err(MppError::Http("test provider failure".into()));
            }
            let echo = challenge.to_echo();
            Ok(PaymentCredential::new(
                echo,
                PaymentPayload::hash("0xmockhash"),
            ))
        }

        async fn commit_payment(
            &self,
            _: &PaymentChallenge,
            _: &PaymentCredential,
        ) -> Result<(), MppError> {
            self.commit_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn rollback_payment(
            &self,
            _: &PaymentChallenge,
            _: &PaymentCredential,
        ) -> Result<(), MppError> {
            self.rollback_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn test_challenge() -> (PaymentChallenge, String) {
        test_challenge_with_id_and_expires("mw-test-id", None)
    }

    fn test_challenge_with_expires(expires: Option<&str>) -> (PaymentChallenge, String) {
        test_challenge_with_id_and_expires("mw-test-id", expires)
    }

    fn test_challenge_with_id(id: &str) -> (PaymentChallenge, String) {
        test_challenge_with_id_and_expires(id, None)
    }

    fn test_challenge_with_id_and_expires(
        id: &str,
        expires: Option<&str>,
    ) -> (PaymentChallenge, String) {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "500"})).unwrap();
        let mut challenge =
            PaymentChallenge::new(id, "middleware.example.com", "tempo", "charge", request);
        if let Some(expires) = expires {
            challenge = challenge.with_expires(expires);
        }
        let header = format_www_authenticate(&challenge).unwrap();
        (challenge, header)
    }

    fn http_error(err: &reqwest_middleware::Error) -> &HttpError {
        match err {
            reqwest_middleware::Error::Middleware(err) => {
                err.downcast_ref().expect("middleware errors are HttpError")
            }
            reqwest_middleware::Error::Reqwest(err) => panic!("unexpected reqwest error: {err}"),
        }
    }

    async fn spawn_server(app: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{}", addr)
    }

    #[tokio::test]
    async fn test_middleware_happy_path() {
        let (_, www_auth) = test_challenge();
        let call_count = Arc::new(AtomicU32::new(0));
        let counter = call_count.clone();

        let app = Router::new().route(
            "/paid",
            get(move |req: axum::http::Request<axum::body::Body>| {
                let www_auth = www_auth.clone();
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    if req.headers().get("authorization").is_some() {
                        (AxumStatusCode::OK, "ok").into_response()
                    } else {
                        (
                            AxumStatusCode::PAYMENT_REQUIRED,
                            [(WWW_AUTH_NAME, www_auth)],
                            "pay up",
                        )
                            .into_response()
                    }
                }
            }),
        );

        let base_url = spawn_server(app).await;
        let provider = TestProvider::new();
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(PaymentMiddleware::new(provider.clone()))
            .build();

        let resp = client
            .get(format!("{}/paid", base_url))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        assert_eq!(provider.call_count(), 1);
        assert_eq!(provider.commit_count(), 1);
        assert_eq!(provider.rollback_count(), 0);
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_middleware_pays_challenge_with_raw_latin1_bytes() {
        let www_auth = axum::http::HeaderValue::from_bytes(
                b"Payment id=\"latin1\", realm=\"caf\xe9\", method=\"tempo\", intent=\"charge\", request=\"e30\"",
            )
            .unwrap();

        let app = Router::new().route(
            "/paid",
            get(move |req: axum::http::Request<axum::body::Body>| {
                let www_auth = www_auth.clone();
                async move {
                    if req.headers().get("authorization").is_some() {
                        (AxumStatusCode::OK, "ok").into_response()
                    } else {
                        (
                            AxumStatusCode::PAYMENT_REQUIRED,
                            [(WWW_AUTH_NAME, www_auth)],
                            "pay up",
                        )
                            .into_response()
                    }
                }
            }),
        );

        let base_url = spawn_server(app).await;
        let provider = TestProvider::new();
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(PaymentMiddleware::new(provider.clone()))
            .build();

        let resp = client
            .get(format!("{}/paid", base_url))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        assert_eq!(provider.challenge_ids(), vec!["latin1".to_string()]);
    }

    #[tokio::test]
    async fn cross_origin_redirect_before_402_is_rejected() {
        let (_, www_auth) = test_challenge();
        let authorization_observed = Arc::new(AtomicU32::new(0));
        let observed = authorization_observed.clone();
        let target = Router::new().route(
            "/paid",
            get(move |req: axum::http::Request<axum::body::Body>| {
                let www_auth = www_auth.clone();
                let observed = observed.clone();
                async move {
                    if req.headers().contains_key("authorization") {
                        observed.fetch_add(1, Ordering::SeqCst);
                    }
                    (
                        AxumStatusCode::PAYMENT_REQUIRED,
                        [(WWW_AUTH_NAME, www_auth)],
                        "pay up",
                    )
                }
            }),
        );
        let target_url = spawn_server(target).await;
        let source = Router::new().route(
            "/paid",
            get(move || {
                let target_url = target_url.clone();
                async move {
                    (
                        AxumStatusCode::TEMPORARY_REDIRECT,
                        [(axum::http::header::LOCATION, format!("{target_url}/paid"))],
                        "redirect",
                    )
                }
            }),
        );
        let source_url = spawn_server(source).await;
        let provider = TestProvider::new();
        let events = ClientEvents::default();
        let failed_count = Arc::new(AtomicU32::new(0));
        let _failed_sub = events.on_payment_failed({
            let failed_count = failed_count.clone();
            move |ctx| {
                failed_count.fetch_add(1, Ordering::SeqCst);
                async move {
                    assert!(ctx.challenge.is_none());
                    assert_eq!(
                        ctx.error,
                        "Refusing to send payment credential across redirect"
                    );
                }
            }
        });
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(PaymentMiddleware::new(provider.clone()).with_events(events))
            .build();

        let err = client
            .get(format!("{source_url}/paid"))
            .send()
            .await
            .unwrap_err();

        assert!(err
            .to_string()
            .contains("Refusing to send payment credential across redirect"));
        assert_eq!(provider.call_count(), 0);
        assert_eq!(authorization_observed.load(Ordering::SeqCst), 0);
        assert_eq!(failed_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn paid_retry_targets_final_same_origin_url() {
        let (_, www_auth) = test_challenge();
        let app = Router::new()
            .route(
                "/start",
                get(|req: axum::http::Request<axum::body::Body>| async move {
                    if req.headers().contains_key("authorization") {
                        return AxumStatusCode::BAD_REQUEST.into_response();
                    }
                    (
                        AxumStatusCode::TEMPORARY_REDIRECT,
                        [(axum::http::header::LOCATION, "/paid")],
                        "redirect",
                    )
                        .into_response()
                }),
            )
            .route(
                "/paid",
                get(move |req: axum::http::Request<axum::body::Body>| {
                    let www_auth = www_auth.clone();
                    async move {
                        if req.headers().contains_key("authorization") {
                            AxumStatusCode::OK.into_response()
                        } else {
                            (
                                AxumStatusCode::PAYMENT_REQUIRED,
                                [(WWW_AUTH_NAME, www_auth)],
                                "pay up",
                            )
                                .into_response()
                        }
                    }
                }),
            );
        let base_url = spawn_server(app).await;
        let provider = TestProvider::new();
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(PaymentMiddleware::new(provider.clone()))
            .build();

        let resp = client
            .get(format!("{base_url}/start"))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        assert_eq!(resp.url().path(), "/paid");
        assert_eq!(provider.call_count(), 1);
    }

    #[tokio::test]
    async fn test_middleware_passes_request_context_to_concurrent_payments() {
        #[derive(Clone)]
        struct ContextProvider {
            contexts: Arc<Mutex<Vec<(String, String)>>>,
        }

        impl PaymentProvider for ContextProvider {
            fn supports(&self, _method: &str, _intent: &str) -> bool {
                true
            }

            async fn pay(
                &self,
                _challenge: &PaymentChallenge,
            ) -> Result<PaymentCredential, MppError> {
                panic!("middleware must call pay_with_context")
            }

            async fn pay_with_context(
                &self,
                challenge: &PaymentChallenge,
                context: PaymentContext,
            ) -> Result<PaymentCredential, MppError> {
                let marker = context
                    .headers
                    .get("x-payment-context")
                    .expect("request marker is present")
                    .to_str()
                    .expect("request marker is valid text")
                    .to_owned();
                self.contexts
                    .lock()
                    .unwrap()
                    .push((context.url.path().to_owned(), marker));
                Ok(PaymentCredential::new(
                    challenge.to_echo(),
                    PaymentPayload::hash("0xcontext"),
                ))
            }
        }

        let (_, www_auth) = test_challenge();
        let app = Router::new().fallback(move |req: axum::http::Request<axum::body::Body>| {
            let www_auth = www_auth.clone();
            async move {
                if req.headers().get("authorization").is_some() {
                    (AxumStatusCode::OK, "ok").into_response()
                } else {
                    (
                        AxumStatusCode::PAYMENT_REQUIRED,
                        [(WWW_AUTH_NAME, www_auth)],
                        "pay up",
                    )
                        .into_response()
                }
            }
        });

        let base_url = spawn_server(app).await;
        let provider = ContextProvider {
            contexts: Arc::new(Mutex::new(Vec::new())),
        };
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(PaymentMiddleware::new(provider.clone()))
            .build();

        let mut requests = tokio::task::JoinSet::new();
        for index in 0..32 {
            let client = client.clone();
            let url = format!("{base_url}/paid/{index}");
            requests.spawn(async move {
                client
                    .get(url)
                    .header("x-payment-context", index.to_string())
                    .send()
                    .await
            });
        }
        while let Some(response) = requests.join_next().await {
            assert_eq!(response.unwrap().unwrap().status(), reqwest::StatusCode::OK);
        }

        let mut actual = provider.contexts.lock().unwrap().clone();
        actual.sort();
        let mut expected = (0..32)
            .map(|index| (format!("/paid/{index}"), index.to_string()))
            .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn test_middleware_payment_events_fire_on_success() {
        let (_, www_auth) = test_challenge();

        let app = Router::new().route(
            "/paid",
            get(move |req: axum::http::Request<axum::body::Body>| {
                let www_auth = www_auth.clone();
                async move {
                    if req.headers().get("authorization").is_some() {
                        (AxumStatusCode::OK, "ok").into_response()
                    } else {
                        (
                            AxumStatusCode::PAYMENT_REQUIRED,
                            [(WWW_AUTH_NAME, www_auth)],
                            "pay up",
                        )
                            .into_response()
                    }
                }
            }),
        );

        let base_url = spawn_server(app).await;
        let provider = TestProvider::new();
        let events = ClientEvents::default();
        let challenge_count = Arc::new(AtomicU32::new(0));
        let credential_count = Arc::new(AtomicU32::new(0));
        let response_count = Arc::new(AtomicU32::new(0));

        let _challenge_sub = events.on_challenge_received({
            let challenge_count = challenge_count.clone();
            move |ctx| {
                challenge_count.fetch_add(1, Ordering::SeqCst);
                async move {
                    assert_eq!(ctx.challenge.method.as_str(), "tempo");
                    None
                }
            }
        });
        let _credential_sub = events.on_credential_created({
            let credential_count = credential_count.clone();
            move |ctx| {
                credential_count.fetch_add(1, Ordering::SeqCst);
                async move {
                    assert_eq!(ctx.credential.challenge.method.as_str(), "tempo");
                }
            }
        });
        let _response_sub = events.on_payment_response({
            let response_count = response_count.clone();
            move |ctx| {
                response_count.fetch_add(1, Ordering::SeqCst);
                async move {
                    assert_eq!(ctx.status, reqwest::StatusCode::OK);
                }
            }
        });

        let client = ClientBuilder::new(reqwest::Client::new())
            .with(PaymentMiddleware::new(provider.clone()).with_events(events))
            .build();

        let resp = client
            .get(format!("{}/paid", base_url))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        assert_eq!(provider.call_count(), 1);
        assert_eq!(challenge_count.load(Ordering::SeqCst), 1);
        assert_eq!(credential_count.load(Ordering::SeqCst), 1);
        assert_eq!(response_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_middleware_unsuccessful_paid_retry_emits_no_payment_outcome() {
        let (_, www_auth) = test_challenge();

        let app = Router::new().route(
            "/paid",
            get(move |req: axum::http::Request<axum::body::Body>| {
                let www_auth = www_auth.clone();
                async move {
                    if req.headers().get("authorization").is_some() {
                        AxumStatusCode::FORBIDDEN.into_response()
                    } else {
                        (
                            AxumStatusCode::PAYMENT_REQUIRED,
                            [(WWW_AUTH_NAME, www_auth)],
                            "pay up",
                        )
                            .into_response()
                    }
                }
            }),
        );

        let base_url = spawn_server(app).await;
        let provider = TestProvider::new();
        let events = ClientEvents::default();
        let response_count = Arc::new(AtomicU32::new(0));
        let failed_count = Arc::new(AtomicU32::new(0));

        let _response_sub = events.on_payment_response({
            let response_count = response_count.clone();
            move |_| {
                response_count.fetch_add(1, Ordering::SeqCst);
                async {}
            }
        });
        let _failed_sub = events.on_payment_failed({
            let failed_count = failed_count.clone();
            move |_| {
                failed_count.fetch_add(1, Ordering::SeqCst);
                async {}
            }
        });
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(PaymentMiddleware::new(provider.clone()).with_events(events))
            .build();

        let resp = client
            .get(format!("{}/paid", base_url))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
        assert_eq!(provider.call_count(), 1);
        assert_eq!(provider.commit_count(), 0);
        assert_eq!(provider.rollback_count(), 1);
        assert_eq!(response_count.load(Ordering::SeqCst), 0);
        assert_eq!(failed_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_middleware_incremental_402_retries_stop_at_default_cap() {
        let headers = Arc::new(
            (0..DEFAULT_MAX_PAYMENT_RETRIES)
                .map(|i| test_challenge_with_id(&format!("cap-{i}")).1)
                .collect::<Vec<_>>(),
        );
        let request_count = Arc::new(AtomicU32::new(0));
        let counter = request_count.clone();

        let app = Router::new().route(
            "/paid",
            get(move || {
                let headers = headers.clone();
                let counter = counter.clone();
                async move {
                    let index = counter.fetch_add(1, Ordering::SeqCst) as usize;
                    let www_auth = headers
                        .get(index)
                        .unwrap_or_else(|| headers.last().unwrap())
                        .clone();
                    (
                        AxumStatusCode::PAYMENT_REQUIRED,
                        [(WWW_AUTH_NAME, www_auth)],
                        "pay up",
                    )
                }
            }),
        );

        let base_url = spawn_server(app).await;
        let provider = TestProvider::new();
        let events = ClientEvents::default();
        let failed_count = Arc::new(AtomicU32::new(0));

        let _failed_sub = events.on_payment_failed({
            let failed_count = failed_count.clone();
            move |_| {
                failed_count.fetch_add(1, Ordering::SeqCst);
                async {}
            }
        });
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(PaymentMiddleware::new(provider.clone()).with_events(events))
            .build();

        let resp = client
            .get(format!("{}/paid", base_url))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), reqwest::StatusCode::PAYMENT_REQUIRED);
        assert_eq!(provider.call_count(), DEFAULT_MAX_PAYMENT_RETRIES as u32);
        assert_eq!(
            request_count.load(Ordering::SeqCst),
            DEFAULT_MAX_PAYMENT_RETRIES as u32 + 1
        );
        assert_eq!(failed_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_middleware_incremental_402_retries_do_not_pay_repeated_challenge() {
        let (_, www_auth) = test_challenge();
        let request_count = Arc::new(AtomicU32::new(0));
        let counter = request_count.clone();

        let app = Router::new().route(
            "/paid",
            get(move || {
                let www_auth = www_auth.clone();
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    (
                        AxumStatusCode::PAYMENT_REQUIRED,
                        [(WWW_AUTH_NAME, www_auth)],
                        "pay up",
                    )
                }
            }),
        );

        let base_url = spawn_server(app).await;
        let provider = TestProvider::new();
        let events = ClientEvents::default();
        let failed_count = Arc::new(AtomicU32::new(0));

        let _failed_sub = events.on_payment_failed({
            let failed_count = failed_count.clone();
            move |ctx| {
                failed_count.fetch_add(1, Ordering::SeqCst);
                async move {
                    assert!(ctx.challenge.is_some());
                    assert!(ctx.error.contains("previously paid challenge"));
                }
            }
        });
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(PaymentMiddleware::new(provider.clone()).with_events(events))
            .build();

        let resp = client
            .get(format!("{}/paid", base_url))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), reqwest::StatusCode::PAYMENT_REQUIRED);
        assert_eq!(provider.call_count(), 1);
        assert_eq!(request_count.load(Ordering::SeqCst), 2);
        assert_eq!(failed_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_middleware_incremental_402_retries_use_configured_cap() {
        let (_, www_auth) = test_challenge();
        let request_count = Arc::new(AtomicU32::new(0));
        let counter = request_count.clone();

        let app = Router::new().route(
            "/paid",
            get(move || {
                let www_auth = www_auth.clone();
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    (
                        AxumStatusCode::PAYMENT_REQUIRED,
                        [(WWW_AUTH_NAME, www_auth)],
                        "pay up",
                    )
                }
            }),
        );

        let base_url = spawn_server(app).await;
        let provider = TestProvider::new();
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(PaymentMiddleware::new(provider.clone()).with_max_payment_retries(1))
            .build();

        let resp = client
            .get(format!("{}/paid", base_url))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), reqwest::StatusCode::PAYMENT_REQUIRED);
        assert_eq!(provider.call_count(), 1);
        assert_eq!(request_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_middleware_incremental_402_retries_pay_replacement_challenges() {
        let (_, first_header) = test_challenge_with_id("first");
        let (_, second_header) = test_challenge_with_id("second");
        let (_, third_header) = test_challenge_with_id("third");
        let headers = Arc::new([first_header, second_header, third_header]);
        let request_count = Arc::new(AtomicU32::new(0));
        let counter = request_count.clone();

        let app = Router::new().route(
            "/paid",
            get(move || {
                let headers = headers.clone();
                let counter = counter.clone();
                async move {
                    let index = counter.fetch_add(1, Ordering::SeqCst) as usize;
                    if let Some(www_auth) = headers.get(index) {
                        (
                            AxumStatusCode::PAYMENT_REQUIRED,
                            [(WWW_AUTH_NAME, www_auth.clone())],
                            "pay up",
                        )
                            .into_response()
                    } else {
                        (AxumStatusCode::OK, "ok").into_response()
                    }
                }
            }),
        );

        let base_url = spawn_server(app).await;
        let provider = TestProvider::new();
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(PaymentMiddleware::new(provider.clone()))
            .build();

        let resp = client
            .get(format!("{}/paid", base_url))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        assert_eq!(
            provider.challenge_ids(),
            vec![
                "first".to_string(),
                "second".to_string(),
                "third".to_string()
            ]
        );
        assert_eq!(request_count.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn test_middleware_challenge_received_can_override_credential() {
        let (_, www_auth) = test_challenge();

        let app = Router::new().route(
            "/paid",
            get(move |req: axum::http::Request<axum::body::Body>| {
                let www_auth = www_auth.clone();
                async move {
                    if req.headers().get("authorization").is_some() {
                        (AxumStatusCode::OK, "ok").into_response()
                    } else {
                        (
                            AxumStatusCode::PAYMENT_REQUIRED,
                            [(WWW_AUTH_NAME, www_auth)],
                            "pay up",
                        )
                            .into_response()
                    }
                }
            }),
        );

        let base_url = spawn_server(app).await;
        let provider = TestProvider::new();
        let events = ClientEvents::default();
        let _sub = events.on(ClientEventKind::ChallengeReceived, |event| async move {
            match event {
                ClientEvent::ChallengeReceived(ctx) => Some(PaymentCredential::new(
                    ctx.challenge.to_echo(),
                    PaymentPayload::hash("0xoverride"),
                )),
                _ => None,
            }
        });
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(PaymentMiddleware::new(provider.clone()).with_events(events))
            .build();

        let resp = client
            .get(format!("{}/paid", base_url))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        assert_eq!(provider.call_count(), 0);
    }

    #[tokio::test]
    async fn test_middleware_non_402_passthrough() {
        let app = Router::new().route("/free", get(|| async { "free content" }));

        let base_url = spawn_server(app).await;
        let provider = TestProvider::new();
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(PaymentMiddleware::new(provider.clone()))
            .build();

        let resp = client
            .get(format!("{}/free", base_url))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        assert_eq!(provider.call_count(), 0);
    }

    #[tokio::test]
    async fn test_middleware_missing_www_authenticate() {
        let app = Router::new().route(
            "/no-header",
            get(|| async { AxumStatusCode::PAYMENT_REQUIRED }),
        );

        let base_url = spawn_server(app).await;
        let provider = TestProvider::new();
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(PaymentMiddleware::new(provider))
            .build();

        let err = client
            .get(format!("{}/no-header", base_url))
            .send()
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("WWW-Authenticate"),
            "expected WWW-Authenticate error, got: {}",
            err
        );
        assert!(matches!(http_error(&err), HttpError::MissingChallenge));
    }

    #[tokio::test]
    async fn test_middleware_rejects_expired_challenge_before_hooks() {
        let (_, www_auth) = test_challenge_with_expires(Some("2020-01-01T00:00:00Z"));

        let app = Router::new().route(
            "/paid",
            get(move |req: axum::http::Request<axum::body::Body>| {
                let www_auth = www_auth.clone();
                async move {
                    if req.headers().get("authorization").is_some() {
                        (AxumStatusCode::OK, "ok").into_response()
                    } else {
                        (
                            AxumStatusCode::PAYMENT_REQUIRED,
                            [(WWW_AUTH_NAME, www_auth)],
                            "pay up",
                        )
                            .into_response()
                    }
                }
            }),
        );

        let base_url = spawn_server(app).await;
        let provider = TestProvider::new();
        let events = ClientEvents::default();
        let challenge_count = Arc::new(AtomicU32::new(0));
        let failed_count = Arc::new(AtomicU32::new(0));
        let captured_reason: Arc<std::sync::Mutex<Option<PaymentFailureReason>>> =
            Arc::new(Default::default());

        let _challenge_sub = events.on_challenge_received({
            let challenge_count = challenge_count.clone();
            move |_| {
                challenge_count.fetch_add(1, Ordering::SeqCst);
                async { None }
            }
        });
        let _failed_sub = events.on_payment_failed({
            let failed_count = failed_count.clone();
            let captured_reason = captured_reason.clone();
            move |ctx| {
                failed_count.fetch_add(1, Ordering::SeqCst);
                *captured_reason.lock().unwrap() = ctx.reason.clone();
                async move {
                    assert!(ctx.challenge.is_some());
                    assert!(ctx.error.contains("Payment expired"));
                }
            }
        });

        let client = ClientBuilder::new(reqwest::Client::new())
            .with(PaymentMiddleware::new(provider.clone()).with_events(events))
            .build();

        let err = client
            .get(format!("{}/paid", base_url))
            .send()
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("Payment expired"),
            "expected payment expired error, got: {err}"
        );
        assert!(matches!(
            http_error(&err),
            HttpError::Payment(MppError::PaymentExpired(_))
        ));
        assert_eq!(provider.call_count(), 0);
        assert_eq!(challenge_count.load(Ordering::SeqCst), 0);
        assert_eq!(failed_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            captured_reason.lock().unwrap().clone(),
            Some(PaymentFailureReason::PreSigningExpired {
                expires: Some("2020-01-01T00:00:00Z".to_string()),
            }),
        );
    }

    /// Advertises a known header value so tests can observe injection.
    #[derive(Clone)]
    struct AdvertisingProvider;

    impl PaymentProvider for AdvertisingProvider {
        fn supports(&self, _method: &str, _intent: &str) -> bool {
            true
        }

        async fn pay(&self, _challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
            unimplemented!("not used in policy tests")
        }

        fn accept_payment_header(&self) -> Option<String> {
            Some("tempo/charge".to_string())
        }
    }

    async fn spawn_header_capture() -> (String, Arc<std::sync::Mutex<Option<String>>>) {
        let captured: Arc<std::sync::Mutex<Option<String>>> = Arc::new(Default::default());
        let captured_clone = captured.clone();
        let app = Router::new().route(
            "/probe",
            get(move |req: axum::http::Request<axum::body::Body>| {
                let captured = captured_clone.clone();
                async move {
                    let v = req
                        .headers()
                        .get("accept-payment")
                        .and_then(|h| h.to_str().ok())
                        .map(|s| s.to_string());
                    *captured.lock().unwrap() = v;
                    AxumStatusCode::OK
                }
            }),
        );
        let url = spawn_server(app).await;
        (url, captured)
    }

    #[tokio::test]
    async fn test_policy_default_always_injects_header() {
        let (base_url, captured) = spawn_header_capture().await;
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(PaymentMiddleware::new(AdvertisingProvider))
            .build();
        client
            .get(format!("{}/probe", base_url))
            .send()
            .await
            .unwrap();
        assert_eq!(captured.lock().unwrap().as_deref(), Some("tempo/charge"));
    }

    #[tokio::test]
    async fn test_policy_never_suppresses_header() {
        let (base_url, captured) = spawn_header_capture().await;
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(
                PaymentMiddleware::new(AdvertisingProvider)
                    .with_accept_payment_policy(AcceptPaymentPolicy::Never),
            )
            .build();
        client
            .get(format!("{}/probe", base_url))
            .send()
            .await
            .unwrap();
        assert_eq!(captured.lock().unwrap().as_deref(), None);
    }

    #[tokio::test]
    async fn test_policy_same_origin_blocks_cross_origin() {
        let (base_url, captured) = spawn_header_capture().await;
        // same_origin set to a different origin → header must not be sent.
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(
                PaymentMiddleware::new(AdvertisingProvider).with_accept_payment_policy(
                    AcceptPaymentPolicy::SameOrigin {
                        same_origin: "https://app.example.com".to_string(),
                    },
                ),
            )
            .build();
        client
            .get(format!("{}/probe", base_url))
            .send()
            .await
            .unwrap();
        assert_eq!(captured.lock().unwrap().as_deref(), None);
    }

    #[tokio::test]
    async fn test_caller_header_not_overwritten() {
        // Caller sets Accept-Payment: stripe/charge → middleware must
        // NOT replace it with the provider's tempo/charge value.
        let (base_url, captured) = spawn_header_capture().await;
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(PaymentMiddleware::new(AdvertisingProvider))
            .build();
        client
            .get(format!("{}/probe", base_url))
            .header("Accept-Payment", "stripe/charge")
            .send()
            .await
            .unwrap();
        assert_eq!(captured.lock().unwrap().as_deref(), Some("stripe/charge"));
    }

    #[tokio::test]
    async fn test_policy_does_not_disable_402_retry() {
        // A blocked outbound header must not stop the 402-retry path.
        let (_, www_auth) = test_challenge();
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();
        let app = Router::new().route(
            "/paid",
            get(move |req: axum::http::Request<axum::body::Body>| {
                let www_auth = www_auth.clone();
                let counter = counter_clone.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    if req.headers().get("authorization").is_some() {
                        (AxumStatusCode::OK, "ok").into_response()
                    } else {
                        (
                            AxumStatusCode::PAYMENT_REQUIRED,
                            [(WWW_AUTH_NAME, www_auth)],
                            "pay",
                        )
                            .into_response()
                    }
                }
            }),
        );
        let base_url = spawn_server(app).await;
        let provider = TestProvider::new();
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(
                PaymentMiddleware::new(provider.clone())
                    .with_accept_payment_policy(AcceptPaymentPolicy::Never),
            )
            .build();
        let resp = client
            .get(format!("{}/paid", base_url))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        assert_eq!(provider.call_count(), 1);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_middleware_provider_failure() {
        let (_, www_auth) = test_challenge();

        let app = Router::new().route(
            "/paid",
            get(move || {
                let www_auth = www_auth.clone();
                async move {
                    (
                        AxumStatusCode::PAYMENT_REQUIRED,
                        [(WWW_AUTH_NAME, www_auth)],
                    )
                }
            }),
        );

        let base_url = spawn_server(app).await;
        let provider = TestProvider::failing();
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(PaymentMiddleware::new(provider))
            .build();

        let err = client
            .get(format!("{}/paid", base_url))
            .send()
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("payment failed"),
            "expected payment failure, got: {}",
            err
        );
        assert!(matches!(
            http_error(&err),
            HttpError::Payment(MppError::Http(_))
        ));
    }
}
