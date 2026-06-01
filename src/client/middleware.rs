//! reqwest-middleware integration for automatic 402 handling.
//!
//! Provides `PaymentMiddleware` for use with `reqwest_middleware::ClientBuilder`.

use anyhow::Context;
use async_trait::async_trait;
use reqwest::header::WWW_AUTHENTICATE;
use reqwest::{Request, Response, StatusCode};
use reqwest_middleware::{Middleware, Next};

use crate::client::accept_payment_policy::AcceptPaymentPolicy;
use crate::client::challenge_selection::{
    expired_payment_error, select_supported_challenge, ChallengeSelectionError,
};
use crate::client::events::{
    ChallengeReceivedContext, ClientEvent, ClientEventSubscription, ClientEvents,
    CredentialCreatedContext, PaymentFailedContext, PaymentResponseContext,
};
use crate::client::provider::PaymentProvider;
use crate::protocol::core::accept_payment::ACCEPT_PAYMENT_HEADER;
use crate::protocol::core::{
    format_authorization, parse_www_authenticate_all, AUTHORIZATION_HEADER,
};

/// Middleware that automatically handles 402 Payment Required responses.
///
/// When a request returns 402, the middleware:
/// 1. Parses the challenge from the `WWW-Authenticate` header
/// 2. Calls the provider to execute the payment
/// 3. Retries the request with the credential in the `Authorization` header
///
/// # Examples
///
/// ```ignore
/// use mpp::client::{PaymentMiddleware, TempoProvider};
/// use reqwest_middleware::ClientBuilder;
///
/// let provider = TempoProvider::new(signer, "https://rpc.moderato.tempo.xyz")?;
///
/// let client = ClientBuilder::new(reqwest::Client::new())
///     .with(PaymentMiddleware::new(provider))
///     .build();
///
/// // All requests through this client automatically handle 402
/// let resp = client.get("https://api.example.com/paid").send().await?;
/// ```
pub struct PaymentMiddleware<P> {
    provider: P,
    accept_payment_policy: AcceptPaymentPolicy,
    events: ClientEvents,
}

impl<P> PaymentMiddleware<P> {
    /// Create middleware with the given provider. Defaults to
    /// [`AcceptPaymentPolicy::Always`].
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            accept_payment_policy: AcceptPaymentPolicy::default(),
            events: ClientEvents::default(),
        }
    }

    /// Restrict where the `Accept-Payment` header is sent. The 402-retry
    /// path is unaffected.
    pub fn with_accept_payment_policy(mut self, policy: AcceptPaymentPolicy) -> Self {
        self.accept_payment_policy = policy;
        self
    }

    /// Use an existing event registry for payment callbacks.
    pub fn with_events(mut self, events: ClientEvents) -> Self {
        self.events = events;
        self
    }

    /// Get the event registry used by this middleware.
    pub fn events(&self) -> ClientEvents {
        self.events.clone()
    }

    /// Register a `challenge.received` callback.
    pub fn on_challenge_received<F, Fut>(&self, handler: F) -> ClientEventSubscription
    where
        F: Fn(ChallengeReceivedContext) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Option<crate::protocol::core::PaymentCredential>>
            + Send
            + 'static,
    {
        self.events.on_challenge_received(handler)
    }

    /// Register a `credential.created` observer.
    pub fn on_credential_created<F, Fut>(&self, handler: F) -> ClientEventSubscription
    where
        F: Fn(CredentialCreatedContext) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        self.events.on_credential_created(handler)
    }

    /// Register a `payment.response` observer.
    pub fn on_payment_response<F, Fut>(&self, handler: F) -> ClientEventSubscription
    where
        F: Fn(PaymentResponseContext) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        self.events.on_payment_response(handler)
    }

    /// Register a `payment.failed` observer.
    pub fn on_payment_failed<F, Fut>(&self, handler: F) -> ClientEventSubscription
    where
        F: Fn(PaymentFailedContext) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        self.events.on_payment_failed(handler)
    }
}

#[async_trait]
impl<P> Middleware for PaymentMiddleware<P>
where
    P: PaymentProvider + 'static,
{
    async fn handle(
        &self,
        mut req: Request,
        extensions: &mut http_types::Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        // Snapshot any caller-set Accept-Payment header before injection.
        let caller_accept = req
            .headers()
            .get(ACCEPT_PAYMENT_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let provider_accept = self.provider.accept_payment_header();

        // Inject only if the caller didn't set their own header AND the
        // policy permits it. Caller-set headers are never overwritten
        if caller_accept.is_none() && self.accept_payment_policy.allows(req.url()) {
            if let Some(ref header) = provider_accept {
                if let Ok(val) = header.parse() {
                    req.headers_mut().insert(ACCEPT_PAYMENT_HEADER, val);
                }
            }
        }

        // The caller's header (if any) wins for retry-time challenge ranking;
        // otherwise fall back to the provider's preferences.
        let ranking_accept = caller_accept.or(provider_accept);

        let retry_req = req.try_clone();
        let resp = next.clone().run(req, extensions).await?;

        if resp.status() != StatusCode::PAYMENT_REQUIRED {
            return Ok(resp);
        }

        let retry_req = match retry_req {
            Some(req) => req,
            None => {
                let err = anyhow::anyhow!("request could not be cloned for payment retry");
                self.events
                    .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                        challenge: None,
                        error: err.to_string(),
                    }))
                    .await;
                return Err(reqwest_middleware::Error::Middleware(err));
            }
        };

        let www_auth_values: Vec<&str> = resp
            .headers()
            .get_all(WWW_AUTHENTICATE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();

        if www_auth_values.is_empty() {
            self.events
                .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                    challenge: None,
                    error: "402 response missing WWW-Authenticate header".to_string(),
                }))
                .await;
            return Err(reqwest_middleware::Error::Middleware(anyhow::anyhow!(
                "402 response missing WWW-Authenticate header"
            )));
        }

        let challenges: Vec<_> = parse_www_authenticate_all(www_auth_values)
            .into_iter()
            .filter_map(|r| r.ok())
            .collect();

        let challenge =
            match select_supported_challenge(&challenges, ranking_accept.as_deref(), |challenge| {
                self.provider
                    .supports(challenge.method.as_str(), challenge.intent.as_str())
            }) {
                Ok(challenge) => challenge.clone(),
                Err(ChallengeSelectionError::Expired(challenge)) => {
                    let mpp_error = expired_payment_error(&challenge);
                    let error = mpp_error.to_string();
                    self.events
                        .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                            challenge: Some(challenge),
                            error,
                        }))
                        .await;
                    return Err(reqwest_middleware::Error::Middleware(anyhow::anyhow!(
                        mpp_error
                    )));
                }
                Err(ChallengeSelectionError::NoSupportedChallenge(message)) => {
                    let err = anyhow::anyhow!(message);
                    self.events
                        .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                            challenge: None,
                            error: err.to_string(),
                        }))
                        .await;
                    return Err(reqwest_middleware::Error::Middleware(err));
                }
            };

        let override_credential = self
            .events
            .emit_challenge_received(ChallengeReceivedContext {
                challenge: challenge.clone(),
                challenges: challenges.clone(),
            })
            .await;

        let credential = match override_credential {
            Some(credential) => credential,
            None => match self.provider.pay(&challenge).await {
                Ok(credential) => credential,
                Err(err) => {
                    let err = anyhow::anyhow!(err).context("payment failed");
                    self.events
                        .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                            challenge: Some(challenge),
                            error: err.to_string(),
                        }))
                        .await;
                    return Err(reqwest_middleware::Error::Middleware(err));
                }
            },
        };

        self.events
            .emit(ClientEvent::CredentialCreated(CredentialCreatedContext {
                challenge: challenge.clone(),
                credential: credential.clone(),
            }))
            .await;

        let auth_header =
            match format_authorization(&credential).context("failed to format credential") {
                Ok(auth_header) => auth_header,
                Err(err) => {
                    self.events
                        .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                            challenge: Some(challenge),
                            error: err.to_string(),
                        }))
                        .await;
                    return Err(reqwest_middleware::Error::Middleware(err));
                }
            };

        let mut retry_req = retry_req;
        let auth_header_value = match auth_header.parse().context("invalid authorization header") {
            Ok(value) => value,
            Err(err) => {
                self.events
                    .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                        challenge: Some(challenge),
                        error: err.to_string(),
                    }))
                    .await;
                return Err(reqwest_middleware::Error::Middleware(err));
            }
        };
        retry_req
            .headers_mut()
            .insert(AUTHORIZATION_HEADER, auth_header_value);

        let retry_resp = next.run(retry_req, extensions).await;
        match retry_resp {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    self.events
                        .emit(ClientEvent::PaymentResponse(PaymentResponseContext {
                            challenge,
                            credential,
                            status,
                        }))
                        .await;
                } else {
                    self.events
                        .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                            challenge: Some(challenge),
                            error: format!("payment retry returned unsuccessful status: {status}"),
                        }))
                        .await;
                }
                Ok(resp)
            }
            Err(err) => {
                self.events
                    .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                        challenge: Some(challenge),
                        error: err.to_string(),
                    }))
                    .await;
                Err(err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
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
        use crate::client::ClientEventKind;
        use crate::error::MppError;
        use crate::protocol::core::{
            format_www_authenticate, Base64UrlJson, PaymentChallenge, PaymentCredential,
            PaymentPayload,
        };

        use axum::http::header::WWW_AUTHENTICATE as WWW_AUTH_NAME;
        use axum::http::StatusCode as AxumStatusCode;
        use axum::response::IntoResponse;
        use axum::routing::get;
        use axum::Router;
        use reqwest_middleware::ClientBuilder;
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;
        use tokio::net::TcpListener;

        #[derive(Clone)]
        struct TestProvider {
            pay_count: Arc<AtomicU32>,
            fail: bool,
        }

        impl TestProvider {
            fn new() -> Self {
                Self {
                    pay_count: Arc::new(AtomicU32::new(0)),
                    fail: false,
                }
            }

            fn failing() -> Self {
                Self {
                    pay_count: Arc::new(AtomicU32::new(0)),
                    fail: true,
                }
            }

            fn call_count(&self) -> u32 {
                self.pay_count.load(Ordering::SeqCst)
            }
        }

        impl PaymentProvider for TestProvider {
            fn supports(&self, _method: &str, _intent: &str) -> bool {
                true
            }

            async fn pay(
                &self,
                challenge: &PaymentChallenge,
            ) -> Result<PaymentCredential, MppError> {
                self.pay_count.fetch_add(1, Ordering::SeqCst);
                if self.fail {
                    return Err(MppError::Http("test provider failure".into()));
                }
                let echo = challenge.to_echo();
                Ok(PaymentCredential::new(
                    echo,
                    PaymentPayload::hash("0xmockhash"),
                ))
            }
        }

        fn test_challenge() -> (PaymentChallenge, String) {
            test_challenge_with_expires(None)
        }

        fn test_challenge_with_expires(expires: Option<&str>) -> (PaymentChallenge, String) {
            let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "500"})).unwrap();
            let mut challenge = PaymentChallenge::new(
                "mw-test-id",
                "middleware.example.com",
                "tempo",
                "charge",
                request,
            );
            if let Some(expires) = expires {
                challenge = challenge.with_expires(expires);
            }
            let header = format_www_authenticate(&challenge).unwrap();
            (challenge, header)
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
            assert_eq!(call_count.load(Ordering::SeqCst), 2);
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
        async fn test_middleware_unsuccessful_paid_retry_emits_payment_failed() {
            let (_, www_auth) = test_challenge();

            let app = Router::new().route(
                "/paid",
                get(move |req: axum::http::Request<axum::body::Body>| {
                    let www_auth = www_auth.clone();
                    async move {
                        if req.headers().get("authorization").is_some() {
                            AxumStatusCode::PAYMENT_REQUIRED.into_response()
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
                move |ctx| {
                    failed_count.fetch_add(1, Ordering::SeqCst);
                    async move {
                        assert!(ctx.challenge.is_some());
                        assert!(ctx.error.contains("402 Payment Required"));
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
            assert_eq!(response_count.load(Ordering::SeqCst), 0);
            assert_eq!(failed_count.load(Ordering::SeqCst), 1);
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

            let _challenge_sub = events.on_challenge_received({
                let challenge_count = challenge_count.clone();
                move |_| {
                    challenge_count.fetch_add(1, Ordering::SeqCst);
                    async { None }
                }
            });
            let _failed_sub = events.on_payment_failed({
                let failed_count = failed_count.clone();
                move |ctx| {
                    failed_count.fetch_add(1, Ordering::SeqCst);
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
            assert_eq!(provider.call_count(), 0);
            assert_eq!(challenge_count.load(Ordering::SeqCst), 0);
            assert_eq!(failed_count.load(Ordering::SeqCst), 1);
        }

        /// Advertises a known header value so tests can observe injection.
        #[derive(Clone)]
        struct AdvertisingProvider;

        impl PaymentProvider for AdvertisingProvider {
            fn supports(&self, _method: &str, _intent: &str) -> bool {
                true
            }

            async fn pay(
                &self,
                _challenge: &PaymentChallenge,
            ) -> Result<PaymentCredential, MppError> {
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
        }
    }
}
