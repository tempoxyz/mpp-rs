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
use crate::client::error::HttpError;
use crate::client::events::{
    ChallengeReceivedContext, ClientEvent, ClientEventSubscription, ClientEvents,
    CredentialCreatedContext, PaymentFailedContext, PaymentFailureReason, PaymentResponseContext,
};
use crate::client::provider::PaymentProvider;
use crate::client::DEFAULT_MAX_PAYMENT_RETRIES;
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
    max_payment_retries: usize,
}

impl<P> PaymentMiddleware<P> {
    /// Create middleware with the given provider. Defaults to
    /// [`AcceptPaymentPolicy::Always`].
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            accept_payment_policy: AcceptPaymentPolicy::default(),
            events: ClientEvents::default(),
            max_payment_retries: DEFAULT_MAX_PAYMENT_RETRIES,
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

    /// Set the maximum number of payment challenge retries after the initial
    /// 402 response.
    pub fn with_max_payment_retries(mut self, max_payment_retries: usize) -> Self {
        self.max_payment_retries = max_payment_retries;
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
        let mut resp = next.clone().run(req, extensions).await?;

        if resp.status() != StatusCode::PAYMENT_REQUIRED {
            return Ok(resp);
        }

        let base_retry_req = match retry_req {
            Some(req) => req,
            None => {
                let err = anyhow::anyhow!("request could not be cloned for payment retry");
                self.events
                    .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                        challenge: None,
                        error: err.to_string(),
                        reason: None,
                    }))
                    .await;
                return Err(reqwest_middleware::Error::Middleware(err));
            }
        };

        let mut paid_challenge_ids = std::collections::HashSet::new();
        let mut submitted_charge_id: Option<String> = None;

        for attempt in 0..self.max_payment_retries {
            if resp.status() != StatusCode::PAYMENT_REQUIRED {
                return Ok(resp);
            }

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
                        reason: None,
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

            let challenge = match select_supported_challenge(
                &challenges,
                ranking_accept.as_deref(),
                |challenge| {
                    self.provider
                        .supports(challenge.method.as_str(), challenge.intent.as_str())
                },
            ) {
                Ok(challenge) => challenge.clone(),
                Err(ChallengeSelectionError::Expired(challenge)) => {
                    let mpp_error = expired_payment_error(&challenge);
                    let error = mpp_error.to_string();
                    let expires = challenge.expires.clone();
                    self.events
                        .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                            challenge: Some(*challenge),
                            error,
                            reason: Some(PaymentFailureReason::PreSigningExpired { expires }),
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
                            reason: None,
                        }))
                        .await;
                    return Err(reqwest_middleware::Error::Middleware(err));
                }
            };

            if paid_challenge_ids.contains(&challenge.id) {
                self.events
                    .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                        challenge: Some(challenge),
                        error: "payment retry returned a previously paid challenge".to_string(),
                        reason: None,
                    }))
                    .await;
                return Ok(resp);
            }
            if challenge.intent.as_str() == "charge" {
                if let Some(paid_challenge_id) = &submitted_charge_id {
                    let retry_challenge_id = challenge.id.clone();
                    let error = HttpError::IndeterminatePayment {
                        paid_challenge_id: paid_challenge_id.clone(),
                        retry_challenge_id: retry_challenge_id.clone(),
                    };
                    self.events
                        .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                            challenge: Some(challenge),
                            error: error.to_string(),
                            reason: Some(PaymentFailureReason::IndeterminateCharge {
                                paid_challenge_id: paid_challenge_id.clone(),
                                retry_challenge_id,
                            }),
                        }))
                        .await;
                    return Err(reqwest_middleware::Error::Middleware(anyhow::Error::new(
                        error,
                    )));
                }
            }
            paid_challenge_ids.insert(challenge.id.clone());

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
                                reason: None,
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
            if challenge.intent.as_str() == "charge" {
                submitted_charge_id = Some(challenge.id.clone());
            }

            let auth_header =
                match format_authorization(&credential).context("failed to format credential") {
                    Ok(auth_header) => auth_header,
                    Err(err) => {
                        self.events
                            .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                                challenge: Some(challenge),
                                error: err.to_string(),
                                reason: None,
                            }))
                            .await;
                        return Err(reqwest_middleware::Error::Middleware(err));
                    }
                };

            let auth_header_value =
                match auth_header.parse().context("invalid authorization header") {
                    Ok(value) => value,
                    Err(err) => {
                        self.events
                            .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                                challenge: Some(challenge),
                                error: err.to_string(),
                                reason: None,
                            }))
                            .await;
                        return Err(reqwest_middleware::Error::Middleware(err));
                    }
                };
            let mut retry_req = base_retry_req.try_clone().ok_or_else(|| {
                reqwest_middleware::Error::Middleware(anyhow::anyhow!(
                    "request could not be cloned for payment retry"
                ))
            })?;
            retry_req
                .headers_mut()
                .insert(AUTHORIZATION_HEADER, auth_header_value);

            resp = match next.clone().run(retry_req, extensions).await {
                Ok(resp) => resp,
                Err(err) => {
                    self.events
                        .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                            challenge: Some(challenge),
                            error: err.to_string(),
                            reason: None,
                        }))
                        .await;
                    return Err(err);
                }
            };

            let status = resp.status();
            if status.is_success() {
                self.events
                    .emit(ClientEvent::PaymentResponse(PaymentResponseContext {
                        challenge,
                        credential,
                        status,
                    }))
                    .await;
                return Ok(resp);
            }

            if status != StatusCode::PAYMENT_REQUIRED || attempt + 1 == self.max_payment_retries {
                self.events
                    .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                        challenge: Some(challenge),
                        error: format!("payment retry returned unsuccessful status: {status}"),
                        reason: None,
                    }))
                    .await;
                return Ok(resp);
            }
        }

        Ok(resp)
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
        use std::sync::{Arc, Mutex};
        use tokio::net::TcpListener;

        #[derive(Clone)]
        struct TestProvider {
            pay_count: Arc<AtomicU32>,
            challenge_ids: Arc<Mutex<Vec<String>>>,
            fail: bool,
        }

        impl TestProvider {
            fn new() -> Self {
                Self {
                    pay_count: Arc::new(AtomicU32::new(0)),
                    challenge_ids: Arc::new(Mutex::new(Vec::new())),
                    fail: false,
                }
            }

            fn failing() -> Self {
                Self {
                    pay_count: Arc::new(AtomicU32::new(0)),
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

        fn test_challenge_with_intent(id: &str, intent: &str) -> (PaymentChallenge, String) {
            let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "500"})).unwrap();
            let challenge =
                PaymentChallenge::new(id, "middleware.example.com", "tempo", intent, request);
            let header = format_www_authenticate(&challenge).unwrap();
            (challenge, header)
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
                move |ctx| {
                    failed_count.fetch_add(1, Ordering::SeqCst);
                    async move {
                        assert!(ctx.challenge.is_some());
                        assert!(ctx.error.contains("403 Forbidden"));
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

            assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
            assert_eq!(provider.call_count(), 1);
            assert_eq!(response_count.load(Ordering::SeqCst), 0);
            assert_eq!(failed_count.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn test_middleware_incremental_402_retries_stop_at_default_cap() {
            let headers = Arc::new(
                (0..DEFAULT_MAX_PAYMENT_RETRIES)
                    .map(|i| test_challenge_with_intent(&format!("cap-{i}"), "session").1)
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
            assert_eq!(failed_count.load(Ordering::SeqCst), 1);
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
        async fn test_middleware_distinct_charge_after_paid_retry_is_indeterminate() {
            let (_, first_header) = test_challenge_with_id("first");
            let (_, second_header) = test_challenge_with_id("second");
            let headers = Arc::new([first_header, second_header]);
            let request_count = Arc::new(AtomicU32::new(0));
            let counter = request_count.clone();

            let app = Router::new().route(
                "/paid",
                get(move || {
                    let headers = headers.clone();
                    let counter = counter.clone();
                    async move {
                        let index = counter.fetch_add(1, Ordering::SeqCst) as usize;
                        (
                            AxumStatusCode::PAYMENT_REQUIRED,
                            [(WWW_AUTH_NAME, headers[index].clone())],
                            "pay up",
                        )
                    }
                }),
            );

            let base_url = spawn_server(app).await;
            let provider = TestProvider::new();
            let events = ClientEvents::default();
            let observed_reason = Arc::new(Mutex::new(None));
            let _failed_sub = events.on_payment_failed({
                let observed_reason = observed_reason.clone();
                move |context| {
                    *observed_reason.lock().unwrap() = context.reason;
                    async {}
                }
            });
            let client = ClientBuilder::new(reqwest::Client::new())
                .with(PaymentMiddleware::new(provider.clone()).with_events(events))
                .build();

            let error = client
                .get(format!("{}/paid", base_url))
                .send()
                .await
                .unwrap_err();

            assert!(error
                .to_string()
                .contains("payment outcome is indeterminate"));
            assert_eq!(
                *observed_reason.lock().unwrap(),
                Some(PaymentFailureReason::IndeterminateCharge {
                    paid_challenge_id: "first".to_string(),
                    retry_challenge_id: "second".to_string(),
                })
            );
            assert_eq!(provider.call_count(), 1);
            assert_eq!(request_count.load(Ordering::SeqCst), 2);
        }

        #[tokio::test]
        async fn test_middleware_incremental_402_retries_pay_replacement_challenges() {
            let (_, first_header) = test_challenge_with_intent("first", "session");
            let (_, second_header) = test_challenge_with_intent("second", "session");
            let (_, third_header) = test_challenge_with_intent("third", "session");
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
