//! Extension trait for reqwest RequestBuilder.
//!
//! Provides `.send_with_payment()` method for opt-in per-request payment handling.

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, WWW_AUTHENTICATE};
use reqwest::{RequestBuilder, Response, StatusCode};

use super::accept_payment_policy::AcceptPaymentPolicy;
use super::error::HttpError;
use super::events::{
    ChallengeReceivedContext, ClientEvent, ClientEvents, CredentialCreatedContext,
    PaymentFailedContext, PaymentFailureReason, PaymentResponseContext,
};
use super::provider::{PaymentContext, PaymentProvider};
use super::DEFAULT_MAX_PAYMENT_RETRIES;
use crate::client::challenge_selection::{
    expired_payment_error, select_supported_challenge, ChallengeSelectionError,
};
use crate::protocol::core::accept_payment::ACCEPT_PAYMENT_HEADER;
use crate::protocol::core::{format_authorization, parse_www_authenticate_all};

/// Extension trait for `reqwest::RequestBuilder` with payment support.
///
/// This trait adds a `.send_with_payment()` method that automatically handles
/// HTTP 402 responses by executing a payment and retrying the request.
///
/// # Examples
///
/// ```ignore
/// use mpp::client::{Fetch, TempoProvider};
/// use reqwest::Client;
///
/// let provider = TempoProvider::new(signer, "https://rpc.moderato.tempo.xyz")?;
/// let client = Client::new();
///
/// let resp = client
///     .get("https://api.example.com/paid")
///     .send_with_payment(&provider)
///     .await?;
/// ```
pub trait PaymentExt: Sized {
    /// Send the request, automatically handling 402 Payment Required responses.
    ///
    /// Equivalent to [`send_with_payment_policy`](Self::send_with_payment_policy)
    /// with [`AcceptPaymentPolicy::Always`].
    fn send_with_payment<P: PaymentProvider>(
        self,
        provider: &P,
    ) -> impl std::future::Future<Output = Result<Response, HttpError>> + Send {
        self.send_with_payment_policy(provider, &AcceptPaymentPolicy::Always)
    }

    /// Like [`send_with_payment`](Self::send_with_payment) but only injects
    /// `Accept-Payment` when `policy` permits the request URL. The 402-retry
    /// path is unaffected.
    fn send_with_payment_policy<P: PaymentProvider>(
        self,
        provider: &P,
        policy: &AcceptPaymentPolicy,
    ) -> impl std::future::Future<Output = Result<Response, HttpError>> + Send;

    /// Like [`send_with_payment`](Self::send_with_payment), with a custom cap
    /// for incremental payment challenge retries after the initial 402.
    fn send_with_payment_max_retries<P: PaymentProvider>(
        self,
        provider: &P,
        max_payment_retries: usize,
    ) -> impl std::future::Future<Output = Result<Response, HttpError>> + Send {
        self.send_with_payment_policy_max_retries(
            provider,
            &AcceptPaymentPolicy::Always,
            max_payment_retries,
        )
    }

    /// Like [`send_with_payment_policy`](Self::send_with_payment_policy), with
    /// a custom cap for incremental payment challenge retries.
    fn send_with_payment_policy_max_retries<P: PaymentProvider>(
        self,
        provider: &P,
        policy: &AcceptPaymentPolicy,
        max_payment_retries: usize,
    ) -> impl std::future::Future<Output = Result<Response, HttpError>> + Send {
        self.send_with_payment_options_max_retries(
            provider,
            policy,
            ClientEvents::default(),
            max_payment_retries,
        )
    }

    /// Like [`send_with_payment_policy`](Self::send_with_payment_policy), with
    /// event callbacks for the 402 payment flow.
    fn send_with_payment_options<P: PaymentProvider>(
        self,
        provider: &P,
        policy: &AcceptPaymentPolicy,
        events: ClientEvents,
    ) -> impl std::future::Future<Output = Result<Response, HttpError>> + Send {
        let _ = events;
        self.send_with_payment_policy(provider, policy)
    }

    /// Like [`send_with_payment_options`](Self::send_with_payment_options),
    /// with a custom cap for incremental payment challenge retries.
    fn send_with_payment_options_max_retries<P: PaymentProvider>(
        self,
        provider: &P,
        policy: &AcceptPaymentPolicy,
        events: ClientEvents,
        max_payment_retries: usize,
    ) -> impl std::future::Future<Output = Result<Response, HttpError>> + Send {
        let _ = max_payment_retries;
        self.send_with_payment_options(provider, policy, events)
    }
}

impl PaymentExt for RequestBuilder {
    async fn send_with_payment_policy<P: PaymentProvider>(
        self,
        provider: &P,
        policy: &AcceptPaymentPolicy,
    ) -> Result<Response, HttpError> {
        self.send_with_payment_options_max_retries(
            provider,
            policy,
            ClientEvents::default(),
            DEFAULT_MAX_PAYMENT_RETRIES,
        )
        .await
    }

    async fn send_with_payment_policy_max_retries<P: PaymentProvider>(
        self,
        provider: &P,
        policy: &AcceptPaymentPolicy,
        max_payment_retries: usize,
    ) -> Result<Response, HttpError> {
        self.send_with_payment_options_max_retries(
            provider,
            policy,
            ClientEvents::default(),
            max_payment_retries,
        )
        .await
    }

    async fn send_with_payment_options<P: PaymentProvider>(
        self,
        provider: &P,
        policy: &AcceptPaymentPolicy,
        events: ClientEvents,
    ) -> Result<Response, HttpError> {
        self.send_with_payment_options_max_retries(
            provider,
            policy,
            events,
            DEFAULT_MAX_PAYMENT_RETRIES,
        )
        .await
    }

    async fn send_with_payment_options_max_retries<P: PaymentProvider>(
        self,
        provider: &P,
        policy: &AcceptPaymentPolicy,
        events: ClientEvents,
        max_payment_retries: usize,
    ) -> Result<Response, HttpError> {
        let retry_builder = self.try_clone().ok_or(HttpError::CloneFailed)?;

        // Peek the built request to inspect caller-set headers and URL
        // before injecting our own.
        let peek = retry_builder.try_clone().and_then(|b| b.build().ok());
        let url = peek.as_ref().map(|r| r.url().clone());
        let caller_accept = peek.as_ref().and_then(|r| {
            r.headers()
                .get(ACCEPT_PAYMENT_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(String::from)
        });
        let provider_accept = provider.accept_payment_header();

        // Inject only if the caller didn't set their own header AND the
        // policy permits it. Caller-set headers are never overwritten.
        let inject = caller_accept.is_none() && url.as_ref().is_some_and(|u| policy.allows(u));

        let this = if inject {
            if let Some(ref header) = provider_accept {
                self.header(ACCEPT_PAYMENT_HEADER, header)
            } else {
                self
            }
        } else {
            self
        };

        // Caller's header (if any) wins for retry-time ranking.
        let ranking_accept = caller_accept.or(provider_accept);

        let mut paid_challenge_ids = std::collections::HashSet::new();
        let mut submitted_charge_id: Option<String> = None;
        let mut resp = this.send().await?;

        for attempt in 0..max_payment_retries {
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
                events
                    .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                        challenge: None,
                        error: HttpError::MissingChallenge.to_string(),
                        reason: None,
                    }))
                    .await;
                return Err(HttpError::MissingChallenge);
            }

            let challenges: Vec<_> = parse_www_authenticate_all(www_auth_values)
                .into_iter()
                .filter_map(|r| r.ok())
                .collect();

            let challenge = match select_supported_challenge(
                &challenges,
                ranking_accept.as_deref(),
                |challenge| provider.supports(challenge.method.as_str(), challenge.intent.as_str()),
            ) {
                Ok(challenge) => challenge.clone(),
                Err(ChallengeSelectionError::Expired(challenge)) => {
                    let err = HttpError::Payment(expired_payment_error(&challenge));
                    let error = err.to_string();
                    let expires = challenge.expires.clone();
                    events
                        .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                            challenge: Some(*challenge),
                            error,
                            reason: Some(PaymentFailureReason::PreSigningExpired { expires }),
                        }))
                        .await;
                    return Err(err);
                }
                Err(ChallengeSelectionError::NoSupportedChallenge(message)) => {
                    let err = HttpError::NoSupportedChallenge(message);
                    events
                        .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                            challenge: None,
                            error: err.to_string(),
                            reason: None,
                        }))
                        .await;
                    return Err(err);
                }
            };

            if paid_challenge_ids.contains(&challenge.id) {
                events
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
                    let err = HttpError::IndeterminatePayment {
                        paid_challenge_id: paid_challenge_id.clone(),
                        retry_challenge_id: retry_challenge_id.clone(),
                    };
                    events
                        .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                            challenge: Some(challenge),
                            error: err.to_string(),
                            reason: Some(PaymentFailureReason::IndeterminateCharge {
                                paid_challenge_id: paid_challenge_id.clone(),
                                retry_challenge_id,
                            }),
                        }))
                        .await;
                    return Err(err);
                }
            }
            paid_challenge_ids.insert(challenge.id.clone());

            let override_credential = events
                .emit_challenge_received(ChallengeReceivedContext {
                    challenge: challenge.clone(),
                    challenges: challenges.clone(),
                })
                .await;

            let credential = match override_credential {
                Some(credential) => credential,
                None => match provider
                    .pay_with_context(
                        &challenge,
                        PaymentContext {
                            url: url.clone().ok_or(HttpError::CloneFailed)?,
                            headers: peek
                                .as_ref()
                                .map(|request| request.headers().clone())
                                .unwrap_or_default(),
                        },
                    )
                    .await
                {
                    Ok(credential) => credential,
                    Err(err) => {
                        let http_err = HttpError::Payment(err);
                        events
                            .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                                challenge: Some(challenge),
                                error: http_err.to_string(),
                                reason: None,
                            }))
                            .await;
                        return Err(http_err);
                    }
                },
            };

            events
                .emit(ClientEvent::CredentialCreated(CredentialCreatedContext {
                    challenge: challenge.clone(),
                    credential: credential.clone(),
                }))
                .await;
            if challenge.intent.as_str() == "charge" {
                submitted_charge_id = Some(challenge.id.clone());
            }

            let auth_header = match format_authorization(&credential) {
                Ok(auth_header) => auth_header,
                Err(err) => {
                    let http_err = HttpError::InvalidCredential(err.to_string());
                    events
                        .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                            challenge: Some(challenge),
                            error: http_err.to_string(),
                            reason: None,
                        }))
                        .await;
                    return Err(http_err);
                }
            };

            let auth_header = match HeaderValue::from_str(&auth_header) {
                Ok(auth_header) => auth_header,
                Err(err) => {
                    let http_err = HttpError::InvalidCredential(err.to_string());
                    events
                        .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                            challenge: Some(challenge),
                            error: http_err.to_string(),
                            reason: None,
                        }))
                        .await;
                    return Err(http_err);
                }
            };
            let mut payment_headers = HeaderMap::new();
            payment_headers.insert(AUTHORIZATION, auth_header);
            let retry = retry_builder
                .try_clone()
                .ok_or(HttpError::CloneFailed)?
                .headers(payment_headers);
            resp = match retry.send().await {
                Ok(resp) => resp,
                Err(err) => {
                    let http_err = HttpError::Request(err);
                    events
                        .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                            challenge: Some(challenge),
                            error: http_err.to_string(),
                            reason: None,
                        }))
                        .await;
                    return Err(http_err);
                }
            };

            let status = resp.status();
            if status.is_success() {
                events
                    .emit(ClientEvent::PaymentResponse(PaymentResponseContext {
                        challenge,
                        credential,
                        status,
                    }))
                    .await;
                return Ok(resp);
            }

            if status != StatusCode::PAYMENT_REQUIRED || attempt + 1 == max_payment_retries {
                events
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

    #[test]
    fn test_payment_ext_trait_exists() {
        fn assert_payment_ext<T: PaymentExt>() {}
        assert_payment_ext::<RequestBuilder>();
    }

    #[cfg(all(feature = "client", feature = "utils"))]
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
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::{Arc, Mutex};
        use tokio::net::TcpListener;

        /// Mock provider that records calls and returns a fixed credential.
        #[derive(Clone)]
        struct MockProvider {
            pay_count: Arc<AtomicU32>,
            challenge_ids: Arc<Mutex<Vec<String>>>,
            fail: bool,
        }

        impl MockProvider {
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

        impl super::PaymentProvider for MockProvider {
            fn supports(&self, _method: &str, _intent: &str) -> bool {
                true
            }

            async fn pay(
                &self,
                challenge: &crate::protocol::core::PaymentChallenge,
            ) -> Result<PaymentCredential, MppError> {
                self.pay_count.fetch_add(1, Ordering::SeqCst);
                self.challenge_ids
                    .lock()
                    .unwrap()
                    .push(challenge.id.clone());
                if self.fail {
                    return Err(MppError::Http("mock provider failure".into()));
                }
                let echo = challenge.to_echo();
                Ok(PaymentCredential::new(
                    echo,
                    PaymentPayload::hash("0xmockhash"),
                ))
            }
        }

        /// Build a test challenge and its formatted WWW-Authenticate header value.
        fn test_challenge() -> (PaymentChallenge, String) {
            test_challenge_with_id("test-id-123")
        }

        fn test_challenge_with_id(id: &str) -> (PaymentChallenge, String) {
            test_challenge_with_intent(id, "charge")
        }

        fn test_challenge_with_intent(id: &str, intent: &str) -> (PaymentChallenge, String) {
            let request =
                Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
            let challenge = PaymentChallenge::new(id, "test.example.com", "tempo", intent, request);
            let header = format_www_authenticate(&challenge).unwrap();
            (challenge, header)
        }

        /// Spawn an axum server and return its base URL.
        async fn spawn_server(app: Router) -> String {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            format!("http://{}", addr)
        }

        #[tokio::test]
        async fn test_happy_path_402_then_200() {
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
            let provider = MockProvider::new();
            let client = reqwest::Client::new();

            let resp = client
                .get(format!("{}/paid", base_url))
                .send_with_payment(&provider)
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(provider.call_count(), 1);
            assert_eq!(call_count.load(Ordering::SeqCst), 2); // initial 402 + retry
        }

        #[tokio::test]
        async fn test_paid_retry_replaces_caller_authorization() {
            let (_, www_auth) = test_challenge();

            let app = Router::new().route(
                "/paid",
                get(move |req: axum::http::Request<axum::body::Body>| {
                    let www_auth = www_auth.clone();
                    async move {
                        let authorization = req
                            .headers()
                            .get_all("authorization")
                            .iter()
                            .filter_map(|value| value.to_str().ok())
                            .collect::<Vec<_>>();
                        match authorization.as_slice() {
                            [value] if value.starts_with("Payment ") => {
                                (AxumStatusCode::OK, "ok").into_response()
                            }
                            ["Bearer upstream-token"] => (
                                AxumStatusCode::PAYMENT_REQUIRED,
                                [(WWW_AUTH_NAME, www_auth)],
                                "pay up",
                            )
                                .into_response(),
                            _ => (AxumStatusCode::BAD_REQUEST, "duplicate authorization")
                                .into_response(),
                        }
                    }
                }),
            );

            let base_url = spawn_server(app).await;
            let provider = MockProvider::new();
            let client = reqwest::Client::new();

            let resp = client
                .get(format!("{}/paid", base_url))
                .bearer_auth("upstream-token")
                .send_with_payment(&provider)
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(provider.call_count(), 1);
        }

        #[tokio::test]
        async fn test_payment_events_fire_on_success() {
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
            let provider = MockProvider::new();
            let client = reqwest::Client::new();
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
                        assert_eq!(ctx.status, StatusCode::OK);
                    }
                }
            });

            let resp = client
                .get(format!("{}/paid", base_url))
                .send_with_payment_options(&provider, &AcceptPaymentPolicy::Always, events)
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(provider.call_count(), 1);
            assert_eq!(challenge_count.load(Ordering::SeqCst), 1);
            assert_eq!(credential_count.load(Ordering::SeqCst), 1);
            assert_eq!(response_count.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn test_unsuccessful_paid_retry_emits_payment_failed() {
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
            let provider = MockProvider::new();
            let client = reqwest::Client::new();
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

            let resp = client
                .get(format!("{}/paid", base_url))
                .send_with_payment_options(&provider, &AcceptPaymentPolicy::Always, events)
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            assert_eq!(provider.call_count(), 1);
            assert_eq!(response_count.load(Ordering::SeqCst), 0);
            assert_eq!(failed_count.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn test_incremental_402_retries_stop_at_default_cap() {
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
            let provider = MockProvider::new();
            let client = reqwest::Client::new();
            let events = ClientEvents::default();
            let failed_count = Arc::new(AtomicU32::new(0));

            let _failed_sub = events.on_payment_failed({
                let failed_count = failed_count.clone();
                move |_| {
                    failed_count.fetch_add(1, Ordering::SeqCst);
                    async {}
                }
            });

            let resp = client
                .get(format!("{}/paid", base_url))
                .send_with_payment_options(&provider, &AcceptPaymentPolicy::Always, events)
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
            assert_eq!(provider.call_count(), DEFAULT_MAX_PAYMENT_RETRIES as u32);
            assert_eq!(
                request_count.load(Ordering::SeqCst),
                DEFAULT_MAX_PAYMENT_RETRIES as u32 + 1
            );
            assert_eq!(failed_count.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn test_incremental_402_retries_do_not_pay_repeated_challenge() {
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
            let provider = MockProvider::new();
            let client = reqwest::Client::new();
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

            let resp = client
                .get(format!("{}/paid", base_url))
                .send_with_payment_options(&provider, &AcceptPaymentPolicy::Always, events)
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
            assert_eq!(provider.call_count(), 1);
            assert_eq!(request_count.load(Ordering::SeqCst), 2);
            assert_eq!(failed_count.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn test_incremental_402_retries_use_configured_cap() {
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
            let provider = MockProvider::new();
            let client = reqwest::Client::new();

            let resp = client
                .get(format!("{}/paid", base_url))
                .send_with_payment_max_retries(&provider, 1)
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
            assert_eq!(provider.call_count(), 1);
            assert_eq!(request_count.load(Ordering::SeqCst), 2);
        }

        #[tokio::test]
        async fn test_distinct_charge_after_paid_retry_is_indeterminate() {
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
            let provider = MockProvider::new();
            let client = reqwest::Client::new();
            let events = ClientEvents::default();
            let observed_reason = Arc::new(Mutex::new(None));
            let _failed_sub = events.on_payment_failed({
                let observed_reason = observed_reason.clone();
                move |context| {
                    *observed_reason.lock().unwrap() = context.reason;
                    async {}
                }
            });

            let error = client
                .get(format!("{}/paid", base_url))
                .send_with_payment_options(&provider, &AcceptPaymentPolicy::Always, events)
                .await
                .unwrap_err();

            assert!(matches!(
                error,
                HttpError::IndeterminatePayment {
                    ref paid_challenge_id,
                    ref retry_challenge_id,
                } if paid_challenge_id == "first" && retry_challenge_id == "second"
            ));
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
        async fn test_incremental_402_retries_pay_replacement_challenges() {
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
            let provider = MockProvider::new();
            let client = reqwest::Client::new();

            let resp = client
                .get(format!("{}/paid", base_url))
                .send_with_payment(&provider)
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::OK);
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
        async fn test_challenge_received_can_override_credential() {
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
            let provider = MockProvider::new();
            let client = reqwest::Client::new();
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

            let resp = client
                .get(format!("{}/paid", base_url))
                .send_with_payment_options(&provider, &AcceptPaymentPolicy::Always, events)
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(provider.call_count(), 0);
        }

        #[tokio::test]
        async fn test_payment_event_panic_does_not_fail_request() {
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
            let provider = MockProvider::new();
            let client = reqwest::Client::new();
            let events = ClientEvents::default();
            let _sub = events.on::<_, _, ()>(ClientEventKind::ChallengeReceived, |_| async move {
                panic!("hook panic should be isolated");
                #[allow(unreachable_code)]
                ()
            });

            let resp = client
                .get(format!("{}/paid", base_url))
                .send_with_payment_options(&provider, &AcceptPaymentPolicy::Always, events)
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(provider.call_count(), 1);
        }

        #[tokio::test]
        async fn test_non_402_passthrough() {
            let app = Router::new().route("/free", get(|| async { "free content" }));

            let base_url = spawn_server(app).await;
            let provider = MockProvider::new();
            let client = reqwest::Client::new();

            let resp = client
                .get(format!("{}/free", base_url))
                .send_with_payment(&provider)
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(provider.call_count(), 0);
        }

        #[tokio::test]
        async fn test_402_missing_www_authenticate() {
            let app = Router::new().route(
                "/no-header",
                get(|| async { AxumStatusCode::PAYMENT_REQUIRED }),
            );

            let base_url = spawn_server(app).await;
            let provider = MockProvider::new();
            let client = reqwest::Client::new();

            let err = client
                .get(format!("{}/no-header", base_url))
                .send_with_payment(&provider)
                .await
                .unwrap_err();

            assert!(matches!(err, HttpError::MissingChallenge));
        }

        #[tokio::test]
        async fn test_402_malformed_www_authenticate() {
            let app = Router::new().route(
                "/bad-header",
                get(|| async {
                    (
                        AxumStatusCode::PAYMENT_REQUIRED,
                        [(WWW_AUTH_NAME, "garbage-not-a-valid-challenge")],
                    )
                }),
            );

            let base_url = spawn_server(app).await;
            let provider = MockProvider::new();
            let client = reqwest::Client::new();

            let err = client
                .get(format!("{}/bad-header", base_url))
                .send_with_payment(&provider)
                .await
                .unwrap_err();

            assert!(matches!(err, HttpError::NoSupportedChallenge(_)));
        }

        #[tokio::test]
        async fn test_provider_failure_bubbles_up() {
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
            let provider = MockProvider::failing();
            let client = reqwest::Client::new();

            let err = client
                .get(format!("{}/paid", base_url))
                .send_with_payment(&provider)
                .await
                .unwrap_err();

            assert!(matches!(err, HttpError::Payment(_)));
        }

        #[tokio::test]
        async fn test_fetch_rejects_expired_challenge_with_pre_signing_reason() {
            let www_auth = challenge_header_with_expires(
                "exp",
                "tempo",
                "charge",
                Some("2020-01-01T00:00:00Z"),
            );

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
            let provider = MockProvider::new();
            let events = ClientEvents::default();
            let failed_count = Arc::new(AtomicU32::new(0));
            let captured_reason: Arc<std::sync::Mutex<Option<PaymentFailureReason>>> =
                Arc::new(Default::default());

            let _failed_sub = events.on_payment_failed({
                let failed_count = failed_count.clone();
                let captured_reason = captured_reason.clone();
                move |ctx| {
                    failed_count.fetch_add(1, Ordering::SeqCst);
                    *captured_reason.lock().unwrap() = ctx.reason.clone();
                    async {}
                }
            });

            let err = reqwest::Client::new()
                .get(format!("{}/paid", base_url))
                .send_with_payment_options(&provider, &AcceptPaymentPolicy::Always, events)
                .await
                .unwrap_err();

            assert!(matches!(
                err,
                HttpError::Payment(MppError::PaymentExpired(_))
            ));
            assert_eq!(provider.call_count(), 0);
            assert_eq!(failed_count.load(Ordering::SeqCst), 1);
            assert_eq!(
                captured_reason.lock().unwrap().clone(),
                Some(PaymentFailureReason::PreSigningExpired {
                    expires: Some("2020-01-01T00:00:00Z".to_string()),
                }),
            );
        }

        /// Provider that only supports specific method/intent pairs.
        #[derive(Clone)]
        struct SelectiveProvider {
            supported: Vec<(&'static str, &'static str)>,
            pay_count: Arc<AtomicU32>,
        }

        impl SelectiveProvider {
            fn new(supported: Vec<(&'static str, &'static str)>) -> Self {
                Self {
                    supported,
                    pay_count: Arc::new(AtomicU32::new(0)),
                }
            }

            fn call_count(&self) -> u32 {
                self.pay_count.load(Ordering::SeqCst)
            }
        }

        impl super::PaymentProvider for SelectiveProvider {
            fn supports(&self, method: &str, intent: &str) -> bool {
                self.supported
                    .iter()
                    .any(|(m, i)| *m == method && *i == intent)
            }

            async fn pay(
                &self,
                challenge: &PaymentChallenge,
            ) -> Result<PaymentCredential, MppError> {
                self.pay_count.fetch_add(1, Ordering::SeqCst);
                let echo = challenge.to_echo();
                Ok(PaymentCredential::new(
                    echo,
                    PaymentPayload::hash("0xmockhash"),
                ))
            }
        }

        /// Build a challenge header for a specific method and intent.
        fn challenge_header(id: &str, method: &str, intent: &str) -> String {
            challenge_header_with_expires(id, method, intent, None)
        }

        fn challenge_header_with_expires(
            id: &str,
            method: &str,
            intent: &str,
            expires: Option<&str>,
        ) -> String {
            let request =
                Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
            let mut challenge =
                PaymentChallenge::new(id, "test.example.com", method, intent, request);
            if let Some(expires) = expires {
                challenge = challenge.with_expires(expires);
            }
            format_www_authenticate(&challenge).unwrap()
        }

        #[tokio::test]
        async fn test_multi_challenge_selects_supported_method() {
            // Server offers both stripe and tempo; provider only supports tempo.
            let stripe_header = challenge_header("s1", "stripe", "charge");
            let tempo_header = challenge_header("t1", "tempo", "charge");
            let combined = format!("{}, {}", stripe_header, tempo_header);

            let app = Router::new().route(
                "/paid",
                get(move |req: axum::http::Request<axum::body::Body>| {
                    let combined = combined.clone();
                    async move {
                        if req.headers().get("authorization").is_some() {
                            (AxumStatusCode::OK, "ok").into_response()
                        } else {
                            (
                                AxumStatusCode::PAYMENT_REQUIRED,
                                [(WWW_AUTH_NAME, combined)],
                                "pay up",
                            )
                                .into_response()
                        }
                    }
                }),
            );

            let base_url = spawn_server(app).await;
            let provider = SelectiveProvider::new(vec![("tempo", "charge")]);
            let client = reqwest::Client::new();

            let resp = client
                .get(format!("{}/paid", base_url))
                .send_with_payment(&provider)
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(provider.call_count(), 1);
        }

        #[tokio::test]
        async fn test_multi_challenge_picks_first_supported() {
            // Server offers tempo then stripe; provider supports both.
            // Should pick tempo (first match).
            let tempo_header = challenge_header("t1", "tempo", "charge");
            let stripe_header = challenge_header("s1", "stripe", "charge");
            let combined = format!("{}, {}", tempo_header, stripe_header);

            let app = Router::new().route(
                "/paid",
                get(move |req: axum::http::Request<axum::body::Body>| {
                    let combined = combined.clone();
                    async move {
                        if req.headers().get("authorization").is_some() {
                            (AxumStatusCode::OK, "ok").into_response()
                        } else {
                            (
                                AxumStatusCode::PAYMENT_REQUIRED,
                                [(WWW_AUTH_NAME, combined)],
                                "pay up",
                            )
                                .into_response()
                        }
                    }
                }),
            );

            let base_url = spawn_server(app).await;
            let provider = SelectiveProvider::new(vec![("tempo", "charge"), ("stripe", "charge")]);
            let client = reqwest::Client::new();

            let resp = client
                .get(format!("{}/paid", base_url))
                .send_with_payment(&provider)
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(provider.call_count(), 1);
        }

        #[tokio::test]
        async fn test_multi_challenge_skips_expired_preferred_supported() {
            // Caller prefers tempo, but that challenge is expired; stripe is
            // still supported and valid, so the request should continue.
            let tempo_header = challenge_header_with_expires(
                "t1",
                "tempo",
                "charge",
                Some("2020-01-01T00:00:00Z"),
            );
            let stripe_header = challenge_header("s1", "stripe", "charge");
            let combined = format!("{}, {}", tempo_header, stripe_header);

            let picked: Arc<std::sync::Mutex<Option<String>>> = Arc::new(Default::default());
            let picked_clone = picked.clone();

            let app = Router::new().route(
                "/paid",
                get(move |req: axum::http::Request<axum::body::Body>| {
                    let combined = combined.clone();
                    let picked = picked_clone.clone();
                    async move {
                        if let Some(auth) = req.headers().get("authorization") {
                            *picked.lock().unwrap() =
                                Some(auth.to_str().unwrap_or_default().to_string());
                            (AxumStatusCode::OK, "ok").into_response()
                        } else {
                            (
                                AxumStatusCode::PAYMENT_REQUIRED,
                                [(WWW_AUTH_NAME, combined)],
                                "pay up",
                            )
                                .into_response()
                        }
                    }
                }),
            );

            let base_url = spawn_server(app).await;
            let provider = SelectiveProvider::new(vec![("tempo", "charge"), ("stripe", "charge")]);
            let client = reqwest::Client::new();

            let resp = client
                .get(format!("{}/paid", base_url))
                .header("Accept-Payment", "tempo/charge, stripe/charge;q=0.5")
                .send_with_payment(&provider)
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(provider.call_count(), 1);
            let used = picked.lock().unwrap().clone().unwrap_or_default();
            let cred = crate::protocol::core::parse_authorization(&used).unwrap();
            assert_eq!(cred.challenge.id, "s1");
        }

        #[tokio::test]
        async fn test_multi_challenge_skips_malformed_expiry_first_supported() {
            // A bad expires value fails closed for that challenge, but should
            // not block a later valid challenge for the same method/intent.
            let bad_header =
                challenge_header_with_expires("bad", "tempo", "charge", Some("not-a-date"));
            let valid_header = challenge_header("valid", "tempo", "charge");
            let combined = format!("{}, {}", bad_header, valid_header);

            let picked: Arc<std::sync::Mutex<Option<String>>> = Arc::new(Default::default());
            let picked_clone = picked.clone();

            let app = Router::new().route(
                "/paid",
                get(move |req: axum::http::Request<axum::body::Body>| {
                    let combined = combined.clone();
                    let picked = picked_clone.clone();
                    async move {
                        if let Some(auth) = req.headers().get("authorization") {
                            *picked.lock().unwrap() =
                                Some(auth.to_str().unwrap_or_default().to_string());
                            (AxumStatusCode::OK, "ok").into_response()
                        } else {
                            (
                                AxumStatusCode::PAYMENT_REQUIRED,
                                [(WWW_AUTH_NAME, combined)],
                                "pay up",
                            )
                                .into_response()
                        }
                    }
                }),
            );

            let base_url = spawn_server(app).await;
            let provider = SelectiveProvider::new(vec![("tempo", "charge")]);
            let client = reqwest::Client::new();

            let resp = client
                .get(format!("{}/paid", base_url))
                .send_with_payment(&provider)
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(provider.call_count(), 1);
            let used = picked.lock().unwrap().clone().unwrap_or_default();
            let cred = crate::protocol::core::parse_authorization(&used).unwrap();
            assert_eq!(cred.challenge.id, "valid");
        }

        #[tokio::test]
        async fn test_no_supported_challenge_error() {
            // Server offers stripe only; provider only supports tempo.
            let stripe_header = challenge_header("s1", "stripe", "charge");

            let app = Router::new().route(
                "/paid",
                get(move || {
                    let stripe_header = stripe_header.clone();
                    async move {
                        (
                            AxumStatusCode::PAYMENT_REQUIRED,
                            [(WWW_AUTH_NAME, stripe_header)],
                        )
                    }
                }),
            );

            let base_url = spawn_server(app).await;
            let provider = SelectiveProvider::new(vec![("tempo", "charge")]);
            let client = reqwest::Client::new();

            let err = client
                .get(format!("{}/paid", base_url))
                .send_with_payment(&provider)
                .await
                .unwrap_err();

            assert!(matches!(err, HttpError::NoSupportedChallenge(_)));
        }

        #[tokio::test]
        async fn test_multiple_www_authenticate_headers() {
            // Challenges split across separate WWW-Authenticate header instances.
            let stripe_header = challenge_header("s1", "stripe", "charge");
            let tempo_header = challenge_header("t1", "tempo", "charge");

            let app = Router::new().route(
                "/paid",
                get(move |req: axum::http::Request<axum::body::Body>| {
                    let stripe_header = stripe_header.clone();
                    let tempo_header = tempo_header.clone();
                    async move {
                        if req.headers().get("authorization").is_some() {
                            (AxumStatusCode::OK, "ok").into_response()
                        } else {
                            let mut resp =
                                (AxumStatusCode::PAYMENT_REQUIRED, "pay up").into_response();
                            let headers = resp.headers_mut();
                            headers.append(WWW_AUTH_NAME, stripe_header.parse().unwrap());
                            headers.append(WWW_AUTH_NAME, tempo_header.parse().unwrap());
                            resp
                        }
                    }
                }),
            );

            let base_url = spawn_server(app).await;
            let provider = SelectiveProvider::new(vec![("tempo", "charge")]);
            let client = reqwest::Client::new();

            let resp = client
                .get(format!("{}/paid", base_url))
                .send_with_payment(&provider)
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(provider.call_count(), 1);
        }

        #[tokio::test]
        async fn test_intent_matching() {
            // Server offers tempo/session; provider only supports tempo/charge.
            let session_header = challenge_header("t1", "tempo", "session");

            let app = Router::new().route(
                "/paid",
                get(move || {
                    let session_header = session_header.clone();
                    async move {
                        (
                            AxumStatusCode::PAYMENT_REQUIRED,
                            [(WWW_AUTH_NAME, session_header)],
                        )
                    }
                }),
            );

            let base_url = spawn_server(app).await;
            let provider = SelectiveProvider::new(vec![("tempo", "charge")]);
            let client = reqwest::Client::new();

            let err = client
                .get(format!("{}/paid", base_url))
                .send_with_payment(&provider)
                .await
                .unwrap_err();

            assert!(matches!(err, HttpError::NoSupportedChallenge(_)));
        }

        /// Provider that exposes a known Accept-Payment header value so the
        /// test can observe whether it was injected.
        #[derive(Clone)]
        struct AdvertisingProvider;

        impl super::PaymentProvider for AdvertisingProvider {
            fn supports(&self, _method: &str, _intent: &str) -> bool {
                true
            }
            async fn pay(
                &self,
                _challenge: &PaymentChallenge,
            ) -> Result<PaymentCredential, MppError> {
                unimplemented!("not used in policy test")
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
        async fn test_send_with_payment_default_injects() {
            let (base_url, captured) = spawn_header_capture().await;
            reqwest::Client::new()
                .get(format!("{}/probe", base_url))
                .send_with_payment(&AdvertisingProvider)
                .await
                .unwrap();
            assert_eq!(captured.lock().unwrap().as_deref(), Some("tempo/charge"));
        }

        #[tokio::test]
        async fn test_send_with_payment_policy_never_blocks() {
            let (base_url, captured) = spawn_header_capture().await;
            reqwest::Client::new()
                .get(format!("{}/probe", base_url))
                .send_with_payment_policy(&AdvertisingProvider, &AcceptPaymentPolicy::Never)
                .await
                .unwrap();
            assert_eq!(captured.lock().unwrap().as_deref(), None);
        }

        #[tokio::test]
        async fn test_caller_header_not_overwritten() {
            // Caller sets Accept-Payment: stripe/charge → must not be replaced.
            let (base_url, captured) = spawn_header_capture().await;
            reqwest::Client::new()
                .get(format!("{}/probe", base_url))
                .header("Accept-Payment", "stripe/charge")
                .send_with_payment(&AdvertisingProvider)
                .await
                .unwrap();
            assert_eq!(captured.lock().unwrap().as_deref(), Some("stripe/charge"));
        }

        #[tokio::test]
        async fn test_caller_header_drives_ranking() {
            // Server offers tempo/charge AND stripe/charge.
            // Provider supports both. Caller header prefers stripe;
            // retry must select the stripe challenge.
            let tempo_header = challenge_header("t1", "tempo", "charge");
            let stripe_header = challenge_header("s1", "stripe", "charge");
            let combined = format!("{}, {}", tempo_header, stripe_header);

            let picked: Arc<std::sync::Mutex<Option<String>>> = Arc::new(Default::default());
            let picked_clone = picked.clone();

            let app = Router::new().route(
                "/paid",
                get(move |req: axum::http::Request<axum::body::Body>| {
                    let combined = combined.clone();
                    let picked = picked_clone.clone();
                    async move {
                        if let Some(auth) = req.headers().get("authorization") {
                            let v = auth.to_str().unwrap_or("").to_string();
                            // Capture which challenge id was used (s1 vs t1).
                            *picked.lock().unwrap() = Some(v);
                            (AxumStatusCode::OK, "ok").into_response()
                        } else {
                            (
                                AxumStatusCode::PAYMENT_REQUIRED,
                                [(WWW_AUTH_NAME, combined)],
                                "pay",
                            )
                                .into_response()
                        }
                    }
                }),
            );
            let base_url = spawn_server(app).await;
            let provider = SelectiveProvider::new(vec![("tempo", "charge"), ("stripe", "charge")]);
            reqwest::Client::new()
                .get(format!("{}/paid", base_url))
                .header("Accept-Payment", "stripe/charge, tempo/charge;q=0.1")
                .send_with_payment(&provider)
                .await
                .unwrap();
            let used = picked.lock().unwrap().clone().unwrap_or_default();
            let cred = crate::protocol::core::parse_authorization(&used).unwrap();
            assert_eq!(
                cred.challenge.id, "s1",
                "expected stripe challenge (id s1) to be picked, got id: {}",
                cred.challenge.id
            );
        }

        #[tokio::test]
        async fn test_send_with_payment_policy_same_origin_mismatch() {
            let (base_url, captured) = spawn_header_capture().await;
            reqwest::Client::new()
                .get(format!("{}/probe", base_url))
                .send_with_payment_policy(
                    &AdvertisingProvider,
                    &AcceptPaymentPolicy::SameOrigin {
                        same_origin: "https://app.example.com".to_string(),
                    },
                )
                .await
                .unwrap();
            assert_eq!(captured.lock().unwrap().as_deref(), None);
        }
    }
}
