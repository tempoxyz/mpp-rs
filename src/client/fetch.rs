//! Extension trait for reqwest RequestBuilder.
//!
//! Provides `.send_with_payment()` method for opt-in per-request payment handling.

use reqwest::header::WWW_AUTHENTICATE;
use reqwest::{RequestBuilder, Response, StatusCode};

use super::error::HttpError;
use super::provider::PaymentProvider;
use crate::protocol::core::{
    format_authorization, parse_www_authenticate_all, AUTHORIZATION_HEADER,
};

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
pub trait PaymentExt {
    /// Send the request, automatically handling 402 Payment Required responses.
    ///
    /// If the initial request returns 402:
    /// 1. Parse the challenge from the `WWW-Authenticate` header
    /// 2. Call `provider.pay()` to execute the payment
    /// 3. Retry the request with the credential in the `Authorization` header
    ///
    /// # Errors
    ///
    /// Returns `HttpError` if:
    /// - The request cannot be cloned (required for retry)
    /// - The 402 response is missing the `WWW-Authenticate` header
    /// - The challenge cannot be parsed
    /// - The payment fails
    /// - The retry request fails
    fn send_with_payment<P: PaymentProvider>(
        self,
        provider: &P,
    ) -> impl std::future::Future<Output = Result<Response, HttpError>> + Send;
}

impl PaymentExt for RequestBuilder {
    async fn send_with_payment<P: PaymentProvider>(
        self,
        provider: &P,
    ) -> Result<Response, HttpError> {
        let retry_builder = self.try_clone().ok_or(HttpError::CloneFailed)?;

        let resp = self.send().await?;

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
            return Err(HttpError::MissingChallenge);
        }

        let challenges: Vec<_> = parse_www_authenticate_all(www_auth_values)
            .into_iter()
            .filter_map(|r| r.ok())
            .collect();

        let challenge = challenges
            .iter()
            .find(|c| provider.supports(c.method.as_str(), c.intent.as_str()))
            .ok_or_else(|| {
                let offered: Vec<_> = challenges
                    .iter()
                    .map(|c| format!("{}.{}", c.method, c.intent))
                    .collect();
                HttpError::NoSupportedChallenge(format!(
                    "server offered [{}], but provider does not support any",
                    offered.join(", ")
                ))
            })?;

        let credential = provider.pay(challenge).await?;

        let auth_header = format_authorization(&credential)
            .map_err(|e| HttpError::InvalidCredential(e.to_string()))?;

        let retry_resp = retry_builder
            .header(AUTHORIZATION_HEADER, auth_header)
            .send()
            .await?;

        Ok(retry_resp)
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
        use std::sync::Arc;
        use tokio::net::TcpListener;

        /// Mock provider that records calls and returns a fixed credential.
        #[derive(Clone)]
        struct MockProvider {
            pay_count: Arc<AtomicU32>,
            fail: bool,
        }

        impl MockProvider {
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

        impl super::PaymentProvider for MockProvider {
            fn supports(&self, _method: &str, _intent: &str) -> bool {
                true
            }

            async fn pay(
                &self,
                challenge: &crate::protocol::core::PaymentChallenge,
            ) -> Result<PaymentCredential, MppError> {
                self.pay_count.fetch_add(1, Ordering::SeqCst);
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
            let request =
                Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
            let challenge = PaymentChallenge::new(
                "test-id-123",
                "test.example.com",
                "tempo",
                "charge",
                request,
            );
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
            let request =
                Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
            let challenge = PaymentChallenge::new(id, "test.example.com", method, intent, request);
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
    }
}
