//! Extension trait for reqwest RequestBuilder.
//!
//! Provides `.send_with_payment()` method for opt-in per-request payment handling.

use reqwest::header::WWW_AUTHENTICATE;
use reqwest::{RequestBuilder, Response, StatusCode};

use super::error::HttpError;
use super::provider::PaymentProvider;
use crate::protocol::core::{format_authorization, parse_www_authenticate, AUTHORIZATION_HEADER};

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

        let www_auth = resp
            .headers()
            .get(WWW_AUTHENTICATE)
            .ok_or(HttpError::MissingChallenge)?
            .to_str()
            .map_err(|e| HttpError::InvalidChallenge(e.to_string()))?;

        let challenge = parse_www_authenticate(www_auth)
            .map_err(|e| HttpError::InvalidChallenge(e.to_string()))?;

        let credential = provider.pay(&challenge).await?;

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

            assert!(matches!(err, HttpError::InvalidChallenge(_)));
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
    }
}
