//! reqwest-middleware integration for automatic 402 handling.
//!
//! Provides `PaymentMiddleware` for use with `reqwest_middleware::ClientBuilder`.

use anyhow::Context;
use async_trait::async_trait;
use reqwest::header::WWW_AUTHENTICATE;
use reqwest::{Request, Response, StatusCode};
use reqwest_middleware::{Middleware, Next};

use crate::client::provider::PaymentProvider;
use crate::protocol::core::{format_authorization, parse_www_authenticate, AUTHORIZATION_HEADER};

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
}

impl<P> PaymentMiddleware<P> {
    /// Create a new payment middleware with the given provider.
    pub fn new(provider: P) -> Self {
        Self { provider }
    }
}

#[async_trait]
impl<P> Middleware for PaymentMiddleware<P>
where
    P: PaymentProvider + 'static,
{
    async fn handle(
        &self,
        req: Request,
        extensions: &mut http_types::Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        let retry_req = req.try_clone();
        let resp = next.clone().run(req, extensions).await?;

        if resp.status() != StatusCode::PAYMENT_REQUIRED {
            return Ok(resp);
        }

        let retry_req = retry_req
            .context("request could not be cloned for payment retry")
            .map_err(reqwest_middleware::Error::Middleware)?;

        let www_auth = resp
            .headers()
            .get(WWW_AUTHENTICATE)
            .context("402 response missing WWW-Authenticate header")
            .map_err(reqwest_middleware::Error::Middleware)?
            .to_str()
            .context("invalid WWW-Authenticate header")
            .map_err(reqwest_middleware::Error::Middleware)?;

        let challenge = parse_www_authenticate(www_auth)
            .context("invalid challenge")
            .map_err(reqwest_middleware::Error::Middleware)?;

        let credential = self
            .provider
            .pay(&challenge)
            .await
            .context("payment failed")
            .map_err(reqwest_middleware::Error::Middleware)?;

        let auth_header = format_authorization(&credential)
            .context("failed to format credential")
            .map_err(reqwest_middleware::Error::Middleware)?;

        let mut retry_req = retry_req;
        retry_req.headers_mut().insert(
            AUTHORIZATION_HEADER,
            auth_header
                .parse()
                .context("invalid authorization header")
                .map_err(reqwest_middleware::Error::Middleware)?,
        );

        next.run(retry_req, extensions).await
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
            let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "500"})).unwrap();
            let challenge = PaymentChallenge::new(
                "mw-test-id",
                "middleware.example.com",
                "tempo",
                "charge",
                request,
            );
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
