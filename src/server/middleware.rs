//! Tower middleware for payment gating.
//!
//! Provides a [`PaymentLayer`] that wraps the 402 challenge/verify flow
//! into a standard Tower `Layer`/`Service`, compatible with axum, tonic,
//! and any Tower-based framework.
//!
//! # Example (axum)
//!
//! ```ignore
//! use axum::{Router, routing::get};
//! use mpp::server::middleware::PaymentLayer;
//! use mpp::server::{Mpp, tempo, TempoConfig};
//!
//! let mpp = Mpp::create(tempo(TempoConfig {
//!     recipient: "0xabc...",
//! })).unwrap();
//!
//! let app = Router::new()
//!     .route("/premium", get(handler))
//!     .layer(PaymentLayer::charge(&mpp, "0.10").unwrap());
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http_types::{header, HeaderValue, Request, Response, StatusCode};

use crate::protocol::core::headers::{
    extract_payment_scheme, format_receipt, format_www_authenticate, parse_authorization,
    PAYMENT_RECEIPT_HEADER, WWW_AUTHENTICATE_HEADER,
};

/// Trait for payment verification in middleware context.
///
/// This abstracts over the `Mpp` type's generics so the middleware
/// can be used without propagating generic parameters.
pub trait PaymentVerifier: Send + Sync + 'static {
    /// Generate a `WWW-Authenticate: Payment ...` challenge header value.
    fn challenge(&self) -> Result<String, String>;

    /// Verify a credential string and return a `Payment-Receipt` header value.
    ///
    /// The `credential` is the raw `Authorization` header value
    /// (e.g., `"Payment eyJ..."` including the scheme prefix).
    fn verify(
        &self,
        credential: &str,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send>>;
}

// ==================== FnVerifier ====================

/// A [`PaymentVerifier`] built from closures.
#[allow(clippy::type_complexity)]
pub struct FnVerifier {
    challenge_fn: Box<dyn Fn() -> Result<String, String> + Send + Sync>,
    verify_fn: Box<
        dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send>>
            + Send
            + Sync,
    >,
}

impl PaymentVerifier for FnVerifier {
    fn challenge(&self) -> Result<String, String> {
        (self.challenge_fn)()
    }

    fn verify(
        &self,
        credential: &str,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send>> {
        (self.verify_fn)(credential.to_string())
    }
}

// ==================== PaymentLayer ====================

/// Tower [`Layer`](tower_layer::Layer) that gates requests behind payment verification.
///
/// Requests without a valid `Authorization: Payment ...` header receive
/// a `402 Payment Required` response with a `WWW-Authenticate` challenge.
/// Valid payments are verified and a `Payment-Receipt` header is attached
/// to the inner service's response.
#[derive(Clone)]
pub struct PaymentLayer<V> {
    verifier: Arc<V>,
}

impl<V: PaymentVerifier> PaymentLayer<V> {
    /// Create a payment layer with a custom [`PaymentVerifier`].
    pub fn new(verifier: V) -> Self {
        Self {
            verifier: Arc::new(verifier),
        }
    }
}

impl PaymentLayer<FnVerifier> {
    /// Create a payment layer from challenge/verify closures.
    pub fn from_fns(
        challenge_fn: impl Fn() -> Result<String, String> + Send + Sync + 'static,
        verify_fn: impl Fn(String) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send>>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        Self::new(FnVerifier {
            challenge_fn: Box::new(challenge_fn),
            verify_fn: Box::new(verify_fn),
        })
    }
}

impl<S, V: PaymentVerifier> tower_layer::Layer<S> for PaymentLayer<V> {
    type Service = PaymentService<S, V>;

    fn layer(&self, inner: S) -> Self::Service {
        PaymentService {
            inner,
            verifier: Arc::clone(&self.verifier),
        }
    }
}

// ==================== PaymentService ====================

/// Tower [`Service`](tower_service::Service) that wraps an inner service with payment verification.
#[derive(Clone)]
pub struct PaymentService<S, V> {
    inner: S,
    verifier: Arc<V>,
}

impl<S, V, ReqBody, ResBody> tower_service::Service<Request<ReqBody>> for PaymentService<S, V>
where
    S: tower_service::Service<Request<ReqBody>, Response = Response<ResBody>>
        + Clone
        + Send
        + 'static,
    S::Future: Send,
    S::Error: Send,
    V: PaymentVerifier,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response<ResBody>, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let verifier = Arc::clone(&self.verifier);
        // Keep a clone in `self` for future poll_ready cycles and call the
        // currently-ready service instance moved out of `self`.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            // Extract the Authorization header.
            let auth_header = req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(extract_payment_scheme)
                .map(|s| s.to_string());

            let credential = match auth_header {
                Some(c) => c,
                None => {
                    // No credential — return 402 with challenge.
                    let challenge = match verifier.challenge() {
                        Ok(c) => c,
                        Err(e) => {
                            return Ok(error_response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                &format!("Failed to generate challenge: {}", e),
                            ));
                        }
                    };
                    let mut resp = Response::new(ResBody::default());
                    *resp.status_mut() = StatusCode::PAYMENT_REQUIRED;
                    resp.headers_mut().insert(
                        WWW_AUTHENTICATE_HEADER,
                        HeaderValue::from_str(&challenge)
                            .unwrap_or_else(|_| HeaderValue::from_static("Payment")),
                    );
                    return Ok(resp);
                }
            };

            // Verify the credential.
            let receipt_header = match verifier.verify(&credential).await {
                Ok(r) => r,
                Err(e) => {
                    return Ok(error_response(
                        StatusCode::PAYMENT_REQUIRED,
                        &format!("Payment verification failed: {}", e),
                    ));
                }
            };

            // Call the inner service.
            let mut resp = inner.call(req).await?;

            // Attach the receipt header.
            if let Ok(val) = HeaderValue::from_str(&receipt_header) {
                resp.headers_mut().insert(PAYMENT_RECEIPT_HEADER, val);
            }

            Ok(resp)
        })
    }
}

/// Build a minimal error response.
fn error_response<B: Default>(status: StatusCode, _message: &str) -> Response<B> {
    let mut resp = Response::new(B::default());
    *resp.status_mut() = status;
    resp
}

// ==================== Mpp integration ====================

/// A [`PaymentVerifier`] backed by an `Mpp` instance's charge flow.
///
/// Created via [`PaymentLayer::charge()`].
#[allow(clippy::type_complexity)]
struct ChargeVerifier {
    /// Builds a fresh `WWW-Authenticate` header value per request.
    challenge_fn: Box<dyn Fn() -> Result<String, String> + Send + Sync>,
    /// Shared mpp instance for verification (type-erased).
    verify_fn: Box<
        dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send>>
            + Send
            + Sync,
    >,
}

impl PaymentVerifier for ChargeVerifier {
    fn challenge(&self) -> Result<String, String> {
        (self.challenge_fn)()
    }

    fn verify(
        &self,
        credential: &str,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send>> {
        (self.verify_fn)(credential.to_string())
    }
}

impl PaymentLayer<ChargeVerifier> {
    /// Create a payment layer that charges a dollar amount per request.
    ///
    /// Generates a fresh challenge for each request and verifies each
    /// incoming credential against the provided `Mpp` instance.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use mpp::server::middleware::PaymentLayer;
    ///
    /// let layer = PaymentLayer::charge(&mpp, "0.10").unwrap();
    /// ```
    #[cfg(feature = "tempo")]
    pub fn charge<M, S>(mpp: &super::Mpp<M, S>, amount: &str) -> crate::error::Result<Self>
    where
        M: crate::protocol::traits::ChargeMethod + Clone + Send + Sync + 'static,
        S: Clone + Send + Sync + 'static,
    {
        // Capture route-scoped expected request once so credential verification
        // compares against endpoint configuration, not echoed credential data.
        let expected_challenge = mpp.charge(amount)?;
        let expected_request: crate::protocol::intents::ChargeRequest =
            expected_challenge.request.decode().map_err(|e| {
                crate::error::MppError::InvalidConfig(format!(
                    "Failed to decode route charge request: {e}"
                ))
            })?;

        let mpp_for_challenge = mpp.clone();
        let charge_amount = amount.to_string();
        let challenge_fn = Box::new(move || {
            let challenge = mpp_for_challenge
                .charge(&charge_amount)
                .map_err(|e| format!("Failed to generate challenge: {e}"))?;
            format_www_authenticate(&challenge)
                .map_err(|e| format!("Failed to format challenge: {e}"))
        });

        let mpp_for_verify = mpp.clone();
        let verify_fn = Box::new(move |credential_str: String| -> Pin<Box<dyn Future<Output = Result<String, String>> + Send>> {
            let mpp = mpp_for_verify.clone();
            let expected_request = expected_request.clone();
            Box::pin(async move {
                let credential = parse_authorization(&credential_str)
                    .map_err(|e| format!("Invalid credential: {e}"))?;

                let receipt = mpp
                    .verify_credential_with_expected_request(&credential, &expected_request)
                    .await
                    .map_err(|e| e.to_string())?;

                format_receipt(&receipt).map_err(|e| format!("Failed to format receipt: {e}"))
            })
        });

        Ok(Self::new(ChargeVerifier {
            challenge_fn,
            verify_fn,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct MockVerifier {
        challenge_value: String,
        accept: bool,
    }

    impl PaymentVerifier for MockVerifier {
        fn challenge(&self) -> Result<String, String> {
            Ok(self.challenge_value.clone())
        }

        fn verify(
            &self,
            _credential: &str,
        ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send>> {
            let accept = self.accept;
            Box::pin(async move {
                if accept {
                    Ok("mock-receipt-token".to_string())
                } else {
                    Err("payment rejected".to_string())
                }
            })
        }
    }

    #[test]
    fn test_payment_verifier_challenge() {
        let v = MockVerifier {
            challenge_value: "Payment id=\"test\"".to_string(),
            accept: true,
        };
        assert_eq!(v.challenge().unwrap(), "Payment id=\"test\"");
    }

    #[tokio::test]
    async fn test_payment_verifier_verify_accept() {
        let v = MockVerifier {
            challenge_value: String::new(),
            accept: true,
        };
        let result = v.verify("Payment eyJ...").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "mock-receipt-token");
    }

    #[tokio::test]
    async fn test_payment_verifier_verify_reject() {
        let v = MockVerifier {
            challenge_value: String::new(),
            accept: false,
        };
        let result = v.verify("Payment eyJ...").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "payment rejected");
    }

    #[test]
    fn test_fn_verifier_challenge() {
        let v = FnVerifier {
            challenge_fn: Box::new(|| Ok("Payment test".to_string())),
            verify_fn: Box::new(|_| Box::pin(async { Ok("receipt".to_string()) })),
        };
        assert_eq!(v.challenge().unwrap(), "Payment test");
    }

    #[test]
    fn test_payment_layer_clones() {
        let layer = PaymentLayer::new(MockVerifier {
            challenge_value: "test".into(),
            accept: true,
        });
        let _clone = layer.clone();
    }

    /// Test the full Tower service flow: no auth → 402.
    #[tokio::test]
    async fn test_service_no_auth_returns_402() {
        use tower_service::Service;

        let layer = PaymentLayer::new(MockVerifier {
            challenge_value: "Payment id=\"challenge\"".to_string(),
            accept: true,
        });

        // A trivial inner service that returns 200.
        #[derive(Clone)]
        struct OkService;

        impl tower_service::Service<Request<()>> for OkService {
            type Response = Response<()>;
            type Error = std::convert::Infallible;
            type Future = Pin<Box<dyn Future<Output = Result<Response<()>, Self::Error>> + Send>>;

            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, _req: Request<()>) -> Self::Future {
                Box::pin(async { Ok(Response::new(())) })
            }
        }

        let mut svc =
            <PaymentLayer<MockVerifier> as tower_layer::Layer<OkService>>::layer(&layer, OkService);

        let req = Request::builder().uri("/premium").body(()).unwrap();

        let resp = svc.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(resp.headers().contains_key(WWW_AUTHENTICATE_HEADER));
    }

    /// Test: valid auth → 200 with receipt.
    #[tokio::test]
    async fn test_service_valid_auth_returns_receipt() {
        use tower_service::Service;

        let layer = PaymentLayer::new(MockVerifier {
            challenge_value: "Payment id=\"challenge\"".to_string(),
            accept: true,
        });

        #[derive(Clone)]
        struct OkService;

        impl tower_service::Service<Request<()>> for OkService {
            type Response = Response<()>;
            type Error = std::convert::Infallible;
            type Future = Pin<Box<dyn Future<Output = Result<Response<()>, Self::Error>> + Send>>;

            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, _req: Request<()>) -> Self::Future {
                Box::pin(async { Ok(Response::new(())) })
            }
        }

        let mut svc =
            <PaymentLayer<MockVerifier> as tower_layer::Layer<OkService>>::layer(&layer, OkService);

        let req = Request::builder()
            .uri("/premium")
            .header(header::AUTHORIZATION, "Payment eyJmYWtlIjp0cnVlfQ")
            .body(())
            .unwrap();

        let resp = svc.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(PAYMENT_RECEIPT_HEADER).unwrap(),
            "mock-receipt-token"
        );
    }

    /// Test: invalid auth → 402 error.
    #[tokio::test]
    async fn test_service_invalid_auth_returns_402() {
        use tower_service::Service;

        let layer = PaymentLayer::new(MockVerifier {
            challenge_value: "Payment id=\"challenge\"".to_string(),
            accept: false,
        });

        #[derive(Clone)]
        struct OkService;

        impl tower_service::Service<Request<()>> for OkService {
            type Response = Response<()>;
            type Error = std::convert::Infallible;
            type Future = Pin<Box<dyn Future<Output = Result<Response<()>, Self::Error>> + Send>>;

            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, _req: Request<()>) -> Self::Future {
                Box::pin(async { Ok(Response::new(())) })
            }
        }

        let mut svc =
            <PaymentLayer<MockVerifier> as tower_layer::Layer<OkService>>::layer(&layer, OkService);

        let req = Request::builder()
            .uri("/premium")
            .header(header::AUTHORIZATION, "Payment eyJmYWtlIjp0cnVlfQ")
            .body(())
            .unwrap();

        let resp = svc.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    }

    // ==================== Real ChargeVerifier tests ====================
    //
    // These tests exercise PaymentLayer with real challenge formatting,
    // HMAC-bound IDs, and the full parse_authorization → verify_credential
    // round-trip, using a mock ChargeMethod to avoid RPC calls.

    #[cfg(feature = "tempo")]
    mod real_charge_verifier {
        use super::*;
        use crate::protocol::core::challenge::{PaymentCredential, PaymentPayload, Receipt};
        use crate::protocol::core::headers::{
            format_authorization, parse_receipt, parse_www_authenticate,
        };
        use crate::protocol::intents::ChargeRequest;
        use crate::protocol::traits::{ChargeMethod, VerificationError};
        use crate::server::Mpp;
        use tower_layer::Layer;
        use tower_service::Service;

        #[derive(Clone)]
        struct SuccessChargeMethod;

        impl ChargeMethod for SuccessChargeMethod {
            fn method(&self) -> &str {
                "tempo"
            }

            async fn verify(
                &self,
                _credential: &PaymentCredential,
                _request: &ChargeRequest,
            ) -> std::result::Result<Receipt, VerificationError> {
                Ok(Receipt::success("tempo", "0xabc123"))
            }
        }

        fn create_mpp_with_mock() -> Mpp<SuccessChargeMethod> {
            Mpp::new_with_config(
                SuccessChargeMethod,
                "test-realm",
                "test-secret",
                "0x20c0000000000000000000000000000000000000",
                "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            )
        }

        #[derive(Clone)]
        struct OkService;

        impl tower_service::Service<Request<()>> for OkService {
            type Response = Response<()>;
            type Error = std::convert::Infallible;
            type Future = Pin<Box<dyn Future<Output = Result<Response<()>, Self::Error>> + Send>>;

            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, _req: Request<()>) -> Self::Future {
                Box::pin(async { Ok(Response::new(())) })
            }
        }

        #[tokio::test]
        async fn test_no_auth_returns_402_with_parseable_challenge() {
            let mpp = create_mpp_with_mock();
            let layer = PaymentLayer::charge(&mpp, "0.10").unwrap();
            let mut svc = layer.layer(OkService);

            let req = Request::builder().uri("/premium").body(()).unwrap();
            let resp = svc.call(req).await.unwrap();

            assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);

            let www_auth = resp
                .headers()
                .get(WWW_AUTHENTICATE_HEADER)
                .expect("missing WWW-Authenticate header")
                .to_str()
                .unwrap();

            let challenge = parse_www_authenticate(www_auth)
                .expect("WWW-Authenticate header should be parseable");

            assert_eq!(challenge.method.as_str(), "tempo");
            assert_eq!(challenge.intent.as_str(), "charge");
            assert_eq!(challenge.realm, "test-realm");
            assert!(!challenge.id.is_empty());

            let request: ChargeRequest = challenge.request.decode().unwrap();
            assert_eq!(request.amount, "100000");
            assert_eq!(
                request.currency,
                "0x20c0000000000000000000000000000000000000"
            );
            assert_eq!(
                request.recipient,
                Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into())
            );
        }

        #[tokio::test]
        async fn test_valid_credential_roundtrip_returns_200_with_receipt() {
            let mpp = create_mpp_with_mock();
            let layer = PaymentLayer::charge(&mpp, "0.10").unwrap();

            // First call: get the challenge from 402.
            let mut svc = layer.layer(OkService);
            let req = Request::builder().uri("/premium").body(()).unwrap();
            let resp = svc.call(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);

            let www_auth = resp
                .headers()
                .get(WWW_AUTHENTICATE_HEADER)
                .unwrap()
                .to_str()
                .unwrap();
            let challenge = parse_www_authenticate(www_auth).unwrap();

            // Build a credential from the challenge.
            let credential =
                PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xdeadbeef"));
            let auth_header = format_authorization(&credential).unwrap();

            // Second call: send credential, expect 200 + receipt.
            let mut svc = layer.layer(OkService);
            let req = Request::builder()
                .uri("/premium")
                .header(header::AUTHORIZATION, &auth_header)
                .body(())
                .unwrap();
            let resp = svc.call(req).await.unwrap();

            assert_eq!(resp.status(), StatusCode::OK);

            let receipt_header = resp
                .headers()
                .get(PAYMENT_RECEIPT_HEADER)
                .expect("missing Payment-Receipt header")
                .to_str()
                .unwrap();
            let receipt =
                parse_receipt(receipt_header).expect("Payment-Receipt header should be parseable");
            assert!(receipt.is_success());
            assert_eq!(receipt.method.as_str(), "tempo");
            assert_eq!(receipt.reference, "0xabc123");
        }

        #[tokio::test]
        async fn test_wrong_scheme_returns_402() {
            let mpp = create_mpp_with_mock();
            let layer = PaymentLayer::charge(&mpp, "0.10").unwrap();
            let mut svc = layer.layer(OkService);

            let req = Request::builder()
                .uri("/premium")
                .header(header::AUTHORIZATION, "Bearer some-token")
                .body(())
                .unwrap();
            let resp = svc.call(req).await.unwrap();

            assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
            assert!(resp.headers().contains_key(WWW_AUTHENTICATE_HEADER));
        }

        #[tokio::test]
        async fn test_garbage_authorization_returns_402() {
            let mpp = create_mpp_with_mock();
            let layer = PaymentLayer::charge(&mpp, "0.10").unwrap();
            let mut svc = layer.layer(OkService);

            let req = Request::builder()
                .uri("/premium")
                .header(header::AUTHORIZATION, "Payment not-valid-base64!!!")
                .body(())
                .unwrap();
            let resp = svc.call(req).await.unwrap();

            assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        }
    }
}
