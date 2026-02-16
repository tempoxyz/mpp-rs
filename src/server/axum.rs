//! Axum extractors and response types for payment gating.
//!
//! Provides [`MppCharge`], an axum extractor that handles the full
//! 402 challenge/verify flow automatically:
//!
//! - No `Authorization: Payment` header → 402 with `WWW-Authenticate` challenge
//! - Invalid credential → 402 error
//! - Valid credential → extracts the [`Receipt`] for the handler
//!
//! Also provides [`IntoResponse`](axum_core::response::IntoResponse)
//! implementations for [`PaymentChallenge`] (402 response) and
//! [`Receipt`] (response header).
//!
//! # Per-route pricing
//!
//! The default [`MppCharge`] charges `$0.01`. To set a different amount
//! per route, define a [`ChargeAmount`] type and use [`MppChargeFor<P>`]:
//!
//! ```ignore
//! use mpp::server::axum::{ChargeAmount, MppChargeFor};
//!
//! struct OneDollar;
//! impl ChargeAmount for OneDollar {
//!     fn amount() -> &'static str { "1.00" }
//! }
//!
//! async fn expensive(charge: MppChargeFor<OneDollar>) -> &'static str {
//!     "premium content"
//! }
//! ```
//!
//! # State setup
//!
//! The extractors require `Arc<dyn ChargeChallenger>` in the router state
//! (either directly or via [`FromRef`](axum_core::extract::FromRef)):
//!
//! ```ignore
//! use axum::{routing::get, Router, Json};
//! use mpp::server::{Mpp, tempo, TempoConfig};
//! use mpp::server::axum::{MppCharge, ChargeChallenger};
//! use std::sync::Arc;
//!
//! let mpp = Mpp::create(tempo(TempoConfig {
//!     currency: "0x20c...",
//!     recipient: "0xabc...",
//! })).unwrap();
//!
//! async fn handler(charge: MppCharge) -> Json<serde_json::Value> {
//!     Json(serde_json::json!({ "paid": true }))
//! }
//!
//! let app = Router::new()
//!     .route("/api/premium", get(handler))
//!     .with_state(Arc::new(mpp) as Arc<dyn ChargeChallenger>);
//! ```

use std::sync::Arc;

use axum_core::extract::{FromRef, FromRequestParts};
use axum_core::response::IntoResponse;
use http_types::{header, HeaderValue, StatusCode};

use crate::protocol::core::headers::{
    extract_payment_scheme, format_receipt, format_www_authenticate, parse_authorization,
    PAYMENT_RECEIPT_HEADER, WWW_AUTHENTICATE_HEADER,
};
use crate::protocol::core::{PaymentChallenge, Receipt};

// ==================== IntoResponse for PaymentChallenge ====================

/// A 402 Payment Required response wrapping a [`PaymentChallenge`].
///
/// Returned as a rejection from [`MppCharge`] when no credential is present,
/// or can be used directly in handlers.
///
/// # Example
///
/// ```ignore
/// use mpp::server::axum::PaymentRequired;
///
/// async fn handler() -> PaymentRequired {
///     let challenge = mpp.charge("1.00").unwrap();
///     PaymentRequired(challenge)
/// }
/// ```
#[derive(Debug)]
pub struct PaymentRequired(pub PaymentChallenge);

impl IntoResponse for PaymentRequired {
    fn into_response(self) -> axum_core::response::Response {
        match format_www_authenticate(&self.0) {
            Ok(www_auth) => {
                let mut resp = (
                    StatusCode::PAYMENT_REQUIRED,
                    serde_json::json!({ "error": "Payment Required" }).to_string(),
                )
                    .into_response();
                resp.headers_mut().insert(
                    WWW_AUTHENTICATE_HEADER,
                    HeaderValue::from_str(&www_auth)
                        .unwrap_or_else(|_| HeaderValue::from_static("Payment")),
                );
                resp.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                resp
            }
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to format challenge: {}", e),
            )
                .into_response(),
        }
    }
}

// ==================== Charge amount policy ====================

/// Trait for specifying a static charge amount on a per-route basis.
///
/// Implement this on a marker type and use [`MppChargeFor<P>`] as your
/// extractor to control the dollar amount charged per route.
///
/// This is designed for fixed per-route pricing. For dynamic pricing
/// (per-user, per-request, etc.), implement [`ChargeChallenger`] directly
/// or use a custom extractor.
///
/// # Example
///
/// ```ignore
/// use mpp::server::axum::{ChargeAmount, MppChargeFor};
///
/// struct TenCents;
/// impl ChargeAmount for TenCents {
///     fn amount() -> &'static str { "0.10" }
/// }
///
/// async fn handler(charge: MppChargeFor<TenCents>) -> &'static str {
///     "paid content"
/// }
/// ```
pub trait ChargeAmount {
    /// The dollar amount to charge (e.g., `"0.01"`, `"1.00"`).
    fn amount() -> &'static str;
}

/// Default charge amount: $0.01.
#[derive(Debug)]
pub struct DefaultAmount;

impl ChargeAmount for DefaultAmount {
    fn amount() -> &'static str {
        "0.01"
    }
}

// ==================== MppCharge extractor ====================

/// Axum extractor that gates a handler behind charge payment verification.
///
/// Uses the default charge amount of `$0.01`. For custom amounts, use
/// [`MppChargeFor`] with a [`ChargeAmount`] implementation.
///
/// # State Requirements
///
/// Requires `Arc<dyn ChargeChallenger>` in the router state, either directly or
/// via [`FromRef`](axum_core::extract::FromRef).
///
/// # Example
///
/// ```ignore
/// use axum::{routing::get, Router, Json};
/// use mpp::server::axum::{MppCharge, ChargeChallenger};
/// use mpp::server::{Mpp, tempo, TempoConfig};
/// use std::sync::Arc;
///
/// let mpp = Mpp::create(tempo(TempoConfig {
///     currency: "0x20c...",
///     recipient: "0xabc...",
/// })).unwrap();
///
/// async fn handler(charge: MppCharge) -> Json<serde_json::Value> {
///     Json(serde_json::json!({ "status": "paid", "ref": charge.receipt.reference }))
/// }
///
/// let app = Router::new()
///     .route("/premium", get(handler))
///     .with_state(Arc::new(mpp) as Arc<dyn ChargeChallenger>);
/// ```
pub type MppCharge = MppChargeFor<DefaultAmount>;

/// Axum extractor that gates a handler with a configurable charge amount.
///
/// The type parameter `A` determines the dollar amount via [`ChargeAmount`].
///
/// # Example
///
/// ```ignore
/// use mpp::server::axum::{ChargeAmount, MppChargeFor};
///
/// struct OneDollar;
/// impl ChargeAmount for OneDollar {
///     fn amount() -> &'static str { "1.00" }
/// }
///
/// async fn expensive(charge: MppChargeFor<OneDollar>) -> &'static str {
///     "premium content"
/// }
/// ```
#[derive(Debug)]
pub struct MppChargeFor<A: ChargeAmount> {
    /// The verified payment receipt.
    pub receipt: Receipt,
    _amount: std::marker::PhantomData<A>,
}

/// Rejection type for [`MppCharge`] and [`MppChargeFor`] extractors.
#[derive(Debug)]
#[non_exhaustive]
pub enum MppChargeRejection {
    /// No credential — return 402 with challenge.
    Challenge(PaymentRequired),
    /// Verification failed — return 402 with challenge for retry.
    VerificationFailed(PaymentRequired),
    /// Internal error generating challenge.
    InternalError(String),
}

impl IntoResponse for MppChargeRejection {
    fn into_response(self) -> axum_core::response::Response {
        match self {
            MppChargeRejection::Challenge(pr) => pr.into_response(),
            MppChargeRejection::VerificationFailed(pr) => {
                // Return 402 with challenge so the client can retry.
                pr.into_response()
            }
            MppChargeRejection::InternalError(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response()
            }
        }
    }
}

// ==================== ChargeChallenger ====================

/// Trait for generating payment challenges and verifying credentials.
///
/// Implemented automatically for `Mpp<TempoChargeMethod<P>, S>` when
/// the `tempo` feature is enabled. Can also be implemented manually
/// for custom payment methods.
///
/// The extractors require `Arc<dyn ChargeChallenger>` in router state.
pub trait ChargeChallenger: Send + Sync + 'static {
    /// Generate a charge challenge for the given dollar amount.
    fn challenge(&self, amount: &str) -> Result<PaymentChallenge, String>;

    /// Verify a credential string and return a receipt.
    fn verify_payment(
        &self,
        credential_str: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>>;
}

#[cfg(feature = "tempo")]
impl<P, S> ChargeChallenger for super::Mpp<super::TempoChargeMethod<P>, S>
where
    P: alloy::providers::Provider<tempo_alloy::TempoNetwork> + Clone + Send + Sync + 'static,
    S: Clone + Send + Sync + 'static,
{
    fn challenge(&self, amount: &str) -> Result<PaymentChallenge, String> {
        self.charge(amount).map_err(|e| e.to_string())
    }

    fn verify_payment(
        &self,
        credential_str: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>> {
        let credential = match parse_authorization(credential_str) {
            Ok(c) => c,
            Err(e) => {
                return Box::pin(std::future::ready(Err(format!(
                    "Invalid credential: {}",
                    e
                ))))
            }
        };
        let mpp = self.clone();
        Box::pin(async move {
            super::Mpp::verify_credential(&mpp, &credential)
                .await
                .map_err(|e| e.to_string())
        })
    }
}

impl<S, A> FromRequestParts<S> for MppChargeFor<A>
where
    Arc<dyn ChargeChallenger>: FromRef<S>,
    A: ChargeAmount,
    S: Send + Sync,
{
    type Rejection = MppChargeRejection;

    fn from_request_parts(
        parts: &mut http_types::request::Parts,
        state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let challenger: Arc<dyn ChargeChallenger> = FromRef::from_ref(state);
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(extract_payment_scheme)
            .map(|s| s.to_string());

        async move {
            let credential_str = match auth_header {
                Some(c) => c,
                None => {
                    let challenge = challenger
                        .challenge(A::amount())
                        .map_err(MppChargeRejection::InternalError)?;
                    return Err(MppChargeRejection::Challenge(PaymentRequired(challenge)));
                }
            };

            let receipt = match challenger.verify_payment(&credential_str).await {
                Ok(r) => r,
                Err(_) => {
                    let challenge = challenger
                        .challenge(A::amount())
                        .map_err(MppChargeRejection::InternalError)?;
                    return Err(MppChargeRejection::VerificationFailed(PaymentRequired(
                        challenge,
                    )));
                }
            };

            Ok(MppChargeFor {
                receipt,
                _amount: std::marker::PhantomData,
            })
        }
    }
}

// ==================== Receipt IntoResponse helper ====================

/// A successful response with a [`Receipt`] attached as a `Payment-Receipt` header.
///
/// Wraps an inner response and attaches the receipt header.
///
/// # Example
///
/// ```ignore
/// use mpp::server::axum::{MppCharge, WithReceipt};
/// use axum::Json;
///
/// async fn handler(charge: MppCharge) -> WithReceipt<Json<serde_json::Value>> {
///     WithReceipt {
///         receipt: charge.receipt,
///         body: Json(serde_json::json!({ "fortune": "good luck" })),
///     }
/// }
/// ```
pub struct WithReceipt<T> {
    /// The payment receipt to include in the response.
    pub receipt: Receipt,
    /// The inner response body.
    pub body: T,
}

impl<T: IntoResponse> IntoResponse for WithReceipt<T> {
    fn into_response(self) -> axum_core::response::Response {
        let mut resp = self.body.into_response();
        if let Ok(header_val) = format_receipt(&self.receipt) {
            if let Ok(val) = HeaderValue::from_str(&header_val) {
                resp.headers_mut().insert(PAYMENT_RECEIPT_HEADER, val);
            }
        }
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::Base64UrlJson;

    // ==================== Test helpers ====================

    fn test_challenge() -> PaymentChallenge {
        PaymentChallenge::new(
            "test-id",
            "test-realm",
            "tempo",
            "charge",
            Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap(),
        )
    }

    /// Mock [`ChargeChallenger`] for extractor tests.
    struct MockChallenger {
        accept: bool,
    }

    impl ChargeChallenger for MockChallenger {
        fn challenge(&self, amount: &str) -> Result<PaymentChallenge, String> {
            Ok(PaymentChallenge::new(
                "mock-id",
                "mock-realm",
                "tempo",
                "charge",
                Base64UrlJson::from_value(&serde_json::json!({"amount": amount})).unwrap(),
            ))
        }

        fn verify_payment(
            &self,
            _credential_str: &str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>>
        {
            let accept = self.accept;
            Box::pin(async move {
                if accept {
                    Ok(Receipt {
                        status: crate::protocol::core::ReceiptStatus::Success,
                        method: crate::protocol::core::MethodName::new("tempo"),
                        timestamp: "2025-01-01T00:00:00Z".into(),
                        reference: "0xabc".into(),
                    })
                } else {
                    Err("payment rejected".into())
                }
            })
        }
    }

    // ==================== PaymentRequired tests ====================

    #[test]
    fn test_payment_required_into_response() {
        let resp = PaymentRequired(test_challenge()).into_response();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(resp.headers().contains_key(WWW_AUTHENTICATE_HEADER));
    }

    #[test]
    fn test_payment_required_has_json_content_type() {
        let resp = PaymentRequired(test_challenge()).into_response();
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    // ==================== MppChargeRejection tests ====================

    #[test]
    fn test_rejection_challenge_returns_402_with_header() {
        let rejection = MppChargeRejection::Challenge(PaymentRequired(test_challenge()));
        let resp = rejection.into_response();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(resp.headers().contains_key(WWW_AUTHENTICATE_HEADER));
    }

    #[test]
    fn test_rejection_verification_failed_returns_402_with_header() {
        let rejection = MppChargeRejection::VerificationFailed(PaymentRequired(test_challenge()));
        let resp = rejection.into_response();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(resp.headers().contains_key(WWW_AUTHENTICATE_HEADER));
    }

    #[test]
    fn test_rejection_internal_error() {
        let rejection = MppChargeRejection::InternalError("oops".into());
        let resp = rejection.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ==================== ChargeAmount tests ====================

    #[test]
    fn test_default_amount() {
        assert_eq!(DefaultAmount::amount(), "0.01");
    }

    #[test]
    fn test_custom_amount() {
        struct FiveDollars;
        impl ChargeAmount for FiveDollars {
            fn amount() -> &'static str {
                "5.00"
            }
        }
        assert_eq!(FiveDollars::amount(), "5.00");
    }

    // ==================== WithReceipt tests ====================

    #[test]
    fn test_with_receipt_attaches_header() {
        use crate::protocol::core::{MethodName, ReceiptStatus};

        let receipt = Receipt {
            status: ReceiptStatus::Success,
            method: MethodName::new("tempo"),
            timestamp: "2025-01-01T00:00:00Z".into(),
            reference: "0xabc".into(),
        };

        let resp = WithReceipt {
            receipt,
            body: "ok",
        }
        .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key(PAYMENT_RECEIPT_HEADER));
    }

    // ==================== ChargeChallenger mock tests ====================

    #[test]
    fn test_mock_challenger_generates_challenge() {
        let challenger = MockChallenger { accept: true };
        let challenge = challenger.challenge("0.50").unwrap();
        assert_eq!(challenge.id, "mock-id");
    }

    #[tokio::test]
    async fn test_mock_challenger_verify_accept() {
        let challenger = MockChallenger { accept: true };
        let result = challenger.verify_payment("Payment eyJ...").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().reference, "0xabc");
    }

    #[tokio::test]
    async fn test_mock_challenger_verify_reject() {
        let challenger = MockChallenger { accept: false };
        let result = challenger.verify_payment("Payment eyJ...").await;
        assert!(result.is_err());
    }

    // ==================== FromRequestParts integration tests ====================

    /// Helper to run the extractor against a mock request.
    async fn run_extractor<A: ChargeAmount>(
        challenger: MockChallenger,
        auth_header: Option<&str>,
    ) -> Result<MppChargeFor<A>, MppChargeRejection> {
        let state: Arc<dyn ChargeChallenger> = Arc::new(challenger);
        let mut builder = http_types::Request::builder().uri("/test");
        if let Some(auth) = auth_header {
            builder = builder.header(header::AUTHORIZATION, auth);
        }
        let req = builder.body(()).unwrap();
        let (mut parts, _body) = req.into_parts();
        MppChargeFor::<A>::from_request_parts(&mut parts, &state).await
    }

    #[tokio::test]
    async fn test_extractor_no_auth_returns_challenge() {
        let result = run_extractor::<DefaultAmount>(MockChallenger { accept: true }, None).await;
        let err = result.unwrap_err();
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(resp.headers().contains_key(WWW_AUTHENTICATE_HEADER));
    }

    #[tokio::test]
    async fn test_extractor_valid_payment_returns_receipt() {
        let result = run_extractor::<DefaultAmount>(
            MockChallenger { accept: true },
            Some("Payment eyJmYWtlIjp0cnVlfQ"),
        )
        .await;
        let charge = result.unwrap();
        assert_eq!(charge.receipt.reference, "0xabc");
    }

    #[tokio::test]
    async fn test_extractor_invalid_payment_returns_challenge_for_retry() {
        let result = run_extractor::<DefaultAmount>(
            MockChallenger { accept: false },
            Some("Payment eyJmYWtlIjp0cnVlfQ"),
        )
        .await;
        let err = result.unwrap_err();
        assert!(matches!(err, MppChargeRejection::VerificationFailed(_)));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(resp.headers().contains_key(WWW_AUTHENTICATE_HEADER));
    }

    #[tokio::test]
    async fn test_extractor_wrong_scheme_returns_challenge() {
        let result = run_extractor::<DefaultAmount>(
            MockChallenger { accept: true },
            Some("Bearer some-token"),
        )
        .await;
        let err = result.unwrap_err();
        assert!(matches!(err, MppChargeRejection::Challenge(_)));
    }

    #[tokio::test]
    async fn test_extractor_custom_amount() {
        struct TenCents;
        impl ChargeAmount for TenCents {
            fn amount() -> &'static str {
                "0.10"
            }
        }

        // No auth → challenge should be generated (verifying custom amount type works)
        let result =
            run_extractor::<TenCents>(MockChallenger { accept: true }, None).await;
        assert!(result.is_err());
    }
}
