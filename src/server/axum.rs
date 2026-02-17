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
//! Define a [`ChargeConfig`] type for each price point and use
//! [`MppCharge<C>`] as the extractor:
//!
//! ```ignore
//! use mpp::server::axum::{ChargeConfig, MppCharge};
//!
//! struct OneCent;
//! impl ChargeConfig for OneCent {
//!     fn amount() -> &'static str { "0.01" }
//! }
//!
//! struct OneDollar;
//! impl ChargeConfig for OneDollar {
//!     fn amount() -> &'static str { "1.00" }
//!     fn description() -> Option<&'static str> { Some("Premium content") }
//! }
//!
//! async fn cheap(charge: MppCharge<OneCent>) -> &'static str {
//!     "basic content"
//! }
//!
//! async fn expensive(charge: MppCharge<OneDollar>) -> &'static str {
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
//! use mpp::server::axum::{MppCharge, ChargeConfig, ChargeChallenger};
//! use std::sync::Arc;
//!
//! struct OneCent;
//! impl ChargeConfig for OneCent {
//!     fn amount() -> &'static str { "0.01" }
//! }
//!
//! let mpp = Mpp::create(tempo(TempoConfig {
//!     recipient: "0xabc...",
//! })).unwrap();
//!
//! async fn handler(charge: MppCharge<OneCent>) -> Json<serde_json::Value> {
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

/// Per-route charge configuration.
///
/// Implement this on a marker type to define the amount and optional
/// description for a payment-gated route. Only [`amount()`](ChargeConfig::amount)
/// is required; [`description()`](ChargeConfig::description) defaults to `None`.
///
/// Server-level settings like `fee_payer` and `external_id` are configured
/// on the [`Mpp`](super::Mpp) instance, not per-route.
///
/// # Example
///
/// ```ignore
/// use mpp::server::axum::{ChargeConfig, MppCharge};
///
/// struct PremiumFortune;
/// impl ChargeConfig for PremiumFortune {
///     fn amount() -> &'static str { "1.00" }
///     fn description() -> Option<&'static str> { Some("Premium fortune reading") }
/// }
///
/// async fn handler(charge: MppCharge<PremiumFortune>) -> &'static str {
///     "paid content"
/// }
/// ```
pub trait ChargeConfig {
    /// The dollar amount to charge (e.g., `"0.01"`, `"1.00"`).
    fn amount() -> &'static str;

    /// Human-readable description included in the challenge.
    fn description() -> Option<&'static str> {
        None
    }
}

/// Options passed from a [`ChargeConfig`] to [`ChargeChallenger::challenge`].
#[derive(Debug, Default)]
pub struct ChallengeOptions {
    /// Human-readable description.
    pub description: Option<&'static str>,
}

/// Axum extractor that gates a handler behind payment verification.
///
/// The type parameter `C` determines the charge configuration via [`ChargeConfig`].
///
/// # State Requirements
///
/// Requires `Arc<dyn ChargeChallenger>` in the router state, either directly or
/// via [`FromRef`](axum_core::extract::FromRef).
///
/// # Example
///
/// ```ignore
/// use mpp::server::axum::{ChargeConfig, MppCharge, ChargeChallenger};
/// use mpp::server::{Mpp, tempo, TempoConfig};
/// use axum::{routing::get, Router, Json};
/// use std::sync::Arc;
///
/// struct OneCent;
/// impl ChargeConfig for OneCent {
///     fn amount() -> &'static str { "0.01" }
/// }
///
/// let mpp = Mpp::create(tempo(TempoConfig {
///     recipient: "0xabc...",
/// })).unwrap();
///
/// async fn handler(charge: MppCharge<OneCent>) -> Json<serde_json::Value> {
///     Json(serde_json::json!({ "status": "paid", "ref": charge.receipt.reference }))
/// }
///
/// let app = Router::new()
///     .route("/premium", get(handler))
///     .with_state(Arc::new(mpp) as Arc<dyn ChargeChallenger>);
/// ```
#[derive(Debug)]
pub struct MppCharge<C: ChargeConfig> {
    /// The verified payment receipt.
    pub receipt: Receipt,
    _config: std::marker::PhantomData<C>,
}

/// Rejection type for [`MppCharge`] extractors.
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
            MppChargeRejection::VerificationFailed(pr) => pr.into_response(),
            MppChargeRejection::InternalError(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response()
            }
        }
    }
}

/// Trait for generating payment challenges and verifying credentials.
///
/// Implemented automatically for `Mpp<TempoChargeMethod<P>, S>` when
/// the `tempo` feature is enabled. Can also be implemented manually
/// for custom payment methods.
///
/// The extractors require `Arc<dyn ChargeChallenger>` in router state.
pub trait ChargeChallenger: Send + Sync + 'static {
    /// Generate a charge challenge for the given dollar amount and options.
    fn challenge(
        &self,
        amount: &str,
        options: ChallengeOptions,
    ) -> Result<PaymentChallenge, String>;

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
    fn challenge(
        &self,
        amount: &str,
        options: ChallengeOptions,
    ) -> Result<PaymentChallenge, String> {
        self.charge_with_options(
            amount,
            super::ChargeOptions {
                description: options.description,
                ..Default::default()
            },
        )
        .map_err(|e| e.to_string())
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

impl<S, C> FromRequestParts<S> for MppCharge<C>
where
    Arc<dyn ChargeChallenger>: FromRef<S>,
    C: ChargeConfig,
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
            let options = ChallengeOptions {
                description: C::description(),
            };

            let credential_str = match auth_header {
                Some(c) => c,
                None => {
                    let challenge = challenger
                        .challenge(C::amount(), options)
                        .map_err(MppChargeRejection::InternalError)?;
                    return Err(MppChargeRejection::Challenge(PaymentRequired(challenge)));
                }
            };

            let receipt = match challenger.verify_payment(&credential_str).await {
                Ok(r) => r,
                Err(_) => {
                    let challenge = challenger
                        .challenge(C::amount(), options)
                        .map_err(MppChargeRejection::InternalError)?;
                    return Err(MppChargeRejection::VerificationFailed(PaymentRequired(
                        challenge,
                    )));
                }
            };

            Ok(MppCharge {
                receipt,
                _config: std::marker::PhantomData,
            })
        }
    }
}

/// A successful response with a [`Receipt`] attached as a `Payment-Receipt` header.
///
/// Wraps an inner response and attaches the receipt header.
///
/// # Example
///
/// ```ignore
/// use mpp::server::axum::{ChargeConfig, MppCharge, WithReceipt};
/// use axum::Json;
///
/// struct OneCent;
/// impl ChargeConfig for OneCent {
///     fn amount() -> &'static str { "0.01" }
/// }
///
/// async fn handler(charge: MppCharge<OneCent>) -> WithReceipt<Json<serde_json::Value>> {
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

    fn test_challenge() -> PaymentChallenge {
        PaymentChallenge::new(
            "test-id",
            "test-realm",
            "tempo",
            "charge",
            Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap(),
        )
    }

    struct MockChallenger {
        accept: bool,
    }

    impl ChargeChallenger for MockChallenger {
        fn challenge(
            &self,
            amount: &str,
            _options: ChallengeOptions,
        ) -> Result<PaymentChallenge, String> {
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

    #[derive(Debug)]
    struct OneCent;
    impl ChargeConfig for OneCent {
        fn amount() -> &'static str {
            "0.01"
        }
    }

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

    #[test]
    fn test_custom_amount() {
        struct FiveDollars;
        impl ChargeConfig for FiveDollars {
            fn amount() -> &'static str {
                "5.00"
            }
        }
        assert_eq!(FiveDollars::amount(), "5.00");
    }

    #[test]
    fn test_config_defaults() {
        assert_eq!(OneCent::description(), None);
    }

    #[test]
    fn test_config_overrides() {
        struct Premium;
        impl ChargeConfig for Premium {
            fn amount() -> &'static str {
                "10.00"
            }
            fn description() -> Option<&'static str> {
                Some("Premium access")
            }
        }
        assert_eq!(Premium::amount(), "10.00");
        assert_eq!(Premium::description(), Some("Premium access"));
    }

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

    #[test]
    fn test_mock_challenger_generates_challenge() {
        let challenger = MockChallenger { accept: true };
        let challenge = challenger
            .challenge("0.50", ChallengeOptions::default())
            .unwrap();
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

    async fn run_extractor<C: ChargeConfig>(
        challenger: MockChallenger,
        auth_header: Option<&str>,
    ) -> Result<MppCharge<C>, MppChargeRejection> {
        let state: Arc<dyn ChargeChallenger> = Arc::new(challenger);
        let mut builder = http_types::Request::builder().uri("/test");
        if let Some(auth) = auth_header {
            builder = builder.header(header::AUTHORIZATION, auth);
        }
        let req = builder.body(()).unwrap();
        let (mut parts, _body) = req.into_parts();
        MppCharge::<C>::from_request_parts(&mut parts, &state).await
    }

    #[tokio::test]
    async fn test_extractor_no_auth_returns_challenge() {
        let result = run_extractor::<OneCent>(MockChallenger { accept: true }, None).await;
        let err = result.unwrap_err();
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(resp.headers().contains_key(WWW_AUTHENTICATE_HEADER));
    }

    #[tokio::test]
    async fn test_extractor_valid_payment_returns_receipt() {
        let result = run_extractor::<OneCent>(
            MockChallenger { accept: true },
            Some("Payment eyJmYWtlIjp0cnVlfQ"),
        )
        .await;
        let charge = result.unwrap();
        assert_eq!(charge.receipt.reference, "0xabc");
    }

    #[tokio::test]
    async fn test_extractor_invalid_payment_returns_challenge_for_retry() {
        let result = run_extractor::<OneCent>(
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
        let result =
            run_extractor::<OneCent>(MockChallenger { accept: true }, Some("Bearer some-token"))
                .await;
        let err = result.unwrap_err();
        assert!(matches!(err, MppChargeRejection::Challenge(_)));
    }

    #[tokio::test]
    async fn test_extractor_custom_amount() {
        #[derive(Debug)]
        struct TenCents;
        impl ChargeConfig for TenCents {
            fn amount() -> &'static str {
                "0.10"
            }
        }

        let result = run_extractor::<TenCents>(MockChallenger { accept: true }, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_extractor_challenge_failure_returns_internal_error() {
        struct FailingChallenger;
        impl ChargeChallenger for FailingChallenger {
            fn challenge(
                &self,
                _amount: &str,
                _options: ChallengeOptions,
            ) -> Result<PaymentChallenge, String> {
                Err("config error".into())
            }
            fn verify_payment(
                &self,
                _credential_str: &str,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>>
            {
                Box::pin(std::future::ready(Err("unused".into())))
            }
        }

        let state: Arc<dyn ChargeChallenger> = Arc::new(FailingChallenger);
        let req = http_types::Request::builder()
            .uri("/test")
            .body(())
            .unwrap();
        let (mut parts, _body) = req.into_parts();
        let result = MppCharge::<OneCent>::from_request_parts(&mut parts, &state).await;
        let err = result.unwrap_err();
        assert!(matches!(err, MppChargeRejection::InternalError(_)));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_extractor_malformed_payment_credential_returns_verification_failed() {
        let result = run_extractor::<OneCent>(
            MockChallenger { accept: false },
            Some("Payment !!not-base64!!"),
        )
        .await;
        let err = result.unwrap_err();
        assert!(matches!(err, MppChargeRejection::VerificationFailed(_)));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    }
}
