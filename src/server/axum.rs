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

use crate::error::{MppError, PaymentError, PaymentErrorDetails};
#[cfg(any(feature = "stripe", feature = "tempo"))]
use crate::protocol::core::headers::parse_authorization;
use crate::protocol::core::headers::{
    extract_payment_scheme, format_receipt, format_www_authenticate, with_private_cache_control,
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
///     PaymentRequired::new(challenge)
/// }
/// ```
#[derive(Debug)]
pub struct PaymentRequired {
    /// The challenge to advertise in `WWW-Authenticate`.
    pub challenge: PaymentChallenge,
    /// The typed error that triggered this response, if any.
    ///
    /// When `Some`, the body is rendered as that error's RFC 9457 problem
    /// document; when `None` (a fresh challenge), `payment-required` is used.
    pub error: Option<MppError>,
}

impl PaymentRequired {
    /// Create a fresh-challenge response (no prior error → `payment-required`).
    pub fn new(challenge: PaymentChallenge) -> Self {
        Self {
            challenge,
            error: None,
        }
    }

    /// Create a re-challenge response carrying the error that caused it.
    pub fn with_error(challenge: PaymentChallenge, error: MppError) -> Self {
        Self {
            challenge,
            error: Some(error),
        }
    }
}

impl IntoResponse for PaymentRequired {
    fn into_response(self) -> axum_core::response::Response {
        match format_www_authenticate(&self.challenge) {
            Ok(www_auth) => {
                // RFC 9457 problem body: the specific error's type when present,
                // otherwise a generic `payment-required` challenge.
                let mut problem = match &self.error {
                    Some(err) => err.to_problem_details(Some(self.challenge.id.as_str())),
                    None => PaymentErrorDetails::payment_required(self.challenge.id.as_str()),
                };
                // This is always a 402 re-challenge; keep the problem `status` in
                // sync with the HTTP status (some errors otherwise carry 400/410).
                problem.status = 402;
                let body = serde_json::to_string(&problem)
                    .expect("PaymentErrorDetails serialization cannot fail");

                let mut resp = (StatusCode::PAYMENT_REQUIRED, body).into_response();
                resp.headers_mut().insert(
                    WWW_AUTHENTICATE_HEADER,
                    HeaderValue::from_str(&www_auth)
                        .unwrap_or_else(|_| HeaderValue::from_static("Payment")),
                );
                resp.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/problem+json"),
                );
                resp.headers_mut()
                    .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
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
    ) -> Result<PaymentChallenge, MppError>;

    /// Verify a credential string and return a receipt.
    ///
    /// Errors are returned as a typed [`MppError`] so the rejection can render
    /// the correct RFC 9457 problem `type` on the retry challenge.
    fn verify_payment(
        &self,
        credential_str: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, MppError>> + Send>>;

    /// Verify a credential string against the route's expected dollar amount.
    ///
    /// High-level integrations should prefer this method so verification can
    /// compare the echoed credential challenge against the route's expected
    /// charge request, rather than trusting the echoed request alone.
    fn verify_payment_for_amount(
        &self,
        credential_str: &str,
        _amount: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, MppError>> + Send>>
    {
        self.verify_payment(credential_str)
    }
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
    ) -> Result<PaymentChallenge, MppError> {
        self.charge_with_options(
            amount,
            super::ChargeOptions {
                description: options.description,
                ..Default::default()
            },
        )
    }

    fn verify_payment(
        &self,
        credential_str: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, MppError>> + Send>>
    {
        let credential = match parse_authorization(credential_str) {
            Ok(c) => c,
            Err(e) => {
                return Box::pin(std::future::ready(Err(MppError::MalformedCredential(
                    Some(e.to_string()),
                ))))
            }
        };
        let mpp = self.clone();
        Box::pin(async move {
            super::Mpp::verify_credential(&mpp, &credential)
                .await
                .map_err(MppError::from)
        })
    }

    fn verify_payment_for_amount(
        &self,
        credential_str: &str,
        amount: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, MppError>> + Send>>
    {
        let credential = match parse_authorization(credential_str) {
            Ok(c) => c,
            Err(e) => {
                return Box::pin(std::future::ready(Err(MppError::MalformedCredential(
                    Some(e.to_string()),
                ))))
            }
        };

        let expected_challenge = match self.charge(amount) {
            Ok(challenge) => challenge,
            Err(e) => return Box::pin(std::future::ready(Err(e))),
        };

        let expected_request = match expected_challenge.request.decode() {
            Ok(request) => request,
            Err(e) => {
                return Box::pin(std::future::ready(Err(MppError::InvalidConfig(format!(
                    "Failed to decode expected request: {}",
                    e
                )))))
            }
        };

        let mpp = self.clone();
        Box::pin(async move {
            super::Mpp::verify_credential_with_expected_request(
                &mpp,
                &credential,
                &expected_request,
            )
            .await
            .map_err(MppError::from)
        })
    }
}

#[cfg(feature = "stripe")]
impl<S> ChargeChallenger for super::Mpp<super::StripeChargeMethod, S>
where
    S: Clone + Send + Sync + 'static,
{
    fn challenge(
        &self,
        amount: &str,
        options: ChallengeOptions,
    ) -> Result<PaymentChallenge, MppError> {
        self.stripe_charge_with_options(
            amount,
            super::StripeChargeOptions {
                description: options.description,
                ..Default::default()
            },
        )
    }

    fn verify_payment(
        &self,
        credential_str: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, MppError>> + Send>>
    {
        let credential = match parse_authorization(credential_str) {
            Ok(c) => c,
            Err(e) => {
                return Box::pin(std::future::ready(Err(MppError::MalformedCredential(
                    Some(e.to_string()),
                ))))
            }
        };
        let mpp = self.clone();
        Box::pin(async move {
            super::Mpp::verify_credential(&mpp, &credential)
                .await
                .map_err(MppError::from)
        })
    }

    fn verify_payment_for_amount(
        &self,
        credential_str: &str,
        amount: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, MppError>> + Send>>
    {
        let credential = match parse_authorization(credential_str) {
            Ok(c) => c,
            Err(e) => {
                return Box::pin(std::future::ready(Err(MppError::MalformedCredential(
                    Some(e.to_string()),
                ))))
            }
        };

        let expected_challenge = match self.stripe_charge(amount) {
            Ok(challenge) => challenge,
            Err(e) => return Box::pin(std::future::ready(Err(e))),
        };

        let expected_request = match expected_challenge.request.decode() {
            Ok(request) => request,
            Err(e) => {
                return Box::pin(std::future::ready(Err(MppError::InvalidConfig(format!(
                    "Failed to decode expected request: {}",
                    e
                )))))
            }
        };

        let mpp = self.clone();
        Box::pin(async move {
            super::Mpp::verify_credential_with_expected_request(
                &mpp,
                &credential,
                &expected_request,
            )
            .await
            .map_err(MppError::from)
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
        // A non-UTF-8 Authorization header is a malformed credential, not an
        // absent one; preserve that so it re-challenges as `malformed-credential`.
        let auth_header: Result<Option<String>, MppError> =
            match parts.headers.get(header::AUTHORIZATION) {
                None => Ok(None),
                Some(v) => match v.to_str() {
                    Ok(s) => Ok(extract_payment_scheme(s).map(|s| s.to_string())),
                    Err(e) => Err(MppError::MalformedCredential(Some(format!(
                        "invalid header: {e}"
                    )))),
                },
            };

        async move {
            let options = ChallengeOptions {
                description: C::description(),
            };

            let credential_str = match auth_header {
                Ok(Some(c)) => c,
                Ok(None) => {
                    let challenge = challenger
                        .challenge(C::amount(), options)
                        .map_err(|e| MppChargeRejection::InternalError(e.to_string()))?;
                    return Err(MppChargeRejection::Challenge(PaymentRequired::new(
                        challenge,
                    )));
                }
                Err(err) => {
                    let challenge = challenger
                        .challenge(C::amount(), options)
                        .map_err(|e| MppChargeRejection::InternalError(e.to_string()))?;
                    return Err(MppChargeRejection::VerificationFailed(
                        PaymentRequired::with_error(challenge, err),
                    ));
                }
            };

            let receipt = match challenger
                .verify_payment_for_amount(&credential_str, C::amount())
                .await
            {
                Ok(r) => r,
                Err(err) => {
                    // Re-challenge, carrying the typed error so the response
                    // renders the correct RFC 9457 problem type.
                    let challenge = challenger
                        .challenge(C::amount(), options)
                        .map_err(|e| MppChargeRejection::InternalError(e.to_string()))?;
                    return Err(MppChargeRejection::VerificationFailed(
                        PaymentRequired::with_error(challenge, err),
                    ));
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

                // Receipt responses MUST be Cache-Control: private (spec §11.10).
                let existing_cc = resp
                    .headers()
                    .get_all(header::CACHE_CONTROL)
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .collect::<Vec<_>>()
                    .join(", ");
                let cache_control = with_private_cache_control(Some(existing_cc.as_str()));
                if let Ok(cc) = HeaderValue::from_str(&cache_control) {
                    resp.headers_mut().insert(header::CACHE_CONTROL, cc);
                }
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
        ) -> Result<PaymentChallenge, MppError> {
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
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, MppError>> + Send>>
        {
            let accept = self.accept;
            Box::pin(async move {
                if accept {
                    Ok(Receipt {
                        status: crate::protocol::core::ReceiptStatus::Success,
                        method: crate::protocol::core::MethodName::new("tempo"),
                        timestamp: "2025-01-01T00:00:00Z".into(),
                        reference: "0xabc".into(),
                        external_id: None,
                    })
                } else {
                    Err(MppError::VerificationFailed(Some(
                        "payment rejected".into(),
                    )))
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
        let resp = PaymentRequired::new(test_challenge()).into_response();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(resp.headers().contains_key(WWW_AUTHENTICATE_HEADER));
        assert_eq!(
            resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    }

    #[test]
    fn test_payment_required_has_problem_json_content_type() {
        let resp = PaymentRequired::new(test_challenge()).into_response();
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/problem+json"
        );
    }

    #[test]
    fn test_rejection_challenge_returns_402_with_header() {
        let rejection = MppChargeRejection::Challenge(PaymentRequired::new(test_challenge()));
        let resp = rejection.into_response();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(resp.headers().contains_key(WWW_AUTHENTICATE_HEADER));
    }

    #[test]
    fn test_rejection_verification_failed_renders_problem_type() {
        let rejection = MppChargeRejection::VerificationFailed(PaymentRequired::with_error(
            test_challenge(),
            MppError::PaymentExpired(Some("too late".into())),
        ));
        let resp = rejection.into_response();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(resp.headers().contains_key(WWW_AUTHENTICATE_HEADER));
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/problem+json"
        );
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
            external_id: None,
        };

        let resp = WithReceipt {
            receipt,
            body: "ok",
        }
        .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key(PAYMENT_RECEIPT_HEADER));
        // Per spec, receipt responses must be Cache-Control: private.
        assert_eq!(
            resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "private"
        );
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
        challenger: impl ChargeChallenger,
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
    async fn test_extractor_non_utf8_header_is_malformed_not_absent() {
        // A non-UTF-8 Authorization header must re-challenge as a malformed
        // credential, not be silently treated as "no credential".
        let state: Arc<dyn ChargeChallenger> = Arc::new(MockChallenger { accept: true });
        let req = http_types::Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, &[0xff, 0xfe][..])
            .body(())
            .unwrap();
        let (mut parts, _body) = req.into_parts();
        let result = MppCharge::<OneCent>::from_request_parts(&mut parts, &state).await;
        let err = result.unwrap_err();
        assert!(matches!(err, MppChargeRejection::VerificationFailed(_)));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/problem+json"
        );
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
            ) -> Result<PaymentChallenge, MppError> {
                Err(MppError::InvalidConfig("config error".into()))
            }
            fn verify_payment(
                &self,
                _credential_str: &str,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<Receipt, MppError>> + Send>,
            > {
                Box::pin(std::future::ready(Err(MppError::VerificationFailed(Some(
                    "unused".into(),
                )))))
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

    #[tokio::test]
    async fn test_extractor_uses_route_aware_verification_path() {
        struct RouteAwareChallenger {
            seen_amount: Arc<std::sync::Mutex<Option<String>>>,
        }

        impl ChargeChallenger for RouteAwareChallenger {
            fn challenge(
                &self,
                amount: &str,
                _options: ChallengeOptions,
            ) -> Result<PaymentChallenge, MppError> {
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
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<Receipt, MppError>> + Send>,
            > {
                Box::pin(std::future::ready(Err(MppError::VerificationFailed(Some(
                    "legacy verifier should not be called".into(),
                )))))
            }

            fn verify_payment_for_amount(
                &self,
                _credential_str: &str,
                amount: &str,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<Receipt, MppError>> + Send>,
            > {
                *self.seen_amount.lock().unwrap() = Some(amount.to_string());
                Box::pin(std::future::ready(Ok(Receipt {
                    status: crate::protocol::core::ReceiptStatus::Success,
                    method: crate::protocol::core::MethodName::new("tempo"),
                    timestamp: "2025-01-01T00:00:00Z".into(),
                    reference: "0xroute-aware".into(),
                    external_id: None,
                })))
            }
        }

        let seen_amount = Arc::new(std::sync::Mutex::new(None));
        let result = run_extractor::<OneCent>(
            RouteAwareChallenger {
                seen_amount: seen_amount.clone(),
            },
            Some("Payment eyJmYWtlIjp0cnVlfQ"),
        )
        .await;

        let charge = result.unwrap();
        assert_eq!(charge.receipt.reference, "0xroute-aware");
        assert_eq!(seen_amount.lock().unwrap().as_deref(), Some("0.01"));
    }

    // Framework route-replay conformance: exercise the real extractor
    // (`MppCharge<C>`) and per-route amount selection against the production
    // binding logic, matching the two-price axum-extractor example.
    #[cfg(feature = "tempo")]
    mod route_replay {
        use super::*;
        use crate::protocol::core::headers::format_authorization;
        use crate::protocol::core::{PaymentCredential, PaymentPayload};
        use crate::protocol::intents::ChargeRequest;
        use crate::protocol::traits::VerificationError;
        use crate::server::{ChargeMethod, Mpp};
        use std::future::Future;

        #[derive(Debug)]
        struct OneDollar;
        impl ChargeConfig for OneDollar {
            fn amount() -> &'static str {
                "1.00"
            }
        }

        // Chain-free charge method so verification never needs RPC.
        #[derive(Clone)]
        struct SuccessMethod;

        #[allow(clippy::manual_async_fn)]
        impl ChargeMethod for SuccessMethod {
            fn method(&self) -> &str {
                "tempo"
            }
            fn verify(
                &self,
                _credential: &PaymentCredential,
                _request: &ChargeRequest,
            ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send {
                async { Ok(Receipt::success("tempo", "0xtxhash")) }
            }
        }

        // Faithful challenger delegating to the production binding logic.
        #[derive(Clone)]
        struct RealBindingChallenger {
            mpp: Mpp<SuccessMethod>,
        }

        impl RealBindingChallenger {
            fn new() -> Self {
                Self {
                    mpp: Mpp::new_with_config(
                        SuccessMethod,
                        "MPP Payment",
                        "test-secret",
                        "0x20c0000000000000000000000000000000000000",
                        "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
                    ),
                }
            }
        }

        impl ChargeChallenger for RealBindingChallenger {
            fn challenge(
                &self,
                amount: &str,
                options: ChallengeOptions,
            ) -> Result<PaymentChallenge, MppError> {
                self.mpp.charge_with_options(
                    amount,
                    crate::server::ChargeOptions {
                        description: options.description,
                        ..Default::default()
                    },
                )
            }

            fn verify_payment(
                &self,
                credential_str: &str,
            ) -> std::pin::Pin<Box<dyn Future<Output = Result<Receipt, MppError>> + Send>>
            {
                let credential = match parse_authorization(credential_str) {
                    Ok(c) => c,
                    Err(e) => {
                        return Box::pin(std::future::ready(Err(MppError::MalformedCredential(
                            Some(e.to_string()),
                        ))))
                    }
                };
                let mpp = self.mpp.clone();
                Box::pin(async move {
                    mpp.verify_credential(&credential)
                        .await
                        .map_err(MppError::from)
                })
            }

            fn verify_payment_for_amount(
                &self,
                credential_str: &str,
                amount: &str,
            ) -> std::pin::Pin<Box<dyn Future<Output = Result<Receipt, MppError>> + Send>>
            {
                let credential = match parse_authorization(credential_str) {
                    Ok(c) => c,
                    Err(e) => {
                        return Box::pin(std::future::ready(Err(MppError::MalformedCredential(
                            Some(e.to_string()),
                        ))))
                    }
                };
                let expected = match self.mpp.charge(amount).and_then(|c| c.request.decode()) {
                    Ok(req) => req,
                    Err(e) => return Box::pin(std::future::ready(Err(e))),
                };
                let mpp = self.mpp.clone();
                Box::pin(async move {
                    mpp.verify_credential_with_expected_request(&credential, &expected)
                        .await
                        .map_err(MppError::from)
                })
            }
        }

        // Mint an `Authorization: Payment …` string for the given route amount.
        fn mint_credential(challenger: &RealBindingChallenger, amount: &str) -> String {
            let challenge = challenger
                .challenge(amount, ChallengeOptions::default())
                .unwrap();
            let credential =
                PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xdeadbeef"));
            format_authorization(&credential).unwrap()
        }

        #[tokio::test]
        async fn test_extractor_accepts_credential_on_matching_route() {
            let challenger = RealBindingChallenger::new();
            let auth = mint_credential(&challenger, OneCent::amount());

            let charge = run_extractor::<OneCent>(challenger, Some(&auth))
                .await
                .expect("credential minted for the route must verify");
            assert_eq!(charge.receipt.reference, "0xtxhash");
        }

        #[tokio::test]
        async fn test_extractor_rejects_cross_route_credential_replay() {
            let challenger = RealBindingChallenger::new();
            // Mint for the cheap route, replay on the expensive route.
            let auth = mint_credential(&challenger, OneCent::amount());

            let err = run_extractor::<OneDollar>(challenger, Some(&auth))
                .await
                .expect_err("cross-route replay must be rejected");
            assert!(matches!(err, MppChargeRejection::VerificationFailed(_)));

            // The rendered 402 body must be the specific `malformed-credential`
            // (binding check fails), not a generic `verification-failed`.
            let resp = err.into_response();
            assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
            assert_eq!(
                resp.headers().get(header::CONTENT_TYPE).unwrap(),
                "application/problem+json"
            );
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let problem: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                problem["type"],
                "https://paymentauth.org/problems/malformed-credential"
            );
            assert_eq!(problem["status"], 402);
        }

        #[tokio::test]
        async fn test_extractor_selects_per_route_amount() {
            let challenger = RealBindingChallenger::new();
            // A credential minted at $1.00 is accepted by the premium route...
            let auth = mint_credential(&challenger, OneDollar::amount());
            assert!(run_extractor::<OneDollar>(challenger.clone(), Some(&auth))
                .await
                .is_ok());
            // ...but rejected by the cheap route, proving the extractor passes
            // each route's own `ChargeConfig::amount()` to verification.
            let err = run_extractor::<OneCent>(challenger, Some(&auth))
                .await
                .expect_err("premium credential must not satisfy the cheap route");
            assert!(matches!(err, MppChargeRejection::VerificationFailed(_)));
        }
    }
}
