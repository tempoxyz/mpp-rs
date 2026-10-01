//! Axum extractors and response types for payment gating.
//!
//! Provides [`MppCharge`], an axum extractor that handles the full
//! 402 challenge/verify flow automatically:
//!
//! - No `Authorization: Payment` header → 402 with `WWW-Authenticate` challenge
//! - Rejected credential → RFC 9457 problem details, with a fresh challenge
//!   (402) unless the failure is the server's own (500)
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

use axum_core::extract::rejection::BytesRejection;
use axum_core::extract::{FromRef, FromRequest, FromRequestParts, Request};
use axum_core::response::IntoResponse;
use bytes::Bytes;
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
///     let challenge = mpp.charge("1.00").unwrap().remove(0);
///     PaymentRequired(challenge)
/// }
/// ```
#[derive(Debug)]
pub struct PaymentRequired(pub PaymentChallenge);

impl IntoResponse for PaymentRequired {
    fn into_response(self) -> axum_core::response::Response {
        PaymentOffers(vec![self.0]).into_response()
    }
}

/// A 402 Payment Required response carrying several equivalent offers.
///
/// Each [`PaymentChallenge`] is emitted as its own `WWW-Authenticate` header,
/// in order. Returned by the extractors when the [`ChargeChallenger`] offers
/// more than one challenge (for example, one per accepted currency).
#[derive(Debug)]
pub struct PaymentOffers(pub Vec<PaymentChallenge>);

impl IntoResponse for PaymentOffers {
    fn into_response(self) -> axum_core::response::Response {
        let Some(values) = challenge_header_values(&self.0) else {
            return internal_error_response();
        };
        let mut resp = (
            StatusCode::PAYMENT_REQUIRED,
            serde_json::json!({ "error": "Payment Required" }).to_string(),
        )
            .into_response();
        for value in values {
            resp.headers_mut().append(WWW_AUTHENTICATE_HEADER, value);
        }
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        resp.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        resp
    }
}

/// A rejected payment credential, answered with RFC 9457 problem details.
///
/// Payment problems (expired, invalid challenge, failed verification, …) are
/// answered with the problem's status and one fresh `WWW-Authenticate`
/// challenge per offer. A server-side failure is answered with `500` and no
/// challenge, so that clients do not pay again for a fault that is not theirs.
#[derive(Debug)]
pub struct PaymentProblem {
    /// Problem details sent as the `application/problem+json` body.
    pub problem: PaymentErrorDetails,
    /// Fresh challenges for retry. Not sent with a `5xx` problem.
    pub offers: Vec<PaymentChallenge>,
}

impl PaymentProblem {
    /// Build the response for `error`, retryable with `offers`.
    ///
    /// The problem references the first offer's challenge id.
    pub fn new(error: &impl PaymentError, offers: Vec<PaymentChallenge>) -> Self {
        let problem = error.to_problem_details(offers.first().map(|offer| offer.id.as_str()));
        Self { problem, offers }
    }
}

impl IntoResponse for PaymentProblem {
    fn into_response(self) -> axum_core::response::Response {
        let status =
            StatusCode::from_u16(self.problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let values = if status.is_server_error() {
            Vec::new()
        } else {
            match challenge_header_values(&self.offers) {
                Some(values) => values,
                None => return internal_error_response(),
            }
        };
        let Ok(body) = serde_json::to_string(&self.problem) else {
            return internal_error_response();
        };
        let mut resp = (status, body).into_response();
        for value in values {
            resp.headers_mut().append(WWW_AUTHENTICATE_HEADER, value);
        }
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        resp.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        resp
    }
}

/// Format each challenge as a `WWW-Authenticate` header value, or `None` if
/// one of them cannot be sent.
fn challenge_header_values(challenges: &[PaymentChallenge]) -> Option<Vec<HeaderValue>> {
    challenges
        .iter()
        .map(|challenge| {
            let value = format_www_authenticate(challenge).ok()?;
            HeaderValue::from_str(&value).ok()
        })
        .collect()
}

/// `500` with the `internal-payment-error` problem and no challenge.
fn internal_error_response() -> axum_core::response::Response {
    PaymentProblem::new(&MppError::Internal(String::new()), Vec::new()).into_response()
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
#[derive(Debug, Default, Clone)]
pub struct ChallengeOptions {
    /// Human-readable description.
    pub description: Option<&'static str>,
    /// Framework adapter route/resource/query scope.
    pub mppx_scope: Option<serde_json::Value>,
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

/// Axum extractor that gates a handler behind body-bound payment verification.
///
/// This extractor consumes the request body, binds issued challenges to the
/// body digest, verifies submitted credentials against the same bytes, and
/// exposes the preserved bytes to the handler.
///
/// The body is buffered before any payment is made, so its size is capped by
/// axum's `DefaultBodyLimit` (2 MiB unless configured otherwise). Larger
/// bodies are rejected with `413 Payload Too Large`.
#[derive(Debug)]
pub struct MppChargeWithBody<C: ChargeConfig> {
    /// The verified payment receipt.
    pub receipt: Receipt,
    /// The request body bytes that were bound to the challenge digest.
    pub body: Bytes,
    _config: std::marker::PhantomData<C>,
}

/// Rejection type for [`MppCharge`] extractors.
#[derive(Debug)]
#[non_exhaustive]
pub enum MppChargeRejection {
    /// No credential — return 402 with challenge.
    Challenge(PaymentRequired),
    /// Verification failed — return 402 with challenge for retry.
    ///
    /// No longer returned by the extractors, which report a rejected
    /// credential as [`Problem`](Self::Problem).
    VerificationFailed(PaymentRequired),
    /// Internal error generating challenge — return 500 without a challenge.
    InternalError(String),
    /// No credential — return 402 with several offers (one header each).
    Offers(PaymentOffers),
    /// Verification failed — return 402 with several offers for retry.
    ///
    /// No longer returned by the extractors, which report a rejected
    /// credential as [`Problem`](Self::Problem).
    VerificationFailedOffers(PaymentOffers),
    /// The request body could not be buffered — 413 if it exceeds the body
    /// limit, 400 if reading it failed.
    Body(BytesRejection),
    /// The credential was rejected — return its problem details, with fresh
    /// challenges for retry unless the failure is the server's own.
    Problem(PaymentProblem),
}

impl MppChargeRejection {
    /// Build a 402 rejection from the challenger's offers.
    ///
    /// A single offer keeps the [`Challenge`](Self::Challenge) variant;
    /// several offers use [`Offers`](Self::Offers).
    fn from_offers(mut offers: Vec<PaymentChallenge>) -> Self {
        match offers.len() {
            0 => Self::InternalError("No payment challenges generated".into()),
            1 => Self::Challenge(PaymentRequired(offers.remove(0))),
            _ => Self::Offers(PaymentOffers(offers)),
        }
    }

    /// Build the rejection for a credential that failed with `error`.
    ///
    /// `offers` generates the fresh challenges; it is only called for payment
    /// problems, since a server-side failure is not answered with a challenge.
    fn from_error(
        error: MppError,
        offers: impl FnOnce() -> Result<Vec<PaymentChallenge>, String>,
    ) -> Self {
        if !error.is_payment_problem() {
            return Self::Problem(PaymentProblem::new(&error, Vec::new()));
        }
        match offers() {
            Ok(offers) if offers.is_empty() => {
                Self::InternalError("No payment challenges generated".into())
            }
            Ok(offers) => Self::Problem(PaymentProblem::new(&error, offers)),
            Err(e) => Self::InternalError(e),
        }
    }
}

impl IntoResponse for MppChargeRejection {
    fn into_response(self) -> axum_core::response::Response {
        match self {
            MppChargeRejection::Challenge(pr) => pr.into_response(),
            MppChargeRejection::VerificationFailed(pr) => pr.into_response(),
            MppChargeRejection::InternalError(_) => internal_error_response(),
            MppChargeRejection::Offers(offers) => offers.into_response(),
            MppChargeRejection::VerificationFailedOffers(offers) => offers.into_response(),
            MppChargeRejection::Body(rejection) => rejection.into_response(),
            MppChargeRejection::Problem(problem) => problem.into_response(),
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

    /// Generate a charge challenge bound to the actual request body bytes.
    fn challenge_with_body(
        &self,
        amount: &str,
        options: ChallengeOptions,
        body: &[u8],
    ) -> Result<PaymentChallenge, String> {
        let _ = body;
        self.challenge(amount, options)
    }

    /// Verify a credential string and return a receipt.
    fn verify_payment(
        &self,
        credential_str: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>>;

    /// Verify a credential string against the route's expected dollar amount.
    ///
    /// High-level integrations should prefer this method so verification can
    /// compare the echoed credential challenge against the route's expected
    /// charge request, rather than trusting the echoed request alone.
    fn verify_payment_for_amount(
        &self,
        credential_str: &str,
        _amount: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>> {
        self.verify_payment(credential_str)
    }

    /// Verify a credential string against route amount and framework scope.
    fn verify_payment_for_amount_and_scope(
        &self,
        credential_str: &str,
        amount: &str,
        mppx_scope: Option<serde_json::Value>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>> {
        if mppx_scope.is_some() {
            let _ = credential_str;
            let _ = amount;
            return Box::pin(std::future::ready(Err(
                "framework scope verification is not implemented for this ChargeChallenger".into(),
            )));
        }
        self.verify_payment_for_amount(credential_str, amount)
    }

    /// Verify a credential string against route amount and actual request body bytes.
    fn verify_payment_for_amount_with_body(
        &self,
        credential_str: &str,
        amount: &str,
        body: &[u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>> {
        let _ = body;
        self.verify_payment_for_amount(credential_str, amount)
    }

    /// Verify a credential string against route amount, framework scope, and request body bytes.
    fn verify_payment_for_amount_scope_and_body(
        &self,
        credential_str: &str,
        amount: &str,
        mppx_scope: Option<serde_json::Value>,
        body: &[u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>> {
        if mppx_scope.is_some() {
            let _ = credential_str;
            let _ = amount;
            let _ = body;
            return Box::pin(std::future::ready(Err(
                "framework scope verification is not implemented for this ChargeChallenger".into(),
            )));
        }
        self.verify_payment_for_amount_with_body(credential_str, amount, body)
    }

    /// Verify a credential string against route amount, framework scope and,
    /// for body-bound routes, the request body, keeping the failure typed.
    ///
    /// The extractors call this method and answer a failure with its problem
    /// details: a payment problem gets a fresh challenge, a server-side
    /// failure a `500` without one. The default delegates to the
    /// string-returning methods and reports every failure as
    /// `verification-failed`.
    fn verify_payment_for_route(
        &self,
        credential_str: &str,
        amount: &str,
        mppx_scope: Option<serde_json::Value>,
        body: Option<&[u8]>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, MppError>> + Send>>
    {
        let verified = match body {
            Some(body) => self.verify_payment_for_amount_scope_and_body(
                credential_str,
                amount,
                mppx_scope,
                body,
            ),
            None => self.verify_payment_for_amount_and_scope(credential_str, amount, mppx_scope),
        };
        Box::pin(async move { verified.await.map_err(MppError::verification_failed) })
    }

    /// HTTP field containing the Payment credential.
    ///
    /// Defaults to `Authorization`. Servers created with `requires_auth`
    /// return `Payment-Authorization`.
    fn credential_header(&self) -> &str {
        header::AUTHORIZATION.as_str()
    }

    /// Generate every equivalent charge challenge, in preference order.
    ///
    /// The extractors return all of them in the 402 response. Defaults to the
    /// single [`challenge`](Self::challenge). Tempo servers return one
    /// challenge per accepted currency.
    fn challenges(
        &self,
        amount: &str,
        options: ChallengeOptions,
    ) -> Result<Vec<PaymentChallenge>, String> {
        self.challenge(amount, options)
            .map(|challenge| vec![challenge])
    }

    /// Generate every equivalent body-bound charge challenge, in preference order.
    ///
    /// Defaults to the single [`challenge_with_body`](Self::challenge_with_body).
    fn challenges_with_body(
        &self,
        amount: &str,
        options: ChallengeOptions,
        body: &[u8],
    ) -> Result<Vec<PaymentChallenge>, String> {
        self.challenge_with_body(amount, options, body)
            .map(|challenge| vec![challenge])
    }
}

/// Verify a credential string against the route's expected challenge.
#[cfg(any(feature = "stripe", feature = "tempo"))]
fn verify_expected<M, S>(
    mpp: &super::Mpp<M, S>,
    credential_str: &str,
    expected: crate::error::Result<PaymentChallenge>,
    body: Option<&[u8]>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, MppError>> + Send>>
where
    M: crate::protocol::traits::ChargeMethod + Clone + Send + Sync + 'static,
    S: Clone + Send + Sync + 'static,
{
    let prepared = parse_authorization(credential_str).and_then(|credential| {
        let expected_request = expected?.request.decode()?;
        Ok((credential, expected_request))
    });
    let mpp = mpp.clone();
    let body = body.map(<[u8]>::to_vec);
    Box::pin(async move {
        let (credential, expected_request) = prepared?;
        let receipt = match &body {
            Some(body) => {
                mpp.verify_credential_with_expected_request_and_body(
                    &credential,
                    &expected_request,
                    body,
                )
                .await
            }
            None => {
                mpp.verify_credential_with_expected_request(&credential, &expected_request)
                    .await
            }
        };
        Ok(receipt?)
    })
}

/// Adapt a typed verification future to the string-returning trait methods.
#[cfg(any(feature = "stripe", feature = "tempo"))]
fn stringify_error(
    verified: std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Receipt, MppError>> + Send>,
    >,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>> {
    Box::pin(async move { verified.await.map_err(|e| e.to_string()) })
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
                mppx_scope: options.mppx_scope.as_ref(),
                ..Default::default()
            },
        )
        .map(|mut offers| offers.remove(0))
        .map_err(|e| e.to_string())
    }

    fn challenge_with_body(
        &self,
        amount: &str,
        options: ChallengeOptions,
        body: &[u8],
    ) -> Result<PaymentChallenge, String> {
        self.charge_with_options_and_body(
            amount,
            super::ChargeOptions {
                description: options.description,
                mppx_scope: options.mppx_scope.as_ref(),
                ..Default::default()
            },
            body,
        )
        .map(|mut offers| offers.remove(0))
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
            super::Mpp::broadcast_credential(&mpp, &credential)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn verify_payment_for_amount(
        &self,
        credential_str: &str,
        amount: &str,
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

        let expected_challenge = match self.charge(amount).map(|mut offers| offers.remove(0)) {
            Ok(challenge) => challenge,
            Err(e) => {
                return Box::pin(std::future::ready(Err(format!(
                    "Failed to generate expected challenge: {}",
                    e
                ))))
            }
        };

        let expected_request = match expected_challenge.request.decode() {
            Ok(request) => request,
            Err(e) => {
                return Box::pin(std::future::ready(Err(format!(
                    "Failed to decode expected request: {}",
                    e
                ))))
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
            .map_err(|e| e.to_string())
        })
    }

    fn verify_payment_for_amount_and_scope(
        &self,
        credential_str: &str,
        amount: &str,
        mppx_scope: Option<serde_json::Value>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>> {
        stringify_error(self.verify_payment_for_route(credential_str, amount, mppx_scope, None))
    }

    fn verify_payment_for_amount_with_body(
        &self,
        credential_str: &str,
        amount: &str,
        body: &[u8],
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

        let expected_challenge = match self.charge(amount).map(|mut offers| offers.remove(0)) {
            Ok(challenge) => challenge,
            Err(e) => {
                return Box::pin(std::future::ready(Err(format!(
                    "Failed to generate expected challenge: {}",
                    e
                ))))
            }
        };

        let expected_request = match expected_challenge.request.decode() {
            Ok(request) => request,
            Err(e) => {
                return Box::pin(std::future::ready(Err(format!(
                    "Failed to decode expected request: {}",
                    e
                ))))
            }
        };

        let mpp = self.clone();
        let body = body.to_vec();
        Box::pin(async move {
            super::Mpp::verify_credential_with_expected_request_and_body(
                &mpp,
                &credential,
                &expected_request,
                &body,
            )
            .await
            .map_err(|e| e.to_string())
        })
    }

    fn verify_payment_for_amount_scope_and_body(
        &self,
        credential_str: &str,
        amount: &str,
        mppx_scope: Option<serde_json::Value>,
        body: &[u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>> {
        stringify_error(self.verify_payment_for_route(
            credential_str,
            amount,
            mppx_scope,
            Some(body),
        ))
    }

    fn verify_payment_for_route(
        &self,
        credential_str: &str,
        amount: &str,
        mppx_scope: Option<serde_json::Value>,
        body: Option<&[u8]>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, MppError>> + Send>>
    {
        let expected = self
            .charge_with_options(
                amount,
                super::ChargeOptions {
                    mppx_scope: mppx_scope.as_ref(),
                    ..Default::default()
                },
            )
            .map(|mut offers| offers.remove(0));
        verify_expected(self, credential_str, expected, body)
    }

    fn credential_header(&self) -> &str {
        super::Mpp::credential_header(self)
    }

    fn challenges(
        &self,
        amount: &str,
        options: ChallengeOptions,
    ) -> Result<Vec<PaymentChallenge>, String> {
        self.charge_with_options(
            amount,
            super::ChargeOptions {
                description: options.description,
                mppx_scope: options.mppx_scope.as_ref(),
                ..Default::default()
            },
        )
        .map_err(|e| e.to_string())
    }

    fn challenges_with_body(
        &self,
        amount: &str,
        options: ChallengeOptions,
        body: &[u8],
    ) -> Result<Vec<PaymentChallenge>, String> {
        self.charge_with_options_and_body(
            amount,
            super::ChargeOptions {
                description: options.description,
                mppx_scope: options.mppx_scope.as_ref(),
                ..Default::default()
            },
            body,
        )
        .map_err(|e| e.to_string())
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
    ) -> Result<PaymentChallenge, String> {
        self.stripe_charge_with_options(
            amount,
            super::StripeChargeOptions {
                description: options.description,
                mppx_scope: options.mppx_scope.as_ref(),
                ..Default::default()
            },
        )
        .map_err(|e| e.to_string())
    }

    fn challenge_with_body(
        &self,
        amount: &str,
        options: ChallengeOptions,
        body: &[u8],
    ) -> Result<PaymentChallenge, String> {
        self.stripe_charge_with_options_and_body(
            amount,
            super::StripeChargeOptions {
                description: options.description,
                mppx_scope: options.mppx_scope.as_ref(),
                ..Default::default()
            },
            body,
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
            super::Mpp::broadcast_credential(&mpp, &credential)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn verify_payment_for_amount(
        &self,
        credential_str: &str,
        amount: &str,
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

        let expected_challenge = match self.stripe_charge(amount) {
            Ok(challenge) => challenge,
            Err(e) => {
                return Box::pin(std::future::ready(Err(format!(
                    "Failed to generate expected challenge: {}",
                    e
                ))))
            }
        };

        let expected_request = match expected_challenge.request.decode() {
            Ok(request) => request,
            Err(e) => {
                return Box::pin(std::future::ready(Err(format!(
                    "Failed to decode expected request: {}",
                    e
                ))))
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
            .map_err(|e| e.to_string())
        })
    }

    fn verify_payment_for_amount_and_scope(
        &self,
        credential_str: &str,
        amount: &str,
        mppx_scope: Option<serde_json::Value>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>> {
        stringify_error(self.verify_payment_for_route(credential_str, amount, mppx_scope, None))
    }

    fn verify_payment_for_amount_with_body(
        &self,
        credential_str: &str,
        amount: &str,
        body: &[u8],
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

        let expected_challenge = match self.stripe_charge(amount) {
            Ok(challenge) => challenge,
            Err(e) => {
                return Box::pin(std::future::ready(Err(format!(
                    "Failed to generate expected challenge: {}",
                    e
                ))))
            }
        };

        let expected_request = match expected_challenge.request.decode() {
            Ok(request) => request,
            Err(e) => {
                return Box::pin(std::future::ready(Err(format!(
                    "Failed to decode expected request: {}",
                    e
                ))))
            }
        };

        let mpp = self.clone();
        let body = body.to_vec();
        Box::pin(async move {
            super::Mpp::verify_credential_with_expected_request_and_body(
                &mpp,
                &credential,
                &expected_request,
                &body,
            )
            .await
            .map_err(|e| e.to_string())
        })
    }

    fn verify_payment_for_amount_scope_and_body(
        &self,
        credential_str: &str,
        amount: &str,
        mppx_scope: Option<serde_json::Value>,
        body: &[u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>> {
        stringify_error(self.verify_payment_for_route(
            credential_str,
            amount,
            mppx_scope,
            Some(body),
        ))
    }

    fn verify_payment_for_route(
        &self,
        credential_str: &str,
        amount: &str,
        mppx_scope: Option<serde_json::Value>,
        body: Option<&[u8]>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, MppError>> + Send>>
    {
        let expected = self.stripe_charge_with_options(
            amount,
            super::StripeChargeOptions {
                mppx_scope: mppx_scope.as_ref(),
                ..Default::default()
            },
        );
        verify_expected(self, credential_str, expected, body)
    }

    fn credential_header(&self) -> &str {
        super::Mpp::credential_header(self)
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
        let mppx_scope = mppx_scope_from_parts(parts);
        let auth_header = parts
            .headers
            .get(challenger.credential_header())
            .and_then(|v| v.to_str().ok())
            .and_then(extract_payment_scheme)
            .map(|s| s.to_string());

        async move {
            let options = ChallengeOptions {
                description: C::description(),
                mppx_scope: mppx_scope.clone(),
            };

            let credential_str = match auth_header {
                Some(c) => c,
                None => {
                    let offers = challenger
                        .challenges(C::amount(), options)
                        .map_err(MppChargeRejection::InternalError)?;
                    return Err(MppChargeRejection::from_offers(offers));
                }
            };

            let receipt = match challenger
                .verify_payment_for_route(&credential_str, C::amount(), mppx_scope, None)
                .await
            {
                Ok(r) => r,
                Err(error) => {
                    return Err(MppChargeRejection::from_error(error, || {
                        challenger.challenges(C::amount(), options)
                    }));
                }
            };

            Ok(MppCharge {
                receipt,
                _config: std::marker::PhantomData,
            })
        }
    }
}

impl<S, C> FromRequest<S> for MppChargeWithBody<C>
where
    Arc<dyn ChargeChallenger>: FromRef<S>,
    C: ChargeConfig,
    S: Send + Sync,
{
    type Rejection = MppChargeRejection;

    fn from_request(
        req: Request,
        state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let challenger: Arc<dyn ChargeChallenger> = FromRef::from_ref(state);
        let (parts, body) = req.into_parts();
        let mppx_scope = mppx_scope_from_parts(&parts);
        let auth_header = parts
            .headers
            .get(challenger.credential_header())
            .and_then(|v| v.to_str().ok())
            .and_then(extract_payment_scheme)
            .map(|s| s.to_string());
        let req = Request::from_parts(parts, body);

        async move {
            // Buffer through axum's `Bytes` extractor so `DefaultBodyLimit` applies.
            let body = Bytes::from_request(req, state)
                .await
                .map_err(MppChargeRejection::Body)?;
            let options = ChallengeOptions {
                description: C::description(),
                mppx_scope: mppx_scope.clone(),
            };

            let credential_str = match auth_header {
                Some(c) => c,
                None => {
                    let offers = challenger
                        .challenges_with_body(C::amount(), options, &body)
                        .map_err(MppChargeRejection::InternalError)?;
                    return Err(MppChargeRejection::from_offers(offers));
                }
            };

            let receipt = match challenger
                .verify_payment_for_route(&credential_str, C::amount(), mppx_scope, Some(&body))
                .await
            {
                Ok(r) => r,
                Err(error) => {
                    return Err(MppChargeRejection::from_error(error, || {
                        challenger.challenges_with_body(C::amount(), options, &body)
                    }));
                }
            };

            Ok(MppChargeWithBody {
                receipt,
                body,
                _config: std::marker::PhantomData,
            })
        }
    }
}

fn mppx_scope_from_parts(parts: &http_types::request::Parts) -> Option<serde_json::Value> {
    let mut scope = serde_json::Map::new();
    let path = parts.uri.path();
    let route = parts
        .extensions
        .get::<::axum::extract::MatchedPath>()
        .map(|matched| matched.as_str())
        .unwrap_or(path);
    if !route.is_empty() {
        scope.insert("route".into(), serde_json::Value::String(route.to_string()));
    }
    if !path.is_empty() {
        scope.insert(
            "resource".into(),
            serde_json::Value::String(path.to_string()),
        );
    }
    if let Some(query) = parts.uri.query() {
        if !query.is_empty() {
            scope.insert("query".into(), serde_json::Value::String(query.to_string()));
        }
    }
    if scope.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(scope))
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
        if !resp.status().is_success() {
            return resp;
        }
        let Ok(header_val) = format_receipt(&self.receipt) else {
            return resp;
        };
        let Ok(val) = HeaderValue::from_str(&header_val) else {
            return resp;
        };
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
        resp
    }
}

#[cfg(test)]
#[allow(clippy::result_large_err)]
mod tests;
