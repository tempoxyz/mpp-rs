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
//! Also provides [`IntoResponse`]
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
//! (either directly or via [`FromRef`]):
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
/// via [`FromRef`].
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
                        external_id: None,
                        subscription_id: None,
                        extensions: serde_json::Map::new(),
                    })
                } else {
                    Err("payment rejected".into())
                }
            })
        }

        fn verify_payment_for_amount_and_scope(
            &self,
            credential_str: &str,
            amount: &str,
            _mppx_scope: Option<serde_json::Value>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>>
        {
            self.verify_payment_for_amount(credential_str, amount)
        }
    }

    struct BodyAwareChallenger {
        seen_challenge_body: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
        seen_verify_body: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    }

    impl ChargeChallenger for BodyAwareChallenger {
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

        fn challenge_with_body(
            &self,
            amount: &str,
            options: ChallengeOptions,
            body: &[u8],
        ) -> Result<PaymentChallenge, String> {
            *self.seen_challenge_body.lock().unwrap() = Some(body.to_vec());
            let mut challenge = self.challenge(amount, options)?;
            challenge.digest = Some(crate::body_digest::compute(body));
            Ok(challenge)
        }

        fn verify_payment(
            &self,
            _credential_str: &str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>>
        {
            Box::pin(std::future::ready(Err(
                "legacy verifier should not be called".into(),
            )))
        }

        fn verify_payment_for_amount_with_body(
            &self,
            _credential_str: &str,
            _amount: &str,
            body: &[u8],
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>>
        {
            *self.seen_verify_body.lock().unwrap() = Some(body.to_vec());
            Box::pin(std::future::ready(Ok(Receipt {
                status: crate::protocol::core::ReceiptStatus::Success,
                method: crate::protocol::core::MethodName::new("tempo"),
                timestamp: "2025-01-01T00:00:00Z".into(),
                reference: "0xbody-aware".into(),
                external_id: None,
                subscription_id: None,
                extensions: serde_json::Map::new(),
            })))
        }

        fn verify_payment_for_amount_scope_and_body(
            &self,
            credential_str: &str,
            amount: &str,
            _mppx_scope: Option<serde_json::Value>,
            body: &[u8],
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>>
        {
            self.verify_payment_for_amount_with_body(credential_str, amount, body)
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
        assert_eq!(
            resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    }

    #[test]
    fn test_unformattable_challenge_returns_500_without_challenge() {
        let mut challenge = test_challenge();
        challenge.realm = "a\nb".to_string();
        let resp = PaymentRequired(challenge).into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!resp.headers().contains_key(WWW_AUTHENTICATE_HEADER));
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/problem+json"
        );
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
        assert!(!resp.headers().contains_key(WWW_AUTHENTICATE_HEADER));
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/problem+json"
        );
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
            subscription_id: None,
            extensions: serde_json::Map::new(),
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
    fn test_with_receipt_does_not_attach_header_to_error_response() {
        use crate::protocol::core::{MethodName, ReceiptStatus};

        for status in [
            StatusCode::FOUND,
            StatusCode::FORBIDDEN,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            let receipt = Receipt {
                status: ReceiptStatus::Success,
                method: MethodName::new("tempo"),
                timestamp: "2025-01-01T00:00:00Z".into(),
                reference: "0xabc".into(),
                external_id: None,
                subscription_id: None,
                extensions: serde_json::Map::new(),
            };
            let resp = WithReceipt {
                receipt,
                body: (status, "error"),
            }
            .into_response();

            assert_eq!(resp.status(), status);
            assert!(!resp.headers().contains_key(PAYMENT_RECEIPT_HEADER));
            assert!(!resp.headers().contains_key(header::CACHE_CONTROL));
        }
    }

    #[test]
    fn test_with_receipt_preserves_existing_cache_control() {
        use crate::protocol::core::{MethodName, ReceiptStatus};

        let receipt = Receipt {
            status: ReceiptStatus::Success,
            method: MethodName::new("tempo"),
            timestamp: "2025-01-01T00:00:00Z".into(),
            reference: "0xabc".into(),
            external_id: None,
            subscription_id: None,
            extensions: serde_json::Map::new(),
        };
        let mut body = "ok".into_response();
        body.headers_mut()
            .append(header::CACHE_CONTROL, HeaderValue::from_static("public"));
        body.headers_mut().append(
            header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=60"),
        );

        let resp = WithReceipt { receipt, body }.into_response();

        assert!(resp.headers().contains_key(PAYMENT_RECEIPT_HEADER));
        assert_eq!(
            resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "public, max-age=60, private"
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
        run_extractor_with_uri::<C>(challenger, auth_header, "/test").await
    }

    async fn run_extractor_with_uri<C: ChargeConfig>(
        challenger: impl ChargeChallenger,
        auth_header: Option<&str>,
        uri: &str,
    ) -> Result<MppCharge<C>, MppChargeRejection> {
        let state: Arc<dyn ChargeChallenger> = Arc::new(challenger);
        let mut builder = http_types::Request::builder().uri(uri);
        if let Some(auth) = auth_header {
            builder = builder.header(header::AUTHORIZATION, auth);
        }
        let req = builder.body(()).unwrap();
        let (mut parts, _body) = req.into_parts();
        MppCharge::<C>::from_request_parts(&mut parts, &state).await
    }

    #[tokio::test]
    async fn test_extractor_binds_axum_matched_route_scope() {
        use axum::routing::get;
        use tower::ServiceExt;

        #[derive(Clone)]
        struct ScopeCaptureChallenger {
            seen_scope: Arc<std::sync::Mutex<Option<serde_json::Value>>>,
        }

        impl ChargeChallenger for ScopeCaptureChallenger {
            fn challenge(
                &self,
                amount: &str,
                options: ChallengeOptions,
            ) -> Result<PaymentChallenge, String> {
                *self.seen_scope.lock().unwrap() = options.mppx_scope;
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
                Box::pin(std::future::ready(Err("unused".into())))
            }
        }

        async fn paid(_charge: MppCharge<OneCent>) -> &'static str {
            "paid"
        }

        let seen_scope = Arc::new(std::sync::Mutex::new(None));
        let state: Arc<dyn ChargeChallenger> = Arc::new(ScopeCaptureChallenger {
            seen_scope: seen_scope.clone(),
        });
        let app = axum::Router::new()
            .route("/paid/{id}", get(paid))
            .with_state(state);

        let response = app
            .oneshot(
                http_types::Request::builder()
                    .uri("/paid/one?view=full")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(
            seen_scope.lock().unwrap().as_ref(),
            Some(&serde_json::json!({
                "route": "/paid/{id}",
                "resource": "/paid/one",
                "query": "view=full",
            }))
        );
    }

    async fn run_body_extractor<C: ChargeConfig>(
        challenger: impl ChargeChallenger,
        auth_header: Option<&str>,
        body: &'static str,
    ) -> Result<MppChargeWithBody<C>, MppChargeRejection> {
        let state: Arc<dyn ChargeChallenger> = Arc::new(challenger);
        let mut builder = Request::builder().uri("/test");
        if let Some(auth) = auth_header {
            builder = builder.header(header::AUTHORIZATION, auth);
        }
        let req = builder.body(axum_core::body::Body::from(body)).unwrap();
        MppChargeWithBody::<C>::from_request(req, &state).await
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
    async fn test_extractor_fails_closed_when_challenger_does_not_verify_scope() {
        struct LegacyChallenger;

        impl ChargeChallenger for LegacyChallenger {
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
                Box::pin(std::future::ready(Ok(Receipt {
                    status: crate::protocol::core::ReceiptStatus::Success,
                    method: crate::protocol::core::MethodName::new("tempo"),
                    timestamp: "2025-01-01T00:00:00Z".into(),
                    reference: "0xlegacy".into(),
                    external_id: None,
                    subscription_id: None,
                    extensions: serde_json::Map::new(),
                })))
            }
        }

        let result =
            run_extractor::<OneCent>(LegacyChallenger, Some("Payment eyJmYWtlIjp0cnVlfQ")).await;

        let err = result.unwrap_err();
        assert!(matches!(err, MppChargeRejection::Problem(_)));
    }

    #[tokio::test]
    async fn test_extractor_invalid_payment_returns_challenge_for_retry() {
        let result = run_extractor::<OneCent>(
            MockChallenger { accept: false },
            Some("Payment eyJmYWtlIjp0cnVlfQ"),
        )
        .await;
        let err = result.unwrap_err();
        assert!(matches!(err, MppChargeRejection::Problem(_)));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(resp.headers().contains_key(WWW_AUTHENTICATE_HEADER));
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
        assert!(matches!(err, MppChargeRejection::Problem(_)));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    }

    #[tokio::test]
    async fn test_body_extractor_challenge_binds_request_body() {
        let seen_challenge_body = Arc::new(std::sync::Mutex::new(None));
        let seen_verify_body = Arc::new(std::sync::Mutex::new(None));
        let result = run_body_extractor::<OneCent>(
            BodyAwareChallenger {
                seen_challenge_body: seen_challenge_body.clone(),
                seen_verify_body,
            },
            None,
            r#"{"query":"paid"}"#,
        )
        .await;

        let err = result.unwrap_err();
        let challenge = match err {
            MppChargeRejection::Challenge(PaymentRequired(challenge)) => challenge,
            other => panic!("expected challenge rejection, got {other:?}"),
        };
        assert_eq!(
            challenge.digest.as_deref(),
            Some(crate::body_digest::compute(br#"{"query":"paid"}"#).as_str())
        );
        assert_eq!(
            seen_challenge_body.lock().unwrap().as_deref(),
            Some(br#"{"query":"paid"}"#.as_slice())
        );
    }

    #[tokio::test]
    async fn test_body_extractor_verifies_and_preserves_request_body() {
        let seen_challenge_body = Arc::new(std::sync::Mutex::new(None));
        let seen_verify_body = Arc::new(std::sync::Mutex::new(None));
        let result = run_body_extractor::<OneCent>(
            BodyAwareChallenger {
                seen_challenge_body,
                seen_verify_body: seen_verify_body.clone(),
            },
            Some("Payment eyJmYWtlIjp0cnVlfQ"),
            r#"{"query":"paid"}"#,
        )
        .await;

        let charge = result.unwrap();
        assert_eq!(charge.receipt.reference, "0xbody-aware");
        assert_eq!(charge.body.as_ref(), br#"{"query":"paid"}"#);
        assert_eq!(
            seen_verify_body.lock().unwrap().as_deref(),
            Some(br#"{"query":"paid"}"#.as_slice())
        );
    }

    async fn post_to_body_extractor(body: axum_core::body::Body) -> StatusCode {
        use axum::routing::post;
        use tower::ServiceExt;

        async fn paid(_charge: MppChargeWithBody<OneCent>) {}

        let state: Arc<dyn ChargeChallenger> = Arc::new(MockChallenger { accept: true });
        let app = axum::Router::new()
            .route("/paid", post(paid))
            .layer(axum_core::extract::DefaultBodyLimit::max(1024))
            .with_state(state);

        let req = Request::builder()
            .method("POST")
            .uri("/paid")
            .body(body)
            .unwrap();
        app.oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn test_body_extractor_respects_default_body_limit() {
        use futures_util::StreamExt;

        let chunks = futures_util::stream::iter(0..).map(|i| {
            assert!(i < 4, "body read past the limit");
            Ok::<_, std::convert::Infallible>(Bytes::from_static(&[0; 512]))
        });
        let status = post_to_body_extractor(axum_core::body::Body::from_stream(chunks)).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_body_extractor_body_read_error_returns_400() {
        let chunks = futures_util::stream::iter([Err::<Bytes, _>(std::io::Error::other("reset"))]);
        let status = post_to_body_extractor(axum_core::body::Body::from_stream(chunks)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
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
                Box::pin(std::future::ready(Err(
                    "legacy verifier should not be called".into(),
                )))
            }

            fn verify_payment_for_amount(
                &self,
                _credential_str: &str,
                amount: &str,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>>
            {
                *self.seen_amount.lock().unwrap() = Some(amount.to_string());
                Box::pin(std::future::ready(Ok(Receipt {
                    status: crate::protocol::core::ReceiptStatus::Success,
                    method: crate::protocol::core::MethodName::new("tempo"),
                    timestamp: "2025-01-01T00:00:00Z".into(),
                    reference: "0xroute-aware".into(),
                    external_id: None,
                    subscription_id: None,
                    extensions: serde_json::Map::new(),
                })))
            }

            fn verify_payment_for_amount_and_scope(
                &self,
                credential_str: &str,
                amount: &str,
                _mppx_scope: Option<serde_json::Value>,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>>
            {
                self.verify_payment_for_amount(credential_str, amount)
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
                        "test-secret-key-at-least-32-bytes",
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
            ) -> Result<PaymentChallenge, String> {
                self.mpp
                    .charge_with_options(
                        amount,
                        crate::server::ChargeOptions {
                            description: options.description,
                            mppx_scope: options.mppx_scope.as_ref(),
                            ..Default::default()
                        },
                    )
                    .map(|mut offers| offers.remove(0))
                    .map_err(|e| e.to_string())
            }

            fn verify_payment(
                &self,
                credential_str: &str,
            ) -> std::pin::Pin<Box<dyn Future<Output = Result<Receipt, String>> + Send>>
            {
                let credential = match parse_authorization(credential_str) {
                    Ok(c) => c,
                    Err(e) => return Box::pin(std::future::ready(Err(e.to_string()))),
                };
                let mpp = self.mpp.clone();
                Box::pin(async move {
                    mpp.broadcast_credential(&credential)
                        .await
                        .map_err(|e| e.to_string())
                })
            }

            fn verify_payment_for_amount(
                &self,
                credential_str: &str,
                amount: &str,
            ) -> std::pin::Pin<Box<dyn Future<Output = Result<Receipt, String>> + Send>>
            {
                let credential = match parse_authorization(credential_str) {
                    Ok(c) => c,
                    Err(e) => return Box::pin(std::future::ready(Err(e.to_string()))),
                };
                let expected = match self
                    .mpp
                    .charge(amount)
                    .map(|mut offers| offers.remove(0))
                    .and_then(|c| c.request.decode())
                {
                    Ok(req) => req,
                    Err(e) => return Box::pin(std::future::ready(Err(e.to_string()))),
                };
                let mpp = self.mpp.clone();
                Box::pin(async move {
                    mpp.verify_credential_with_expected_request(&credential, &expected)
                        .await
                        .map_err(|e| e.to_string())
                })
            }

            fn verify_payment_for_amount_and_scope(
                &self,
                credential_str: &str,
                amount: &str,
                mppx_scope: Option<serde_json::Value>,
            ) -> std::pin::Pin<Box<dyn Future<Output = Result<Receipt, String>> + Send>>
            {
                let credential = match parse_authorization(credential_str) {
                    Ok(c) => c,
                    Err(e) => return Box::pin(std::future::ready(Err(e.to_string()))),
                };
                let expected = match self
                    .mpp
                    .charge_with_options(
                        amount,
                        crate::server::ChargeOptions {
                            mppx_scope: mppx_scope.as_ref(),
                            ..Default::default()
                        },
                    )
                    .map(|mut offers| offers.remove(0))
                    .and_then(|c| c.request.decode())
                {
                    Ok(req) => req,
                    Err(e) => return Box::pin(std::future::ready(Err(e.to_string()))),
                };
                let mpp = self.mpp.clone();
                Box::pin(async move {
                    mpp.verify_credential_with_expected_request(&credential, &expected)
                        .await
                        .map_err(|e| e.to_string())
                })
            }
        }

        // Mint an `Authorization: Payment …` string for the given route amount.
        fn scope_for_uri(uri: &str) -> serde_json::Value {
            let req = http_types::Request::builder().uri(uri).body(()).unwrap();
            let (parts, _body) = req.into_parts();
            mppx_scope_from_parts(&parts).unwrap()
        }

        fn mint_credential(challenger: &RealBindingChallenger, amount: &str) -> String {
            mint_scoped_credential(challenger, amount, "/test")
        }

        fn mint_scoped_credential(
            challenger: &RealBindingChallenger,
            amount: &str,
            uri: &str,
        ) -> String {
            let challenge = challenger
                .challenge(
                    amount,
                    ChallengeOptions {
                        mppx_scope: Some(scope_for_uri(uri)),
                        ..Default::default()
                    },
                )
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
            assert!(matches!(err, MppChargeRejection::Problem(_)));
            assert_eq!(err.into_response().status(), StatusCode::PAYMENT_REQUIRED);
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
            assert!(matches!(err, MppChargeRejection::Problem(_)));
        }

        #[tokio::test]
        async fn test_extractor_rejects_cross_resource_credential_replay() {
            let challenger = RealBindingChallenger::new();
            let auth =
                mint_scoped_credential(&challenger, OneCent::amount(), "/paid/one?view=full");

            let err =
                run_extractor_with_uri::<OneCent>(challenger, Some(&auth), "/paid/two?view=full")
                    .await
                    .expect_err("same-price cross-resource replay must be rejected");
            assert!(matches!(err, MppChargeRejection::Problem(_)));
            assert_eq!(err.into_response().status(), StatusCode::PAYMENT_REQUIRED);
        }
    }

    #[cfg(feature = "tempo")]
    mod currency_offers {
        use super::*;
        use crate::protocol::core::headers::{format_authorization, parse_www_authenticate_all};
        use crate::protocol::core::{PaymentCredential, PaymentPayload};
        use crate::protocol::intents::ChargeRequest;
        use crate::protocol::methods::tempo::{CHAIN_ID, OUSD, PATH_USD, USDC};
        use crate::protocol::traits::VerificationError;
        use crate::server::{tempo, ChargeMethod, Mpp, TempoConfig};
        use std::future::Future;

        const RECIPIENT: &str = "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2";

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

        /// RPC-free challenger mirroring the Tempo `ChargeChallenger` binding.
        #[derive(Clone)]
        struct OffersChallenger {
            mpp: Mpp<SuccessMethod>,
        }

        impl OffersChallenger {
            fn new(currencies: &[&str]) -> Self {
                Self {
                    mpp: Mpp::new_with_config(
                        SuccessMethod,
                        "MPP Payment",
                        "test-secret-key-at-least-32-bytes",
                        "",
                        RECIPIENT,
                    )
                    .with_currencies(currencies.iter().map(|c| c.to_string()).collect()),
                }
            }

            fn options(options: &ChallengeOptions) -> crate::server::ChargeOptions<'_> {
                crate::server::ChargeOptions {
                    description: options.description,
                    mppx_scope: options.mppx_scope.as_ref(),
                    ..Default::default()
                }
            }
        }

        impl ChargeChallenger for OffersChallenger {
            fn challenge(
                &self,
                amount: &str,
                options: ChallengeOptions,
            ) -> Result<PaymentChallenge, String> {
                self.mpp
                    .charge_with_options(amount, Self::options(&options))
                    .map(|mut offers| offers.remove(0))
                    .map_err(|e| e.to_string())
            }

            fn verify_payment(
                &self,
                credential_str: &str,
            ) -> std::pin::Pin<Box<dyn Future<Output = Result<Receipt, String>> + Send>>
            {
                self.verify_payment_for_amount_and_scope(credential_str, "0.01", None)
            }

            fn verify_payment_for_amount_and_scope(
                &self,
                credential_str: &str,
                amount: &str,
                mppx_scope: Option<serde_json::Value>,
            ) -> std::pin::Pin<Box<dyn Future<Output = Result<Receipt, String>> + Send>>
            {
                let credential = match parse_authorization(credential_str) {
                    Ok(c) => c,
                    Err(e) => return Box::pin(std::future::ready(Err(e.to_string()))),
                };
                // Same as the Tempo binding: expected request from the preferred offer.
                let options = ChallengeOptions {
                    mppx_scope,
                    ..Default::default()
                };
                let expected = match self
                    .mpp
                    .charge_with_options(amount, Self::options(&options))
                    .map(|mut offers| offers.remove(0))
                    .and_then(|c| c.request.decode::<ChargeRequest>())
                {
                    Ok(req) => req,
                    Err(e) => return Box::pin(std::future::ready(Err(e.to_string()))),
                };
                let mpp = self.mpp.clone();
                Box::pin(async move {
                    mpp.verify_credential_with_expected_request(&credential, &expected)
                        .await
                        .map_err(|e| e.to_string())
                })
            }

            fn challenges(
                &self,
                amount: &str,
                options: ChallengeOptions,
            ) -> Result<Vec<PaymentChallenge>, String> {
                self.mpp
                    .charge_with_options(amount, Self::options(&options))
                    .map_err(|e| e.to_string())
            }
        }

        fn currencies_of(challenges: &[PaymentChallenge]) -> Vec<String> {
            challenges
                .iter()
                .map(|c| c.request.decode::<ChargeRequest>().unwrap().currency)
                .collect()
        }

        fn response_offers(rejection: MppChargeRejection) -> Vec<PaymentChallenge> {
            let resp = rejection.into_response();
            assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
            let values: Vec<&str> = resp
                .headers()
                .get_all(WWW_AUTHENTICATE_HEADER)
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect();
            let challenges: Vec<PaymentChallenge> = parse_www_authenticate_all(values.clone())
                .into_iter()
                .map(|r| r.unwrap())
                .collect();
            // One header per offer.
            assert_eq!(values.len(), challenges.len());
            challenges
        }

        fn scoped_auth(challenger: &OffersChallenger, currency: &str) -> String {
            let req = http_types::Request::builder()
                .uri("/test")
                .body(())
                .unwrap();
            let (parts, _body) = req.into_parts();
            let challenges = challenger
                .challenges(
                    OneCent::amount(),
                    ChallengeOptions {
                        mppx_scope: mppx_scope_from_parts(&parts),
                        ..Default::default()
                    },
                )
                .unwrap();
            let challenge = challenges
                .iter()
                .find(|c| c.request.decode::<ChargeRequest>().unwrap().currency == currency)
                .unwrap();
            let credential =
                PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xdeadbeef"));
            format_authorization(&credential).unwrap()
        }

        #[tokio::test]
        async fn test_extractor_returns_every_offer_in_order() {
            let err = run_extractor::<OneCent>(OffersChallenger::new(&[OUSD, USDC]), None)
                .await
                .unwrap_err();
            assert!(matches!(err, MppChargeRejection::Offers(_)));
            let offers = response_offers(err);
            assert_eq!(currencies_of(&offers), [OUSD, USDC]);
            assert!(offers
                .iter()
                .all(|c| c.verify("test-secret-key-at-least-32-bytes")));
        }

        #[tokio::test]
        async fn test_extractor_single_offer_keeps_challenge_variant() {
            let err = run_extractor::<OneCent>(OffersChallenger::new(&[PATH_USD]), None)
                .await
                .unwrap_err();
            let MppChargeRejection::Challenge(PaymentRequired(challenge)) = err else {
                panic!("single offer should use the Challenge variant: {err:?}");
            };
            assert_eq!(currencies_of(&[challenge]), [PATH_USD]);
        }

        #[tokio::test]
        async fn test_extractor_accepts_credential_for_each_offer() {
            let challenger = OffersChallenger::new(&[OUSD, USDC]);
            for currency in [OUSD, USDC] {
                let auth = scoped_auth(&challenger, currency);
                let charge = run_extractor::<OneCent>(challenger.clone(), Some(&auth))
                    .await
                    .unwrap_or_else(|err| panic!("{currency} credential rejected: {err:?}"));
                assert_eq!(charge.receipt.reference, "0xtxhash");
            }
        }

        #[tokio::test]
        async fn test_extractor_rejects_non_offered_currency_with_all_offers() {
            // Credential minted by a server that offered pathUSD, replayed against
            // a server (same secret/realm) that only accepts OUSD and USDC.e.
            let auth = scoped_auth(&OffersChallenger::new(&[PATH_USD]), PATH_USD);
            let err = run_extractor::<OneCent>(OffersChallenger::new(&[OUSD, USDC]), Some(&auth))
                .await
                .unwrap_err();
            assert!(matches!(err, MppChargeRejection::Problem(_)));
            assert_eq!(currencies_of(&response_offers(err)), [OUSD, USDC]);
        }

        #[tokio::test]
        async fn test_tempo_challenger_reports_typed_problems() {
            let mpp = Mpp::create(
                tempo(TempoConfig {
                    recipient: RECIPIENT,
                })
                .rpc_url("http://127.0.0.1:1")
                .chain_id(CHAIN_ID)
                .secret_key("test-secret-key-at-least-32-bytes"),
            )
            .unwrap();
            let unpaid = run_extractor::<OneCent>(mpp.clone(), None)
                .await
                .unwrap_err();
            let offer = response_offers(unpaid).remove(0);
            let authorization = |challenge: &PaymentChallenge| {
                let credential =
                    PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xdeadbeef"));
                format_authorization(&credential).unwrap()
            };
            let rejected = |rejection| match rejection {
                MppChargeRejection::Problem(rejected) => rejected,
                other => panic!("unexpected rejection: {other:?}"),
            };

            let mut forged = offer.clone();
            forged.id = "forged".to_string();
            let err = run_extractor::<OneCent>(mpp.clone(), Some(&authorization(&forged)))
                .await
                .unwrap_err();
            let problem = rejected(err);
            assert!(problem.problem.problem_type.ends_with("/invalid-challenge"));
            assert_eq!(currencies_of(&problem.offers), [OUSD, USDC]);

            // The chain ID lookup hits an unreachable RPC.
            let err = run_extractor::<OneCent>(mpp, Some(&authorization(&offer)))
                .await
                .unwrap_err();
            let problem = rejected(err);
            assert_eq!(problem.problem.status, 500);
            assert!(problem.offers.is_empty());
        }

        #[tokio::test]
        async fn test_tempo_challenger_offers_mainnet_defaults() {
            let mpp = Mpp::create(
                tempo(TempoConfig {
                    recipient: RECIPIENT,
                })
                .chain_id(CHAIN_ID)
                .secret_key("test-secret-key-at-least-32-bytes"),
            )
            .unwrap();
            let challenger: Arc<dyn ChargeChallenger> = Arc::new(mpp);

            let offers = challenger
                .challenges("0.01", ChallengeOptions::default())
                .unwrap();
            assert_eq!(currencies_of(&offers), [OUSD, USDC]);
            let single = challenger
                .challenge("0.01", ChallengeOptions::default())
                .unwrap();
            assert_eq!(currencies_of(&[single]), [OUSD]);

            let body_offers = challenger
                .challenges_with_body("0.01", ChallengeOptions::default(), b"{}")
                .unwrap();
            assert_eq!(currencies_of(&body_offers), [OUSD, USDC]);
            let digest = crate::body_digest::compute(b"{}");
            assert!(body_offers
                .iter()
                .all(|c| c.digest.as_deref() == Some(digest.as_str())));

            let err = run_extractor::<OneCent>(ArcChallenger(challenger.clone()), None)
                .await
                .unwrap_err();
            assert_eq!(currencies_of(&response_offers(err)), [OUSD, USDC]);

            let err = run_body_extractor::<OneCent>(ArcChallenger(challenger), None, "{}")
                .await
                .unwrap_err();
            assert!(matches!(err, MppChargeRejection::Offers(_)));
            let offers = response_offers(err);
            assert_eq!(currencies_of(&offers), [OUSD, USDC]);
            assert!(offers
                .iter()
                .all(|c| c.digest.as_deref() == Some(digest.as_str())));
        }

        #[test]
        fn test_payment_offers_response_headers() {
            let challenger = OffersChallenger::new(&[OUSD, USDC]);
            let offers = challenger
                .challenges("0.01", ChallengeOptions::default())
                .unwrap();
            let resp = PaymentOffers(offers).into_response();
            assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
            assert_eq!(
                resp.headers()
                    .get_all(WWW_AUTHENTICATE_HEADER)
                    .iter()
                    .count(),
                2
            );
            assert_eq!(
                resp.headers().get(header::CACHE_CONTROL).unwrap(),
                "no-store"
            );
            assert_eq!(
                resp.headers().get(header::CONTENT_TYPE).unwrap(),
                "application/json"
            );
        }

        /// Forwards to a shared challenger so tests can reuse one `Arc`.
        struct ArcChallenger(Arc<dyn ChargeChallenger>);

        impl ChargeChallenger for ArcChallenger {
            fn challenge(
                &self,
                amount: &str,
                options: ChallengeOptions,
            ) -> Result<PaymentChallenge, String> {
                self.0.challenge(amount, options)
            }

            fn verify_payment(
                &self,
                credential_str: &str,
            ) -> std::pin::Pin<Box<dyn Future<Output = Result<Receipt, String>> + Send>>
            {
                self.0.verify_payment(credential_str)
            }

            fn challenges(
                &self,
                amount: &str,
                options: ChallengeOptions,
            ) -> Result<Vec<PaymentChallenge>, String> {
                self.0.challenges(amount, options)
            }

            fn challenges_with_body(
                &self,
                amount: &str,
                options: ChallengeOptions,
                body: &[u8],
            ) -> Result<Vec<PaymentChallenge>, String> {
                self.0.challenges_with_body(amount, options, body)
            }
        }
    }
}
