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
use crate::protocol::core::headers::parse_authorization;
use crate::protocol::core::headers::{
    format_receipt, format_www_authenticate, with_private_cache_control, PAYMENT_RECEIPT_HEADER,
    WWW_AUTHENTICATE_HEADER,
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
        let description = self.0.first().and_then(|offer| offer.description.clone());
        let error = MppError::PaymentRequired {
            realm: None,
            description,
        };
        PaymentProblem::new(&error, self.0).into_response()
    }
}

/// A rejected payment credential, answered with RFC 9457 problem details.
///
/// Payment problems (expired, invalid challenge, failed verification, …) are
/// answered with the problem's status and one fresh `WWW-Authenticate`
/// challenge per offer. A server-side failure (`5xx`), a final `403` or a
/// `bad-request` (more than one credential) is answered without a
/// challenge, so that clients do not pay again when paying would not help.
#[derive(Debug)]
pub struct PaymentProblem {
    /// Problem details sent as the `application/problem+json` body.
    pub problem: PaymentErrorDetails,
    /// Fresh challenges for retry. Not sent with a `5xx`, `403` or `bad-request` problem.
    pub offers: Vec<PaymentChallenge>,
}

impl PaymentProblem {
    /// Build the response for `error`, retryable with `offers`.
    ///
    /// The problem references the first offer's challenge id. A problem
    /// answered without a challenge (`5xx`, `403` or `bad-request`) drops the offers and
    /// references none.
    pub fn new(error: &impl PaymentError, offers: Vec<PaymentChallenge>) -> Self {
        let problem = error.to_problem_details(None);
        if !sends_challenges(&problem) {
            return Self {
                problem,
                offers: Vec::new(),
            };
        }
        let problem = error.to_problem_details(offers.first().map(|offer| offer.id.as_str()));
        Self { problem, offers }
    }
}

/// Whether a problem with `status` is answered with fresh challenges: a
/// server-side failure, a final `403` or a `bad-request` (more than one
/// credential, which the core spec answers without a challenge) is not.
fn sends_challenges(problem: &PaymentErrorDetails) -> bool {
    let status = StatusCode::from_u16(problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    !(status.is_server_error()
        || status == StatusCode::FORBIDDEN
        || problem.problem_type.ends_with("/bad-request"))
}

impl IntoResponse for PaymentProblem {
    fn into_response(self) -> axum_core::response::Response {
        let status =
            StatusCode::from_u16(self.problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let values = if !sends_challenges(&self.problem) {
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
    /// Hostname of the current HTTP request, used for an unconfigured realm.
    pub request_realm: Option<String>,
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
    /// Verified identities, when the route carries a
    /// [`RouteIdentity`](crate::identity::RouteIdentity) extension; empty otherwise.
    #[cfg(feature = "identity")]
    pub identity: crate::identity::IdentityResults,
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
    /// Verified identities, when the route carries a
    /// [`RouteIdentity`](crate::identity::RouteIdentity) extension; empty otherwise.
    #[cfg(feature = "identity")]
    pub identity: crate::identity::IdentityResults,
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
    /// The route's identity was rejected — return the rejection as is: its
    /// status code, headers and reason, never a 402.
    #[cfg(feature = "identity")]
    Identity(crate::identity::IdentityRejection),
    /// A 402 of a route with an identity payment check: the inner rejection,
    /// with this `Identity-Required` header when it answers 402.
    #[cfg(feature = "identity")]
    IdentityRequired(Box<MppChargeRejection>, HeaderValue),
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
    /// problems a new payment can resolve, since a server-side failure, a
    /// `403` or a `bad-request` is not answered with a challenge.
    fn from_error(
        error: MppError,
        offers: impl FnOnce() -> Result<Vec<PaymentChallenge>, String>,
    ) -> Self {
        if !error.is_payment_problem() || !sends_challenges(&error.to_problem_details(None)) {
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
            MppChargeRejection::VerificationFailed(pr) => {
                PaymentProblem::new(&MppError::VerificationFailed(None), vec![pr.0]).into_response()
            }
            MppChargeRejection::InternalError(_) => internal_error_response(),
            MppChargeRejection::Offers(offers) => offers.into_response(),
            MppChargeRejection::VerificationFailedOffers(offers) => {
                PaymentProblem::new(&MppError::VerificationFailed(None), offers.0).into_response()
            }
            MppChargeRejection::Body(rejection) => rejection.into_response(),
            MppChargeRejection::Problem(problem) => problem.into_response(),
            #[cfg(feature = "identity")]
            MppChargeRejection::Identity(rejection) => {
                let (parts, body) = rejection.into_response().into_parts();
                axum_core::response::Response::from_parts(parts, body.into())
            }
            #[cfg(feature = "identity")]
            MppChargeRejection::IdentityRequired(inner, required) => {
                let mut response = inner.into_response();
                if response.status() == StatusCode::PAYMENT_REQUIRED {
                    response
                        .headers_mut()
                        .insert(crate::identity::requirements::HEADER, required);
                }
                response
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
    ///
    /// With a scope, the default re-issues this route's challenge with
    /// [`challenge`](Self::challenge) and rejects a credential whose echoed
    /// challenge does not carry the route's scope in `_mppx_scope` or whose
    /// method, intent or pinned request fields (amount, currency, recipient
    /// and method details, as in mppx) differ from it, so a credential issued for
    /// another route, amount or HTTP method is rejected, as mppx's
    /// `verifyCredential` does. It then delegates to
    /// [`verify_payment_for_amount`](Self::verify_payment_for_amount), which
    /// must authenticate the echoed challenge (e.g. its HMAC `id`): that is
    /// what binds the echoed request to a challenge the server issued.
    /// Override this method if `challenge` output is not deterministic for a
    /// given amount and scope.
    fn verify_payment_for_amount_and_scope(
        &self,
        credential_str: &str,
        amount: &str,
        mppx_scope: Option<serde_json::Value>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>> {
        if let Some(scope) = mppx_scope {
            let expected = self.challenge(amount, scoped_challenge_options(&scope));
            if let Err(e) = check_route_binding(credential_str, &scope, expected) {
                return Box::pin(std::future::ready(Err(e)));
            }
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
    ///
    /// The default checks the credential against this route's challenge as
    /// [`verify_payment_for_amount_and_scope`](Self::verify_payment_for_amount_and_scope)
    /// does, re-issuing it with
    /// [`challenge_with_body`](Self::challenge_with_body) so its body
    /// `digest` must match too, then delegates to
    /// [`verify_payment_for_amount_with_body`](Self::verify_payment_for_amount_with_body).
    fn verify_payment_for_amount_scope_and_body(
        &self,
        credential_str: &str,
        amount: &str,
        mppx_scope: Option<serde_json::Value>,
        body: &[u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>> {
        if let Some(scope) = mppx_scope {
            let expected = self.challenge_with_body(amount, scoped_challenge_options(&scope), body);
            if let Err(e) = check_route_binding(credential_str, &scope, expected) {
                return Box::pin(std::future::ready(Err(e)));
            }
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

    /// Verify with the hostname of the HTTP request as the default realm.
    fn verify_payment_for_route_with_realm(
        &self,
        credential_str: &str,
        amount: &str,
        mppx_scope: Option<serde_json::Value>,
        body: Option<&[u8]>,
        _request_realm: Option<&str>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, MppError>> + Send>>
    {
        self.verify_payment_for_route(credential_str, amount, mppx_scope, body)
    }

    /// Verify a credential for a route with an identity payment check,
    /// settling it only if `gate` admits it. Returns `Ok(None)` when the
    /// gate refuses; the extractors then answer with the identity rejection.
    ///
    /// The built-in Tempo and Stripe challengers run the gate after the
    /// credential's HMAC, expiry and pinned fields are checked and before it
    /// settles, as mppx does. The default runs it on the parsed credential
    /// before polling the future of
    /// [`verify_payment_for_route_with_realm`](Self::verify_payment_for_route_with_realm),
    /// which it creates first, so that method must not settle until polled.
    /// A custom challenger should override this to check provenance first.
    #[cfg(feature = "identity")]
    fn verify_payment_for_route_with_identity(
        &self,
        credential_str: &str,
        amount: &str,
        mppx_scope: Option<serde_json::Value>,
        body: Option<&[u8]>,
        request_realm: Option<&str>,
        gate: crate::identity::PaymentGate,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Option<Receipt>, MppError>> + Send>,
    > {
        // The verification future is created here but polled only after the
        // gate admits the Credential: implementations must settle when polled,
        // not in the method body, as the built-in Tempo and Stripe ones do
        // (they override this method and admit first).
        let credential = parse_authorization(credential_str);
        let verified = self.verify_payment_for_route_with_realm(
            credential_str,
            amount,
            mppx_scope,
            body,
            request_realm,
        );
        Box::pin(async move {
            let credential = credential?;
            if !gate.admit(&credential).await {
                return Ok(None);
            }
            verified.await.map(Some)
        })
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

/// Verify a credential string against the route's expected charge request.
#[cfg(any(feature = "stripe", feature = "tempo"))]
fn verify_expected<M, S>(
    mpp: &super::Mpp<M, S>,
    credential_str: &str,
    expected: crate::error::Result<crate::protocol::intents::ChargeRequest>,
    body: Option<&[u8]>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, MppError>> + Send>>
where
    M: crate::protocol::traits::ChargeMethod + Clone + Send + Sync + 'static,
    S: Clone + Send + Sync + 'static,
{
    let verified = verify_expected_gated(mpp, credential_str, expected, body, None);
    Box::pin(async move {
        verified
            .await?
            .ok_or_else(|| MppError::Internal("credential refused before settlement".to_owned()))
    })
}

/// Verify a credential string against the route's expected charge request,
/// settling it only if `gate` admits it. `None` when the gate refuses.
#[cfg(any(feature = "stripe", feature = "tempo"))]
#[allow(clippy::type_complexity)]
fn verify_expected_gated<M, S>(
    mpp: &super::Mpp<M, S>,
    credential_str: &str,
    expected: crate::error::Result<crate::protocol::intents::ChargeRequest>,
    body: Option<&[u8]>,
    gate: Option<Arc<dyn super::CredentialGate>>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<Receipt>, MppError>> + Send>>
where
    M: crate::protocol::traits::ChargeMethod + Clone + Send + Sync + 'static,
    S: Clone + Send + Sync + 'static,
{
    let prepared =
        parse_authorization(credential_str).and_then(|credential| Ok((credential, expected?)));
    let mpp = mpp.clone();
    let body = body.map(<[u8]>::to_vec);
    Box::pin(async move {
        let (credential, expected_request) = prepared?;
        let receipt = mpp
            .verify_credential_with_expected_request_gated(
                &credential,
                &expected_request,
                body.as_deref(),
                gate.as_deref(),
            )
            .await;
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
        self.for_request_realm(options.request_realm.as_deref())
            .charge_with_options(
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
        self.for_request_realm(options.request_realm.as_deref())
            .charge_with_options_and_body(
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

        let expected_request = match self.expected_charge_request(amount, Default::default()) {
            Ok(request) => request,
            Err(e) => {
                return Box::pin(std::future::ready(Err(format!(
                    "Failed to generate expected request: {}",
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

        let expected_request = match self.expected_charge_request(amount, Default::default()) {
            Ok(request) => request,
            Err(e) => {
                return Box::pin(std::future::ready(Err(format!(
                    "Failed to generate expected request: {}",
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
        self.verify_payment_for_route_with_realm(credential_str, amount, mppx_scope, body, None)
    }

    fn verify_payment_for_route_with_realm(
        &self,
        credential_str: &str,
        amount: &str,
        mppx_scope: Option<serde_json::Value>,
        body: Option<&[u8]>,
        request_realm: Option<&str>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, MppError>> + Send>>
    {
        let mpp = self.for_request_realm(request_realm);
        let expected = mpp.expected_charge_request(
            amount,
            super::ChargeOptions {
                mppx_scope: mppx_scope.as_ref(),
                ..Default::default()
            },
        );
        verify_expected(&mpp, credential_str, expected, body)
    }

    #[cfg(feature = "identity")]
    fn verify_payment_for_route_with_identity(
        &self,
        credential_str: &str,
        amount: &str,
        mppx_scope: Option<serde_json::Value>,
        body: Option<&[u8]>,
        request_realm: Option<&str>,
        gate: crate::identity::PaymentGate,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Option<Receipt>, MppError>> + Send>,
    > {
        let mpp = self.for_request_realm(request_realm);
        let expected = mpp.expected_charge_request(
            amount,
            super::ChargeOptions {
                mppx_scope: mppx_scope.as_ref(),
                ..Default::default()
            },
        );
        verify_expected_gated(&mpp, credential_str, expected, body, Some(Arc::new(gate)))
    }

    fn credential_header(&self) -> &str {
        super::Mpp::credential_header(self)
    }

    fn challenges(
        &self,
        amount: &str,
        options: ChallengeOptions,
    ) -> Result<Vec<PaymentChallenge>, String> {
        self.for_request_realm(options.request_realm.as_deref())
            .charge_with_options(
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
        self.for_request_realm(options.request_realm.as_deref())
            .charge_with_options_and_body(
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
        self.for_request_realm(options.request_realm.as_deref())
            .stripe_charge_with_options(
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
        self.for_request_realm(options.request_realm.as_deref())
            .stripe_charge_with_options_and_body(
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

        let expected_request = match self.stripe_expected_charge_request(amount, Default::default())
        {
            Ok(request) => request,
            Err(e) => {
                return Box::pin(std::future::ready(Err(format!(
                    "Failed to generate expected request: {}",
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

        let expected_request = match self.stripe_expected_charge_request(amount, Default::default())
        {
            Ok(request) => request,
            Err(e) => {
                return Box::pin(std::future::ready(Err(format!(
                    "Failed to generate expected request: {}",
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
        self.verify_payment_for_route_with_realm(credential_str, amount, mppx_scope, body, None)
    }

    fn verify_payment_for_route_with_realm(
        &self,
        credential_str: &str,
        amount: &str,
        mppx_scope: Option<serde_json::Value>,
        body: Option<&[u8]>,
        request_realm: Option<&str>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, MppError>> + Send>>
    {
        let mpp = self.for_request_realm(request_realm);
        let expected = mpp.stripe_expected_charge_request(
            amount,
            super::StripeChargeOptions {
                mppx_scope: mppx_scope.as_ref(),
                ..Default::default()
            },
        );
        verify_expected(&mpp, credential_str, expected, body)
    }

    #[cfg(feature = "identity")]
    fn verify_payment_for_route_with_identity(
        &self,
        credential_str: &str,
        amount: &str,
        mppx_scope: Option<serde_json::Value>,
        body: Option<&[u8]>,
        request_realm: Option<&str>,
        gate: crate::identity::PaymentGate,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Option<Receipt>, MppError>> + Send>,
    > {
        let mpp = self.for_request_realm(request_realm);
        let expected = mpp.stripe_expected_charge_request(
            amount,
            super::StripeChargeOptions {
                mppx_scope: mppx_scope.as_ref(),
                ..Default::default()
            },
        );
        verify_expected_gated(&mpp, credential_str, expected, body, Some(Arc::new(gate)))
    }

    fn credential_header(&self) -> &str {
        super::Mpp::credential_header(self)
    }
}

/// The identity a route runs, from its [`RouteIdentity`](crate::identity::RouteIdentity) extension.
#[cfg(feature = "identity")]
type RouteIdentityInput = Option<(
    crate::identity::RouteIdentity,
    crate::identity::IdentityContext,
)>;
#[cfg(not(feature = "identity"))]
type RouteIdentityInput = ();

#[cfg(feature = "identity")]
type Identified = crate::identity::IdentityResults;
#[cfg(not(feature = "identity"))]
type Identified = ();

#[cfg(feature = "identity")]
fn route_identity(parts: &http_types::request::Parts) -> RouteIdentityInput {
    let route = parts
        .extensions
        .get::<crate::identity::RouteIdentity>()?
        .clone();
    // A nested router sees its path without the nesting prefix, but a proof
    // names the URI the client requested.
    let uri = parts
        .extensions
        .get::<axum::extract::OriginalUri>()
        .map_or_else(|| parts.uri.clone(), |original| original.0.clone());
    let request =
        crate::identity::IdentityRequest::new(parts.method.clone(), uri, parts.headers.clone());
    Some((route, crate::identity::IdentityContext::new(request)))
}

#[cfg(not(feature = "identity"))]
fn route_identity(_parts: &http_types::request::Parts) -> RouteIdentityInput {}

/// The route's offers, bound to `body` when the route binds one.
fn route_offers(
    challenger: &dyn ChargeChallenger,
    amount: &str,
    options: ChallengeOptions,
    body: Option<&[u8]>,
) -> Result<Vec<PaymentChallenge>, String> {
    match body {
        Some(body) => challenger.challenges_with_body(amount, options, body),
        None => challenger.challenges(amount, options),
    }
}

/// Adds the route's `Identity-Required` header to a 402 rejection.
#[cfg(feature = "identity")]
fn identity_required(
    rejection: MppChargeRejection,
    call: &mut Option<crate::identity::server::IdentityCall>,
) -> MppChargeRejection {
    match call
        .as_mut()
        .and_then(crate::identity::server::IdentityCall::challenge)
    {
        Some(required) => MppChargeRejection::IdentityRequired(Box::new(rejection), required),
        None => rejection,
    }
}

/// Runs a route's identity and payment checks, as mppx's route handler:
/// request-stage verifiers first (a rejection is sent as is), then a 402 with
/// the route's offers and `Identity-Required` header, or the Credential's
/// verification with the payment check before it settles.
#[allow(clippy::result_large_err)]
async fn verify_route(
    challenger: Arc<dyn ChargeChallenger>,
    amount: &'static str,
    options: ChallengeOptions,
    credential: Result<Option<String>, MppError>,
    body: Option<&[u8]>,
    identity: RouteIdentityInput,
) -> Result<(Receipt, Identified), MppChargeRejection> {
    let mppx_scope = options.mppx_scope.clone();
    let request_realm = options.request_realm.clone();

    #[cfg(feature = "identity")]
    let mut call = match identity {
        None => None,
        Some((route, context)) => {
            // A verifier reading Authorization would take the Payment Credential's header.
            if route.reads_authorization()
                && challenger
                    .credential_header()
                    .eq_ignore_ascii_case(header::AUTHORIZATION.as_str())
            {
                return Err(MppChargeRejection::InternalError(
                    "route identity reads Authorization: create the server with requires_auth"
                        .into(),
                ));
            }
            Some(
                route
                    .verify_request(&context)
                    .await
                    .map_err(MppChargeRejection::Identity)?,
            )
        }
    };
    #[cfg(not(feature = "identity"))]
    let () = identity;

    let credential_str = match credential {
        // More than one Payment credential: 400 without a challenge.
        Err(error) => {
            return Err(MppChargeRejection::Problem(PaymentProblem::new(
                &error,
                Vec::new(),
            )))
        }
        Ok(credential_str) => credential_str,
    };
    let Some(credential_str) = credential_str else {
        let offers = route_offers(challenger.as_ref(), amount, options, body)
            .map_err(MppChargeRejection::InternalError)?;
        let rejection = MppChargeRejection::from_offers(offers);
        #[cfg(feature = "identity")]
        let rejection = identity_required(rejection, &mut call);
        return Err(rejection);
    };

    #[cfg(feature = "identity")]
    let verified = match call
        .as_ref()
        .and_then(crate::identity::server::IdentityCall::payment_gate)
    {
        Some(gate) => {
            challenger
                .verify_payment_for_route_with_identity(
                    &credential_str,
                    amount,
                    mppx_scope,
                    body,
                    request_realm.as_deref(),
                    gate,
                )
                .await
        }
        None => challenger
            .verify_payment_for_route_with_realm(
                &credential_str,
                amount,
                mppx_scope,
                body,
                request_realm.as_deref(),
            )
            .await
            .map(Some),
    };
    #[cfg(not(feature = "identity"))]
    let verified = challenger
        .verify_payment_for_route_with_realm(
            &credential_str,
            amount,
            mppx_scope,
            body,
            request_realm.as_deref(),
        )
        .await
        .map(Some);

    let receipt = match verified {
        Ok(receipt) => receipt,
        Err(error) => {
            let rejection = MppChargeRejection::from_error(error, || {
                route_offers(challenger.as_ref(), amount, options, body)
            });
            #[cfg(feature = "identity")]
            let rejection = identity_required(rejection, &mut call);
            return Err(rejection);
        }
    };

    #[cfg(feature = "identity")]
    {
        let identified = match call {
            None => crate::identity::IdentityResults::default(),
            Some(call) => {
                let credential = parse_authorization(&credential_str)
                    .map_err(|e| MppChargeRejection::InternalError(e.to_string()))?;
                // The payment check's memoized outcome: a refusal is sent as is.
                call.accept(&credential)
                    .await
                    .map_err(MppChargeRejection::Identity)?
            }
        };
        let receipt = receipt.ok_or_else(|| {
            MppChargeRejection::InternalError("credential refused before settlement".into())
        })?;
        Ok((receipt, identified))
    }
    #[cfg(not(feature = "identity"))]
    {
        let receipt = receipt.ok_or_else(|| {
            MppChargeRejection::InternalError("credential refused before settlement".into())
        })?;
        Ok((receipt, ()))
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
        let request_realm = request_realm_from_parts(parts);
        let credential =
            super::credential_from_headers(&parts.headers, challenger.credential_header());
        let identity = route_identity(parts);

        async move {
            let options = ChallengeOptions {
                description: C::description(),
                mppx_scope,
                request_realm,
            };
            #[allow(clippy::let_unit_value)]
            let (receipt, identified) =
                verify_route(challenger, C::amount(), options, credential, None, identity).await?;
            #[cfg(not(feature = "identity"))]
            let () = identified;
            Ok(MppCharge {
                receipt,
                #[cfg(feature = "identity")]
                identity: identified,
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
        let request_realm = request_realm_from_parts(&parts);
        let credential =
            super::credential_from_headers(&parts.headers, challenger.credential_header());
        let identity = route_identity(&parts);
        let req = Request::from_parts(parts, body);

        async move {
            // Buffer through axum's `Bytes` extractor so `DefaultBodyLimit` applies.
            let body = Bytes::from_request(req, state)
                .await
                .map_err(MppChargeRejection::Body)?;
            let options = ChallengeOptions {
                description: C::description(),
                mppx_scope,
                request_realm,
            };
            #[allow(clippy::let_unit_value)]
            let (receipt, identified) = verify_route(
                challenger,
                C::amount(),
                options,
                credential,
                Some(&body),
                identity,
            )
            .await?;
            #[cfg(not(feature = "identity"))]
            let () = identified;
            Ok(MppChargeWithBody {
                receipt,
                #[cfg(feature = "identity")]
                identity: identified,
                body,
                _config: std::marker::PhantomData,
            })
        }
    }
}

fn request_realm_from_parts(parts: &http_types::request::Parts) -> Option<String> {
    if parts
        .uri
        .scheme_str()
        .is_some_and(|scheme| !matches!(scheme, "http" | "https"))
    {
        return None;
    }
    let authority = match parts.uri.authority() {
        Some(authority) => authority.clone(),
        None => parts
            .headers
            .get(header::HOST)?
            .to_str()
            .ok()?
            .parse::<http_types::uri::Authority>()
            .ok()?,
    };
    if authority.as_str().contains('@') || authority.host().is_empty() {
        return None;
    }
    Some(authority.host().to_ascii_lowercase())
}

/// Challenge options the default scoped verifiers re-issue a route's challenge with.
fn scoped_challenge_options(scope: &serde_json::Value) -> ChallengeOptions {
    ChallengeOptions {
        mppx_scope: Some(scope.clone()),
        ..Default::default()
    }
}

/// Reject a credential whose echoed challenge was not issued for this route.
///
/// Mirrors mppx's `verifyCredential`, which rejects a credential whose
/// challenge scope differs from the route's and then compares the route's
/// re-issued challenge with the echoed one (`getChallengeBindingMismatch`).
fn check_route_binding(
    credential_str: &str,
    scope: &serde_json::Value,
    expected: Result<PaymentChallenge, String>,
) -> Result<(), String> {
    let echo = parse_authorization(credential_str)
        .map_err(|e| e.to_string())?
        .challenge;
    let request = echo.request.decode_value().map_err(|e| e.to_string())?;
    if request.get("_mppx_scope") != Some(scope) {
        return Err("credential scope does not match this route's requirements".into());
    }
    let expected = expected?;
    let expected_request = expected.request.decode_value().map_err(|e| e.to_string())?;
    if echo.method != expected.method
        || echo.intent != expected.intent
        || pinned_request_binding(&request) != pinned_request_binding(&expected_request)
        || echo.digest != expected.digest
    {
        return Err("credential request does not match this route's requirements".into());
    }
    Ok(())
}

/// The request fields a credential must share with the route's challenge.
///
/// Mirrors mppx's `getPinnedRequestBinding`: only the economically
/// significant fields are compared, read from the request or its
/// `methodDetails`, so fields such as `description` that the re-issued
/// challenge may lack do not reject a valid credential. The HMAC check in
/// `verify_payment` covers the rest of the echoed request.
fn pinned_request_binding(request: &serde_json::Value) -> Vec<Option<&serde_json::Value>> {
    let details = request.get("methodDetails");
    let field = |name: &str| {
        request
            .get(name)
            .or_else(|| details.and_then(|d| d.get(name)))
    };
    let detail = |name: &str| details.and_then(|d| d.get(name));
    vec![
        field("amount"),
        field("currency"),
        field("recipient"),
        field("chainId"),
        detail("memo"),
        detail("sessionProtocol"),
        detail("splits"),
        field("unitType"),
    ]
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

#[cfg(all(test, feature = "identity"))]
mod identity_tests;
