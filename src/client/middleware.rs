//! reqwest-middleware integration for automatic 402 handling.
//!
//! Provides `PaymentMiddleware` for use with `reqwest_middleware::ClientBuilder`.

use async_trait::async_trait;
use reqwest::header::{HeaderValue, WWW_AUTHENTICATE};
use reqwest::{Request, Response, StatusCode};
use reqwest_middleware::{Middleware, Next};

use crate::client::accept_payment_policy::AcceptPaymentPolicy;
use crate::client::challenge_selection::{
    expired_payment_error, select_supported_challenge, ChallengeSelectionError,
};
use crate::client::events::{
    ChallengeReceivedContext, ClientEvent, ClientEventSubscription, ClientEvents,
    CredentialCreatedContext, PaymentFailedContext, PaymentFailureReason, PaymentResponseContext,
};
use crate::client::provider::{PaymentContext, PaymentProvider, PendingPayment};
use crate::client::HttpError;
use crate::client::DEFAULT_MAX_PAYMENT_RETRIES;
use crate::protocol::core::accept_payment::ACCEPT_PAYMENT_HEADER;
use crate::protocol::core::{format_authorization, parse_www_authenticate_all_bytes};

fn middleware_error(error: HttpError) -> reqwest_middleware::Error {
    reqwest_middleware::Error::Middleware(anyhow::Error::new(error))
}

async fn commit_middleware_payment<P: PaymentProvider>(
    payment: PendingPayment<P>,
) -> reqwest_middleware::Result<()> {
    payment
        .commit()
        .await
        .map_err(|error| middleware_error(HttpError::Payment(error)))
}

async fn rollback_middleware_payment<P: PaymentProvider>(
    payment: PendingPayment<P>,
) -> reqwest_middleware::Result<()> {
    payment
        .rollback()
        .await
        .map_err(|error| middleware_error(HttpError::Payment(error)))
}

/// Middleware that automatically handles 402 Payment Required responses.
///
/// When a request returns 402, the middleware:
/// 1. Parses the challenge from the `WWW-Authenticate` header
/// 2. Calls the provider to execute the payment
/// 3. Retries the request with the credential in the `Authorization` header
///
/// Payment failures are returned as [`HttpError`] inside
/// [`reqwest_middleware::Error::Middleware`] and can be recovered with
/// `downcast_ref::<HttpError>()`.
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
    accept_payment_policy: AcceptPaymentPolicy,
    events: ClientEvents,
    max_payment_retries: usize,
}

impl<P> PaymentMiddleware<P> {
    /// Create middleware with the given provider. Defaults to
    /// [`AcceptPaymentPolicy::Always`].
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            accept_payment_policy: AcceptPaymentPolicy::default(),
            events: ClientEvents::default(),
            max_payment_retries: DEFAULT_MAX_PAYMENT_RETRIES,
        }
    }

    /// Restrict where the `Accept-Payment` header is sent. The 402-retry
    /// path is unaffected.
    pub fn with_accept_payment_policy(mut self, policy: AcceptPaymentPolicy) -> Self {
        self.accept_payment_policy = policy;
        self
    }

    /// Use an existing event registry for payment callbacks.
    pub fn with_events(mut self, events: ClientEvents) -> Self {
        self.events = events;
        self
    }

    /// Set the maximum number of payment challenge retries after the initial
    /// 402 response.
    pub fn with_max_payment_retries(mut self, max_payment_retries: usize) -> Self {
        self.max_payment_retries = max_payment_retries;
        self
    }

    /// Get the event registry used by this middleware.
    pub fn events(&self) -> ClientEvents {
        self.events.clone()
    }

    /// Register a `challenge.received` callback.
    pub fn on_challenge_received<F, Fut>(&self, handler: F) -> ClientEventSubscription
    where
        F: Fn(ChallengeReceivedContext) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Option<crate::protocol::core::PaymentCredential>>
            + Send
            + 'static,
    {
        self.events.on_challenge_received(handler)
    }

    /// Register a `credential.created` observer.
    pub fn on_credential_created<F, Fut>(&self, handler: F) -> ClientEventSubscription
    where
        F: Fn(CredentialCreatedContext) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        self.events.on_credential_created(handler)
    }

    /// Register a `payment.response` observer.
    pub fn on_payment_response<F, Fut>(&self, handler: F) -> ClientEventSubscription
    where
        F: Fn(PaymentResponseContext) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        self.events.on_payment_response(handler)
    }

    /// Register a `payment.failed` observer.
    pub fn on_payment_failed<F, Fut>(&self, handler: F) -> ClientEventSubscription
    where
        F: Fn(PaymentFailedContext) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        self.events.on_payment_failed(handler)
    }
}

#[async_trait]
impl<P> Middleware for PaymentMiddleware<P>
where
    P: PaymentProvider + 'static,
{
    async fn handle(
        &self,
        mut req: Request,
        extensions: &mut http_types::Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        let payment_context = PaymentContext {
            url: req.url().clone(),
            headers: req.headers().clone(),
        };

        // Snapshot any caller-set Accept-Payment header before injection.
        let caller_accept = req
            .headers()
            .get(ACCEPT_PAYMENT_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let provider_accept = self.provider.accept_payment_header();

        // Inject only if the caller didn't set their own header AND the
        // policy permits it. Caller-set headers are never overwritten
        if caller_accept.is_none() && self.accept_payment_policy.allows(req.url()) {
            if let Some(ref header) = provider_accept {
                if let Ok(val) = header.parse() {
                    req.headers_mut().insert(ACCEPT_PAYMENT_HEADER, val);
                }
            }
        }

        // The caller's header (if any) wins for retry-time challenge ranking;
        // otherwise fall back to the provider's preferences.
        let ranking_accept = caller_accept.or(provider_accept);

        let retry_req = req.try_clone();
        let mut resp = next.clone().run(req, extensions).await?;

        if resp.status() != StatusCode::PAYMENT_REQUIRED {
            return Ok(resp);
        }

        let base_retry_req = match retry_req {
            Some(req) => req,
            None => {
                let err = HttpError::CloneFailed;
                self.events
                    .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                        challenge: None,
                        error: err.to_string(),
                        reason: None,
                    }))
                    .await;
                return Err(middleware_error(err));
            }
        };

        let mut paid_challenge_ids = std::collections::HashSet::new();

        for attempt in 0..self.max_payment_retries {
            if resp.status() != StatusCode::PAYMENT_REQUIRED {
                return Ok(resp);
            }

            if payment_context.url.origin() != resp.url().origin() {
                let err = HttpError::CrossOriginRedirect;
                self.events
                    .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                        challenge: None,
                        error: err.to_string(),
                        reason: None,
                    }))
                    .await;
                return Err(middleware_error(err));
            }

            let www_auth_values: Vec<&[u8]> = resp
                .headers()
                .get_all(WWW_AUTHENTICATE)
                .iter()
                .map(|v| v.as_bytes())
                .collect();

            if www_auth_values.is_empty() {
                let err = HttpError::MissingChallenge;
                self.events
                    .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                        challenge: None,
                        error: err.to_string(),
                        reason: None,
                    }))
                    .await;
                return Err(middleware_error(err));
            }

            let challenges: Vec<_> = parse_www_authenticate_all_bytes(www_auth_values)
                .into_iter()
                .filter_map(|r| r.ok())
                .collect();

            let challenge = match select_supported_challenge(
                &challenges,
                ranking_accept.as_deref(),
                |challenge| {
                    self.provider
                        .supports(challenge.method.as_str(), challenge.intent.as_str())
                },
                |challenges| self.provider.select_challenge(challenges),
            ) {
                Ok(challenge) => challenge.clone(),
                Err(ChallengeSelectionError::Expired(challenge)) => {
                    let err = HttpError::Payment(expired_payment_error(&challenge));
                    let error = err.to_string();
                    let expires = challenge.expires.clone();
                    self.events
                        .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                            challenge: Some(*challenge),
                            error,
                            reason: Some(PaymentFailureReason::PreSigningExpired { expires }),
                        }))
                        .await;
                    return Err(middleware_error(err));
                }
                Err(ChallengeSelectionError::NoSupportedChallenge(message)) => {
                    let err = HttpError::NoSupportedChallenge(message);
                    self.events
                        .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                            challenge: None,
                            error: err.to_string(),
                            reason: None,
                        }))
                        .await;
                    return Err(middleware_error(err));
                }
            };

            if !paid_challenge_ids.insert(challenge.id.clone()) {
                self.events
                    .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                        challenge: Some(challenge),
                        error: "payment retry returned a previously paid challenge".to_string(),
                        reason: None,
                    }))
                    .await;
                return Ok(resp);
            }

            let override_credential = self
                .events
                .emit_challenge_received(ChallengeReceivedContext {
                    challenge: challenge.clone(),
                    challenges: challenges.clone(),
                })
                .await;

            let credential = match override_credential {
                Some(credential) => credential,
                None => match self
                    .provider
                    .pay_with_context(&challenge, payment_context.clone())
                    .await
                {
                    Ok(credential) => credential,
                    Err(err) => {
                        let err = HttpError::Payment(err);
                        self.events
                            .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                                challenge: Some(challenge),
                                error: err.to_string(),
                                reason: None,
                            }))
                            .await;
                        return Err(middleware_error(err));
                    }
                },
            };

            let pending =
                PendingPayment::new(self.provider.clone(), challenge.clone(), credential.clone());

            self.events
                .emit(ClientEvent::CredentialCreated(CredentialCreatedContext {
                    challenge: challenge.clone(),
                    credential: credential.clone(),
                }))
                .await;

            let auth_header = match format_authorization(&credential) {
                Ok(auth_header) => auth_header,
                Err(err) => {
                    let err = HttpError::InvalidCredential(err.to_string());
                    self.events
                        .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                            challenge: Some(challenge),
                            error: err.to_string(),
                            reason: None,
                        }))
                        .await;
                    rollback_middleware_payment(pending).await?;
                    return Err(middleware_error(err));
                }
            };

            let auth_header_value = match HeaderValue::from_str(&auth_header) {
                Ok(value) => value,
                Err(err) => {
                    let err = HttpError::InvalidCredential(err.to_string());
                    self.events
                        .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                            challenge: Some(challenge),
                            error: err.to_string(),
                            reason: None,
                        }))
                        .await;
                    rollback_middleware_payment(pending).await?;
                    return Err(middleware_error(err));
                }
            };
            let Some(mut retry_req) = base_retry_req.try_clone() else {
                rollback_middleware_payment(pending).await?;
                return Err(middleware_error(HttpError::CloneFailed));
            };
            // The challenge came from the final URL of any same-origin redirect,
            // so that is where the credential goes.
            *retry_req.url_mut() = resp.url().clone();
            retry_req.headers_mut().insert(
                crate::client::payment_credential_header_name(&challenge),
                auth_header_value,
            );

            resp = match next.clone().run(retry_req, extensions).await {
                Ok(resp) => resp,
                Err(err) => {
                    self.events
                        .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                            challenge: Some(challenge),
                            error: err.to_string(),
                            reason: None,
                        }))
                        .await;
                    // The request may have reached the server even though its
                    // response was lost. Preserve optimistic provider state
                    // until a later challenge can reconcile it, while
                    // releasing any delivery lease held by the provider.
                    commit_middleware_payment(pending).await?;
                    return Err(err);
                }
            };

            let status = resp.status();
            if status.is_success() {
                self.events
                    .emit(ClientEvent::PaymentResponse(PaymentResponseContext {
                        challenge,
                        credential,
                        status,
                    }))
                    .await;
                commit_middleware_payment(pending).await?;
                return Ok(resp);
            }

            // The server no longer has the session channel. Let the provider
            // forget it so the next request can open a fresh one.
            if status == StatusCode::GONE && challenge.intent.as_str() == "session" {
                pending
                    .invalidate()
                    .await
                    .map_err(|error| middleware_error(HttpError::Payment(error)))?;
                return Ok(resp);
            }

            // A completed HTTP response is the application's answer, not a
            // payment flow error. Match MPPx by returning non-402 responses
            // and the final 402 without emitting `payment.failed`.
            if status != StatusCode::PAYMENT_REQUIRED || attempt + 1 == self.max_payment_retries {
                if resp.headers().contains_key("payment-receipt") {
                    commit_middleware_payment(pending).await?;
                } else {
                    rollback_middleware_payment(pending).await?;
                }
                return Ok(resp);
            }

            if resp.headers().contains_key("payment-receipt") {
                commit_middleware_payment(pending).await?;
            } else {
                rollback_middleware_payment(pending).await?;
            }
        }

        Ok(resp)
    }
}

#[cfg(test)]
mod tests;
