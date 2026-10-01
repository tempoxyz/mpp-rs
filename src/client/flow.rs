//! The HTTP 402 payment flow shared by [`Fetch`](super::Fetch) and
//! [`PaymentMiddleware`](super::PaymentMiddleware).

use std::collections::HashSet;
use std::fmt::Display;
use std::future::Future;

use reqwest::header::{HeaderValue, WWW_AUTHENTICATE};
use reqwest::{Request, Response, StatusCode};

use super::accept_payment_policy::AcceptPaymentPolicy;
use super::challenge_selection::{
    expired_payment_error, select_supported_challenge, ChallengeSelectionError,
};
use super::error::HttpError;
use super::events::{
    ChallengeReceivedContext, ClientEvent, ClientEvents, CredentialCreatedContext,
    PaymentFailedContext, PaymentFailureReason, PaymentResponseContext,
};
use super::provider::{PaymentContext, PaymentProvider, PendingPayment};
use crate::error::MppError;
use crate::protocol::core::accept_payment::ACCEPT_PAYMENT_HEADER;
use crate::protocol::core::{
    format_authorization, parse_www_authenticate_all_bytes, PaymentChallenge, PaymentCredential,
};

/// Sends the requests of a payment flow.
pub(crate) trait Exchange: Send {
    /// Error of a request that could not be sent.
    type Error: Display + Send;

    /// Sends `request` and returns its response.
    fn send(
        &mut self,
        request: Request,
    ) -> impl Future<Output = Result<Response, Self::Error>> + Send;
}

/// Failure of a payment flow.
pub(crate) enum FlowError<E> {
    /// The payment could not be made or reconciled.
    Payment(HttpError),
    /// A request could not be sent.
    Send(E),
}

impl<E> From<HttpError> for FlowError<E> {
    fn from(error: HttpError) -> Self {
        Self::Payment(error)
    }
}

/// Answers `402 Payment Required` responses by paying a challenge and
/// repeating the request with the credential.
pub(crate) struct PaymentFlow<'a, P> {
    pub(crate) provider: &'a P,
    pub(crate) policy: &'a AcceptPaymentPolicy,
    pub(crate) events: &'a ClientEvents,
    pub(crate) max_payment_retries: usize,
}

impl<P: PaymentProvider> PaymentFlow<'_, P> {
    /// Sends `request`, or continues from `initial_response` when the caller
    /// already sent it.
    pub(crate) async fn run<X: Exchange>(
        &self,
        exchange: &mut X,
        mut request: Request,
        initial_response: Option<Response>,
    ) -> Result<Response, FlowError<X::Error>> {
        // Snapshot any caller-set Accept-Payment header before injection.
        let caller_accept = request
            .headers()
            .get(ACCEPT_PAYMENT_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let provider_accept = self.provider.accept_payment_header();

        // Inject only if the caller didn't set their own header AND the
        // policy permits it. Caller-set headers are never overwritten.
        let mut injected = false;
        if caller_accept.is_none() && self.policy.allows(request.url()) {
            if let Some(value) = provider_accept
                .as_deref()
                .and_then(|header| HeaderValue::from_str(header).ok())
            {
                request.headers_mut().append(ACCEPT_PAYMENT_HEADER, value);
                injected = true;
            }
        }

        // The caller's header (if any) wins for retry-time challenge ranking;
        // otherwise fall back to the provider's preferences.
        let ranking_accept = caller_accept.or(provider_accept);

        let retry = request.try_clone();
        let mut resp = match initial_response {
            Some(response) => response,
            None => exchange.send(request).await.map_err(FlowError::Send)?,
        };

        if resp.status() != StatusCode::PAYMENT_REQUIRED {
            return Ok(resp);
        }

        let Some(retry) = retry else {
            return Err(self.fail(None, HttpError::CloneFailed).await);
        };

        // The provider sees the request as the caller built it.
        let mut headers = retry.headers().clone();
        if injected {
            headers.remove(ACCEPT_PAYMENT_HEADER);
        }
        let payment_context = PaymentContext {
            url: retry.url().clone(),
            headers,
        };

        let mut paid_challenge_ids = HashSet::new();
        let mut retried_stale_session = false;
        let mut refreshed_after_provider_setup = false;
        let mut payment_attempt = 0;
        while payment_attempt < self.max_payment_retries {
            if resp.status() != StatusCode::PAYMENT_REQUIRED {
                return Ok(resp);
            }

            if payment_context.url.origin() != resp.url().origin() {
                return Err(self.fail(None, HttpError::CrossOriginRedirect).await);
            }

            let www_auth_values: Vec<&[u8]> = resp
                .headers()
                .get_all(WWW_AUTHENTICATE)
                .iter()
                .map(|v| v.as_bytes())
                .collect();

            if www_auth_values.is_empty() {
                if !paid_challenge_ids.is_empty() {
                    return Ok(resp);
                }
                return Err(self.fail(None, HttpError::MissingChallenge).await);
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
                    let expires = challenge.expires.clone();
                    self.events
                        .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                            challenge: Some(*challenge),
                            error: err.to_string(),
                            reason: Some(PaymentFailureReason::PreSigningExpired { expires }),
                        }))
                        .await;
                    return Err(err.into());
                }
                Err(ChallengeSelectionError::NoSupportedChallenge(message)) => {
                    // A paid request answered with challenges the provider
                    // cannot pay is the server's final answer.
                    if !paid_challenge_ids.is_empty() {
                        return Ok(resp);
                    }
                    return Err(self
                        .fail(None, HttpError::NoSupportedChallenge(message))
                        .await);
                }
            };

            let challenge = match self
                .provider
                .prepare_http_payment_challenge(&challenge, payment_context.clone())
                .await
            {
                Ok(Some(challenge)) => challenge,
                Ok(None) => {
                    if refreshed_after_provider_setup {
                        return Err(HttpError::Payment(MppError::InvalidConfig(
                            "payment provider repeatedly requested a fresh HTTP challenge"
                                .to_owned(),
                        ))
                        .into());
                    }
                    refreshed_after_provider_setup = true;
                    paid_challenge_ids.clear();
                    resp = exchange
                        .send(retry.try_clone().ok_or(HttpError::CloneFailed)?)
                        .await
                        .map_err(FlowError::Send)?;
                    continue;
                }
                Err(err) => {
                    return Err(self.fail(Some(challenge), HttpError::Payment(err)).await);
                }
            };
            payment_attempt += 1;

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
                    challenges,
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
                        return Err(self.fail(Some(challenge), HttpError::Payment(err)).await);
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

            let auth_header = match authorization_value(&credential) {
                Ok(auth_header) => auth_header,
                Err(err) => {
                    let err = self.fail(Some(challenge), err).await;
                    pending.rollback().await.map_err(HttpError::Payment)?;
                    return Err(err);
                }
            };

            let Some(mut paid) = retry.try_clone() else {
                pending.rollback().await.map_err(HttpError::Payment)?;
                return Err(HttpError::CloneFailed.into());
            };
            // The challenge came from the final URL of any same-origin redirect,
            // so that is where the credential goes.
            *paid.url_mut() = resp.url().clone();
            paid.headers_mut().insert(
                crate::client::payment_credential_header_name(&challenge),
                auth_header,
            );

            resp = match exchange.send(paid).await {
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
                    pending.commit().await.map_err(HttpError::Payment)?;
                    return Err(FlowError::Send(err));
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
                pending.commit().await.map_err(HttpError::Payment)?;
                return Ok(resp);
            }

            // A durable session may outlive the server-side channel record.
            // Invalidate that local channel and retry the original unpaid
            // request once through the normal 402 flow so a fresh channel can
            // be opened without surfacing a recoverable 410 to the caller.
            if status == StatusCode::GONE && challenge.intent.as_str() == "session" {
                pending.invalidate().await.map_err(HttpError::Payment)?;
                if retried_stale_session {
                    return Ok(resp);
                }
                retried_stale_session = true;
                paid_challenge_ids.clear();
                resp = exchange
                    .send(retry.try_clone().ok_or(HttpError::CloneFailed)?)
                    .await
                    .map_err(FlowError::Send)?;
                continue;
            }

            if resp.headers().contains_key("payment-receipt") {
                pending.commit().await.map_err(HttpError::Payment)?;
            } else {
                pending.rollback().await.map_err(HttpError::Payment)?;
            }

            // A completed HTTP response is the application's answer, not a
            // payment flow error. Match MPPx by returning non-402 responses
            // and the final 402 without emitting `payment.failed`.
            if status != StatusCode::PAYMENT_REQUIRED || payment_attempt == self.max_payment_retries
            {
                return Ok(resp);
            }
        }

        Ok(resp)
    }

    /// Emits `payment.failed` for `error` and hands it back.
    async fn fail<E>(&self, challenge: Option<PaymentChallenge>, error: HttpError) -> FlowError<E> {
        self.events
            .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                challenge,
                error: error.to_string(),
                reason: None,
            }))
            .await;
        FlowError::Payment(error)
    }
}

fn authorization_value(credential: &PaymentCredential) -> Result<HeaderValue, HttpError> {
    let header = format_authorization(credential)
        .map_err(|err| HttpError::InvalidCredential(err.to_string()))?;
    HeaderValue::from_str(&header).map_err(|err| HttpError::InvalidCredential(err.to_string()))
}

#[cfg(all(test, feature = "middleware"))]
mod tests;
