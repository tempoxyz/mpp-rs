//! Extension trait for reqwest RequestBuilder.
//!
//! Provides `.send_with_payment()` method for opt-in per-request payment handling.

use reqwest::header::{HeaderMap, HeaderValue, WWW_AUTHENTICATE};
use reqwest::{RequestBuilder, Response, StatusCode};

use super::accept_payment_policy::AcceptPaymentPolicy;
use super::error::HttpError;
use super::events::{
    ChallengeReceivedContext, ClientEvent, ClientEvents, CredentialCreatedContext,
    PaymentFailedContext, PaymentFailureReason, PaymentResponseContext,
};
use super::provider::{PaymentContext, PaymentProvider, PendingPayment};
use super::DEFAULT_MAX_PAYMENT_RETRIES;
use crate::client::challenge_selection::{
    expired_payment_error, select_supported_challenge, ChallengeSelectionError,
};
use crate::error::MppError;
use crate::protocol::core::accept_payment::ACCEPT_PAYMENT_HEADER;
use crate::protocol::core::{format_authorization, parse_www_authenticate_all_bytes};

/// Extension trait for `reqwest::RequestBuilder` with payment support.
///
/// This trait adds a `.send_with_payment()` method that automatically handles
/// HTTP 402 responses by executing a payment and retrying the request.
///
/// # Examples
///
/// ```ignore
/// use mpp::client::{Fetch, TempoProvider};
/// use reqwest::Client;
///
/// let provider = TempoProvider::new(signer, "https://rpc.moderato.tempo.xyz")?;
/// let client = Client::new();
///
/// let resp = client
///     .get("https://api.example.com/paid")
///     .send_with_payment(&provider)
///     .await?;
/// ```
pub trait PaymentExt: Sized {
    /// Send the request, automatically handling 402 Payment Required responses.
    ///
    /// Equivalent to [`send_with_payment_policy`](Self::send_with_payment_policy)
    /// with [`AcceptPaymentPolicy::Always`].
    fn send_with_payment<P: PaymentProvider>(
        self,
        provider: &P,
    ) -> impl std::future::Future<Output = Result<Response, HttpError>> + Send {
        self.send_with_payment_policy(provider, &AcceptPaymentPolicy::Always)
    }

    /// Continue an MPP flow from an initial response already sent with this
    /// request builder.
    ///
    /// This lets transports keep ordinary requests outside a paid-flow
    /// concurrency limit while reusing the canonical challenge lifecycle.
    fn send_with_payment_from_response<P: PaymentProvider>(
        self,
        provider: &P,
        response: Response,
    ) -> impl std::future::Future<Output = Result<Response, HttpError>> + Send;

    /// Like [`send_with_payment`](Self::send_with_payment) but only injects
    /// `Accept-Payment` when `policy` permits the request URL. The 402-retry
    /// path is unaffected.
    fn send_with_payment_policy<P: PaymentProvider>(
        self,
        provider: &P,
        policy: &AcceptPaymentPolicy,
    ) -> impl std::future::Future<Output = Result<Response, HttpError>> + Send;

    /// Like [`send_with_payment`](Self::send_with_payment), with a custom cap
    /// for incremental payment challenge retries after the initial 402.
    fn send_with_payment_max_retries<P: PaymentProvider>(
        self,
        provider: &P,
        max_payment_retries: usize,
    ) -> impl std::future::Future<Output = Result<Response, HttpError>> + Send {
        self.send_with_payment_policy_max_retries(
            provider,
            &AcceptPaymentPolicy::Always,
            max_payment_retries,
        )
    }

    /// Like [`send_with_payment_policy`](Self::send_with_payment_policy), with
    /// a custom cap for incremental payment challenge retries.
    fn send_with_payment_policy_max_retries<P: PaymentProvider>(
        self,
        provider: &P,
        policy: &AcceptPaymentPolicy,
        max_payment_retries: usize,
    ) -> impl std::future::Future<Output = Result<Response, HttpError>> + Send {
        self.send_with_payment_options_max_retries(
            provider,
            policy,
            ClientEvents::default(),
            max_payment_retries,
        )
    }

    /// Like [`send_with_payment_policy`](Self::send_with_payment_policy), with
    /// event callbacks for the 402 payment flow.
    fn send_with_payment_options<P: PaymentProvider>(
        self,
        provider: &P,
        policy: &AcceptPaymentPolicy,
        events: ClientEvents,
    ) -> impl std::future::Future<Output = Result<Response, HttpError>> + Send {
        let _ = events;
        self.send_with_payment_policy(provider, policy)
    }

    /// Like [`send_with_payment_options`](Self::send_with_payment_options),
    /// with a custom cap for incremental payment challenge retries.
    fn send_with_payment_options_max_retries<P: PaymentProvider>(
        self,
        provider: &P,
        policy: &AcceptPaymentPolicy,
        events: ClientEvents,
        max_payment_retries: usize,
    ) -> impl std::future::Future<Output = Result<Response, HttpError>> + Send {
        let _ = max_payment_retries;
        self.send_with_payment_options(provider, policy, events)
    }
}

impl PaymentExt for RequestBuilder {
    async fn send_with_payment_from_response<P: PaymentProvider>(
        self,
        provider: &P,
        response: Response,
    ) -> Result<Response, HttpError> {
        send_with_payment(
            self,
            provider,
            &AcceptPaymentPolicy::Always,
            ClientEvents::default(),
            DEFAULT_MAX_PAYMENT_RETRIES,
            Some(response),
        )
        .await
    }

    async fn send_with_payment_policy<P: PaymentProvider>(
        self,
        provider: &P,
        policy: &AcceptPaymentPolicy,
    ) -> Result<Response, HttpError> {
        self.send_with_payment_options_max_retries(
            provider,
            policy,
            ClientEvents::default(),
            DEFAULT_MAX_PAYMENT_RETRIES,
        )
        .await
    }

    async fn send_with_payment_policy_max_retries<P: PaymentProvider>(
        self,
        provider: &P,
        policy: &AcceptPaymentPolicy,
        max_payment_retries: usize,
    ) -> Result<Response, HttpError> {
        self.send_with_payment_options_max_retries(
            provider,
            policy,
            ClientEvents::default(),
            max_payment_retries,
        )
        .await
    }

    async fn send_with_payment_options<P: PaymentProvider>(
        self,
        provider: &P,
        policy: &AcceptPaymentPolicy,
        events: ClientEvents,
    ) -> Result<Response, HttpError> {
        self.send_with_payment_options_max_retries(
            provider,
            policy,
            events,
            DEFAULT_MAX_PAYMENT_RETRIES,
        )
        .await
    }

    async fn send_with_payment_options_max_retries<P: PaymentProvider>(
        self,
        provider: &P,
        policy: &AcceptPaymentPolicy,
        events: ClientEvents,
        max_payment_retries: usize,
    ) -> Result<Response, HttpError> {
        send_with_payment(self, provider, policy, events, max_payment_retries, None).await
    }
}

async fn send_with_payment<P: PaymentProvider>(
    request: RequestBuilder,
    provider: &P,
    policy: &AcceptPaymentPolicy,
    events: ClientEvents,
    max_payment_retries: usize,
    initial_response: Option<Response>,
) -> Result<Response, HttpError> {
    let retry_builder = request.try_clone().ok_or(HttpError::CloneFailed)?;

    // Peek the built request to inspect caller-set headers and URL
    // before injecting our own.
    let peek = retry_builder.try_clone().and_then(|b| b.build().ok());
    let url = peek.as_ref().map(|r| r.url().clone());
    let caller_accept = peek.as_ref().and_then(|r| {
        r.headers()
            .get(ACCEPT_PAYMENT_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(String::from)
    });
    let provider_accept = provider.accept_payment_header();

    // Inject only if the caller didn't set their own header AND the
    // policy permits it. Caller-set headers are never overwritten.
    let inject = caller_accept.is_none() && url.as_ref().is_some_and(|u| policy.allows(u));

    let request = if inject {
        if let Some(ref header) = provider_accept {
            request.header(ACCEPT_PAYMENT_HEADER, header)
        } else {
            request
        }
    } else {
        request
    };

    // Caller's header (if any) wins for retry-time ranking.
    let ranking_accept = caller_accept.or(provider_accept);

    let mut paid_challenge_ids = std::collections::HashSet::new();
    let mut retried_stale_session = false;
    let mut refreshed_after_provider_setup = false;
    let mut resp = match initial_response {
        Some(response) => response,
        None => request.send().await?,
    };

    let mut payment_attempt = 0;
    while payment_attempt < max_payment_retries {
        if resp.status() != StatusCode::PAYMENT_REQUIRED {
            return Ok(resp);
        }

        if url
            .as_ref()
            .is_some_and(|request_url| request_url.origin() != resp.url().origin())
        {
            let err = HttpError::CrossOriginRedirect;
            events
                .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                    challenge: None,
                    error: err.to_string(),
                    reason: None,
                }))
                .await;
            return Err(err);
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
            events
                .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                    challenge: None,
                    error: HttpError::MissingChallenge.to_string(),
                    reason: None,
                }))
                .await;
            return Err(HttpError::MissingChallenge);
        }

        let challenges: Vec<_> = parse_www_authenticate_all_bytes(www_auth_values)
            .into_iter()
            .filter_map(|r| r.ok())
            .collect();

        let challenge = match select_supported_challenge(
            &challenges,
            ranking_accept.as_deref(),
            |challenge| provider.supports(challenge.method.as_str(), challenge.intent.as_str()),
            |challenges| provider.select_challenge(challenges),
        ) {
            Ok(challenge) => challenge.clone(),
            Err(ChallengeSelectionError::Expired(challenge)) => {
                let err = HttpError::Payment(expired_payment_error(&challenge));
                let error = err.to_string();
                let expires = challenge.expires.clone();
                events
                    .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                        challenge: Some(*challenge),
                        error,
                        reason: Some(PaymentFailureReason::PreSigningExpired { expires }),
                    }))
                    .await;
                return Err(err);
            }
            Err(ChallengeSelectionError::NoSupportedChallenge(message)) => {
                let err = HttpError::NoSupportedChallenge(message);
                events
                    .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                        challenge: None,
                        error: err.to_string(),
                        reason: None,
                    }))
                    .await;
                return Err(err);
            }
        };

        let Some(url) = url.clone() else {
            return Err(HttpError::CloneFailed);
        };
        let payment_context = PaymentContext {
            url,
            headers: peek
                .as_ref()
                .map(|request| request.headers().clone())
                .unwrap_or_default(),
        };
        let challenge = match provider
            .prepare_http_payment_challenge(&challenge, payment_context.clone())
            .await
        {
            Ok(Some(challenge)) => challenge,
            Ok(None) => {
                if refreshed_after_provider_setup {
                    return Err(HttpError::Payment(MppError::InvalidConfig(
                        "payment provider repeatedly requested a fresh HTTP challenge".to_owned(),
                    )));
                }
                refreshed_after_provider_setup = true;
                paid_challenge_ids.clear();
                resp = retry_builder
                    .try_clone()
                    .ok_or(HttpError::CloneFailed)?
                    .send()
                    .await
                    .map_err(HttpError::request)?;
                continue;
            }
            Err(err) => {
                let http_err = HttpError::Payment(err);
                events
                    .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                        challenge: Some(challenge),
                        error: http_err.to_string(),
                        reason: None,
                    }))
                    .await;
                return Err(http_err);
            }
        };
        payment_attempt += 1;

        if !paid_challenge_ids.insert(challenge.id.clone()) {
            events
                .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                    challenge: Some(challenge),
                    error: "payment retry returned a previously paid challenge".to_string(),
                    reason: None,
                }))
                .await;
            return Ok(resp);
        }

        let override_credential = events
            .emit_challenge_received(ChallengeReceivedContext {
                challenge: challenge.clone(),
                challenges: challenges.clone(),
            })
            .await;

        let credential = match override_credential {
            Some(credential) => credential,
            None => match provider.pay_with_context(&challenge, payment_context).await {
                Ok(credential) => credential,
                Err(err) => {
                    let http_err = HttpError::Payment(err);
                    events
                        .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                            challenge: Some(challenge),
                            error: http_err.to_string(),
                            reason: None,
                        }))
                        .await;
                    return Err(http_err);
                }
            },
        };

        let pending = PendingPayment::new(provider.clone(), challenge.clone(), credential.clone());

        events
            .emit(ClientEvent::CredentialCreated(CredentialCreatedContext {
                challenge: challenge.clone(),
                credential: credential.clone(),
            }))
            .await;

        let auth_header = match format_authorization(&credential) {
            Ok(auth_header) => auth_header,
            Err(err) => {
                let http_err = HttpError::InvalidCredential(err.to_string());
                events
                    .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                        challenge: Some(challenge),
                        error: http_err.to_string(),
                        reason: None,
                    }))
                    .await;
                pending.rollback().await.map_err(HttpError::Payment)?;
                return Err(http_err);
            }
        };

        let auth_header = match HeaderValue::from_str(&auth_header) {
            Ok(auth_header) => auth_header,
            Err(err) => {
                let http_err = HttpError::InvalidCredential(err.to_string());
                events
                    .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                        challenge: Some(challenge),
                        error: http_err.to_string(),
                        reason: None,
                    }))
                    .await;
                pending.rollback().await.map_err(HttpError::Payment)?;
                return Err(http_err);
            }
        };
        let mut payment_headers = HeaderMap::new();
        payment_headers.insert(
            crate::client::payment_credential_header_name(&challenge),
            auth_header,
        );
        let retry = match retry_builder.try_clone() {
            Some(retry) => retry.headers(payment_headers),
            None => {
                pending.rollback().await.map_err(HttpError::Payment)?;
                return Err(HttpError::CloneFailed);
            }
        };
        let (client, retry) = retry.build_split();
        let mut retry = retry.map_err(HttpError::request)?;
        *retry.url_mut() = resp.url().clone();
        resp = match client.execute(retry).await {
            Ok(resp) => resp,
            Err(err) => {
                let http_err = HttpError::request(err);
                events
                    .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                        challenge: Some(challenge),
                        error: http_err.to_string(),
                        reason: None,
                    }))
                    .await;
                // The request may have reached the server even though its
                // response was lost. Preserve optimistic provider state
                // until a later challenge can reconcile it, while
                // releasing any delivery lease held by the provider.
                pending.commit().await.map_err(HttpError::Payment)?;
                return Err(http_err);
            }
        };

        let status = resp.status();
        if status.is_success() {
            events
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
        if !retried_stale_session
            && status == StatusCode::GONE
            && challenge.intent.as_str() == "session"
        {
            retried_stale_session = true;
            pending.invalidate().await.map_err(HttpError::Payment)?;
            paid_challenge_ids.clear();
            resp = retry_builder
                .try_clone()
                .ok_or(HttpError::CloneFailed)?
                .send()
                .await
                .map_err(HttpError::request)?;
            continue;
        }

        // A completed HTTP response is the application's answer, not a
        // payment flow error. Match MPPx by returning non-402 responses
        // and the final 402 without emitting `payment.failed`.
        if status != StatusCode::PAYMENT_REQUIRED || payment_attempt == max_payment_retries {
            if resp.headers().contains_key("payment-receipt") {
                pending.commit().await.map_err(HttpError::Payment)?;
            } else {
                pending.rollback().await.map_err(HttpError::Payment)?;
            }
            return Ok(resp);
        }

        if resp.headers().contains_key("payment-receipt") {
            pending.commit().await.map_err(HttpError::Payment)?;
        } else {
            pending.rollback().await.map_err(HttpError::Payment)?;
        }
    }

    Ok(resp)
}

#[cfg(test)]
mod tests;
