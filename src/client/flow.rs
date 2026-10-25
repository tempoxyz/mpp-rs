//! The HTTP 402 payment flow shared by [`Fetch`](super::Fetch) and
//! [`PaymentMiddleware`](super::PaymentMiddleware).

use std::collections::HashSet;
use std::fmt::Display;
use std::future::Future;

use reqwest::header::{HeaderMap, HeaderValue, HOST, WWW_AUTHENTICATE};
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
    format_authorization, parse_receipt, parse_www_authenticate_all_bytes, PaymentChallenge,
    PaymentCredential, Receipt,
};

/// Sends the requests of a payment flow.
///
/// Implement this to run the HTTP 402 payment flow over a transport other
/// than a [`reqwest::Client`], such as a host application's HTTP stack. See
/// [`send_with_exchange`].
pub trait Exchange: Send {
    /// Error of a request that could not be sent.
    type Error: Display + Send;

    /// Restricts server challenges before provider preparation and after preparation.
    /// Prepaid credentials are controlled separately by [`Self::allows_prepaid`].
    ///
    /// The default rejects custom credential headers because a caller-owned
    /// client may forward them across redirects. Only override this restriction
    /// when the transport enforces its own redirect-safe credential handling.
    fn check_challenge(&self, challenge: &PaymentChallenge) -> Result<(), HttpError> {
        if challenge.credential_header() == "Authorization" {
            Ok(())
        } else {
            Err(HttpError::UnsafeCredentialHeader)
        }
    }

    /// Whether the provider may prepare a credential before a server challenge.
    ///
    /// Defaults to true. Return false to skip
    /// [`PaymentProvider::prepaid_credential`] entirely, for example when the
    /// transport only admits charge challenges and cannot prepare session vouchers.
    fn allows_prepaid(&self) -> bool {
        true
    }

    /// Caller-configured client available for session management requests.
    fn http_client(&self) -> Option<reqwest::Client> {
        None
    }

    /// Sends `request` and returns its response.
    fn send(
        &mut self,
        request: Request,
    ) -> impl Future<Output = Result<Response, Self::Error>> + Send;
}

/// Failure of a payment flow.
#[derive(Debug)]
pub enum FlowError<E> {
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

/// Outcome of a request sent with a credential prepared before any `402`.
enum Prepaid {
    /// The server answered the paid request.
    Answered(Response),
    /// The server asked for payment again; this is the unpaid request's response.
    Unpaid(Response),
}

/// Sends `request` through `exchange`, paying any `402 Payment Required`
/// answer with `provider` and repeating the request with the credential.
///
/// The returned response is the last one `exchange` produced. Request
/// failures are returned as [`FlowError::Send`] with the exchange's own error,
/// so callers keep its retry and delivery classification.
pub async fn send_with_exchange<P: PaymentProvider, X: Exchange>(
    exchange: &mut X,
    request: Request,
    provider: &P,
    policy: &AcceptPaymentPolicy,
    events: &ClientEvents,
    max_payment_retries: usize,
) -> Result<Response, FlowError<X::Error>> {
    PaymentFlow {
        provider,
        policy,
        events,
        max_payment_retries,
    }
    .run(exchange, request, None)
    .await
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
        let payment_allowed = !matches!(self.policy, AcceptPaymentPolicy::Disabled)
            && if request.headers().contains_key(ACCEPT_PAYMENT_HEADER) {
                caller_accept.as_deref().is_some_and(|value| {
                    crate::protocol::core::accept_payment::parse(value)
                        .is_ok_and(|entries| !entries.is_empty())
                })
            } else {
                self.policy.allows(request.url())
            };
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
        // The provider sees the request as the caller built it.
        let payment_context = retry.as_ref().map(|retry| {
            let mut headers = retry.headers().clone();
            if injected {
                headers.remove(ACCEPT_PAYMENT_HEADER);
            }
            PaymentContext {
                http_client: exchange.http_client(),
                url: retry.url().clone(),
                headers,
            }
        });
        let prepaid = match (&initial_response, &payment_context) {
            (None, Some(context)) if payment_allowed && exchange.allows_prepaid() => {
                self.provider.prepaid_credential(context.clone()).await
            }
            _ => None,
        };
        let mut resp = match (initial_response, prepaid, &payment_context) {
            (Some(response), _, _) => response,
            (None, Some((challenge, credential)), Some(context)) => match self
                .send_prepaid(
                    exchange,
                    request,
                    retry.as_ref(),
                    context,
                    challenge,
                    credential,
                )
                .await?
            {
                Prepaid::Answered(response) => return Ok(response),
                Prepaid::Unpaid(response) => response,
            },
            _ => exchange.send(request).await.map_err(FlowError::Send)?,
        };

        if resp.status() != StatusCode::PAYMENT_REQUIRED || !payment_allowed {
            return Ok(resp);
        }

        let (Some(retry), Some(payment_context)) = (retry, payment_context) else {
            return Err(self.fail(None, HttpError::CloneFailed).await);
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

            let safe_supported = challenges.iter().any(|challenge| {
                exchange.check_challenge(challenge).is_ok()
                    && self
                        .provider
                        .supports(challenge.method.as_str(), challenge.intent.as_str())
            });
            if !safe_supported {
                for challenge in challenges.iter().filter(|challenge| {
                    self.provider
                        .supports(challenge.method.as_str(), challenge.intent.as_str())
                }) {
                    if let Err(error) = exchange.check_challenge(challenge) {
                        return Err(self.fail(Some(challenge.clone()), error).await);
                    }
                }
            }

            let challenge = match select_supported_challenge(
                &challenges,
                ranking_accept.as_deref(),
                |challenge| {
                    exchange.check_challenge(challenge).is_ok()
                        && self
                            .provider
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

            // A provider's selector must not bypass transport restrictions.
            if let Err(error) =
                self.check_challenge(exchange, &challenge, ranking_accept.as_deref())
            {
                return Err(self.fail(Some(challenge), error).await);
            }

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
            if is_cross_realm_proof_with_trust(
                &challenge,
                &payment_context.url,
                &payment_context.headers,
                self.provider
                    .trusted_tempo_proof_realm(&payment_context.url),
            ) {
                return Err(self.fail(Some(challenge), HttpError::CrossRealmProof).await);
            }
            // Preparation may replace the challenge. Recheck before creating
            // a credential, including the charge-only owned transport's limit.
            if let Err(error) =
                self.check_challenge(exchange, &challenge, ranking_accept.as_deref())
            {
                return Err(self.fail(Some(challenge), error).await);
            }
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
                    let reason = outcome_unknown(None, &challenge, &credential);
                    self.events
                        .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                            challenge: Some(challenge),
                            error: err.to_string(),
                            reason,
                        }))
                        .await;
                    // The request may have reached the server even though its
                    // response was lost. Preserve optimistic provider state
                    // until a later challenge can reconcile it, while
                    // releasing any delivery lease held by the provider.
                    drop(pending);
                    return Err(FlowError::Send(err));
                }
            };

            let status = resp.status();
            let receipt = paid_receipt(&resp, &challenge, &credential);
            let session = challenge.intent.as_str() == "session";
            let session_receipt_valid = !session || receipt.is_some();
            if status.is_success() {
                let amount = self.charged(&payment_context, &challenge, receipt.as_ref(), session);
                let funding_currency = self.provider.funding_currency(&challenge);
                self.events
                    .emit(ClientEvent::PaymentResponse(PaymentResponseContext {
                        challenge,
                        credential,
                        status,
                        url: payment_context.url.clone(),
                        receipt: receipt.map(Box::new),
                        amount,
                        funding_currency,
                    }))
                    .await;
                if session_receipt_valid {
                    pending.commit().await.map_err(HttpError::Payment)?;
                } else {
                    drop(pending);
                }
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

            let has_receipt = resp.headers().contains_key("payment-receipt");

            // The credential was spent but the server failed, so the payment
            // may have settled. Report it like mppx before any fallible state
            // transition, and still return the response so callers can inspect
            // it. The request is not retried.
            if status.is_server_error() {
                let reason = outcome_unknown(Some(status.as_u16()), &challenge, &credential);
                self.events
                    .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                        challenge: Some(challenge),
                        error: format!("payment outcome unknown: paid request returned {status}"),
                        reason,
                    }))
                    .await;
                if has_receipt && session_receipt_valid {
                    pending.commit().await.map_err(HttpError::Payment)?;
                } else {
                    // Like a lost response, an unknown outcome must not roll
                    // back state the server may already have accepted.
                    drop(pending);
                }
                return Ok(resp);
            }

            if has_receipt {
                if session_receipt_valid {
                    pending.commit().await.map_err(HttpError::Payment)?;
                } else {
                    drop(pending);
                }
            } else {
                pending.rollback().await.map_err(HttpError::Payment)?;
            }

            // Any other completed HTTP response is the application's answer,
            // not a payment flow error. Match MPPx by returning non-402
            // responses and the final 402 without emitting `payment.failed`.
            if status != StatusCode::PAYMENT_REQUIRED || payment_attempt == self.max_payment_retries
            {
                return Ok(resp);
            }
        }

        Ok(resp)
    }

    /// Neither provider selection nor preparation can expand transport or
    /// request permissions, or replace an offer with an unsupported/expired one.
    fn check_challenge<X: Exchange>(
        &self,
        exchange: &X,
        challenge: &PaymentChallenge,
        ranking_accept: Option<&str>,
    ) -> Result<(), HttpError> {
        exchange.check_challenge(challenge)?;
        select_supported_challenge(
            std::slice::from_ref(challenge),
            ranking_accept,
            |challenge| {
                self.provider
                    .supports(challenge.method.as_str(), challenge.intent.as_str())
            },
            |candidates| candidates.first().copied(),
        )
        .map(|_| ())
        .map_err(|error| match error {
            ChallengeSelectionError::Expired(challenge) => {
                HttpError::Payment(expired_payment_error(&challenge))
            }
            ChallengeSelectionError::NoSupportedChallenge(message) => {
                HttpError::NoSupportedChallenge(message)
            }
        })
    }

    /// Sends `request` with a credential the provider prepared before any
    /// `402`. When the server asks for payment again, or no longer knows the
    /// session channel, the request is sent once more without it so the normal
    /// flow pays a freshly quoted challenge.
    async fn send_prepaid<X: Exchange>(
        &self,
        exchange: &mut X,
        mut request: Request,
        retry: Option<&Request>,
        context: &PaymentContext,
        challenge: PaymentChallenge,
        credential: PaymentCredential,
    ) -> Result<Prepaid, FlowError<X::Error>> {
        let Ok(header) = authorization_value(&credential) else {
            return exchange
                .send(request)
                .await
                .map(Prepaid::Unpaid)
                .map_err(FlowError::Send);
        };
        request.headers_mut().insert(
            crate::client::payment_credential_header_name(&challenge),
            header,
        );
        self.events
            .emit(ClientEvent::CredentialCreated(CredentialCreatedContext {
                challenge: challenge.clone(),
                credential: credential.clone(),
            }))
            .await;
        let resp = match exchange.send(request).await {
            Ok(resp) => resp,
            Err(err) => {
                let reason = outcome_unknown(None, &challenge, &credential);
                self.events
                    .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                        challenge: Some(challenge),
                        error: err.to_string(),
                        reason,
                    }))
                    .await;
                return Err(FlowError::Send(err));
            }
        };
        let status = resp.status();
        if status.is_server_error() {
            let reason = outcome_unknown(Some(status.as_u16()), &challenge, &credential);
            self.events
                .emit(ClientEvent::PaymentFailed(PaymentFailedContext {
                    challenge: Some(challenge),
                    error: format!("payment outcome unknown: paid request returned {status}"),
                    reason,
                }))
                .await;
            return Ok(Prepaid::Answered(resp));
        }
        if status == StatusCode::PAYMENT_REQUIRED || status == StatusCode::GONE {
            if status == StatusCode::GONE {
                self.provider
                    .invalidate_payment(&challenge, &credential)
                    .await
                    .map_err(HttpError::Payment)?;
            }
            let retry = retry
                .and_then(Request::try_clone)
                .ok_or(HttpError::CloneFailed)?;
            return exchange
                .send(retry)
                .await
                .map(Prepaid::Unpaid)
                .map_err(FlowError::Send);
        }
        if status.is_success() {
            let receipt = paid_receipt(&resp, &challenge, &credential);
            let session = challenge.intent.as_str() == "session";
            let amount = self.charged(context, &challenge, receipt.as_ref(), session);
            let funding_currency = self.provider.funding_currency(&challenge);
            self.events
                .emit(ClientEvent::PaymentResponse(PaymentResponseContext {
                    challenge,
                    credential,
                    status,
                    url: context.url.clone(),
                    receipt: receipt.map(Box::new),
                    amount,
                    funding_currency,
                }))
                .await;
        }
        Ok(Prepaid::Answered(resp))
    }

    /// Records a paid response's receipt and returns what the request cost: a
    /// session's change in `spent` as the provider tracks it, or the amount a
    /// charge challenge asked for.
    fn charged(
        &self,
        context: &PaymentContext,
        challenge: &PaymentChallenge,
        receipt: Option<&Receipt>,
        session: bool,
    ) -> Option<u128> {
        if session {
            return receipt
                .and_then(|receipt| self.provider.record_receipt(context, challenge, receipt));
        }
        challenge
            .request
            .decode::<serde_json::Value>()
            .ok()?
            .get("amount")?
            .as_str()?
            .parse()
            .ok()
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

/// Whether a zero-amount Tempo challenge names a different host than the caller's request.
pub fn is_cross_realm_proof(
    challenge: &PaymentChallenge,
    url: &reqwest::Url,
    headers: &HeaderMap,
) -> bool {
    is_cross_realm_proof_with_trust(challenge, url, headers, None)
}

/// Apply an explicit caller-pinned proof realm for a known HTTP origin.
pub fn is_cross_realm_proof_with_trust(
    challenge: &PaymentChallenge,
    url: &reqwest::Url,
    headers: &HeaderMap,
    trusted_realm: Option<&str>,
) -> bool {
    let requested_host = headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| reqwest::Url::parse(&format!("http://{value}")).ok())
        .and_then(|host| host.host_str().map(str::to_owned))
        .or_else(|| url.host_str().map(str::to_owned))
        .unwrap_or_default();
    challenge.method.as_str() == "tempo"
        && challenge.intent.as_str() == "charge"
        && challenge
            .request
            .decode::<crate::protocol::intents::ChargeRequest>()
            .ok()
            .and_then(|request| request.parse_amount().ok())
            == Some(0)
        && !challenge.realm.eq_ignore_ascii_case(&requested_host)
        && trusted_realm != Some(challenge.realm.as_str())
}

/// The receipt answering a session `credential`, when the response carries a valid one.
/// The paid response's receipt: for a session only one that matches the
/// challenge and the channel the credential paid from.
fn paid_receipt(
    resp: &Response,
    challenge: &PaymentChallenge,
    credential: &PaymentCredential,
) -> Option<Receipt> {
    if challenge.intent.as_str() == "session" {
        return session_receipt(resp, challenge, credential);
    }
    resp.headers()
        .get("payment-receipt")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| parse_receipt(v).ok())
}

fn session_receipt(
    resp: &Response,
    challenge: &PaymentChallenge,
    credential: &PaymentCredential,
) -> Option<Receipt> {
    resp.headers()
        .get("payment-receipt")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| parse_receipt(v).ok())
        .filter(|receipt| {
            receipt.is_success()
                && receipt.method == challenge.method
                && receipt
                    .extensions
                    .get("challengeId")
                    .and_then(|v| v.as_str())
                    == Some(challenge.id.as_str())
                && credential
                    .payload
                    .get("channelId")
                    .and_then(|v| v.as_str())
                    .is_some_and(|id| receipt.reference.eq_ignore_ascii_case(id))
        })
}

/// The `payment.failed` reason for a credential that was sent without a
/// successful answer, or `None` when the credential cannot be serialized.
fn outcome_unknown(
    status: Option<u16>,
    challenge: &PaymentChallenge,
    credential: &PaymentCredential,
) -> Option<PaymentFailureReason> {
    let transaction_hash = (challenge.method.as_str() == "tempo"
        && challenge.intent.as_str() == "charge"
        && credential.payload.get("type").and_then(|v| v.as_str()) == Some("hash"))
    .then(|| credential.payload.get("hash").and_then(|v| v.as_str()))
    .flatten()
    .map(str::to_owned);
    Some(PaymentFailureReason::OutcomeUnknown {
        status,
        credential: format_authorization(credential).ok()?,
        transaction_hash,
    })
}

fn authorization_value(credential: &PaymentCredential) -> Result<HeaderValue, HttpError> {
    let header = format_authorization(credential)
        .map_err(|err| HttpError::InvalidCredential(err.to_string()))?;
    HeaderValue::from_str(&header).map_err(|err| HttpError::InvalidCredential(err.to_string()))
}

#[cfg(all(test, feature = "middleware"))]
mod tests;
