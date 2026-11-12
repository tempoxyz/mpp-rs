//! The HTTP 402 payment flow shared by [`Fetch`](super::Fetch) and
//! [`PaymentMiddleware`](super::PaymentMiddleware).

use std::collections::HashSet;
use std::fmt::Display;
use std::future::Future;

use reqwest::header::{HeaderMap, HeaderValue, HOST, WWW_AUTHENTICATE};
use reqwest::{Method, Request, Response, StatusCode};

use super::accept_payment_policy::AcceptPaymentPolicy;
use super::challenge_selection::{
    expired_payment_error, select_supported_challenge, with_available_methods,
    ChallengeSelectionError,
};
use super::error::HttpError;
use super::events::{
    ChallengeDecision, ChallengeReceivedContext, ClientEvent, ClientEvents,
    CredentialCreatedContext, OnChallengeContext, PaymentFailedContext, PaymentFailureReason,
    PaymentResponseContext,
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
    /// The default accepts only challenges that send the credential in
    /// `Authorization`, which HTTP clients drop on a redirect to another
    /// host. A client that follows redirects forwards `Payment-Authorization`
    /// to wherever the server redirects the paid request, so the default
    /// refuses it with [`HttpError::UnsafeCredentialHeader`] before signing.
    /// Override this to accept `Payment-Authorization` on a transport that
    /// never follows redirects, as [`ChargeClient`](super::ChargeClient) does,
    /// or to restrict challenges further.
    fn check_challenge(&self, challenge: &PaymentChallenge) -> Result<(), HttpError> {
        if challenge
            .credential_header()
            .eq_ignore_ascii_case("Authorization")
        {
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

    /// Whether the request sent to `request_url` was redirected before
    /// `response` arrived.
    ///
    /// A redirected non-GET/HEAD request may have become a GET (301/302/303),
    /// so the flow refuses to pay it automatically. reqwest keeps no redirect
    /// history, so the default treats any change of URL (ignoring the
    /// fragment) as a redirect. It cannot see a redirect back to the same URL;
    /// disable redirects on the client to rule those out. Override this when
    /// the transport knows: return `false` when it never follows redirects
    /// (so a URL rewritten below the flow is still paid), or `true` when its
    /// recorded redirect history shows a hop, including a same-URL one.
    fn redirected(&self, request_url: &reqwest::Url, response: &Response) -> bool {
        !same_resource(request_url, response.url())
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
        // A credential the caller set on the request is sent as it is, like
        // mppx's `initialCredentialSent`; its rejection is answered below.
        let caller_credential = carries_payment_credential(request.headers());
        let request_headers = caller_credential.then(|| request.headers().clone());
        let prepaid = match (&initial_response, &payment_context) {
            // A prepaid credential is sent before any 402, so it would bypass
            // the approval hook; with a hook set, every payment waits for one.
            (None, Some(context))
                if payment_allowed
                    && !caller_credential
                    && exchange.allows_prepaid()
                    && !self.events.has_on_challenge() =>
            {
                self.provider.prepaid_credential(context.clone()).await
            }
            _ => None,
        };
        // A cached Challenge must still satisfy this caller's realm pins for
        // this request, as a fresh one would before it is paid below.
        let prepaid = prepaid.filter(|(challenge, credential)| {
            let cross_realm = payment_context.as_ref().is_none_or(|context| {
                is_cross_realm_proof_with_trust(
                    challenge,
                    &context.url,
                    &context.headers,
                    self.provider.trusted_tempo_proof_realm(&context.url),
                )
            });
            if cross_realm
                || self
                    .check_challenge(exchange, challenge, ranking_accept.as_deref())
                    .is_err()
            {
                self.provider.abandon_payment(challenge, credential);
                false
            } else {
                true
            }
        });
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

        // The caller's own credential was refused. Under the same rules as a
        // credential this flow sent, the 402 is final: the earlier payment
        // behind that credential may have settled, so paying the fresh
        // challenge could pay twice.
        if caller_credential {
            // A hash credential's transfer is already on chain, so any 402
            // answering it is final, as for a hash credential this flow sent.
            if carries_hash_credential(request_headers.as_ref()) {
                return Ok(resp);
            }
            let (rebuilt, rejected) = credential_rejected(resp).await;
            resp = rebuilt;
            if rejected {
                return Ok(resp);
            }
        } else if is_problem_json(&resp) {
            // A credential can reach the server without being on the request
            // seen here, such as from the client's default headers. Servers
            // answer invalid-challenge only to a credential, so it is final
            // here too.
            let (rebuilt, problem_type) = read_problem_type(resp).await;
            resp = rebuilt;
            if problem_type.is_some_and(|kind| kind.ends_with("/invalid-challenge")) {
                return Ok(resp);
            }
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

            // A redirected non-GET/HEAD request may have become a GET
            // (301/302/303) before reaching the challenge. Refuse to guess the
            // method to pay with; the transport says whether it was redirected.
            let method = retry.method();
            if *method != Method::GET
                && *method != Method::HEAD
                && exchange.redirected(&payment_context.url, &resp)
            {
                // After a paid retry the request may already have run, so hand
                // back the redirected 402 instead of an error that reads unpaid.
                if payment_attempt > 0 {
                    return Ok(resp);
                }
                return Err(self
                    .fail(None, HttpError::RedirectedRequest(method.to_string()))
                    .await);
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
                    let message = with_available_methods(
                        message,
                        self.provider.accept_payment_header().as_deref(),
                    );
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

            let mut override_credential = self
                .events
                .emit_challenge_received(ChallengeReceivedContext {
                    challenge: challenge.clone(),
                    challenges: challenges.clone(),
                })
                .await;
            // As in mppx, `challenge.received` credentials skip `onChallenge`.
            if override_credential.is_none() {
                match self
                    .events
                    .decide_on_challenge(OnChallengeContext {
                        challenge: challenge.clone(),
                        challenges,
                        // The credential goes to the final URL of any
                        // same-origin redirect, so that is what is approved.
                        url: resp.url().clone(),
                        method: retry.method().clone(),
                        headers: payment_context.headers.clone(),
                    })
                    .await
                {
                    ChallengeDecision::Pay => {}
                    // Declined before anything was signed: hand back the 402.
                    ChallengeDecision::Decline => return Ok(resp),
                    ChallengeDecision::Credential(credential) => {
                        override_credential = Some(*credential);
                    }
                }
            }

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
            // The paid retry carries this credential alone: a caller's
            // credential in the field the challenge does not select would
            // make the server refuse a request that now carries two.
            remove_payment_credentials(paid.headers_mut());
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

            let session = challenge.intent.as_str() == "session";
            if session && resp.url().origin() != payment_context.url.origin() {
                // The credential may have been applied before the redirect.
                drop(pending);
                return Err(self
                    .fail(Some(challenge), session_response_origin_mismatch())
                    .await);
            }
            let status = resp.status();
            let receipt = paid_receipt(&resp, &challenge, &credential);
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

            // A hash credential's transfer is already on chain: paying a new
            // challenge for the same request would pay twice, so its answer is
            // final.
            if credential
                .charge_payload()
                .is_ok_and(|payload| payload.is_hash())
            {
                return Ok(resp);
            }

            // A credential the server refused as an invalid challenge (which is
            // also how a replayed credential is answered) must not be paid
            // again: the earlier payment may have settled, and paying the fresh
            // challenge could pay twice, so that 402 is final. So is an empty
            // 402, which is how the default Tower layer answers a rejected
            // credential, and a problem whose type cannot be read. A problem
            // naming another failure, such as verification-failed, or a 402
            // with another body is paid again, as in mppx (which has no
            // empty-body rejections to tell apart).
            if status == StatusCode::PAYMENT_REQUIRED {
                let (rebuilt, rejected) = credential_rejected(resp).await;
                resp = rebuilt;
                if rejected {
                    return Ok(resp);
                }
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
        if challenge.intent.as_str() == "session" && resp.url().origin() != context.url.origin() {
            return Err(self
                .fail(Some(challenge), session_response_origin_mismatch())
                .await);
        }
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

/// Whether two URLs name the same resource; fragments are never sent.
pub(crate) fn same_resource(a: &reqwest::Url, b: &reqwest::Url) -> bool {
    a.as_str().split('#').next() == b.as_str().split('#').next()
}

/// Whether a zero-amount Tempo proof or a Tempo session challenge names a
/// different host than the caller's request.
pub fn is_cross_realm_proof(
    challenge: &PaymentChallenge,
    url: &reqwest::Url,
    headers: &HeaderMap,
) -> bool {
    is_cross_realm_proof_with_trust(challenge, url, headers, None)
}

/// Apply an explicit caller-pinned proof realm for a known HTTP origin.
///
/// A zero-amount Tempo proof authenticates the payer at its realm, and a
/// session payment signs vouchers for it, so both are refused unless the realm
/// is the request's hostname or `trusted_realm`, as mppx does. A WebSocket
/// URL counts as HTTP; any other URL, such as an MCP resource, trusts only
/// `trusted_realm`.
pub fn is_cross_realm_proof_with_trust(
    challenge: &PaymentChallenge,
    url: &reqwest::Url,
    headers: &HeaderMap,
    trusted_realm: Option<&str>,
) -> bool {
    let requested_host = if matches!(url.scheme(), "http" | "https" | "ws" | "wss") {
        headers
            .get(HOST)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| reqwest::Url::parse(&format!("http://{value}")).ok())
            .and_then(|host| host.host_str().map(str::to_owned))
            .or_else(|| url.host_str().map(str::to_owned))
    } else {
        None
    };
    let binds_realm = challenge.method.as_str() == "tempo"
        && match challenge.intent.as_str() {
            "session" => true,
            "charge" => {
                challenge
                    .request
                    .decode::<crate::protocol::intents::ChargeRequest>()
                    .ok()
                    .and_then(|request| request.parse_amount().ok())
                    == Some(0)
            }
            _ => false,
        };
    binds_realm
        && !requested_host.is_some_and(|host| challenge.realm.eq_ignore_ascii_case(&host))
        && trusted_realm != Some(challenge.realm.as_str())
}

/// Whether `headers` carry a Payment credential: a `Payment-Authorization`
/// header, or a `Payment` scheme anywhere in an `Authorization` value,
/// including one comma-joined after another scheme, as the server reads it.
fn carries_payment_credential(headers: &reqwest::header::HeaderMap) -> bool {
    headers.contains_key("payment-authorization")
        || headers
            .get_all(reqwest::header::AUTHORIZATION)
            .iter()
            .any(authorization_has_payment)
}

/// Whether an `Authorization` value holds a `Payment` scheme in any of its
/// comma-separated elements.
fn authorization_has_payment(value: &HeaderValue) -> bool {
    match value.to_str() {
        Ok(text) => {
            !crate::protocol::core::headers::payment_credentials(text).is_empty()
                || scheme_starts(text)
                    .any(|(element, starts)| starts && is_payment_element(element))
        }
        Err(_) => value.as_bytes().split(|byte| *byte == b',').any(|element| {
            element
                .trim_ascii_start()
                .split(|byte| *byte == b' ')
                .next()
                .is_some_and(|scheme| scheme.eq_ignore_ascii_case(b"payment"))
        }),
    }
}

/// The comma-separated elements of an `Authorization` value, with commas
/// inside quoted strings kept.
fn authorization_elements(value: &str) -> Vec<&str> {
    let mut elements = Vec::new();
    let (mut start, mut quoted, mut escaped) = (0, false, false);
    for (index, byte) in value.bytes().enumerate() {
        if escaped {
            escaped = false;
        } else if quoted && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            quoted = !quoted;
        } else if byte == b',' && !quoted {
            elements.push(&value[start..index]);
            start = index + 1;
        }
    }
    elements.push(&value[start..]);
    elements
}

/// The elements of an `Authorization` value, each with whether it starts a
/// new scheme. The first non-empty element is the first word of the value.
fn scheme_starts(value: &str) -> impl Iterator<Item = (&str, bool)> {
    let mut first = true;
    authorization_elements(value)
        .into_iter()
        .map(move |element| {
            let starts = starts_scheme(element, first);
            first &= element.trim_ascii().is_empty();
            (element, starts)
        })
}

/// Whether an element that starts a scheme starts a `Payment` one:
/// `Payment` alone or followed by whitespace.
fn is_payment_element(element: &str) -> bool {
    let scheme = element
        .trim_ascii_start()
        .split(|c: char| c.is_ascii_whitespace())
        .next()
        .unwrap_or("");
    scheme.eq_ignore_ascii_case("payment")
}

/// Whether an element starts a new scheme rather than continuing the
/// previous one's auth-params (`name BWS = BWS value`), as the crate's
/// header tokenizer decides: a first word followed by `=`, after optional
/// whitespace, is an auth-param, except in the first element of the value
/// (`first`), where a word followed by SP or HTAB is always a scheme. A
/// token68 ending in `=` padding follows its scheme and a space, so it does
/// not make its element an auth-param.
fn starts_scheme(element: &str, first: bool) -> bool {
    let element = element.trim_ascii_start();
    if element.is_empty() {
        return false;
    }
    let name_end = element
        .find(|c: char| c == '=' || c.is_ascii_whitespace())
        .unwrap_or(element.len());
    let after_name = &element[name_end..];
    !after_name.trim_ascii_start().starts_with('=')
        || (first && after_name.starts_with([' ', '\t']))
}

/// An `Authorization` value without its `Payment` schemes and their
/// parameters, or `None` when nothing else is left.
fn without_payment_schemes(value: &str) -> Option<String> {
    let mut kept: Vec<&str> = Vec::new();
    let mut in_payment = false;
    for (element, starts) in scheme_starts(value) {
        if starts {
            in_payment = is_payment_element(element);
        }
        if !in_payment && !element.trim().is_empty() {
            kept.push(element.trim());
        }
    }
    (!kept.is_empty()).then(|| kept.join(", "))
}

/// Remove every Payment credential from a request's headers:
/// `Payment-Authorization` and any `Payment` scheme in an `Authorization`
/// value, including one comma-joined with another scheme. The other schemes
/// stay.
fn remove_payment_credentials(headers: &mut HeaderMap) {
    headers.remove("payment-authorization");
    let kept: Vec<HeaderValue> = headers
        .get_all(reqwest::header::AUTHORIZATION)
        .iter()
        .filter_map(|value| {
            if !authorization_has_payment(value) {
                return Some(value.clone());
            }
            let rest = without_payment_schemes(value.to_str().ok()?)?;
            let mut rebuilt = HeaderValue::from_str(&rest).ok()?;
            rebuilt.set_sensitive(value.is_sensitive());
            Some(rebuilt)
        })
        .collect();
    headers.remove(reqwest::header::AUTHORIZATION);
    for value in kept {
        headers.append(reqwest::header::AUTHORIZATION, value);
    }
}

/// Whether the caller's own credential on a request is a Tempo hash (push)
/// credential, whose transfer is already on chain. Reads `Authorization:
/// Payment` and `Payment-Authorization` (with or without the scheme).
fn carries_hash_credential(headers: Option<&HeaderMap>) -> bool {
    let Some(headers) = headers else {
        return false;
    };
    let is_hash = |value: &str| {
        crate::protocol::core::parse_authorization(value)
            .or_else(|_| crate::protocol::core::parse_authorization(&format!("Payment {value}")))
            .ok()
            .and_then(|credential| credential.charge_payload().ok())
            .is_some_and(|payload| payload.is_hash())
    };
    headers
        .get_all(reqwest::header::AUTHORIZATION)
        .iter()
        .chain(headers.get_all("payment-authorization").iter())
        .filter_map(|value| value.to_str().ok())
        .any(is_hash)
}

/// Whether a `402` answering a credential is final rather than a fresh
/// Challenge to pay: an `invalid-challenge` problem (how a replayed
/// credential is answered), a problem whose type cannot be read, or an empty
/// body (how the default Tower layer answers a rejected credential). A
/// problem naming another failure, such as `verification-failed`, or a 402
/// with another body is paid again, as in mppx. Returns an equivalent
/// response, since reading the problem type consumes the body.
async fn credential_rejected(resp: Response) -> (Response, bool) {
    if is_problem_json(&resp) {
        let (rebuilt, problem_type) = read_problem_type(resp).await;
        let rejected = problem_type.is_none_or(|kind| kind.ends_with("/invalid-challenge"));
        (rebuilt, rejected)
    } else {
        has_empty_body(resp).await
    }
}

/// Whether a response's body is RFC 9457 problem details.
fn is_problem_json(resp: &Response) -> bool {
    resp.headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(';').next().is_some_and(|media| {
                media
                    .trim()
                    .eq_ignore_ascii_case("application/problem+json")
            })
        })
}

/// The most of a paid request's `402` body the flow reads to learn its
/// problem type or whether it is empty. The server picks the body's size, so
/// reading stops here; the rest is handed back unread.
const MAX_PROBLEM_BODY_BYTES: usize = 64 * 1024;

/// Read up to `limit` bytes of `resp`'s body and return them, whether that
/// was the whole body, and an equivalent response: same status, version,
/// headers, extensions and URL, whose body is the bytes read followed by the
/// unread rest of the stream, or by the read error that cut it short.
async fn peek_body(mut resp: Response, limit: usize) -> (Response, Vec<u8>, bool) {
    use futures_util::StreamExt;
    use reqwest::ResponseBuilderExt;

    let status = resp.status();
    let version = resp.version();
    let url = resp.url().clone();
    let headers = resp.headers().clone();
    let extensions = resp.extensions().clone();
    let mut read = Vec::new();
    let mut overflow = None;
    let mut error = None;
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let room = limit - read.len();
                if chunk.len() > room {
                    read.extend_from_slice(&chunk[..room]);
                    overflow = Some(chunk.slice(room..));
                    break;
                }
                read.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(err) => {
                error = Some(err);
                break;
            }
        }
    }
    let complete = overflow.is_none() && error.is_none();
    let body = if complete {
        reqwest::Body::from(read.clone())
    } else {
        let head = futures_util::stream::once(std::future::ready(Ok::<_, reqwest::Error>(
            bytes::Bytes::from(read.clone()),
        )));
        match (overflow, error) {
            (Some(overflow), _) => reqwest::Body::wrap_stream(
                head.chain(futures_util::stream::once(std::future::ready(Ok(overflow))))
                    .chain(resp.bytes_stream()),
            ),
            (None, Some(err)) => reqwest::Body::wrap_stream(
                head.chain(futures_util::stream::once(std::future::ready(Err(err)))),
            ),
            (None, None) => unreachable!("an incomplete read has overflow or an error"),
        }
    };
    let mut builder = http_types::Response::builder()
        .status(status)
        .version(version);
    if let Some(builder_extensions) = builder.extensions_mut() {
        *builder_extensions = extensions;
    }
    // After the extensions, so the URL is kept.
    let mut builder = builder.url(url);
    if let Some(builder_headers) = builder.headers_mut() {
        *builder_headers = headers;
    }
    let rebuilt = builder
        .body(body)
        .map(Response::from)
        .unwrap_or_else(|_| Response::from(http_types::Response::new(Vec::<u8>::new())));
    (rebuilt, read, complete)
}

/// Whether `resp`'s body is empty, with an equivalent response. A body
/// that fails to arrive is not counted as empty.
async fn has_empty_body(resp: Response) -> (Response, bool) {
    let (rebuilt, read, complete) = peek_body(resp, MAX_PROBLEM_BODY_BYTES).await;
    (rebuilt, complete && read.is_empty())
}

/// Read the problem type of a problem-details response, and return an
/// equivalent response with the same status, headers, extensions, URL and
/// whole body. A body cut at the limit or by a read error has no type.
async fn read_problem_type(resp: Response) -> (Response, Option<String>) {
    let (rebuilt, read, complete) = peek_body(resp, MAX_PROBLEM_BODY_BYTES).await;
    let problem_type = complete
        .then(|| serde_json::from_slice::<serde_json::Value>(&read).ok())
        .flatten()
        .and_then(|problem| problem.get("type")?.as_str().map(str::to_string));
    (rebuilt, problem_type)
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
                && session_receipt_within_authorization(receipt, credential)
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

/// Remote receipt accounting cannot exceed the voucher sent on this request.
fn session_receipt_within_authorization(receipt: &Receipt, credential: &PaymentCredential) -> bool {
    let amount = |value: &serde_json::Value| value.as_str()?.parse::<u128>().ok();
    let Some(spent) = receipt.extensions.get("spent") else {
        return true;
    };
    let Some(spent) = amount(spent) else {
        return false;
    };
    let Some(authorized) = credential.payload.get("cumulativeAmount").and_then(amount) else {
        return false;
    };
    if spent > authorized {
        return false;
    }
    receipt
        .extensions
        .get("acceptedCumulative")
        .is_none_or(|value| {
            amount(value).is_some_and(|accepted| spent <= accepted && accepted <= authorized)
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

/// A paid session request answered from another origin, after a redirect the
/// caller's client followed. Its receipt must not update session state, as in
/// mppx's `SessionManager`.
fn session_response_origin_mismatch() -> HttpError {
    HttpError::Payment(MppError::InvalidConfig(
        "session response origin mismatch".into(),
    ))
}

fn authorization_value(credential: &PaymentCredential) -> Result<HeaderValue, HttpError> {
    let header = format_authorization(credential)
        .map_err(|err| HttpError::InvalidCredential(err.to_string()))?;
    HeaderValue::from_str(&header).map_err(|err| HttpError::InvalidCredential(err.to_string()))
}

#[cfg(all(test, feature = "middleware"))]
mod tests;
