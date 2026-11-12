//! SDK-owned HTTP client for opt-in charge payments without redirects.

use reqwest::{Client, ClientBuilder, IntoUrl, Method, Request, RequestBuilder, Response};

use super::flow::{Exchange, FlowError, PaymentFlow};
use super::{
    AcceptPaymentPolicy, ClientEvents, HttpError, PaymentProvider, DEFAULT_MAX_PAYMENT_RETRIES,
};
use crate::protocol::core::accept_payment::{self, ACCEPT_PAYMENT_HEADER};
use crate::protocol::core::PaymentChallenge;

/// An HTTP client that can answer charge challenges using either credential header.
///
/// This client always disables redirects, including for the initial request.
/// A `3xx` is returned to the caller without following its `Location`. Both the
/// initial request and every paid retry execute through the retained client.
/// Session challenges and session management are excluded. The provider's
/// prepaid-credential hook is never called; payment follows a server challenge.
///
/// It pays without a request-level `Accept-Payment` header by default, as
/// mppx does ([`AcceptPaymentPolicy::Always`]). Select
/// [`AcceptPaymentPolicy::Explicit`] with [`Self::with_accept_payment_policy`]
/// to require a valid request-level header; client default headers never count.
/// A request-level header that is repeated, malformed or opts out of every
/// method (`q=0`) is never paid. Approve or decline each payment with
/// [`Self::with_on_challenge`].
///
/// ```no_run
/// # async fn example<P: mpp::client::PaymentProvider>(provider: &P)
/// # -> Result<(), Box<dyn std::error::Error>> {
/// use mpp::client::ChargeClient;
/// use reqwest::Method;
///
/// let client = ChargeClient::new(reqwest::Client::builder())?;
/// let response = client.send_with_payment(
///     client.request(Method::GET, "https://api.example.com/paid")
///         .bearer_auth("api-key"),
///     provider,
/// ).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct ChargeClient {
    client: Client,
    accept_payment_policy: AcceptPaymentPolicy,
    events: ClientEvents,
}

impl ChargeClient {
    /// Build the retained client, overriding the builder's redirect policy last.
    /// No constructor accepts an already-built client with an opaque policy.
    pub fn new(builder: ClientBuilder) -> Result<Self, HttpError> {
        Ok(Self {
            client: builder
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            accept_payment_policy: AcceptPaymentPolicy::default(),
            events: ClientEvents::default(),
        })
    }

    /// Choose when requests are paid and carry the provider's `Accept-Payment`
    /// preferences. Defaults to [`AcceptPaymentPolicy::Always`];
    /// [`AcceptPaymentPolicy::Explicit`] pays only requests with a valid
    /// request-level header, and [`AcceptPaymentPolicy::Disabled`] never pays.
    pub fn with_accept_payment_policy(mut self, policy: AcceptPaymentPolicy) -> Self {
        self.accept_payment_policy = policy;
        self
    }

    /// Use an existing event registry for payment callbacks, including its
    /// [`on_challenge`](ClientEvents::set_on_challenge) hook.
    pub fn with_events(mut self, events: ClientEvents) -> Self {
        self.events = events;
        self
    }

    /// Call `handler` before paying each challenge, as mppx's `onChallenge`
    /// option does: return `true` to pay, `false` to return the `402` response
    /// without paying, or a [`ChallengeDecision`](super::ChallengeDecision).
    /// See [`ClientEvents::set_on_challenge`]; the hook is set on this client's
    /// event registry, which its clones share.
    pub fn with_on_challenge<F, Fut, R>(self, handler: F) -> Self
    where
        F: Fn(super::OnChallengeContext) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = R> + Send + 'static,
        R: Into<super::ChallengeDecision> + Send + 'static,
    {
        self.events.set_on_challenge(handler);
        self
    }

    /// Build a request for this client. Use [`Self::send_with_payment`] to send it.
    pub fn request(&self, method: Method, url: impl IntoUrl) -> RequestBuilder {
        self.client.request(method, url)
    }

    /// Send a request with charge-only payment handling.
    ///
    /// Only the request is taken from `request`; its embedded client is ignored.
    /// A request built by another client still executes through this client.
    pub async fn send_with_payment<P: PaymentProvider>(
        &self,
        request: RequestBuilder,
        provider: &P,
    ) -> Result<Response, HttpError> {
        self.send_with_payment_max_retries(request, provider, DEFAULT_MAX_PAYMENT_RETRIES)
            .await
    }

    /// Like [`Self::send_with_payment`], with a cap on paid challenge retries.
    /// Zero sends the initial request but never prepares or creates a payment.
    pub async fn send_with_payment_max_retries<P: PaymentProvider>(
        &self,
        request: RequestBuilder,
        provider: &P,
        max_payment_retries: usize,
    ) -> Result<Response, HttpError> {
        let request = request.build().map_err(HttpError::request)?;
        let preference = request.headers().get(ACCEPT_PAYMENT_HEADER);
        // Fail closed for ambiguous repeated or malformed preferences. Reqwest
        // applies client defaults at execute time, after this decision.
        let payment_allowed = match &self.accept_payment_policy {
            AcceptPaymentPolicy::Disabled => false,
            policy if preference.is_none() => {
                !matches!(policy, AcceptPaymentPolicy::Explicit) && policy.allows(request.url())
            }
            _ => {
                request
                    .headers()
                    .get_all(ACCEPT_PAYMENT_HEADER)
                    .iter()
                    .count()
                    == 1
                    && preference
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| accept_payment::parse(value).ok())
                        .is_some_and(|entries| entries.iter().any(|entry| entry.q > 0.0))
            }
        };
        let mut exchange = ChargeExchange(&self.client);
        if !payment_allowed || max_payment_retries == 0 {
            return exchange.send(request).await;
        }

        let flow = PaymentFlow {
            provider,
            policy: &self.accept_payment_policy,
            events: &self.events,
            max_payment_retries,
        };
        flow.run(&mut exchange, request, None)
            .await
            .map_err(|error| match error {
                FlowError::Payment(error) | FlowError::Send(error) => error,
            })
    }
}

// This transport can only be constructed beside the privately retained client.
struct ChargeExchange<'a>(&'a Client);

impl Exchange for ChargeExchange<'_> {
    type Error = HttpError;

    fn allows_prepaid(&self) -> bool {
        false
    }

    fn check_challenge(&self, challenge: &PaymentChallenge) -> Result<(), HttpError> {
        if challenge.intent.as_str() != "charge" {
            return Err(HttpError::NoSupportedChallenge(
                "ChargeClient only supports charge intents".to_owned(),
            ));
        }
        let header = challenge.credential_header();
        if header.eq_ignore_ascii_case("Authorization")
            || header.eq_ignore_ascii_case("Payment-Authorization")
        {
            Ok(())
        } else {
            Err(HttpError::UnsafeCredentialHeader)
        }
    }

    // The retained client never follows redirects, so a changed URL is not one.
    fn redirected(&self, _request_url: &reqwest::Url, _response: &Response) -> bool {
        false
    }

    async fn send(&mut self, request: Request) -> Result<Response, Self::Error> {
        self.0.execute(request).await.map_err(HttpError::request)
    }
}

#[cfg(test)]
mod tests;
