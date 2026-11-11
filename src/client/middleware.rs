//! reqwest-middleware integration for automatic 402 handling.
//!
//! Provides `PaymentMiddleware` for use with `reqwest_middleware::ClientBuilder`.

use async_trait::async_trait;
use reqwest::{Request, Response};
use reqwest_middleware::{Middleware, Next};

use crate::client::accept_payment_policy::AcceptPaymentPolicy;
use crate::client::events::{
    ChallengeDecision, ChallengeReceivedContext, ClientEventSubscription, ClientEvents,
    CredentialCreatedContext, OnChallengeContext, PaymentFailedContext, PaymentResponseContext,
};
use crate::client::flow::{same_resource, Exchange, FlowError, PaymentFlow};
use crate::client::provider::PaymentProvider;
use crate::client::DEFAULT_MAX_PAYMENT_RETRIES;

/// Middleware that automatically handles 402 Payment Required responses.
///
/// When a request returns 402, the middleware:
/// 1. Parses the challenge from the `WWW-Authenticate` header
/// 2. Calls the provider to execute the payment
/// 3. Retries the request with the credential in the header the challenge
///    names: `Authorization`, or `Payment-Authorization` for servers that keep
///    `Authorization` for their own auth
///
/// It pays without a request-level `Accept-Payment` header by default, as
/// mppx does; select [`AcceptPaymentPolicy::Explicit`] to pay only requests
/// that set one. A client that follows redirects forwards
/// `Payment-Authorization` to another host, so build the inner client with
/// `reqwest::redirect::Policy::none()` when servers use that header. Approve
/// or decline each payment with [`with_on_challenge`](Self::with_on_challenge).
///
/// Payment failures are returned as [`HttpError`](crate::client::HttpError) inside
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
/// // A 402 is paid automatically
/// let resp = client.get("https://api.example.com/paid").send().await?;
/// ```
pub struct PaymentMiddleware<P> {
    provider: P,
    accept_payment_policy: AcceptPaymentPolicy,
    events: ClientEvents,
    max_payment_retries: usize,
    http_client: Option<reqwest::Client>,
    redirects_disabled: bool,
}

impl<P> PaymentMiddleware<P> {
    /// Create middleware with the given provider. Defaults to
    /// [`AcceptPaymentPolicy::Always`].
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            http_client: None,
            redirects_disabled: false,
            accept_payment_policy: AcceptPaymentPolicy::default(),
            events: ClientEvents::default(),
            max_payment_retries: DEFAULT_MAX_PAYMENT_RETRIES,
        }
    }

    /// Use the same configured HTTP client as the middleware stack for session
    /// management requests. Without this, automatic session top-ups are disabled.
    /// Management requests use this client directly, without the middleware chain.
    /// Put required redirect, proxy, TLS, and timeout policies on this client.
    ///
    /// ```ignore
    /// let http = reqwest::Client::builder()
    ///     .redirect(reqwest::redirect::Policy::none())
    ///     .build()?;
    /// let client = reqwest_middleware::ClientBuilder::new(http.clone())
    ///     .with(PaymentMiddleware::new(provider).with_http_client(http))
    ///     .build();
    /// ```
    pub fn with_http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    /// Declare that the client below this middleware never follows redirects,
    /// for example one built with `reqwest::redirect::Policy::none()`.
    ///
    /// The middleware cannot see the client's redirects, so by default a
    /// non-GET/HEAD request whose 402 arrives at a different URL is refused
    /// with [`HttpError::RedirectedRequest`](crate::client::HttpError::RedirectedRequest).
    /// With redirects disabled, a URL changed by inner middleware (an added
    /// signature query, a path prefix) is a rewrite, and the request is paid.
    pub fn with_redirects_disabled(mut self) -> Self {
        self.redirects_disabled = true;
        self
    }

    /// Explicitly permit provider preferences for matching URLs, or require
    /// request-level preferences. `Disabled` prevents payment regardless of headers.
    pub fn with_accept_payment_policy(mut self, policy: AcceptPaymentPolicy) -> Self {
        self.accept_payment_policy = policy;
        self
    }

    /// Use an existing event registry for payment callbacks.
    ///
    /// This replaces the registry, including an
    /// [`on_challenge`](Self::with_on_challenge) hook set before it.
    pub fn with_events(mut self, events: ClientEvents) -> Self {
        self.events = events;
        self
    }

    /// Call `handler` before paying each challenge, as mppx's `onChallenge`
    /// option does: return `true` to pay, `false` to return the `402` response
    /// without paying, or a [`ChallengeDecision`]. See
    /// [`ClientEvents::set_on_challenge`]. The hook is set on this
    /// middleware's event registry, which clones of it share.
    pub fn with_on_challenge<F, Fut, R>(self, handler: F) -> Self
    where
        F: Fn(OnChallengeContext) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = R> + Send + 'static,
        R: Into<ChallengeDecision> + Send + 'static,
    {
        self.events.set_on_challenge(handler);
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
        req: Request,
        extensions: &mut http_types::Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        let flow = PaymentFlow {
            provider: &self.provider,
            policy: &self.accept_payment_policy,
            events: &self.events,
            max_payment_retries: self.max_payment_retries,
        };
        flow.run(
            &mut NextExchange {
                next,
                extensions,
                http_client: self.http_client.clone(),
                redirects_disabled: self.redirects_disabled,
            },
            req,
            None,
        )
        .await
        .map_err(|err| match err {
            FlowError::Payment(err) => {
                reqwest_middleware::Error::Middleware(anyhow::Error::new(err))
            }
            FlowError::Send(err) => err,
        })
    }
}

/// The rest of the middleware chain.
struct NextExchange<'a, 'b> {
    next: Next<'a>,
    http_client: Option<reqwest::Client>,
    extensions: &'b mut http_types::Extensions,
    redirects_disabled: bool,
}

impl Exchange for NextExchange<'_, '_> {
    type Error = reqwest_middleware::Error;

    fn http_client(&self) -> Option<reqwest::Client> {
        self.http_client.clone()
    }

    fn redirected(&self, request_url: &reqwest::Url, response: &Response) -> bool {
        !self.redirects_disabled && !same_resource(request_url, response.url())
    }

    async fn send(&mut self, request: Request) -> reqwest_middleware::Result<Response> {
        self.next.clone().run(request, self.extensions).await
    }
}

#[cfg(test)]
mod tests;
