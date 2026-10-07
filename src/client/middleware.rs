//! reqwest-middleware integration for automatic 402 handling.
//!
//! Provides `PaymentMiddleware` for use with `reqwest_middleware::ClientBuilder`.

use async_trait::async_trait;
use reqwest::{Request, Response};
use reqwest_middleware::{Middleware, Next};

use crate::client::accept_payment_policy::AcceptPaymentPolicy;
use crate::client::events::{
    ChallengeReceivedContext, ClientEventSubscription, ClientEvents, CredentialCreatedContext,
    PaymentFailedContext, PaymentResponseContext,
};
use crate::client::flow::{Exchange, FlowError, PaymentFlow};
use crate::client::provider::PaymentProvider;
use crate::client::DEFAULT_MAX_PAYMENT_RETRIES;

/// Middleware that automatically handles 402 Payment Required responses.
///
/// When a request returns 402, the middleware:
/// 1. Parses the challenge from the `WWW-Authenticate` header
/// 2. Calls the provider to execute the payment
/// 3. Retries the request with the credential in the `Authorization` header
///
/// Challenges that select `Payment-Authorization` are rejected before payment
/// because this middleware cannot control the underlying client's redirect policy.
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
        flow.run(&mut NextExchange { next, extensions }, req, None)
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
    extensions: &'b mut http_types::Extensions,
}

impl Exchange for NextExchange<'_, '_> {
    type Error = reqwest_middleware::Error;

    async fn send(&mut self, request: Request) -> reqwest_middleware::Result<Response> {
        self.next.clone().run(request, self.extensions).await
    }
}

#[cfg(test)]
mod tests;
