//! Extension trait for reqwest RequestBuilder.
//!
//! Provides `.send_with_payment()` method for opt-in per-request payment handling.

use reqwest::{Request, RequestBuilder, Response};

use super::accept_payment_policy::AcceptPaymentPolicy;
use super::error::HttpError;
use super::events::ClientEvents;
use super::flow::{Exchange, FlowError, PaymentFlow, Quirks};
use super::provider::PaymentProvider;
use super::DEFAULT_MAX_PAYMENT_RETRIES;

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
    // A request that cannot be repeated is refused before it is sent.
    let request = request.try_clone().ok_or(HttpError::CloneFailed)?;
    let (mut client, request) = request.build_split();
    let request = request.map_err(HttpError::request)?;

    let flow = PaymentFlow {
        provider,
        policy,
        events: &events,
        max_payment_retries,
        quirks: Quirks::FETCH,
    };
    flow.run(&mut client, request, initial_response)
        .await
        .map_err(|err| match err {
            FlowError::Payment(err) | FlowError::Send(err) => err,
        })
}

impl Exchange for reqwest::Client {
    type Error = HttpError;

    async fn send(&mut self, request: Request) -> Result<Response, HttpError> {
        self.execute(request).await.map_err(HttpError::request)
    }
}

#[cfg(test)]
mod tests;
