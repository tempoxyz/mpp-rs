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
/// Automatic payment requires a valid request-level `Accept-Payment` header.
/// Client default headers do not authorize payment. Preferences, including
/// `q=0` opt-outs, are respected by the shared challenge selector.
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
///         .bearer_auth("api-key")
///         .header("Accept-Payment", "tempo/charge"),
///     provider,
/// ).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct ChargeClient {
    client: Client,
    #[cfg(feature = "identity")]
    identity: Option<crate::identity::client::IdentityClient>,
}

impl ChargeClient {
    /// Build the retained client, overriding the builder's redirect policy last.
    /// No constructor accepts an already-built client with an opaque policy.
    pub fn new(builder: ClientBuilder) -> Result<Self, HttpError> {
        Ok(Self {
            client: builder
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            #[cfg(feature = "identity")]
            identity: None,
        })
    }

    /// Proves every attempt of each request, unpaid and paid, with
    /// `identity`'s in-scope provers, as mppx's `Mppx.create({ identity })`.
    ///
    /// Provers run on requests that do not authorize payment too. This client
    /// never follows redirects, so proofs never reach another URL. A prover may
    /// resend a rejected unpaid attempt once; a paid attempt is never resent.
    #[cfg(feature = "identity")]
    pub fn with_identity(mut self, identity: crate::identity::client::IdentityClient) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Build a request for this client. Use [`Self::send_with_payment`] to send it.
    pub fn request(&self, method: Method, url: impl IntoUrl) -> RequestBuilder {
        self.client.request(method, url)
    }

    /// Send a request with explicit, charge-only payment handling.
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
        // applies client defaults at execute time, after this opt-in decision.
        let payment_allowed = request
            .headers()
            .get_all(ACCEPT_PAYMENT_HEADER)
            .iter()
            .count()
            == 1
            && preference
                .and_then(|value| value.to_str().ok())
                .and_then(|value| accept_payment::parse(value).ok())
                .is_some_and(|entries| entries.iter().any(|entry| entry.q > 0.0));
        let exchange = ChargeExchange(&self.client);
        let max_payment_retries = if payment_allowed {
            max_payment_retries
        } else {
            0
        };
        #[cfg(feature = "identity")]
        if let Some(identity) = &self.identity {
            let exchange = crate::identity::client::IdentityExchange::new(exchange, identity);
            return run(exchange, request, provider, max_payment_retries).await;
        }
        run(exchange, request, provider, max_payment_retries).await
    }
}

/// Sends `request` through `exchange`, paying charge challenges unless
/// `max_payment_retries` is zero.
async fn run<X, P>(
    mut exchange: X,
    request: Request,
    provider: &P,
    max_payment_retries: usize,
) -> Result<Response, HttpError>
where
    X: Exchange<Error = HttpError>,
    P: PaymentProvider,
{
    if max_payment_retries == 0 {
        return exchange.send(request).await;
    }
    let flow = PaymentFlow {
        provider,
        policy: &AcceptPaymentPolicy::Never,
        events: &ClientEvents::default(),
        max_payment_retries,
    };
    flow.run(&mut exchange, request, None)
        .await
        .map_err(|error| match error {
            FlowError::Payment(error) | FlowError::Send(error) => error,
        })
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
        if challenge
            .credential_header()
            .eq_ignore_ascii_case("Authorization")
            || challenge
                .credential_header()
                .eq_ignore_ascii_case("Payment-Authorization")
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
