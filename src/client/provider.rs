//! Payment provider trait and implementations.
//!
//! The `PaymentProvider` trait abstracts over payment execution, allowing
//! different payment methods (Tempo, Stripe, etc.) to be used with the
//! HTTP client extensions.

use crate::error::MppError;
use crate::protocol::core::{PaymentChallenge, PaymentCredential};
use reqwest::header::HeaderMap;
use reqwest::Url;
use std::future::Future;

/// HTTP request context available while creating a payment credential.
///
/// Session providers use this to submit management credentials, such as a
/// channel top-up, to the same resource before replaying the paid request.
#[derive(Clone, Debug)]
pub struct PaymentContext {
    /// URL of the request that returned the payment challenge.
    pub url: Url,
    /// Caller-provided request headers to preserve for management requests.
    pub headers: HeaderMap,
}

/// Trait for payment providers that can execute payments for challenges.
///
/// Implement this trait to add support for custom payment methods.
/// PaymentProvider is the client-side counterpart to server-side method traits
/// like [`ChargeMethod`](crate::protocol::traits::ChargeMethod).
///
/// # Examples
///
/// ```ignore
/// use mpp::client::PaymentProvider;
/// use mpp::protocol::core::{PaymentChallenge, PaymentCredential, PaymentPayload};
/// use mpp::MppError;
///
/// #[derive(Clone)]
/// struct MyProvider { /* ... */ }
///
/// impl PaymentProvider for MyProvider {
///     fn supports(&self, method: &str, intent: &str) -> bool {
///         method == "my_network" && intent == "charge"
///     }
///
///     async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
///         // 1. Parse the challenge request
///         // 2. Execute payment (sign tx, call API, etc.)
///         // 3. Return credential with proof
///         let echo = challenge.to_echo();
///         Ok(PaymentCredential::new(echo, PaymentPayload::hash("0x...")))
///     }
/// }
/// ```
pub trait PaymentProvider: Clone + Send + Sync {
    /// Check if this provider supports the given method and intent combination.
    ///
    /// This allows clients to filter providers based on challenge requirements
    /// before attempting payment.
    ///
    /// # Arguments
    ///
    /// * `method` - Payment method name (e.g., "tempo", "stripe")
    /// * `intent` - Payment intent name (e.g., "charge", "authorize")
    ///
    /// # Returns
    ///
    /// `true` if this provider can handle the combination.
    fn supports(&self, method: &str, intent: &str) -> bool;

    /// Execute payment for the given challenge and return a credential.
    ///
    /// This method should:
    /// 1. Parse the challenge request for payment details
    /// 2. Execute the payment (sign transaction, call API, etc.)
    /// 3. Build and return a `PaymentCredential` with the proof
    fn pay(
        &self,
        challenge: &PaymentChallenge,
    ) -> impl Future<Output = Result<PaymentCredential, MppError>> + Send;

    /// Execute payment with access to the challenged HTTP request.
    ///
    /// Most providers only need the challenge and inherit this default. A
    /// session provider may use the URL and headers to top up its channel via
    /// the resource's management endpoint before returning a voucher.
    fn pay_with_context(
        &self,
        challenge: &PaymentChallenge,
        context: PaymentContext,
    ) -> impl Future<Output = Result<PaymentCredential, MppError>> + Send {
        let _ = context;
        self.pay(challenge)
    }

    /// Reconcile a challenge before opening an application WebSocket.
    ///
    /// Session providers may use this hook to refresh persisted state from the
    /// server before creating the socket-bound credential. Other providers
    /// inherit the challenge unchanged.
    fn prepare_application_websocket_challenge(
        &self,
        challenge: &PaymentChallenge,
        context: PaymentContext,
    ) -> impl Future<Output = Result<PaymentChallenge, MppError>> + Send {
        let challenge = challenge.clone();
        async move {
            let _ = context;
            Ok(challenge)
        }
    }

    /// Commit optimistic provider state after the server accepts a credential.
    fn commit_payment(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> impl Future<Output = Result<(), MppError>> + Send {
        let _ = (challenge, credential);
        async { Ok(()) }
    }

    /// Roll back optimistic provider state after the server rejects a credential.
    fn rollback_payment(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> impl Future<Output = Result<(), MppError>> + Send {
        let _ = (challenge, credential);
        async { Ok(()) }
    }

    /// Build an `Accept-Payment` header value from this provider's supported methods.
    ///
    /// Returns `None` if the provider does not advertise specific methods.
    /// The default implementation returns `None`; providers that know their
    /// supported `(method, intent)` pairs should override this.
    fn accept_payment_header(&self) -> Option<String> {
        None
    }
}

pub(crate) async fn commit_payments<P: PaymentProvider>(
    provider: &P,
    payments: &[(PaymentChallenge, PaymentCredential)],
) -> Result<(), MppError> {
    for (challenge, credential) in payments {
        provider.commit_payment(challenge, credential).await?;
    }
    Ok(())
}

pub(crate) async fn rollback_payments<P: PaymentProvider>(
    provider: &P,
    payments: &[(PaymentChallenge, PaymentCredential)],
) -> Result<(), MppError> {
    for (challenge, credential) in payments {
        provider.rollback_payment(challenge, credential).await?;
    }
    Ok(())
}

/// A provider that wraps multiple payment providers and picks the right one.
///
/// `MultiProvider` iterates through its providers and uses the first one that
/// supports the challenge's method and intent combination.
///
/// # Examples
///
/// ```ignore
/// use mpp::client::{MultiProvider, TempoProvider};
///
/// let provider = MultiProvider::new()
///     .with(TempoProvider::new(signer, "https://rpc.moderato.tempo.xyz")?);
///
/// // Automatically picks the right provider based on challenge.method
/// let resp = client.get(url).send_with_payment(&provider).await?;
/// ```
#[derive(Clone)]
pub struct MultiProvider {
    providers: Vec<Box<dyn DynPaymentProvider>>,
}

impl MultiProvider {
    /// Create a new empty multi-provider.
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    /// Add a provider to the list.
    pub fn with<P: PaymentProvider + 'static>(mut self, provider: P) -> Self {
        self.providers.push(Box::new(provider));
        self
    }

    /// Add a provider to the list (mutable reference version).
    pub fn add<P: PaymentProvider + 'static>(&mut self, provider: P) -> &mut Self {
        self.providers.push(Box::new(provider));
        self
    }

    /// Check if any provider supports the given method and intent.
    pub fn has_support(&self, method: &str, intent: &str) -> bool {
        self.providers
            .iter()
            .any(|p| p.dyn_supports(method, intent))
    }
}

impl Default for MultiProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl PaymentProvider for MultiProvider {
    fn supports(&self, method: &str, intent: &str) -> bool {
        self.has_support(method, intent)
    }

    async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
        let method = challenge.method.as_str();
        let intent = challenge.intent.as_str();

        for provider in &self.providers {
            if provider.dyn_supports(method, intent) {
                return provider.dyn_pay(challenge).await;
            }
        }

        Err(MppError::UnsupportedPaymentMethod(format!(
            "no provider supports method={}, intent={}",
            method, intent
        )))
    }

    async fn pay_with_context(
        &self,
        challenge: &PaymentChallenge,
        context: PaymentContext,
    ) -> Result<PaymentCredential, MppError> {
        let method = challenge.method.as_str();
        let intent = challenge.intent.as_str();

        for provider in &self.providers {
            if provider.dyn_supports(method, intent) {
                return provider.dyn_pay_with_context(challenge, context).await;
            }
        }

        Err(MppError::UnsupportedPaymentMethod(format!(
            "no provider supports method={}, intent={}",
            method, intent
        )))
    }

    async fn prepare_application_websocket_challenge(
        &self,
        challenge: &PaymentChallenge,
        context: PaymentContext,
    ) -> Result<PaymentChallenge, MppError> {
        let method = challenge.method.as_str();
        let intent = challenge.intent.as_str();

        for provider in &self.providers {
            if provider.dyn_supports(method, intent) {
                return provider
                    .dyn_prepare_application_websocket_challenge(challenge, context)
                    .await;
            }
        }

        Err(MppError::UnsupportedPaymentMethod(format!(
            "no provider supports method={}, intent={}",
            method, intent
        )))
    }

    async fn commit_payment(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<(), MppError> {
        let method = challenge.method.as_str();
        let intent = challenge.intent.as_str();

        for provider in &self.providers {
            if provider.dyn_supports(method, intent) {
                return provider.dyn_commit_payment(challenge, credential).await;
            }
        }

        Err(MppError::UnsupportedPaymentMethod(format!(
            "no provider supports method={}, intent={}",
            method, intent
        )))
    }

    async fn rollback_payment(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<(), MppError> {
        let method = challenge.method.as_str();
        let intent = challenge.intent.as_str();

        for provider in &self.providers {
            if provider.dyn_supports(method, intent) {
                return provider.dyn_rollback_payment(challenge, credential).await;
            }
        }

        Err(MppError::UnsupportedPaymentMethod(format!(
            "no provider supports method={}, intent={}",
            method, intent
        )))
    }

    fn accept_payment_header(&self) -> Option<String> {
        let headers: Vec<String> = self
            .providers
            .iter()
            .filter_map(|p| p.dyn_accept_payment_header())
            .collect();

        if headers.is_empty() {
            None
        } else {
            Some(headers.join(", "))
        }
    }
}

/// Object-safe version of PaymentProvider for use in MultiProvider.
trait DynPaymentProvider: Send + Sync {
    fn dyn_supports(&self, method: &str, intent: &str) -> bool;
    fn dyn_pay<'a>(
        &'a self,
        challenge: &'a PaymentChallenge,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<PaymentCredential, MppError>> + Send + 'a>>;
    fn dyn_pay_with_context<'a>(
        &'a self,
        challenge: &'a PaymentChallenge,
        context: PaymentContext,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<PaymentCredential, MppError>> + Send + 'a>>;
    fn dyn_prepare_application_websocket_challenge<'a>(
        &'a self,
        challenge: &'a PaymentChallenge,
        context: PaymentContext,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<PaymentChallenge, MppError>> + Send + 'a>>;
    fn dyn_commit_payment<'a>(
        &'a self,
        challenge: &'a PaymentChallenge,
        credential: &'a PaymentCredential,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), MppError>> + Send + 'a>>;
    fn dyn_rollback_payment<'a>(
        &'a self,
        challenge: &'a PaymentChallenge,
        credential: &'a PaymentCredential,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), MppError>> + Send + 'a>>;
    fn dyn_accept_payment_header(&self) -> Option<String>;
    fn clone_box(&self) -> Box<dyn DynPaymentProvider>;
}

impl<P: PaymentProvider + 'static> DynPaymentProvider for P {
    fn dyn_supports(&self, method: &str, intent: &str) -> bool {
        PaymentProvider::supports(self, method, intent)
    }

    fn dyn_pay<'a>(
        &'a self,
        challenge: &'a PaymentChallenge,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<PaymentCredential, MppError>> + Send + 'a>>
    {
        Box::pin(PaymentProvider::pay(self, challenge))
    }

    fn dyn_pay_with_context<'a>(
        &'a self,
        challenge: &'a PaymentChallenge,
        context: PaymentContext,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<PaymentCredential, MppError>> + Send + 'a>>
    {
        Box::pin(PaymentProvider::pay_with_context(self, challenge, context))
    }

    fn dyn_prepare_application_websocket_challenge<'a>(
        &'a self,
        challenge: &'a PaymentChallenge,
        context: PaymentContext,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<PaymentChallenge, MppError>> + Send + 'a>>
    {
        Box::pin(PaymentProvider::prepare_application_websocket_challenge(
            self, challenge, context,
        ))
    }

    fn dyn_commit_payment<'a>(
        &'a self,
        challenge: &'a PaymentChallenge,
        credential: &'a PaymentCredential,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), MppError>> + Send + 'a>> {
        Box::pin(PaymentProvider::commit_payment(self, challenge, credential))
    }

    fn dyn_rollback_payment<'a>(
        &'a self,
        challenge: &'a PaymentChallenge,
        credential: &'a PaymentCredential,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), MppError>> + Send + 'a>> {
        Box::pin(PaymentProvider::rollback_payment(
            self, challenge, credential,
        ))
    }

    fn dyn_accept_payment_header(&self) -> Option<String> {
        PaymentProvider::accept_payment_header(self)
    }

    fn clone_box(&self) -> Box<dyn DynPaymentProvider> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn DynPaymentProvider> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct MockProvider {
        method: &'static str,
        intent: &'static str,
    }

    impl PaymentProvider for MockProvider {
        fn supports(&self, method: &str, intent: &str) -> bool {
            self.method == method && self.intent == intent
        }

        async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
            use crate::protocol::core::PaymentPayload;
            Ok(PaymentCredential::new(
                challenge.to_echo(),
                PaymentPayload::hash(format!("mock-{}", self.method)),
            ))
        }
    }

    #[test]
    fn test_multi_provider_supports() {
        let multi = MultiProvider::new()
            .with(MockProvider {
                method: "tempo",
                intent: "charge",
            })
            .with(MockProvider {
                method: "stripe",
                intent: "charge",
            });

        assert!(multi.has_support("tempo", "charge"));
        assert!(multi.has_support("stripe", "charge"));
        assert!(!multi.has_support("bitcoin", "charge"));
        assert!(!multi.has_support("tempo", "authorize"));
    }

    #[test]
    fn test_multi_provider_empty() {
        let multi = MultiProvider::new();
        assert!(!multi.has_support("tempo", "charge"));
    }

    #[test]
    fn test_multi_provider_clone() {
        let multi = MultiProvider::new().with(MockProvider {
            method: "tempo",
            intent: "charge",
        });

        let cloned = multi.clone();
        assert!(cloned.has_support("tempo", "charge"));
    }
}
