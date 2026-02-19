//! Payment provider trait and implementations.
//!
//! The `PaymentProvider` trait abstracts over payment execution, allowing
//! different payment methods (Tempo, Stripe, etc.) to be used with the
//! HTTP client extensions.

use crate::error::MppError;
use crate::protocol::core::{PaymentChallenge, PaymentCredential};
use std::future::Future;

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
}

/// Object-safe version of PaymentProvider for use in MultiProvider.
trait DynPaymentProvider: Send + Sync {
    fn dyn_supports(&self, method: &str, intent: &str) -> bool;
    fn dyn_pay<'a>(
        &'a self,
        challenge: &'a PaymentChallenge,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<PaymentCredential, MppError>> + Send + 'a>>;
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
