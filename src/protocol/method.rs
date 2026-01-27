//! Method trait for client-side payment execution.
//!
//! A Method represents a payment network (e.g., Tempo, Stripe) and provides:
//! - Named intents for different payment operations
//! - Client-side credential creation
//!
//! This trait extends the concept of [`crate::http::PaymentProvider`] with
//! support for multiple intents and named method identification.
//!
//! # Examples
//!
//! ```
//! use mpay::protocol::method::Method;
//! use mpay::protocol::core::{PaymentChallenge, PaymentCredential};
//! use mpay::MppError;
//! use std::future::Future;
//!
//! #[derive(Clone)]
//! struct MyMethod {
//!     api_key: String,
//! }
//!
//! impl Method for MyMethod {
//!     fn name(&self) -> &str {
//!         "my_payment"
//!     }
//!
//!     fn supports_intent(&self, intent: &str) -> bool {
//!         intent == "charge"
//!     }
//!
//!     fn create_credential(
//!         &self,
//!         challenge: &PaymentChallenge,
//!     ) -> impl Future<Output = Result<PaymentCredential, MppError>> + Send {
//!         let challenge = challenge.clone();
//!         async move {
//!             // Build credential for the challenge...
//!             todo!()
//!         }
//!     }
//! }
//! ```

use crate::error::MppError;
use crate::protocol::core::{PaymentChallenge, PaymentCredential};
use std::future::Future;

/// Method trait for client-side payment execution.
///
/// A Method represents a payment network and provides the ability to
/// create credentials for payment challenges. This is the client-side
/// counterpart to the server-side [`Intent`](super::intent::Intent) trait.
///
/// # Relationship to PaymentProvider
///
/// The `Method` trait is a more feature-rich version of
/// [`PaymentProvider`](crate::http::PaymentProvider):
///
/// - `PaymentProvider::pay()` ≈ `Method::create_credential()`
/// - `Method` adds `name()` and `supports_intent()` for introspection
///
/// Any `Method` implementation can be used as a `PaymentProvider` by
/// extracting its `create_credential` method.
///
/// # Implementation Notes
///
/// - Methods should be `Clone + Send + Sync` for use in async contexts
/// - The `create_credential` method may execute transactions or sign data
/// - Methods should validate challenge compatibility before execution
///
/// # Examples
///
/// ## Multi-intent method
///
/// ```
/// use mpay::protocol::method::Method;
/// use mpay::protocol::core::{PaymentChallenge, PaymentCredential, PaymentPayload};
/// use mpay::MppError;
/// use std::future::Future;
///
/// #[derive(Clone)]
/// struct MultiIntentMethod {
///     wallet: String,
/// }
///
/// impl Method for MultiIntentMethod {
///     fn name(&self) -> &str {
///         "multi"
///     }
///
///     fn supports_intent(&self, intent: &str) -> bool {
///         matches!(intent, "charge" | "authorize" | "subscription")
///     }
///
///     fn create_credential(
///         &self,
///         challenge: &PaymentChallenge,
///     ) -> impl Future<Output = Result<PaymentCredential, MppError>> + Send {
///         let challenge = challenge.clone();
///         async move {
///             if !matches!(challenge.intent.as_str(), "charge" | "authorize" | "subscription") {
///                 return Err(MppError::UnsupportedPaymentIntent(
///                     challenge.intent.to_string(),
///                 ));
///             }
///             // Handle each intent type...
///             let echo = challenge.to_echo();
///             Ok(PaymentCredential::new(echo, PaymentPayload::hash("0x...")))
///         }
///     }
/// }
/// ```
pub trait Method: Clone + Send + Sync {
    /// The name of this payment method (e.g., "tempo", "stripe", "base").
    ///
    /// This should match the `method` field in payment challenges.
    fn name(&self) -> &str;

    /// Check if this method supports the given intent.
    ///
    /// # Arguments
    ///
    /// * `intent` - The intent name (e.g., "charge", "authorize")
    ///
    /// # Returns
    ///
    /// `true` if this method can handle the intent, `false` otherwise.
    fn supports_intent(&self, intent: &str) -> bool;

    /// Create a credential to satisfy the given challenge.
    ///
    /// This is called on the client side when a 402 response is received.
    /// The implementation should:
    ///
    /// 1. Validate the challenge is compatible with this method
    /// 2. Parse the request for payment details
    /// 3. Execute the payment (sign transaction, call API, etc.)
    /// 4. Return a credential with the proof
    ///
    /// # Arguments
    ///
    /// * `challenge` - The payment challenge from the server
    ///
    /// # Returns
    ///
    /// * `Ok(PaymentCredential)` - Credential to send in Authorization header
    /// * `Err(MppError)` - Failed to create credential
    fn create_credential(
        &self,
        challenge: &PaymentChallenge,
    ) -> impl Future<Output = Result<PaymentCredential, MppError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::{Base64UrlJson, PaymentPayload};

    #[derive(Clone)]
    struct TestMethod;

    impl Method for TestMethod {
        fn name(&self) -> &str {
            "test"
        }

        fn supports_intent(&self, intent: &str) -> bool {
            intent == "charge"
        }

        fn create_credential(
            &self,
            challenge: &PaymentChallenge,
        ) -> impl Future<Output = Result<PaymentCredential, MppError>> + Send {
            let echo = challenge.to_echo();
            async move { Ok(PaymentCredential::new(echo, PaymentPayload::hash("0x123"))) }
        }
    }

    #[test]
    fn test_method_name() {
        let method = TestMethod;
        assert_eq!(method.name(), "test");
    }

    #[test]
    fn test_supports_intent() {
        let method = TestMethod;
        assert!(method.supports_intent("charge"));
        assert!(!method.supports_intent("authorize"));
    }

    #[tokio::test]
    async fn test_create_credential() {
        let method = TestMethod;
        let challenge = PaymentChallenge {
            id: "test-id".into(),
            realm: "test.com".into(),
            method: "test".into(),
            intent: "charge".into(),
            request: Base64UrlJson::from_raw("eyJ0ZXN0IjoidmFsdWUifQ"),
            expires: None,
            description: None,
        };

        let result = method.create_credential(&challenge).await;
        assert!(result.is_ok());
        let credential = result.unwrap();
        assert_eq!(credential.challenge.id, "test-id");
    }
}
