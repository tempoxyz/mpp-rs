//! Intent and Method traits for Web Payment Auth.
//!
//! This module provides the core abstractions for payment verification and execution:
//!
//! - [`Intent`]: Server-side verification of payment credentials
//! - [`Method`]: Client-side payment execution and credential creation
//! - [`VerificationError`]: Error types for verification failures
//!
//! # Architecture
//!
//! ```text
//! Server                          Client
//! ┌──────────────────┐            ┌──────────────────┐
//! │ Intent::verify() │◄───────────│ Method::create() │
//! │   - ChargeIntent │ Credential │   - TempoMethod  │
//! │   - StripeIntent │            │   - StripeMethod │
//! └──────────────────┘            └──────────────────┘
//! ```
//!
//! # Server-Side: Intent Trait
//!
//! Implement [`Intent`] for custom payment verification:
//!
//! ```ignore
//! use mpay::protocol::traits::{Intent, VerificationError};
//! use mpay::protocol::core::{PaymentCredential, PaymentReceipt};
//!
//! struct MyChargeIntent { /* ... */ }
//!
//! impl Intent for MyChargeIntent {
//!     fn name(&self) -> &str { "charge" }
//!
//!     async fn verify(
//!         &self,
//!         credential: &PaymentCredential,
//!         request: &serde_json::Value,
//!     ) -> Result<PaymentReceipt, VerificationError> {
//!         // Verify the payment...
//!     }
//! }
//! ```
//!
//! # Client-Side: Method Trait
//!
//! Implement [`Method`] for custom payment execution:
//!
//! ```ignore
//! use mpay::protocol::traits::Method;
//! use mpay::protocol::core::{PaymentChallenge, PaymentCredential};
//!
//! struct MyPaymentMethod { /* ... */ }
//!
//! impl Method for MyPaymentMethod {
//!     fn name(&self) -> &str { "my-method" }
//!
//!     async fn create_credential(
//!         &self,
//!         challenge: &PaymentChallenge,
//!     ) -> Result<PaymentCredential, mpay::MppError> {
//!         // Execute payment and create credential...
//!     }
//! }
//! ```

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use thiserror::Error;

use super::core::{PaymentChallenge, PaymentCredential, PaymentReceipt};
use crate::error::MppError;

/// Boxed future type for dyn-compatible async methods.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Error type for payment verification failures.
///
/// Returned by [`Intent::verify`] when a credential fails verification.
///
/// # Examples
///
/// ```
/// use mpay::protocol::traits::VerificationError;
///
/// let err = VerificationError::AmountMismatch {
///     expected: "1000".to_string(),
///     got: "500".to_string(),
/// };
/// assert!(err.to_string().contains("Amount mismatch"));
/// ```
#[derive(Error, Debug, Clone)]
pub enum VerificationError {
    /// Payment not found on-chain or in payment system
    #[error("Payment not found: {0}")]
    NotFound(String),

    /// Payment or challenge has expired
    #[error("Payment expired: {0}")]
    Expired(String),

    /// Payment amount does not match request
    #[error("Amount mismatch: expected {expected}, got {got}")]
    AmountMismatch { expected: String, got: String },

    /// Payment recipient does not match request
    #[error("Recipient mismatch: expected {expected}, got {got}")]
    RecipientMismatch { expected: String, got: String },

    /// Currency/asset does not match request
    #[error("Currency mismatch: expected {expected}, got {got}")]
    CurrencyMismatch { expected: String, got: String },

    /// Transaction reverted or failed on-chain
    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    /// Generic verification failure
    #[error("Verification failed: {0}")]
    Failed(String),
}

impl From<VerificationError> for MppError {
    fn from(err: VerificationError) -> Self {
        MppError::InvalidChallenge(err.to_string())
    }
}

/// Payment intent trait for server-side verification.
///
/// An intent represents a type of payment operation (e.g., one-time charge,
/// authorization, subscription). Implement this trait to add custom payment
/// verification logic.
///
/// # Design
///
/// Following the Python pympay pattern, intents are duck-typed:
/// - `name`: Identifies the intent type (e.g., "charge", "authorize")
/// - `verify()`: Validates a credential against the original request
///
/// # Thread Safety
///
/// Intents must be `Send + Sync` to be used in async server contexts.
///
/// # Examples
///
/// ```ignore
/// use mpay::protocol::traits::{Intent, VerificationError};
/// use mpay::protocol::core::{PaymentCredential, PaymentReceipt, ReceiptStatus, MethodName};
///
/// struct StripeChargeIntent {
///     api_key: String,
/// }
///
/// impl Intent for StripeChargeIntent {
///     fn name(&self) -> &str { "charge" }
///
///     async fn verify(
///         &self,
///         credential: &PaymentCredential,
///         request: &serde_json::Value,
///     ) -> Result<PaymentReceipt, VerificationError> {
///         // Verify payment with Stripe API...
///         Ok(PaymentReceipt {
///             status: ReceiptStatus::Success,
///             method: MethodName::from("stripe"),
///             timestamp: chrono::Utc::now().to_rfc3339(),
///             reference: "pi_123".to_string(),
///         })
///     }
/// }
/// ```
pub trait Intent: Send + Sync {
    /// Intent name (e.g., "charge", "authorize").
    fn name(&self) -> &str;

    /// Verify a credential against the original request.
    ///
    /// # Arguments
    ///
    /// * `credential` - The payment credential from the client
    /// * `request` - The original payment request (from challenge.request)
    ///
    /// # Returns
    ///
    /// * `Ok(PaymentReceipt)` - Payment verified successfully
    /// * `Err(VerificationError)` - Verification failed
    fn verify<'a>(
        &'a self,
        credential: &'a PaymentCredential,
        request: &'a serde_json::Value,
    ) -> BoxFuture<'a, Result<PaymentReceipt, VerificationError>>;
}

/// Payment method trait for client-side payment execution.
///
/// A method represents a payment network (e.g., Tempo, Stripe, Base) and provides:
/// - Named intents for different payment operations
/// - Client-side credential creation
///
/// # Design
///
/// Following the Python pympay pattern:
/// - `name`: Method identifier (e.g., "tempo", "stripe")
/// - `intents`: Available intents for server-side verification
/// - `create_credential()`: Client-side payment execution
///
/// # Relationship with PaymentProvider
///
/// [`Method`] extends the concept of [`PaymentProvider`](crate::http::PaymentProvider):
/// - `PaymentProvider::pay()` ≈ `Method::create_credential()`
/// - `Method` adds intent registration for server-side use
///
/// # Examples
///
/// ```ignore
/// use mpay::protocol::traits::{Method, Intent};
/// use mpay::protocol::core::{PaymentChallenge, PaymentCredential};
/// use std::collections::HashMap;
/// use std::sync::Arc;
///
/// struct MyMethod {
///     name: String,
///     intents: HashMap<String, Arc<dyn Intent>>,
/// }
///
/// impl Method for MyMethod {
///     fn name(&self) -> &str { &self.name }
///
///     fn intents(&self) -> &HashMap<String, Arc<dyn Intent>> {
///         &self.intents
///     }
///
///     async fn create_credential(
///         &self,
///         challenge: &PaymentChallenge,
///     ) -> Result<PaymentCredential, mpay::MppError> {
///         // Execute payment and return credential
///         todo!()
///     }
/// }
/// ```
pub trait Method: Send + Sync {
    /// Method name (e.g., "tempo", "stripe", "base").
    fn name(&self) -> &str;

    /// Available intents for this method.
    ///
    /// Returns a map of intent name → intent implementation.
    /// Used by servers to verify payments for this method.
    fn intents(&self) -> &HashMap<String, Arc<dyn Intent>>;

    /// Get an intent by name.
    fn intent(&self, name: &str) -> Option<Arc<dyn Intent>> {
        self.intents().get(name).cloned()
    }

    /// Create a credential to satisfy the given challenge.
    ///
    /// This is called on the client side when a 402 response is received.
    /// The implementation should:
    /// 1. Parse the challenge request
    /// 2. Execute the payment (sign tx, call API, etc.)
    /// 3. Return a credential with proof
    fn create_credential<'a>(
        &'a self,
        challenge: &'a PaymentChallenge,
    ) -> BoxFuture<'a, Result<PaymentCredential, MppError>>;
}

/// Registry for intents, keyed by intent name.
///
/// Useful for servers that need to verify payments for multiple intents.
#[derive(Default, Clone)]
pub struct IntentRegistry {
    intents: HashMap<String, Arc<dyn Intent>>,
}

impl IntentRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an intent.
    pub fn register<I: Intent + 'static>(&mut self, intent: I) {
        self.intents
            .insert(intent.name().to_string(), Arc::new(intent));
    }

    /// Get an intent by name.
    pub fn get(&self, name: &str) -> Option<Arc<dyn Intent>> {
        self.intents.get(name).cloned()
    }

    /// List all registered intent names.
    pub fn names(&self) -> Vec<&str> {
        self.intents.keys().map(|s| s.as_str()).collect()
    }

    /// Check if an intent is registered.
    pub fn contains(&self, name: &str) -> bool {
        self.intents.contains_key(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_error_display() {
        let err = VerificationError::NotFound("tx_123".to_string());
        assert!(err.to_string().contains("Payment not found"));

        let err = VerificationError::Expired("2024-01-01".to_string());
        assert!(err.to_string().contains("expired"));

        let err = VerificationError::AmountMismatch {
            expected: "1000".to_string(),
            got: "500".to_string(),
        };
        assert!(err.to_string().contains("Amount mismatch"));
        assert!(err.to_string().contains("1000"));
        assert!(err.to_string().contains("500"));

        let err = VerificationError::RecipientMismatch {
            expected: "0x123".to_string(),
            got: "0x456".to_string(),
        };
        assert!(err.to_string().contains("Recipient mismatch"));

        let err = VerificationError::CurrencyMismatch {
            expected: "USDC".to_string(),
            got: "USDT".to_string(),
        };
        assert!(err.to_string().contains("Currency mismatch"));

        let err = VerificationError::TransactionFailed("reverted".to_string());
        assert!(err.to_string().contains("Transaction failed"));

        let err = VerificationError::Failed("unknown".to_string());
        assert!(err.to_string().contains("Verification failed"));
    }

    #[test]
    fn test_verification_error_to_mpp_error() {
        let err = VerificationError::NotFound("tx_123".to_string());
        let mpp_err: MppError = err.into();
        assert!(matches!(mpp_err, MppError::InvalidChallenge(_)));
    }

    #[test]
    fn test_intent_registry() {
        let registry = IntentRegistry::new();
        assert!(registry.names().is_empty());
        assert!(!registry.contains("charge"));
    }
}
