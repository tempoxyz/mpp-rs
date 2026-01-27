//! Intent trait for server-side payment verification.
//!
//! An Intent represents a payment operation that can be verified server-side.
//! Implement this trait to support custom payment verification flows.
//!
//! # Examples
//!
//! ```
//! use mpay::protocol::intent::{Intent, VerificationError};
//! use mpay::protocol::core::{PaymentCredential, PaymentReceipt};
//! use std::future::Future;
//!
//! #[derive(Clone)]
//! struct MyChargeIntent {
//!     api_key: String,
//! }
//!
//! impl Intent for MyChargeIntent {
//!     fn name(&self) -> &str {
//!         "charge"
//!     }
//!
//!     fn verify(
//!         &self,
//!         credential: &PaymentCredential,
//!         request: &serde_json::Value,
//!     ) -> impl Future<Output = Result<PaymentReceipt, VerificationError>> + Send {
//!         let credential = credential.clone();
//!         let request = request.clone();
//!         async move {
//!             // Verify the payment...
//!             Ok(PaymentReceipt::success("my_method", "tx_123"))
//!         }
//!     }
//! }
//! ```

use crate::protocol::core::{PaymentCredential, PaymentReceipt};
use std::fmt;
use std::future::Future;

/// Error returned when payment verification fails.
///
/// This error type is used by [`Intent::verify`] to indicate why a payment
/// credential could not be verified.
#[derive(Debug, Clone)]
pub struct VerificationError {
    /// Error message describing why verification failed.
    pub message: String,
    /// Error code for programmatic handling (optional).
    pub code: Option<String>,
    /// Whether the error is retryable.
    pub retryable: bool,
}

impl VerificationError {
    /// Create a new verification error.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: None,
            retryable: false,
        }
    }

    /// Create a verification error with an error code.
    pub fn with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: Some(code.into()),
            retryable: false,
        }
    }

    /// Mark this error as retryable.
    pub fn retryable(mut self) -> Self {
        self.retryable = true;
        self
    }

    /// Create an "expired" verification error.
    pub fn expired(message: impl Into<String>) -> Self {
        Self::with_code(message, "expired")
    }

    /// Create an "invalid_amount" verification error.
    pub fn invalid_amount(message: impl Into<String>) -> Self {
        Self::with_code(message, "invalid_amount")
    }

    /// Create an "invalid_recipient" verification error.
    pub fn invalid_recipient(message: impl Into<String>) -> Self {
        Self::with_code(message, "invalid_recipient")
    }

    /// Create a "transaction_failed" verification error.
    pub fn transaction_failed(message: impl Into<String>) -> Self {
        Self::with_code(message, "transaction_failed")
    }

    /// Create a "not_found" verification error.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::with_code(message, "not_found")
    }
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref code) = self.code {
            write!(f, "[{}] {}", code, self.message)
        } else {
            write!(f, "{}", self.message)
        }
    }
}

impl std::error::Error for VerificationError {}

impl From<String> for VerificationError {
    fn from(message: String) -> Self {
        Self::new(message)
    }
}

impl From<&str> for VerificationError {
    fn from(message: &str) -> Self {
        Self::new(message)
    }
}

/// Intent trait for server-side payment verification.
///
/// An Intent defines how to verify a payment credential for a specific
/// payment operation (e.g., charge, authorize, subscription).
///
/// # Implementation Notes
///
/// - Intents are stateless verifiers - all state comes from the request
/// - The `verify` method should be idempotent
/// - Return `VerificationError` for expected failures (expired, amount mismatch)
/// - Panics are caught by the framework and converted to 500 errors
///
/// # Examples
///
/// ## Basic implementation
///
/// ```
/// use mpay::protocol::intent::{Intent, VerificationError};
/// use mpay::protocol::core::{PaymentCredential, PaymentReceipt};
/// use std::future::Future;
///
/// #[derive(Clone)]
/// struct StripeChargeIntent {
///     api_key: String,
/// }
///
/// impl Intent for StripeChargeIntent {
///     fn name(&self) -> &str {
///         "charge"
///     }
///
///     fn verify(
///         &self,
///         credential: &PaymentCredential,
///         request: &serde_json::Value,
///     ) -> impl Future<Output = Result<PaymentReceipt, VerificationError>> + Send {
///         let credential = credential.clone();
///         let request = request.clone();
///         async move {
///             // Verify with Stripe API...
///             Ok(PaymentReceipt::success("stripe", "pi_xxx"))
///         }
///     }
/// }
/// ```
pub trait Intent: Clone + Send + Sync {
    /// The name of this intent (e.g., "charge", "authorize", "subscription").
    fn name(&self) -> &str;

    /// Verify a credential against a payment request.
    ///
    /// # Arguments
    ///
    /// * `credential` - The payment credential from the client
    /// * `request` - The original payment request parameters
    ///
    /// # Returns
    ///
    /// * `Ok(PaymentReceipt)` - Payment was verified successfully
    /// * `Err(VerificationError)` - Verification failed
    fn verify(
        &self,
        credential: &PaymentCredential,
        request: &serde_json::Value,
    ) -> impl Future<Output = Result<PaymentReceipt, VerificationError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::{ChallengeEcho, PaymentPayload};

    #[derive(Clone)]
    struct TestIntent;

    impl Intent for TestIntent {
        fn name(&self) -> &str {
            "test"
        }

        fn verify(
            &self,
            _credential: &PaymentCredential,
            _request: &serde_json::Value,
        ) -> impl Future<Output = Result<PaymentReceipt, VerificationError>> + Send {
            async { Ok(PaymentReceipt::success("test", "test_ref")) }
        }
    }

    #[test]
    fn test_verification_error_display() {
        let err = VerificationError::new("Payment failed");
        assert_eq!(err.to_string(), "Payment failed");

        let err_with_code = VerificationError::with_code("Request expired", "expired");
        assert_eq!(err_with_code.to_string(), "[expired] Request expired");
    }

    #[test]
    fn test_verification_error_constructors() {
        let err = VerificationError::expired("Challenge expired");
        assert_eq!(err.code, Some("expired".into()));
        assert!(!err.retryable);

        let err = VerificationError::invalid_amount("Amount mismatch").retryable();
        assert_eq!(err.code, Some("invalid_amount".into()));
        assert!(err.retryable);
    }

    #[test]
    fn test_intent_trait() {
        let intent = TestIntent;
        assert_eq!(intent.name(), "test");
    }

    #[tokio::test]
    async fn test_intent_verify() {
        let intent = TestIntent;
        let echo = ChallengeEcho {
            id: "test".into(),
            realm: "test.com".into(),
            method: "test".into(),
            intent: "test".into(),
            request: "eyJ0ZXN0IjoidmFsdWUifQ".into(),
            expires: None,
        };
        let credential = PaymentCredential::new(echo, PaymentPayload::hash("0x123"));
        let request = serde_json::json!({"amount": "1000"});

        let result = intent.verify(&credential, &request).await;
        assert!(result.is_ok());
        let receipt = result.unwrap();
        assert_eq!(receipt.reference, "test_ref");
    }
}
