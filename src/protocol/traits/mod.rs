//! Intent-specific method traits for server-side payment verification.
//!
//! This module provides traits for payment methods organized by intent:
//!
//! - [`ChargeMethod`]: One-time payment verification
//! - [`AuthorizeMethod`]: Payment authorization with capture (stub)
//!
//! Each trait enforces a typed request schema, ensuring consistent
//! field names across all implementations.

mod charge;

pub use charge::ChargeMethod;

use std::fmt;

/// Error returned when payment verification fails.
///
/// This error type is used by method traits to indicate why a payment
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
