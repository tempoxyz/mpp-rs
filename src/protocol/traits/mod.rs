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

/// Error codes for payment verification failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// Payment has expired.
    Expired,
    /// Payment amount is incorrect.
    InvalidAmount,
    /// Payment recipient is incorrect.
    InvalidRecipient,
    /// Transaction failed on-chain.
    TransactionFailed,
    /// Payment not found.
    NotFound,
    /// Invalid credential format.
    InvalidCredential,
    /// Network or RPC error.
    NetworkError,
}

impl ErrorCode {
    /// Returns the string representation of the error code.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::InvalidAmount => "invalid_amount",
            Self::InvalidRecipient => "invalid_recipient",
            Self::TransactionFailed => "transaction_failed",
            Self::NotFound => "not_found",
            Self::InvalidCredential => "invalid_credential",
            Self::NetworkError => "network_error",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Error returned when payment verification fails.
///
/// This error type is used by method traits to indicate why a payment
/// credential could not be verified.
#[derive(Debug, Clone)]
pub struct VerificationError {
    /// Error message describing why verification failed.
    pub message: String,
    /// Error code for programmatic handling (optional).
    pub code: Option<ErrorCode>,
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
    pub fn with_code(message: impl Into<String>, code: ErrorCode) -> Self {
        Self {
            message: message.into(),
            code: Some(code),
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
        Self::with_code(message, ErrorCode::Expired)
    }

    /// Create an "invalid_amount" verification error.
    pub fn invalid_amount(message: impl Into<String>) -> Self {
        Self::with_code(message, ErrorCode::InvalidAmount)
    }

    /// Create an "invalid_recipient" verification error.
    pub fn invalid_recipient(message: impl Into<String>) -> Self {
        Self::with_code(message, ErrorCode::InvalidRecipient)
    }

    /// Create a "transaction_failed" verification error.
    pub fn transaction_failed(message: impl Into<String>) -> Self {
        Self::with_code(message, ErrorCode::TransactionFailed)
    }

    /// Create a "not_found" verification error.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::with_code(message, ErrorCode::NotFound)
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

        let err_with_code = VerificationError::with_code("Request expired", ErrorCode::Expired);
        assert_eq!(err_with_code.to_string(), "[expired] Request expired");
    }

    #[test]
    fn test_verification_error_constructors() {
        let err = VerificationError::expired("Challenge expired");
        assert_eq!(err.code, Some(ErrorCode::Expired));
        assert!(!err.retryable);

        let err = VerificationError::invalid_amount("Amount mismatch").retryable();
        assert_eq!(err.code, Some(ErrorCode::InvalidAmount));
        assert!(err.retryable);
    }
}
