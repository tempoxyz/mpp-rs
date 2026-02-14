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
mod session;

pub use charge::ChargeMethod;
pub use session::SessionMethod;

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
    /// Chain ID mismatch between request and provider.
    ChainIdMismatch,
    /// Credential does not match the expected challenge.
    CredentialMismatch,
    /// Payment channel not found.
    ChannelNotFound,
    /// Payment channel has been closed.
    ChannelClosed,
    /// Insufficient balance in payment channel.
    InsufficientBalance,
    /// Invalid credential payload.
    InvalidPayload,
    /// Invalid cryptographic signature.
    InvalidSignature,
    /// Voucher amount exceeds channel deposit.
    AmountExceedsDeposit,
    /// Voucher delta is below the minimum threshold.
    DeltaTooSmall,
}

impl ErrorCode {
    /// Returns the string representation of the error code.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::InvalidAmount => "invalid-amount",
            Self::InvalidRecipient => "invalid-recipient",
            Self::TransactionFailed => "transaction-failed",
            Self::NotFound => "not-found",
            Self::InvalidCredential => "invalid-credential",
            Self::NetworkError => "network-error",
            Self::ChainIdMismatch => "chain-id-mismatch",
            Self::CredentialMismatch => "credential-mismatch",
            Self::ChannelNotFound => "channel-not-found",
            Self::ChannelClosed => "channel-closed",
            Self::InsufficientBalance => "insufficient-balance",
            Self::InvalidPayload => "invalid-payload",
            Self::InvalidSignature => "invalid-signature",
            Self::AmountExceedsDeposit => "amount-exceeds-deposit",
            Self::DeltaTooSmall => "delta-too-small",
        }
    }

    /// Returns the IETF spec-compliant error code string (§8.2).
    ///
    /// These codes are intended for JSON error responses per the spec:
    /// - `payment-required` - Payment is required
    /// - `payment-insufficient` - Payment amount was insufficient
    /// - `payment-expired` - Payment or challenge has expired
    /// - `verification-failed` - Payment verification failed
    /// - `method-unsupported` - Payment method not supported
    /// - `malformed-credential` - Credential format is invalid
    pub fn spec_code(&self) -> &'static str {
        match self {
            Self::Expired => "payment-expired",
            Self::InvalidAmount => "payment-insufficient",
            Self::InvalidRecipient => "verification-failed",
            Self::TransactionFailed => "verification-failed",
            Self::NotFound => "verification-failed",
            Self::InvalidCredential => "malformed-credential",
            Self::NetworkError => "verification-failed",
            Self::ChainIdMismatch => "method-unsupported",
            Self::CredentialMismatch => "malformed-credential",
            Self::ChannelNotFound => "verification-failed",
            Self::ChannelClosed => "verification-failed",
            Self::InsufficientBalance => "payment-insufficient",
            Self::InvalidPayload => "malformed-credential",
            Self::InvalidSignature => "verification-failed",
            Self::AmountExceedsDeposit => "verification-failed",
            Self::DeltaTooSmall => "verification-failed",
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

    /// Create an "invalid-amount" verification error.
    pub fn invalid_amount(message: impl Into<String>) -> Self {
        Self::with_code(message, ErrorCode::InvalidAmount)
    }

    /// Create an "invalid-recipient" verification error.
    pub fn invalid_recipient(message: impl Into<String>) -> Self {
        Self::with_code(message, ErrorCode::InvalidRecipient)
    }

    /// Create a "transaction-failed" verification error.
    pub fn transaction_failed(message: impl Into<String>) -> Self {
        Self::with_code(message, ErrorCode::TransactionFailed)
    }

    /// Create a "not-found" verification error.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::with_code(message, ErrorCode::NotFound)
    }

    /// Create a "chain-id-mismatch" verification error.
    pub fn chain_id_mismatch(message: impl Into<String>) -> Self {
        Self::with_code(message, ErrorCode::ChainIdMismatch)
    }

    /// Create a "credential-mismatch" verification error.
    pub fn credential_mismatch(message: impl Into<String>) -> Self {
        Self::with_code(message, ErrorCode::CredentialMismatch)
    }

    /// Create a retryable network error.
    pub fn network_error(message: impl Into<String>) -> Self {
        Self::with_code(message, ErrorCode::NetworkError).retryable()
    }

    /// Create a retryable "not found" error (e.g., tx not yet mined).
    pub fn pending(message: impl Into<String>) -> Self {
        Self::with_code(message, ErrorCode::NotFound).retryable()
    }

    /// Create a "channel-not-found" verification error.
    pub fn channel_not_found(message: impl Into<String>) -> Self {
        Self::with_code(message, ErrorCode::ChannelNotFound)
    }

    /// Create a "channel-closed" verification error.
    pub fn channel_closed(message: impl Into<String>) -> Self {
        Self::with_code(message, ErrorCode::ChannelClosed)
    }

    /// Create an "insufficient-balance" verification error.
    pub fn insufficient_balance(message: impl Into<String>) -> Self {
        Self::with_code(message, ErrorCode::InsufficientBalance)
    }

    /// Create an "invalid-payload" verification error.
    pub fn invalid_payload(message: impl Into<String>) -> Self {
        Self::with_code(message, ErrorCode::InvalidPayload)
    }

    /// Create an "invalid-signature" verification error.
    pub fn invalid_signature(message: impl Into<String>) -> Self {
        Self::with_code(message, ErrorCode::InvalidSignature)
    }

    /// Create an "amount-exceeds-deposit" verification error.
    pub fn amount_exceeds_deposit(message: impl Into<String>) -> Self {
        Self::with_code(message, ErrorCode::AmountExceedsDeposit)
    }

    /// Create a "delta-too-small" verification error.
    pub fn delta_too_small(message: impl Into<String>) -> Self {
        Self::with_code(message, ErrorCode::DeltaTooSmall)
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

// ==================== Conversion to RFC 9457 Problem Details ====================

use crate::error::{MppError, PaymentError, PaymentErrorDetails};

impl From<VerificationError> for MppError {
    fn from(err: VerificationError) -> Self {
        match err.code {
            Some(ErrorCode::Expired) => MppError::PaymentExpired(None),
            Some(ErrorCode::InvalidCredential) => MppError::MalformedCredential(Some(err.message)),
            Some(ErrorCode::ChannelNotFound) => MppError::ChannelNotFound(Some(err.message)),
            Some(ErrorCode::ChannelClosed) => MppError::ChannelClosed(Some(err.message)),
            Some(ErrorCode::InsufficientBalance) => {
                MppError::InsufficientBalance(Some(err.message))
            }
            Some(ErrorCode::InvalidPayload) => MppError::InvalidPayload(Some(err.message)),
            Some(ErrorCode::InvalidSignature) => MppError::InvalidSignature(Some(err.message)),
            Some(ErrorCode::AmountExceedsDeposit) => {
                MppError::AmountExceedsDeposit(Some(err.message))
            }
            Some(ErrorCode::DeltaTooSmall) => MppError::DeltaTooSmall(Some(err.message)),
            Some(ErrorCode::CredentialMismatch)
            | Some(ErrorCode::InvalidAmount)
            | Some(ErrorCode::InvalidRecipient)
            | Some(ErrorCode::TransactionFailed)
            | Some(ErrorCode::ChainIdMismatch)
            | Some(ErrorCode::NotFound)
            | Some(ErrorCode::NetworkError)
            | None => MppError::VerificationFailed(Some(err.message)),
        }
    }
}

impl PaymentError for VerificationError {
    fn to_problem_details(&self, challenge_id: Option<&str>) -> PaymentErrorDetails {
        MppError::from(self.clone()).to_problem_details(challenge_id)
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

    #[test]
    fn test_error_code_spec_codes() {
        // Verify IETF spec-compliant error codes (§8.2)
        assert_eq!(ErrorCode::Expired.spec_code(), "payment-expired");
        assert_eq!(ErrorCode::InvalidAmount.spec_code(), "payment-insufficient");
        assert_eq!(
            ErrorCode::InvalidCredential.spec_code(),
            "malformed-credential"
        );
        assert_eq!(ErrorCode::ChainIdMismatch.spec_code(), "method-unsupported");
        assert_eq!(
            ErrorCode::TransactionFailed.spec_code(),
            "verification-failed"
        );
    }
}
