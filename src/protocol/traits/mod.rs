//! Intent-specific method traits for server-side payment verification.
//!
//! This module provides traits for payment methods organized by intent:
//!
//! - [`ChargeMethod`]: One-time payment verification
//! - [`SessionMethod`]: Pay-as-you-go session verification
//!
//! Each trait enforces a typed request schema, ensuring consistent
//! field names across all implementations.

mod charge;
mod session;

pub use charge::{ChargeMethod, ChargeValidation};
pub use session::SessionMethod;

use std::fmt;

/// Error codes for payment verification failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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
    /// Challenge was not issued by this server, or not for this request.
    InvalidChallenge,
    /// Server-side failure (store, signer, upstream API) unrelated to the
    /// submitted payment.
    Internal,
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
            Self::InvalidChallenge => "invalid-challenge",
            Self::Internal => "internal",
        }
    }

    /// Returns the problem type this code is reported as, relative to
    /// [`CORE_PROBLEM_TYPE_BASE`](crate::error::CORE_PROBLEM_TYPE_BASE)
    /// (e.g. `payment-expired`, `session/channel-not-found`).
    ///
    /// Derived from the same conversion that builds the problem details of a
    /// [`VerificationError`], so the two cannot disagree.
    pub fn spec_code(&self) -> &'static str {
        MppError::from(VerificationError::with_code(String::new(), *self))
            .problem_type_suffix()
            .unwrap_or(crate::error::INTERNAL_PROBLEM_TYPE_SUFFIX)
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
    /// Whether the client should retry with the same credential.
    ///
    /// Retryable errors are reported as `internal-payment-error` rather than
    /// as a payment problem with a fresh challenge.
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

    /// Create an "invalid-challenge" verification error.
    pub fn invalid_challenge(message: impl Into<String>) -> Self {
        Self::with_code(message, ErrorCode::InvalidChallenge)
    }

    /// Create an "internal" verification error for a server-side failure.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::with_code(message, ErrorCode::Internal)
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
        // A retryable failure is resolved by resending the same credential,
        // so it must not be reported as a payment problem: those are answered
        // with a fresh challenge, which asks the client to pay again.
        if err.retryable {
            return MppError::Internal(err.message);
        }
        match err.code {
            Some(ErrorCode::Expired) => MppError::PaymentExpired(None),
            Some(ErrorCode::InvalidChallenge) => MppError::invalid_challenge_reason(err.message),
            Some(ErrorCode::NetworkError) | Some(ErrorCode::Internal) => {
                MppError::Internal(err.message)
            }
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

    /// Problem types and statuses from the core spec's "Error Codes" table
    /// and the session spec's problem type registry.
    const SPEC_PROBLEMS: &[(&str, u16)] = &[
        ("payment-required", 402),
        ("payment-insufficient", 402),
        ("payment-expired", 402),
        ("verification-failed", 402),
        ("method-unsupported", 400),
        ("malformed-credential", 402),
        ("invalid-challenge", 402),
        ("bad-request", 400),
        ("invalid-payload", 402),
        ("internal-payment-error", 500),
        ("payment-action-required", 402),
        ("session/invalid-signature", 402),
        ("session/signer-mismatch", 402),
        ("session/amount-exceeds-deposit", 402),
        ("session/delta-too-small", 402),
        ("session/channel-not-found", 410),
        ("session/channel-finalized", 410),
        ("session/insufficient-balance", 402),
    ];

    #[track_caller]
    fn assert_spec_problem(label: &str, problem: PaymentErrorDetails, suffix: &str) {
        let (_, status) = SPEC_PROBLEMS
            .iter()
            .find(|(problem_type, _)| *problem_type == suffix)
            .unwrap_or_else(|| panic!("{label}: {suffix} is not a spec problem type"));
        assert_eq!(
            problem.problem_type,
            format!("{}/{suffix}", crate::error::CORE_PROBLEM_TYPE_BASE),
            "{label}"
        );
        assert_eq!(problem.status, *status, "{label}");
        if suffix == "internal-payment-error" {
            assert_eq!(
                problem.detail, "An internal payment error occurred.",
                "{label}"
            );
        }
    }

    #[test]
    fn test_problem_mapping_matches_spec() {
        let reason = || Some("reason".to_string());
        let errors = [
            (
                MppError::MalformedCredential(reason()),
                "malformed-credential",
            ),
            (
                MppError::InvalidChallenge {
                    id: None,
                    reason: reason(),
                },
                "invalid-challenge",
            ),
            (
                MppError::VerificationFailed(reason()),
                "verification-failed",
            ),
            (MppError::PaymentExpired(reason()), "payment-expired"),
            (
                MppError::PaymentRequired {
                    realm: None,
                    description: None,
                },
                "payment-required",
            ),
            (MppError::InvalidPayload(reason()), "invalid-payload"),
            (MppError::BadRequest(reason()), "bad-request"),
            (
                MppError::UnsupportedPaymentMethod("method".into()),
                "method-unsupported",
            ),
            (
                MppError::PaymentActionRequired(reason()),
                "payment-action-required",
            ),
            (
                MppError::PaymentInsufficient(reason()),
                "payment-insufficient",
            ),
            (
                MppError::InsufficientBalance(reason()),
                "session/insufficient-balance",
            ),
            (
                MppError::InvalidSignature(reason()),
                "session/invalid-signature",
            ),
            (
                MppError::SignerMismatch(reason()),
                "session/signer-mismatch",
            ),
            (
                MppError::AmountExceedsDeposit(reason()),
                "session/amount-exceeds-deposit",
            ),
            (MppError::DeltaTooSmall(reason()), "session/delta-too-small"),
            (
                MppError::ChannelNotFound(reason()),
                "session/channel-not-found",
            ),
            (
                MppError::ChannelClosed(reason()),
                "session/channel-finalized",
            ),
            (
                MppError::Internal("store unavailable".into()),
                "internal-payment-error",
            ),
            (
                MppError::Http("rpc unavailable".into()),
                "internal-payment-error",
            ),
        ];
        for (error, suffix) in errors {
            let label = format!("{error:?}");
            let payment_problem = (suffix != "internal-payment-error").then_some(suffix);
            assert_eq!(error.problem_type_suffix(), payment_problem, "{label}");
            assert_spec_problem(&label, error.to_problem_details(None), suffix);
        }

        let codes = [
            (ErrorCode::Expired, "payment-expired"),
            (ErrorCode::InvalidAmount, "verification-failed"),
            (ErrorCode::InvalidRecipient, "verification-failed"),
            (ErrorCode::TransactionFailed, "verification-failed"),
            (ErrorCode::NotFound, "verification-failed"),
            (ErrorCode::InvalidCredential, "malformed-credential"),
            (ErrorCode::NetworkError, "internal-payment-error"),
            (ErrorCode::ChainIdMismatch, "verification-failed"),
            (ErrorCode::CredentialMismatch, "verification-failed"),
            (ErrorCode::ChannelNotFound, "session/channel-not-found"),
            (ErrorCode::ChannelClosed, "session/channel-finalized"),
            (
                ErrorCode::InsufficientBalance,
                "session/insufficient-balance",
            ),
            (ErrorCode::InvalidPayload, "invalid-payload"),
            (ErrorCode::InvalidSignature, "session/invalid-signature"),
            (
                ErrorCode::AmountExceedsDeposit,
                "session/amount-exceeds-deposit",
            ),
            (ErrorCode::DeltaTooSmall, "session/delta-too-small"),
            (ErrorCode::InvalidChallenge, "invalid-challenge"),
            (ErrorCode::Internal, "internal-payment-error"),
        ];
        for (code, suffix) in codes {
            let label = format!("{code:?}");
            assert_eq!(code.spec_code(), suffix, "{label}");
            let error = VerificationError::with_code("message", code);
            assert_spec_problem(&label, error.to_problem_details(None), suffix);
        }

        assert_spec_problem(
            "no code",
            VerificationError::new("message").to_problem_details(None),
            "verification-failed",
        );
        // Retryable failures are resolved with the same credential, so they
        // must not be answered with a payment problem and a fresh challenge.
        for (label, error) in [
            ("pending", VerificationError::pending("not yet mined")),
            ("network", VerificationError::network_error("rpc down")),
            (
                "retryable",
                VerificationError::invalid_amount("message").retryable(),
            ),
        ] {
            assert_spec_problem(
                label,
                error.to_problem_details(None),
                "internal-payment-error",
            );
        }
    }
}
