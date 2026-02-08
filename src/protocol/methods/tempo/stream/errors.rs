//! Stream-specific error types.
//!
//! These errors map to specific HTTP status codes and are used throughout
//! the stream payment verification logic.

use std::fmt;

/// Stream-specific error type.
///
/// Each variant carries a `reason` string and maps to a specific HTTP status code,
/// matching the TypeScript reference implementation's error classes.
#[derive(Debug, Clone)]
pub enum StreamError {
    /// Channel not found in storage (HTTP 410 Gone).
    ChannelNotFound { reason: String },
    /// Channel is finalized/closed (HTTP 410 Gone).
    ChannelClosed { reason: String },
    /// Another stream is active on this channel (HTTP 409 Conflict).
    ChannelConflict { reason: String },
    /// Insufficient balance in session (HTTP 402 Payment Required).
    InsufficientBalance { reason: String },
    /// Invalid voucher signature (HTTP 402 Payment Required).
    InvalidSignature { reason: String },
    /// Recovered signer is not authorized for this channel (HTTP 402 Payment Required).
    SignerMismatch { reason: String },
    /// Voucher amount exceeds channel deposit (HTTP 402 Payment Required).
    AmountExceedsDeposit { reason: String },
    /// Voucher delta is below minimum threshold (HTTP 402 Payment Required).
    DeltaTooSmall { reason: String },
    /// Challenge ID is unknown or expired (HTTP 410 Gone).
    ChallengeNotFound { reason: String },
    /// General verification failure (HTTP 402 Payment Required).
    VerificationFailed { reason: String },
    /// Malformed request (HTTP 400 Bad Request).
    BadRequest { reason: String },
}

impl StreamError {
    /// Returns the HTTP status code for this error.
    pub fn status(&self) -> u16 {
        match self {
            Self::ChannelNotFound { .. } => 410,
            Self::ChannelClosed { .. } => 410,
            Self::ChallengeNotFound { .. } => 410,
            Self::ChannelConflict { .. } => 409,
            Self::InsufficientBalance { .. } => 402,
            Self::InvalidSignature { .. } => 402,
            Self::SignerMismatch { .. } => 402,
            Self::AmountExceedsDeposit { .. } => 402,
            Self::DeltaTooSmall { .. } => 402,
            Self::VerificationFailed { .. } => 402,
            Self::BadRequest { .. } => 400,
        }
    }

    /// Returns the reason string.
    pub fn reason(&self) -> &str {
        match self {
            Self::ChannelNotFound { reason }
            | Self::ChannelClosed { reason }
            | Self::ChallengeNotFound { reason }
            | Self::ChannelConflict { reason }
            | Self::InsufficientBalance { reason }
            | Self::InvalidSignature { reason }
            | Self::SignerMismatch { reason }
            | Self::AmountExceedsDeposit { reason }
            | Self::DeltaTooSmall { reason }
            | Self::VerificationFailed { reason }
            | Self::BadRequest { reason } => reason,
        }
    }

    /// Returns the problem type suffix for RFC 9457.
    pub fn problem_type_suffix(&self) -> &'static str {
        match self {
            Self::ChannelNotFound { .. } => "channel-not-found",
            Self::ChannelClosed { .. } => "channel-finalized",
            Self::ChallengeNotFound { .. } => "challenge-not-found",
            Self::ChannelConflict { .. } => "channel-conflict",
            Self::InsufficientBalance { .. } => "insufficient-balance",
            Self::InvalidSignature { .. } => "invalid-signature",
            Self::SignerMismatch { .. } => "signer-mismatch",
            Self::AmountExceedsDeposit { .. } => "amount-exceeds-deposit",
            Self::DeltaTooSmall { .. } => "delta-too-small",
            Self::VerificationFailed { .. } => "verification-failed",
            Self::BadRequest { .. } => "bad-request",
        }
    }
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.reason())
    }
}

impl std::error::Error for StreamError {}

// ==================== Conversions ====================

#[cfg(feature = "server")]
impl From<StreamError> for crate::protocol::traits::VerificationError {
    fn from(err: StreamError) -> Self {
        use crate::protocol::traits::ErrorCode;

        let code = match &err {
            StreamError::ChannelNotFound { .. } => Some(ErrorCode::NotFound),
            StreamError::ChannelClosed { .. } => Some(ErrorCode::NotFound),
            StreamError::ChallengeNotFound { .. } => Some(ErrorCode::NotFound),
            StreamError::ChannelConflict { .. } => None,
            StreamError::InsufficientBalance { .. } => Some(ErrorCode::InvalidAmount),
            StreamError::InvalidSignature { .. } => Some(ErrorCode::InvalidCredential),
            StreamError::SignerMismatch { .. } => Some(ErrorCode::InvalidCredential),
            StreamError::AmountExceedsDeposit { .. } => Some(ErrorCode::InvalidAmount),
            StreamError::DeltaTooSmall { .. } => Some(ErrorCode::InvalidAmount),
            StreamError::VerificationFailed { .. } => None,
            StreamError::BadRequest { .. } => Some(ErrorCode::InvalidCredential),
        };

        let mut ve = crate::protocol::traits::VerificationError::new(err.to_string());
        ve.code = code;
        ve
    }
}

impl From<StreamError> for crate::error::MppError {
    fn from(err: StreamError) -> Self {
        match &err {
            StreamError::ChannelNotFound { .. }
            | StreamError::ChannelClosed { .. }
            | StreamError::ChallengeNotFound { .. } => {
                crate::error::MppError::VerificationFailed(Some(err.to_string()))
            }
            StreamError::ChannelConflict { .. } => {
                crate::error::MppError::VerificationFailed(Some(err.to_string()))
            }
            StreamError::InvalidSignature { .. } | StreamError::SignerMismatch { .. } => {
                crate::error::MppError::VerificationFailed(Some(err.to_string()))
            }
            StreamError::BadRequest { .. } => {
                crate::error::MppError::InvalidPayload(Some(err.to_string()))
            }
            _ => crate::error::MppError::VerificationFailed(Some(err.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_codes() {
        assert_eq!(
            StreamError::ChannelNotFound {
                reason: "not found".into()
            }
            .status(),
            410
        );
        assert_eq!(
            StreamError::ChannelClosed {
                reason: "closed".into()
            }
            .status(),
            410
        );
        assert_eq!(
            StreamError::ChallengeNotFound {
                reason: "expired".into()
            }
            .status(),
            410
        );
        assert_eq!(
            StreamError::ChannelConflict {
                reason: "conflict".into()
            }
            .status(),
            409
        );
        assert_eq!(
            StreamError::InsufficientBalance {
                reason: "overdraft".into()
            }
            .status(),
            402
        );
        assert_eq!(
            StreamError::InvalidSignature {
                reason: "bad sig".into()
            }
            .status(),
            402
        );
        assert_eq!(
            StreamError::SignerMismatch {
                reason: "wrong signer".into()
            }
            .status(),
            402
        );
        assert_eq!(
            StreamError::AmountExceedsDeposit {
                reason: "too much".into()
            }
            .status(),
            402
        );
        assert_eq!(
            StreamError::DeltaTooSmall {
                reason: "too small".into()
            }
            .status(),
            402
        );
        assert_eq!(
            StreamError::VerificationFailed {
                reason: "failed".into()
            }
            .status(),
            402
        );
        assert_eq!(
            StreamError::BadRequest {
                reason: "bad".into()
            }
            .status(),
            400
        );
    }

    #[test]
    fn test_display() {
        let err = StreamError::ChannelNotFound {
            reason: "channel not found".into(),
        };
        assert_eq!(err.to_string(), "channel not found");
    }

    #[test]
    fn test_problem_type_suffix() {
        assert_eq!(
            StreamError::ChannelNotFound { reason: "".into() }.problem_type_suffix(),
            "channel-not-found"
        );
        assert_eq!(
            StreamError::ChannelClosed { reason: "".into() }.problem_type_suffix(),
            "channel-finalized"
        );
        assert_eq!(
            StreamError::ChallengeNotFound { reason: "".into() }.problem_type_suffix(),
            "challenge-not-found"
        );
        assert_eq!(
            StreamError::InvalidSignature { reason: "".into() }.problem_type_suffix(),
            "invalid-signature"
        );
        assert_eq!(
            StreamError::SignerMismatch { reason: "".into() }.problem_type_suffix(),
            "signer-mismatch"
        );
    }

    #[test]
    #[cfg(feature = "server")]
    fn test_conversion_to_verification_error() {
        use crate::protocol::traits::ErrorCode;

        let err = StreamError::InvalidSignature {
            reason: "invalid voucher signature".into(),
        };
        let ve: crate::protocol::traits::VerificationError = err.into();
        assert_eq!(ve.code, Some(ErrorCode::InvalidCredential));
        assert!(ve.message.contains("invalid voucher signature"));

        let err = StreamError::SignerMismatch {
            reason: "wrong signer".into(),
        };
        let ve: crate::protocol::traits::VerificationError = err.into();
        assert_eq!(ve.code, Some(ErrorCode::InvalidCredential));
        assert!(ve.message.contains("wrong signer"));

        let err = StreamError::ChallengeNotFound {
            reason: "expired".into(),
        };
        let ve: crate::protocol::traits::VerificationError = err.into();
        assert_eq!(ve.code, Some(ErrorCode::NotFound));
    }

    #[test]
    fn test_conversion_to_mpp_error() {
        let err = StreamError::BadRequest {
            reason: "missing field".into(),
        };
        let mpp: crate::error::MppError = err.into();
        assert!(matches!(mpp, crate::error::MppError::InvalidPayload(_)));

        let err = StreamError::SignerMismatch {
            reason: "wrong".into(),
        };
        let mpp: crate::error::MppError = err.into();
        assert!(matches!(mpp, crate::error::MppError::VerificationFailed(_)));
    }
}
