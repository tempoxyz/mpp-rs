//! Tempo-specific client errors.
//!
//! These errors represent failures specific to the Tempo payment method's
//! client-side operations (transaction building, gas estimation, signing).
//! They are scoped under `client::tempo` to make clear they belong to a
//! single payment method, not the protocol layer.

use thiserror::Error;

/// Errors specific to Tempo client-side payment operations.
#[derive(Error, Debug)]
pub enum TempoClientError {
    /// Access key is not provisioned on the wallet's keychain.
    #[error("Access key not provisioned on wallet")]
    AccessKeyNotProvisioned,

    /// Spending limit exceeded for a token.
    #[error("Spending limit exceeded for {token}: limit is {limit}, need {required}")]
    SpendingLimitExceeded {
        /// Token symbol or address.
        token: String,
        /// Current spending limit (human-readable).
        limit: String,
        /// Required amount (human-readable).
        required: String,
    },

    /// Wallet has insufficient balance to complete the payment.
    #[error("Insufficient {token} balance: have {available}, need {required}")]
    InsufficientBalance {
        /// Token symbol or address.
        token: String,
        /// Available balance (human-readable).
        available: String,
        /// Required amount (human-readable).
        required: String,
    },

    /// Transaction reverted on-chain (e.g., during gas estimation or broadcast).
    #[error("Transaction reverted: {0}")]
    TransactionReverted(String),
}

impl TempoClientError {
    /// Classify an RPC or on-chain error message into a typed error.
    ///
    /// Detects common Tempo revert reasons from gas estimation or transaction
    /// broadcast and returns structured variants. Falls back to
    /// `TransactionReverted` for recognized reverts, or returns `None` if the
    /// message doesn't look Tempo-specific.
    pub fn classify_rpc_error(msg: impl Into<String>) -> Option<Self> {
        let msg = msg.into();
        let lower = msg.to_lowercase();

        if lower.contains("not provisioned") {
            return Some(Self::AccessKeyNotProvisioned);
        }

        if lower.contains("spendinglimitexceeded") || lower.contains("spending limit") {
            return Some(Self::TransactionReverted(msg));
        }

        if lower.contains("insufficientbalance")
            || lower.contains("transfer amount exceeds balance")
            || (lower.contains("insufficient") && lower.contains("balance"))
        {
            return Some(Self::TransactionReverted(msg));
        }

        if lower.contains("revert") || lower.contains("execution reverted") {
            return Some(Self::TransactionReverted(msg));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_key_not_provisioned_display() {
        let err = TempoClientError::AccessKeyNotProvisioned;
        assert_eq!(err.to_string(), "Access key not provisioned on wallet");
    }

    #[test]
    fn test_spending_limit_exceeded_display() {
        let err = TempoClientError::SpendingLimitExceeded {
            token: "USDC".to_string(),
            limit: "0.50".to_string(),
            required: "1.00".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Spending limit exceeded for USDC: limit is 0.50, need 1.00"
        );
    }

    #[test]
    fn test_insufficient_balance_display() {
        let err = TempoClientError::InsufficientBalance {
            token: "pathUSD".to_string(),
            available: "0.50".to_string(),
            required: "1.00".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Insufficient pathUSD balance: have 0.50, need 1.00"
        );
    }

    #[test]
    fn test_transaction_reverted_display() {
        let err = TempoClientError::TransactionReverted("SpendingLimitExceeded".to_string());
        assert_eq!(
            err.to_string(),
            "Transaction reverted: SpendingLimitExceeded"
        );
    }

    // --- classify_rpc_error ---

    #[test]
    fn test_classify_not_provisioned() {
        let err = TempoClientError::classify_rpc_error("key not provisioned on wallet");
        assert!(matches!(
            err,
            Some(TempoClientError::AccessKeyNotProvisioned)
        ));
    }

    #[test]
    fn test_classify_spending_limit() {
        let err =
            TempoClientError::classify_rpc_error("SpendingLimitExceeded: limit is 0.50, need 1.00");
        assert!(matches!(
            err,
            Some(TempoClientError::TransactionReverted(_))
        ));
    }

    #[test]
    fn test_classify_insufficient_balance() {
        let err = TempoClientError::classify_rpc_error("InsufficientBalance for transfer");
        assert!(matches!(
            err,
            Some(TempoClientError::TransactionReverted(_))
        ));
    }

    #[test]
    fn test_classify_transfer_exceeds_balance() {
        let err = TempoClientError::classify_rpc_error("transfer amount exceeds balance");
        assert!(matches!(
            err,
            Some(TempoClientError::TransactionReverted(_))
        ));
    }

    #[test]
    fn test_classify_generic_revert() {
        let err = TempoClientError::classify_rpc_error("execution reverted: some reason");
        assert!(matches!(
            err,
            Some(TempoClientError::TransactionReverted(_))
        ));
    }

    #[test]
    fn test_classify_unknown_returns_none() {
        let err = TempoClientError::classify_rpc_error("failed to get nonce");
        assert!(err.is_none());
    }
}
