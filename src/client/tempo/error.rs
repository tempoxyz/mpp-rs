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

/// Extract the value for `key` from a revert string like `"{ key: value, ... }"`.
///
/// Looks for `"{key}: "` and returns the text up to the next `,`, `}`, or `)`.
fn extract_field(raw: &str, key: &str) -> Option<String> {
    let needle = format!("{key}: ");
    let start = raw.find(&needle)? + needle.len();
    let rest = &raw[start..];
    let end = rest.find([',', '}', ')']).unwrap_or(rest.len());
    let value = rest[..end].trim();
    if value.is_empty() {
        return None;
    }
    Some(value.to_string())
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
            if let (Some(token), Some(limit), Some(required)) = (
                extract_field(&msg, "token"),
                extract_field(&msg, "limit"),
                extract_field(&msg, "required"),
            ) {
                return Some(Self::SpendingLimitExceeded {
                    token,
                    limit,
                    required,
                });
            }
            return Some(Self::SpendingLimitExceeded {
                token: String::new(),
                limit: String::new(),
                required: msg,
            });
        }

        if lower.contains("insufficientbalance")
            || lower.contains("transfer amount exceeds balance")
            || (lower.contains("insufficient") && lower.contains("balance"))
        {
            if let (Some(token), Some(available), Some(required)) = (
                extract_field(&msg, "token"),
                extract_field(&msg, "available"),
                extract_field(&msg, "required"),
            ) {
                return Some(Self::InsufficientBalance {
                    token,
                    available,
                    required,
                });
            }
            return Some(Self::InsufficientBalance {
                token: String::new(),
                available: String::new(),
                required: msg,
            });
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
            Some(TempoClientError::SpendingLimitExceeded { .. })
        ));
    }

    #[test]
    fn test_classify_insufficient_balance() {
        let err = TempoClientError::classify_rpc_error("InsufficientBalance for transfer");
        assert!(matches!(
            err,
            Some(TempoClientError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn test_classify_transfer_exceeds_balance() {
        let err = TempoClientError::classify_rpc_error("transfer amount exceeds balance");
        assert!(matches!(
            err,
            Some(TempoClientError::InsufficientBalance { .. })
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

    // --- extract_field ---

    #[test]
    fn test_extract_field_basic() {
        let raw = "InsufficientBalance { available: 0, required: 64467, token: 0xabc }";
        assert_eq!(extract_field(raw, "available"), Some("0".to_string()));
        assert_eq!(extract_field(raw, "required"), Some("64467".to_string()));
        assert_eq!(extract_field(raw, "token"), Some("0xabc".to_string()));
    }

    #[test]
    fn test_extract_field_missing() {
        assert_eq!(extract_field("no fields here", "token"), None);
    }

    // --- classify with field extraction ---

    #[test]
    fn test_classify_insufficient_balance_with_fields() {
        let msg = "server returned error: execution reverted: revert: InsufficientBalance(InsufficientBalance { available: 0, required: 64467, token: 0x20c000000000000000000000b9537d11c60e8b50 })";
        let err = TempoClientError::classify_rpc_error(msg).unwrap();
        match err {
            TempoClientError::InsufficientBalance {
                token,
                available,
                required,
            } => {
                assert_eq!(available, "0");
                assert_eq!(required, "64467");
                assert_eq!(token, "0x20c000000000000000000000b9537d11c60e8b50");
            }
            other => panic!("expected InsufficientBalance, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_spending_limit_with_fields() {
        let msg = "execution reverted: SpendingLimitExceeded(SpendingLimitExceeded { token: 0xabc, limit: 1000, required: 5000 })";
        let err = TempoClientError::classify_rpc_error(msg).unwrap();
        match err {
            TempoClientError::SpendingLimitExceeded {
                token,
                limit,
                required,
            } => {
                assert_eq!(token, "0xabc");
                assert_eq!(limit, "1000");
                assert_eq!(required, "5000");
            }
            other => panic!("expected SpendingLimitExceeded, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_insufficient_balance_fallback_no_fields() {
        let msg = "InsufficientBalance for transfer";
        let err = TempoClientError::classify_rpc_error(msg).unwrap();
        match err {
            TempoClientError::InsufficientBalance {
                token,
                available,
                required,
            } => {
                assert!(token.is_empty());
                assert!(available.is_empty());
                assert_eq!(required, msg);
            }
            other => panic!("expected InsufficientBalance, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_spending_limit_fallback_no_fields() {
        let msg = "SpendingLimitExceeded: limit is 0.50, need 1.00";
        let err = TempoClientError::classify_rpc_error(msg).unwrap();
        match err {
            TempoClientError::SpendingLimitExceeded {
                token,
                limit,
                required,
            } => {
                assert!(token.is_empty());
                assert!(limit.is_empty());
                assert_eq!(required, msg);
            }
            other => panic!("expected SpendingLimitExceeded, got {other:?}"),
        }
    }
}
