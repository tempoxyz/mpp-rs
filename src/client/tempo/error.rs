//! Tempo-specific client errors.
//!
//! These errors represent failures specific to the Tempo payment method's
//! client-side operations (transaction building, gas estimation, signing).
//! They are scoped under `client::tempo` to make clear they belong to a
//! single payment method, not the protocol layer.

use alloy::transports::TransportError;
use tempo_alloy::contracts::precompiles::{IAccountKeychain, ITIP20};
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
    ///
    /// When the payer is short of MACH on Tempo mainnet, `token` is `MACH`,
    /// the amounts are decimal MACH and `funding_url` links to where the
    /// payer can buy the shortfall (see
    /// [`machine_token::funding_url`](crate::protocol::methods::tempo::machine_token::funding_url)).
    #[error(
        "Insufficient {token} balance: have {available}, need {required}{}",
        format_funding_url(.funding_url)
    )]
    InsufficientBalance {
        /// Token symbol or address.
        token: String,
        /// Available balance (human-readable).
        available: String,
        /// Required amount (human-readable).
        required: String,
        /// Where the payer can buy the missing balance, when known.
        funding_url: Option<String>,
    },

    /// Transaction reverted on-chain (e.g., during gas estimation or broadcast).
    #[error("Transaction reverted: {0}")]
    TransactionReverted(String),
}

fn format_funding_url(funding_url: &Option<String>) -> String {
    match funding_url {
        Some(url) => format!(". Buy MACH at {url}"),
        None => String::new(),
    }
}

/// Reports an insufficient-balance failure of a payment the payer could fund
/// with MACH (`currency`, the token it spends or the charge currency) as a
/// MACH shortfall with the link to buy it, as
/// [`TempoClientError::machine_token_shortfall`] builds.
///
/// Other errors, failures naming another token (such as the gas token), chains
/// without MACH funding, a payer already holding `required` MACH and a
/// failed balance read keep the original error.
pub(crate) async fn with_machine_token_funding<P>(
    error: crate::error::MppError,
    provider: &P,
    chain_id: u64,
    payer: alloy::primitives::Address,
    currency: alloy::primitives::Address,
    required: alloy::primitives::U256,
) -> crate::error::MppError
where
    P: alloy::providers::Provider<tempo_alloy::TempoNetwork>,
{
    use crate::error::MppError;
    use crate::protocol::methods::tempo::machine_token::{self, MACH};

    if machine_token::funding_url(chain_id, None, None).is_none() || error.funding_url().is_some() {
        return error;
    }
    let names_payment_token = match &error {
        MppError::InsufficientBalance(_) => true,
        MppError::Tempo(TempoClientError::InsufficientBalance { token, .. }) => {
            match token.parse::<alloy::primitives::Address>() {
                Ok(token) => token == MACH || token == currency,
                // The node's message named no token.
                Err(_) => true,
            }
        }
        _ => false,
    };
    if !names_payment_token {
        return error;
    }
    let Ok(available) = ITIP20::new(MACH, provider).balanceOf(payer).call().await else {
        return error;
    };
    TempoClientError::machine_token_shortfall(chain_id, payer, available, required)
        .map(MppError::from)
        .unwrap_or(error)
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
    /// Where the payer can buy the balance it is missing, such as the MACH
    /// funding link of an [`InsufficientBalance`](Self::InsufficientBalance)
    /// error.
    pub fn funding_url(&self) -> Option<&str> {
        match self {
            Self::InsufficientBalance { funding_url, .. } => funding_url.as_deref(),
            _ => None,
        }
    }

    /// An [`InsufficientBalance`](Self::InsufficientBalance) error for a payer
    /// holding `available` of the `required` MACH on `chain_id`, with the link
    /// to buy the shortfall. `None` when nothing is short or the chain sells
    /// no MACH.
    pub(crate) fn machine_token_shortfall(
        chain_id: u64,
        payer: alloy::primitives::Address,
        available: alloy::primitives::U256,
        required: alloy::primitives::U256,
    ) -> Option<Self> {
        use crate::protocol::methods::tempo::machine_token;

        if available >= required {
            return None;
        }
        let saturate =
            |amount: alloy::primitives::U256| u128::try_from(amount).unwrap_or(u128::MAX);
        let (available, required) = (saturate(available), saturate(required));
        let funding_url =
            machine_token::funding_url(chain_id, Some(payer), Some(required - available))?;
        Some(Self::InsufficientBalance {
            token: "MACH".to_owned(),
            available: machine_token::format_amount(available),
            required: machine_token::format_amount(required),
            funding_url: Some(funding_url),
        })
    }

    /// Classify a transport error by first trying ABI-decoded revert data,
    /// then falling back to string-based classification.
    pub fn from_transport_error(e: &TransportError) -> Option<Self> {
        if let Some(payload) = e.as_error_resp() {
            if let Some(err) = payload.as_decoded_error::<ITIP20::InsufficientBalance>() {
                return Some(Self::InsufficientBalance {
                    token: err.token.to_string(),
                    available: err.available.to_string(),
                    required: err.required.to_string(),
                    funding_url: None,
                });
            }
            if payload
                .as_decoded_error::<IAccountKeychain::SpendingLimitExceeded>()
                .is_some()
            {
                let msg = e.to_string();
                return Some(Self::SpendingLimitExceeded {
                    token: extract_field(&msg, "token").unwrap_or_default(),
                    limit: extract_field(&msg, "limit").unwrap_or_default(),
                    required: extract_field(&msg, "required").unwrap_or(msg),
                });
            }
        }

        Self::classify_rpc_error(e.to_string())
    }

    /// Fallback: classify an error from its display string.
    ///
    /// Detects common Tempo revert reasons via substring matching.
    /// Returns `None` if the message doesn't look Tempo-specific.
    fn classify_rpc_error(msg: impl Into<String>) -> Option<Self> {
        let msg = msg.into();
        let lower = msg.to_lowercase();

        if lower.contains("not provisioned") {
            return Some(Self::AccessKeyNotProvisioned);
        }

        if lower.contains("spendinglimitexceeded") || lower.contains("spending limit") {
            return Some(Self::SpendingLimitExceeded {
                token: extract_field(&msg, "token").unwrap_or_default(),
                limit: extract_field(&msg, "limit").unwrap_or_default(),
                required: extract_field(&msg, "required").unwrap_or(msg),
            });
        }

        if lower.contains("insufficientbalance")
            || lower.contains("transfer amount exceeds balance")
            || (lower.contains("insufficient") && lower.contains("balance"))
        {
            return Some(Self::InsufficientBalance {
                token: extract_field(&msg, "token").unwrap_or_default(),
                available: extract_field(&msg, "available").unwrap_or_default(),
                required: extract_field(&msg, "required").unwrap_or(msg),
                funding_url: None,
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
            funding_url: None,
        };
        assert_eq!(
            err.to_string(),
            "Insufficient pathUSD balance: have 0.50, need 1.00"
        );
        assert_eq!(err.funding_url(), None);
    }

    fn mach_balance_provider(
        balance: u64,
    ) -> impl alloy::providers::Provider<tempo_alloy::TempoNetwork> {
        use alloy::providers::{mock::Asserter, ProviderBuilder};
        use alloy::sol_types::SolCall;

        let asserter = Asserter::new();
        asserter.push_success(&alloy::primitives::Bytes::from(
            ITIP20::balanceOfCall::abi_encode_returns(&alloy::primitives::U256::from(balance)),
        ));
        ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter)
    }

    #[tokio::test]
    async fn test_with_machine_token_funding_reports_the_mach_shortfall() {
        use crate::error::MppError;
        use crate::protocol::methods::tempo::{machine_token::MACH_FUNDING_URL, CHAIN_ID};
        use alloy::primitives::{Address, U256};

        let payer = Address::repeat_byte(0x11);
        let usdc = Address::repeat_byte(0x33);
        let original = MppError::from(TempoClientError::InsufficientBalance {
            token: usdc.to_string(),
            available: "0".into(),
            required: "1000000".into(),
            funding_url: None,
        });
        let error = with_machine_token_funding(
            original,
            &mach_balance_provider(400_000),
            CHAIN_ID,
            payer,
            usdc,
            U256::from(1_000_000),
        )
        .await;
        let url = format!("{MACH_FUNDING_URL}&address={payer}&amount=0.60");
        assert_eq!(error.funding_url(), Some(url.as_str()));
        assert!(
            error.to_string().contains("have 0.40, need 1.00"),
            "{error}"
        );

        // Autoswap's "no route" failure names no token.
        let error = with_machine_token_funding(
            MppError::InsufficientBalance(Some("no route".into())),
            &mach_balance_provider(0),
            CHAIN_ID,
            payer,
            usdc,
            U256::from(1_000_000),
        )
        .await;
        assert!(error.funding_url().is_some());
    }

    #[tokio::test]
    async fn test_with_machine_token_funding_keeps_unrelated_failures() {
        use crate::error::MppError;
        use crate::protocol::methods::tempo::{CHAIN_ID, MODERATO_CHAIN_ID};
        use alloy::primitives::{Address, U256};

        let payer = Address::repeat_byte(0x11);
        let usdc = Address::repeat_byte(0x33);
        let gas = |token: Address| {
            MppError::from(TempoClientError::InsufficientBalance {
                token: token.to_string(),
                available: "0".into(),
                required: "1".into(),
                funding_url: None,
            })
        };
        let required = U256::from(1_000_000);

        // The gas token is short, not the payment.
        let other = Address::repeat_byte(0x44);
        let error = with_machine_token_funding(
            gas(other),
            &mach_balance_provider(0),
            CHAIN_ID,
            payer,
            usdc,
            required,
        )
        .await;
        assert!(error.funding_url().is_none());
        // The payer already holds the MACH.
        let error = with_machine_token_funding(
            gas(usdc),
            &mach_balance_provider(1_000_000),
            CHAIN_ID,
            payer,
            usdc,
            required,
        )
        .await;
        assert!(error.funding_url().is_none());
        // MACH is not sold on testnet.
        let error = with_machine_token_funding(
            gas(usdc),
            &mach_balance_provider(0),
            MODERATO_CHAIN_ID,
            payer,
            usdc,
            required,
        )
        .await;
        assert!(error.funding_url().is_none());
        // Not a balance failure.
        let error = with_machine_token_funding(
            MppError::Http("boom".into()),
            &mach_balance_provider(0),
            CHAIN_ID,
            payer,
            usdc,
            required,
        )
        .await;
        assert!(matches!(error, MppError::Http(_)));
    }

    #[test]
    fn test_machine_token_shortfall_links_the_funding_page() {
        use crate::protocol::methods::tempo::{machine_token::MACH_FUNDING_URL, CHAIN_ID};
        use alloy::primitives::{Address, U256};

        let payer = Address::repeat_byte(0x11);
        let err = TempoClientError::machine_token_shortfall(
            CHAIN_ID,
            payer,
            U256::from(250_000),
            U256::from(1_000_000),
        )
        .unwrap();
        let url = format!("{MACH_FUNDING_URL}&address={payer}&amount=0.75");
        assert_eq!(err.funding_url(), Some(url.as_str()));
        assert_eq!(
            err.to_string(),
            format!("Insufficient MACH balance: have 0.25, need 1.00. Buy MACH at {url}")
        );
        assert_eq!(
            crate::error::MppError::from(err).funding_url(),
            Some(url.as_str())
        );

        assert!(TempoClientError::machine_token_shortfall(
            CHAIN_ID,
            payer,
            U256::from(1_000_000),
            U256::from(1_000_000)
        )
        .is_none());
        assert!(TempoClientError::machine_token_shortfall(
            crate::protocol::methods::tempo::MODERATO_CHAIN_ID,
            payer,
            U256::ZERO,
            U256::from(1_000_000)
        )
        .is_none());
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
                ..
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
                ..
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
