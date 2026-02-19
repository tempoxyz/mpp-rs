//! Auto-swap routing: find a token with sufficient balance to swap from.
//!
//! Given a required token and amount, searches candidate tokens for one with
//! enough balance (including slippage) and spending limit to perform a swap.

use alloy::primitives::{Address, U256};
use tempo_primitives::transaction::SignedKeyAuthorization;

use super::balance::query_token_balance;
use super::keychain::{local_key_spending_limit, query_key_spending_limit};
use super::swap::{BPS_DENOMINATOR, SWAP_SLIPPAGE_BPS};
use crate::error::MppError;

/// A candidate token that can be used as a swap source.
#[derive(Debug, Clone)]
pub struct SwapCandidate {
    /// Token contract address.
    pub address: Address,
    /// Human-readable symbol (e.g., "USDC").
    pub symbol: String,
}

/// A token found with sufficient balance for a swap.
#[derive(Debug, Clone)]
pub struct SwapSource {
    /// Token address that can be used as swap source.
    pub token_address: Address,
    /// Human-readable symbol.
    pub symbol: String,
}

/// Find a token with sufficient balance (and spending limit) to swap from.
///
/// Searches `candidates` for a token with enough balance to cover
/// `required_amount` plus slippage. When `keychain_info` is provided,
/// also checks spending limits and filters candidates accordingly.
///
/// # Arguments
///
/// * `provider` - An alloy provider connected to the target network
/// * `account` - Account to check balances for
/// * `required_token` - The token the merchant wants (excluded from candidates)
/// * `required_amount` - The amount needed (slippage is added automatically)
/// * `candidates` - List of tokens to check as potential swap sources
/// * `keychain_info` - Optional `(wallet_address, key_address)` for spending limit checks
/// * `local_auth` - Optional key authorization for local limit validation
///
/// # Returns
///
/// * `Ok(Some(SwapSource))` - Found a token with sufficient balance and limit
/// * `Ok(None)` - No token qualifies
pub async fn find_swap_source<P: alloy::providers::Provider + Clone>(
    provider: &P,
    account: Address,
    required_token: Address,
    required_amount: U256,
    candidates: &[SwapCandidate],
    keychain_info: Option<(Address, Address)>,
    local_auth: Option<&SignedKeyAuthorization>,
) -> Result<Option<SwapSource>, MppError> {
    let slippage = required_amount * U256::from(SWAP_SLIPPAGE_BPS) / U256::from(BPS_DENOMINATOR);
    let amount_with_slippage = required_amount + slippage;

    // Filter out the required token
    let tokens: Vec<_> = candidates
        .iter()
        .filter(|c| c.address != required_token)
        .collect();

    if let Some((wallet_addr, key_addr)) = keychain_info {
        // With keychain: check spending limits first, then balances for eligible tokens.
        let mut eligible: Vec<(&SwapCandidate, U256)> = Vec::new();

        for candidate in &tokens {
            let effective = match query_key_spending_limit(
                provider,
                wallet_addr,
                key_addr,
                candidate.address,
            )
            .await
            {
                Ok(None) => U256::MAX,
                Ok(Some(l)) if l >= amount_with_slippage => l,
                Ok(Some(_)) => continue,
                Err(_) if local_auth.is_some() => {
                    match local_key_spending_limit(local_auth.unwrap(), candidate.address) {
                        None => U256::MAX,
                        Some(l) if l >= amount_with_slippage => l,
                        Some(_) => continue,
                    }
                }
                Err(_) => continue,
            };
            eligible.push((candidate, effective));
        }

        // Sort by spending limit descending (prefer tokens with most headroom).
        eligible.sort_by(|a, b| b.1.cmp(&a.1));

        for (candidate, _) in eligible {
            if let Ok(balance) = query_token_balance(provider, candidate.address, account).await {
                if balance >= amount_with_slippage {
                    return Ok(Some(SwapSource {
                        token_address: candidate.address,
                        symbol: candidate.symbol.clone(),
                    }));
                }
            }
        }
    } else {
        // Without keychain: just check balances.
        for candidate in &tokens {
            if let Ok(balance) = query_token_balance(provider, candidate.address, account).await {
                if balance >= amount_with_slippage {
                    return Ok(Some(SwapSource {
                        token_address: candidate.address,
                        symbol: candidate.symbol.clone(),
                    }));
                }
            }
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_swap_candidate_fields() {
        let candidate = SwapCandidate {
            address: Address::repeat_byte(0x01),
            symbol: "USDC".to_string(),
        };
        assert_eq!(candidate.address, Address::repeat_byte(0x01));
        assert_eq!(candidate.symbol, "USDC");
    }

    #[test]
    fn test_swap_source_fields() {
        let source = SwapSource {
            token_address: Address::repeat_byte(0x02),
            symbol: "pathUSD".to_string(),
        };
        assert_eq!(source.token_address, Address::repeat_byte(0x02));
        assert_eq!(source.symbol, "pathUSD");
    }
}
