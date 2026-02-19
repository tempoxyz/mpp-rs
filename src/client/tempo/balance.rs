//! TIP-20 token balance queries for Tempo networks.

use alloy::primitives::{Address, U256};

use super::abi::ITIP20;
use crate::error::MppError;

/// Query the TIP-20 balance of a token for an account.
///
/// # Arguments
///
/// * `provider` - An alloy provider connected to the target network
/// * `token` - The TIP-20 token contract address
/// * `account` - The account to check the balance for
///
/// # Examples
///
/// ```ignore
/// use mpp::client::tempo::balance::query_token_balance;
///
/// let balance = query_token_balance(&provider, token_address, wallet_address).await?;
/// ```
pub async fn query_token_balance<P: alloy::providers::Provider + Clone>(
    provider: &P,
    token: Address,
    account: Address,
) -> Result<U256, MppError> {
    let contract = ITIP20::new(token, provider);
    let balance = contract
        .balanceOf(account)
        .call()
        .await
        .map_err(|e| MppError::Http(format!("failed to query token balance: {}", e)))?;

    Ok(balance)
}

/// Compute effective spending capacity from wallet balance and optional spending limit.
///
/// When a key enforces spending limits, the effective capacity is the minimum
/// of the wallet balance and the remaining spending limit. Otherwise, capacity
/// equals the wallet balance.
pub fn effective_capacity(balance: U256, spending_limit: Option<U256>) -> U256 {
    match spending_limit {
        Some(limit) => balance.min(limit),
        None => balance,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_effective_capacity_no_limit() {
        let balance = U256::from(1_000_000u64);
        assert_eq!(effective_capacity(balance, None), balance);
    }

    #[test]
    fn test_effective_capacity_limit_below_balance() {
        let balance = U256::from(1_000_000u64);
        let limit = U256::from(500_000u64);
        assert_eq!(effective_capacity(balance, Some(limit)), limit);
    }

    #[test]
    fn test_effective_capacity_limit_above_balance() {
        let balance = U256::from(500_000u64);
        let limit = U256::from(1_000_000u64);
        assert_eq!(effective_capacity(balance, Some(limit)), balance);
    }

    #[test]
    fn test_effective_capacity_equal() {
        let val = U256::from(1_000_000u64);
        assert_eq!(effective_capacity(val, Some(val)), val);
    }

    #[test]
    fn test_effective_capacity_zero_limit() {
        let balance = U256::from(1_000_000u64);
        assert_eq!(effective_capacity(balance, Some(U256::ZERO)), U256::ZERO);
    }

    #[test]
    fn test_effective_capacity_zero_balance() {
        assert_eq!(
            effective_capacity(U256::ZERO, Some(U256::from(1_000_000u64))),
            U256::ZERO
        );
    }

    #[test]
    fn test_effective_capacity_both_zero() {
        assert_eq!(effective_capacity(U256::ZERO, Some(U256::ZERO)), U256::ZERO);
    }
}
