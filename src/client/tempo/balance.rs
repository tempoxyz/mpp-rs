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
