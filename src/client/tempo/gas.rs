//! Gas fee resolution from on-chain state.
//!
//! Queries the pending nonce and latest block's base fee to produce
//! gas parameters that are competitive in the current fee market.

use alloy::primitives::Address;

use crate::error::MppError;

/// Resolved nonce and gas fees, ready for transaction building.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedGas {
    /// The pending nonce (queues after any in-flight transactions).
    pub nonce: u64,
    /// Max fee per gas in wei.
    pub max_fee_per_gas: u128,
    /// Max priority fee per gas in wei.
    pub max_priority_fee_per_gas: u128,
}

/// Resolve the pending nonce and gas fees for an account.
///
/// This function:
/// 1. Fetches the pending nonce (so sequential payments queue correctly)
/// 2. Reads the latest block's base fee
/// 3. Sets `max_fee_per_gas = max(base_fee * 2 + priority_fee, default_max_fee)`
///
/// # Arguments
///
/// * `provider` - An alloy provider connected to the target network
/// * `from` - The account address to resolve nonce for
/// * `default_max_fee` - Default max fee per gas in wei (used as floor)
/// * `default_priority_fee` - Default max priority fee per gas in wei
pub async fn resolve_gas<P: alloy::providers::Provider>(
    provider: &P,
    from: Address,
    default_max_fee: u128,
    default_priority_fee: u128,
) -> Result<ResolvedGas, MppError> {
    let nonce = provider
        .get_transaction_count(from)
        .pending()
        .await
        .map_err(|e| MppError::Http(format!("failed to get nonce: {}", e)))?;

    let (max_fee_per_gas, max_priority_fee_per_gas) =
        resolve_fees(provider, default_max_fee, default_priority_fee).await;

    Ok(ResolvedGas {
        nonce,
        max_fee_per_gas,
        max_priority_fee_per_gas,
    })
}

/// Resolve gas fees from the latest block's base fee.
///
/// Ensures `max_fee_per_gas >= base_fee * 2 + priority_fee` so the transaction
/// is competitive in the current fee market. Returns the defaults if the
/// base fee cannot be read.
async fn resolve_fees<P: alloy::providers::Provider>(
    provider: &P,
    default_max_fee: u128,
    default_priority_fee: u128,
) -> (u128, u128) {
    let base_fee = async {
        let block_num = provider.get_block_number().await.ok()?;
        let block = provider
            .get_block_by_number(block_num.into())
            .await
            .ok()??;
        block.header.base_fee_per_gas
    }
    .await;

    if let Some(base_fee) = base_fee {
        let min_max_fee = base_fee as u128 * 2 + default_priority_fee;
        if min_max_fee > default_max_fee {
            return (min_max_fee, default_priority_fee);
        }
    }

    (default_max_fee, default_priority_fee)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolved_gas_fields() {
        let resolved = ResolvedGas {
            nonce: 42,
            max_fee_per_gas: 20_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
        };
        assert_eq!(resolved.nonce, 42);
        assert_eq!(resolved.max_fee_per_gas, 20_000_000_000);
        assert_eq!(resolved.max_priority_fee_per_gas, 1_000_000_000);
    }
}
