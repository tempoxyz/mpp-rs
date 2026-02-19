//! Gas-aware nonce resolution and stuck transaction detection.
//!
//! Detects stuck pending transactions by comparing confirmed vs pending nonce,
//! reads stuck tx gas prices via `txpool_content`, and bumps gas fees to replace.
//! Falls back to base fee × 2 + priority when no stuck transactions exist.

use alloy::primitives::Address;

use crate::error::MppError;

/// Resolved nonce and gas fees, ready for transaction building.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedGas {
    /// The confirmed nonce to use (replaces any stuck pending tx).
    pub nonce: u64,
    /// Max fee per gas in wei.
    pub max_fee_per_gas: u128,
    /// Max priority fee per gas in wei.
    pub max_priority_fee_per_gas: u128,
}

/// Resolve the nonce and gas fees for an account, detecting and replacing stuck transactions.
///
/// This function:
/// 1. Fetches the confirmed (latest) nonce
/// 2. Compares against the pending nonce to detect stuck transactions
/// 3. If stuck txs exist: reads their gas via `txpool_content` and bids 2× to replace
/// 4. If no stuck txs: checks the latest block's base fee and ensures max_fee covers it
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
    // Confirmed (latest) nonce — we use this so we replace any stuck txs.
    let nonce = provider
        .get_transaction_count(from)
        .await
        .map_err(|e| MppError::Http(format!("failed to get nonce: {}", e)))?;

    // Pending nonce — if higher, there are stuck txs in the mempool.
    let pending_nonce = provider
        .get_transaction_count(from)
        .pending()
        .await
        .unwrap_or(nonce);

    let (max_fee_per_gas, max_priority_fee_per_gas) = if pending_nonce > nonce {
        // Stuck pending txs detected — bump gas to replace them.
        let stuck_gas = read_stuck_tx_gas(provider, from, nonce).await;

        if let Some((stuck_max_fee, stuck_priority)) = stuck_gas {
            // Bid 2× the stuck tx's gas, floored by defaults.
            (
                std::cmp::max(stuck_max_fee as u128 * 2, default_max_fee),
                std::cmp::max(stuck_priority as u128 * 2, default_priority_fee),
            )
        } else {
            // Can't read stuck tx — use 10× default as safe fallback.
            (default_max_fee * 10, default_priority_fee * 10)
        }
    } else {
        // No stuck txs — check current base fee and bump if needed.
        bump_for_base_fee(provider, default_max_fee, default_priority_fee).await
    };

    Ok(ResolvedGas {
        nonce,
        max_fee_per_gas,
        max_priority_fee_per_gas,
    })
}

/// Read a stuck transaction's gas fees from `txpool_content`.
///
/// Returns `Some((max_fee_per_gas, max_priority_fee_per_gas))` if the stuck tx
/// at the given nonce is found, `None` otherwise.
async fn read_stuck_tx_gas<P: alloy::providers::Provider>(
    provider: &P,
    from: Address,
    nonce: u64,
) -> Option<(u64, u64)> {
    let pool: serde_json::Value = provider
        .raw_request("txpool_content".into(), ())
        .await
        .ok()?;

    let from_hex = format!("{:#x}", from);
    let nonce_str = format!("{}", nonce);

    let tx = pool
        .get("pending")?
        .get(&from_hex)
        .or_else(|| {
            // txpool keys may use checksummed addresses
            pool.get("pending")?
                .as_object()?
                .iter()
                .find(|(k, _)| k.to_lowercase() == from_hex.to_lowercase())
                .map(|(_, v)| v)
        })?
        .get(&nonce_str)?;

    let max_fee = u64::from_str_radix(
        tx.get("maxFeePerGas")?.as_str()?.trim_start_matches("0x"),
        16,
    )
    .ok()?;
    let max_priority = u64::from_str_radix(
        tx.get("maxPriorityFeePerGas")?
            .as_str()?
            .trim_start_matches("0x"),
        16,
    )
    .ok()?;

    Some((max_fee, max_priority))
}

/// Check the latest block's base fee and bump max_fee if it's too low.
///
/// Ensures `max_fee_per_gas >= base_fee * 2 + priority_fee` so the transaction
/// is competitive in the current fee market.
async fn bump_for_base_fee<P: alloy::providers::Provider>(
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
