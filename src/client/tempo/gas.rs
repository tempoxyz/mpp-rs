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

/// Pure fee calculation from an optional base fee and defaults.
///
/// Returns `(max_fee_per_gas, max_priority_fee_per_gas)`.
/// When `base_fee` is present, ensures `max_fee_per_gas >= base_fee * 2 + priority_fee`.
/// Falls back to `default_max_fee` when the base fee is absent or when the
/// computed minimum does not exceed the default.
fn compute_fees(
    base_fee: Option<u64>,
    default_max_fee: u128,
    default_priority_fee: u128,
) -> (u128, u128) {
    if let Some(base_fee) = base_fee {
        let min_max_fee = base_fee as u128 * 2 + default_priority_fee;
        if min_max_fee > default_max_fee {
            return (min_max_fee, default_priority_fee);
        }
    }

    (default_max_fee, default_priority_fee)
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

    compute_fees(base_fee, default_max_fee, default_priority_fee)
}

/// Resolve nonce and gas with stuck-transaction detection.
///
/// Unlike [`resolve_gas`] which uses the pending nonce (queuing after
/// in-flight transactions), this function compares confirmed vs pending
/// nonces to detect stuck transactions and aggressively bumps gas to
/// replace them:
///
/// 1. Fetches confirmed nonce (`latest`) and pending nonce
/// 2. If `pending > confirmed`: a transaction is stuck in the mempool
///    - Tries `txpool_content` to read the stuck tx's gas and bids 2x
///    - Falls back to 10x defaults (capped) if txpool_content is unavailable
/// 3. If no stuck tx: falls back to normal base-fee adjustment via [`resolve_gas`]
///
/// # When to use
///
/// Use this for CLI tools or interactive clients where a previously stuck
/// transaction should be replaced automatically. Library consumers that
/// want standard queuing behavior should use [`resolve_gas`] instead.
pub async fn resolve_gas_with_stuck_detection<P: alloy::providers::Provider>(
    provider: &P,
    from: Address,
    default_max_fee: u128,
    default_priority_fee: u128,
) -> Result<ResolvedGas, MppError> {
    // Use confirmed nonce (not pending) so we can replace stuck transactions.
    let confirmed_nonce = provider
        .get_transaction_count(from)
        .await
        .map_err(|e| MppError::Http(format!("failed to get confirmed nonce: {}", e)))?;

    let pending_nonce = provider
        .get_transaction_count(from)
        .pending()
        .await
        .unwrap_or(confirmed_nonce);

    if pending_nonce > confirmed_nonce {
        // Stuck transaction detected — use confirmed nonce to replace it.
        let (max_fee_per_gas, max_priority_fee_per_gas) = resolve_stuck_tx_fees(
            provider,
            from,
            confirmed_nonce,
            default_max_fee,
            default_priority_fee,
        )
        .await;

        Ok(ResolvedGas {
            nonce: confirmed_nonce,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        })
    } else {
        // No stuck tx — use normal resolution (pending nonce + base-fee bump).
        resolve_gas(provider, from, default_max_fee, default_priority_fee).await
    }
}

/// Try to read the stuck tx's gas from `txpool_content` and bid above it.
///
/// Falls back to a capped 10x default if the RPC doesn't support `txpool_content`.
/// Also ensures the result is competitive with the current base fee.
async fn resolve_stuck_tx_fees<P: alloy::providers::Provider>(
    provider: &P,
    from: Address,
    nonce: u64,
    default_max_fee: u128,
    default_priority_fee: u128,
) -> (u128, u128) {
    // First, get the base-fee-competitive floor
    let (base_fee_max, _) = resolve_fees(provider, default_max_fee, default_priority_fee).await;

    let stuck_gas = read_stuck_tx_gas(provider, from, nonce).await;

    if let Some((stuck_max_fee, stuck_priority)) = stuck_gas {
        // Bid 2x the stuck tx's gas, but at least the base-fee-competitive floor
        let max_fee = std::cmp::max(stuck_max_fee * 2, base_fee_max);
        let priority = std::cmp::max(stuck_priority * 2, default_priority_fee);
        (max_fee, priority)
    } else {
        // Can't read stuck tx — bump defaults but cap to avoid overpayment.
        const MAX_FEE_CAP: u128 = 500_000_000_000; // 500 gwei
        const MAX_PRIORITY_CAP: u128 = 50_000_000_000; // 50 gwei

        let max_fee = std::cmp::min(default_max_fee * 10, MAX_FEE_CAP);
        let priority = std::cmp::min(default_priority_fee * 10, MAX_PRIORITY_CAP);
        // Ensure we're at least competitive with the base fee
        (std::cmp::max(max_fee, base_fee_max), priority)
    }
}

/// Read a stuck transaction's gas fees from `txpool_content`.
///
/// Returns `Some((max_fee_per_gas, max_priority_fee_per_gas))` if the stuck
/// tx can be found, `None` if the RPC doesn't support txpool or the tx
/// can't be parsed.
async fn read_stuck_tx_gas<P: alloy::providers::Provider>(
    provider: &P,
    from: Address,
    nonce: u64,
) -> Option<(u128, u128)> {
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
    let max_fee = u128::from_str_radix(
        tx.get("maxFeePerGas")?.as_str()?.trim_start_matches("0x"),
        16,
    )
    .ok()?;
    let max_priority = u128::from_str_radix(
        tx.get("maxPriorityFeePerGas")?
            .as_str()?
            .trim_start_matches("0x"),
        16,
    )
    .ok()?;
    Some((max_fee, max_priority))
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

    #[test]
    fn test_compute_fees_no_base_fee() {
        let (max_fee, priority) = compute_fees(None, 1_000_000_000, 500_000_000);
        assert_eq!(max_fee, 1_000_000_000);
        assert_eq!(priority, 500_000_000);
    }

    #[test]
    fn test_compute_fees_base_fee_raises_max() {
        // base_fee=2gwei → min_max_fee = 2*2gwei + 1gwei = 5gwei > 1gwei default
        let (max_fee, priority) =
            compute_fees(Some(2_000_000_000), 1_000_000_000, 1_000_000_000);
        assert_eq!(max_fee, 5_000_000_000);
        assert_eq!(priority, 1_000_000_000);
    }

    #[test]
    fn test_compute_fees_default_is_floor() {
        // base_fee=100 → min_max_fee = 200 + 50 = 250 < 1_000_000_000
        let (max_fee, priority) = compute_fees(Some(100), 1_000_000_000, 50);
        assert_eq!(max_fee, 1_000_000_000);
        assert_eq!(priority, 50);
    }

    #[test]
    fn test_compute_fees_boundary_equality() {
        // base_fee=500 → min_max_fee = 1000 + 500 = 1500 == default_max_fee
        // Not strictly greater, so returns defaults.
        let (max_fee, priority) = compute_fees(Some(500), 1500, 500);
        assert_eq!(max_fee, 1500);
        assert_eq!(priority, 500);
    }

    #[test]
    fn test_compute_fees_zero_base_fee() {
        // base_fee=0 → min_max_fee = 0 + 1gwei = 1gwei == default_max_fee
        let (max_fee, priority) =
            compute_fees(Some(0), 1_000_000_000, 1_000_000_000);
        assert_eq!(max_fee, 1_000_000_000);
        assert_eq!(priority, 1_000_000_000);
    }

    #[test]
    fn test_compute_fees_large_base_fee() {
        // u64::MAX → 2 * u64::MAX + priority must not overflow u128
        let base = u64::MAX;
        let priority = 1_000_000_000_u128;
        let default_max = 1_000_000_000_u128;
        let (max_fee, pri) = compute_fees(Some(base), default_max, priority);
        let expected = base as u128 * 2 + priority;
        assert_eq!(max_fee, expected);
        assert_eq!(pri, priority);
        assert!(expected > default_max);
    }

    #[test]
    fn test_compute_fees_priority_always_passes_through() {
        let priority = 7_777_777_777_u128;

        // Case 1: no base fee
        let (_, pri) = compute_fees(None, 1_000_000_000, priority);
        assert_eq!(pri, priority);

        // Case 2: base fee raises max
        let (_, pri) = compute_fees(Some(10_000_000_000), 1_000_000_000, priority);
        assert_eq!(pri, priority);

        // Case 3: default is floor
        let (_, pri) = compute_fees(Some(1), 999_999_999_999, priority);
        assert_eq!(pri, priority);
    }
}
