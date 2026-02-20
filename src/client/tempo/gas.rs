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

/// Pure stuck-tx fee calculation from stuck tx gas values and base-fee floor.
///
/// Returns `(max_fee_per_gas, max_priority_fee_per_gas)`.
/// When stuck tx gas values are available, bids 2x the stuck tx's fees
/// (but at least the base-fee-competitive floor).
/// When unavailable, bumps defaults by 10x with caps.
fn compute_stuck_tx_fees(
    stuck_gas: Option<(u128, u128)>,
    base_fee_floor: u128,
    default_max_fee: u128,
    default_priority_fee: u128,
) -> (u128, u128) {
    if let Some((stuck_max_fee, stuck_priority)) = stuck_gas {
        let max_fee = std::cmp::max(stuck_max_fee * 2, base_fee_floor);
        let priority = std::cmp::max(stuck_priority * 2, default_priority_fee);
        (max_fee, priority)
    } else {
        const MAX_FEE_CAP: u128 = 500_000_000_000; // 500 gwei
        const MAX_PRIORITY_CAP: u128 = 50_000_000_000; // 50 gwei

        let max_fee = std::cmp::min(default_max_fee * 10, MAX_FEE_CAP);
        let priority = std::cmp::min(default_priority_fee * 10, MAX_PRIORITY_CAP);
        (std::cmp::max(max_fee, base_fee_floor), priority)
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
    let (base_fee_floor, _) = resolve_fees(provider, default_max_fee, default_priority_fee).await;

    let stuck_gas = read_stuck_tx_gas(provider, from, nonce).await;

    compute_stuck_tx_fees(
        stuck_gas,
        base_fee_floor,
        default_max_fee,
        default_priority_fee,
    )
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
        let (max_fee, priority) = compute_fees(Some(2_000_000_000), 1_000_000_000, 1_000_000_000);
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
        let (max_fee, priority) = compute_fees(Some(0), 1_000_000_000, 1_000_000_000);
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

    // ── compute_stuck_tx_fees tests ───────────────────────────────────

    #[test]
    fn test_stuck_fees_2x_bidding() {
        // With stuck tx gas, bids 2x the stuck values
        let (max_fee, priority) = compute_stuck_tx_fees(
            Some((10_000_000_000, 1_000_000_000)),
            5_000_000_000, // base_fee_floor lower than 2x
            1_000_000_000,
            500_000_000,
        );
        assert_eq!(max_fee, 20_000_000_000); // 10g * 2
        assert_eq!(priority, 2_000_000_000); // 1g * 2
    }

    #[test]
    fn test_stuck_fees_base_fee_floor_wins() {
        // base_fee_floor > stuck*2 → floor wins for max_fee
        let (max_fee, priority) = compute_stuck_tx_fees(
            Some((1_000_000_000, 500_000_000)),
            50_000_000_000, // 50 gwei floor
            1_000_000_000,
            2_000_000_000, // default_priority > stuck*2
        );
        assert_eq!(max_fee, 50_000_000_000); // floor wins over 2g
        assert_eq!(priority, 2_000_000_000); // default_priority wins over 1g
    }

    #[test]
    fn test_stuck_fees_no_stuck_tx_10x_bump() {
        // Without stuck tx, bumps defaults by 10x
        let (max_fee, priority) = compute_stuck_tx_fees(
            None,
            1_000_000_000, // base_fee_floor
            5_000_000_000, // default_max_fee
            1_000_000_000, // default_priority
        );
        assert_eq!(max_fee, 50_000_000_000); // 5g * 10
        assert_eq!(priority, 10_000_000_000); // 1g * 10
    }

    #[test]
    fn test_stuck_fees_no_stuck_tx_caps() {
        // 10x would exceed caps → capped
        let (max_fee, priority) = compute_stuck_tx_fees(
            None,
            1_000_000_000,   // base_fee_floor
            100_000_000_000, // 100 gwei → 10x = 1000 gwei > 500 gwei cap
            10_000_000_000,  // 10 gwei → 10x = 100 gwei > 50 gwei cap
        );
        assert_eq!(max_fee, 500_000_000_000); // capped at 500 gwei
        assert_eq!(priority, 50_000_000_000); // capped at 50 gwei
    }

    #[test]
    fn test_stuck_fees_no_stuck_tx_base_fee_floor_wins() {
        // base_fee_floor > capped 10x max_fee → floor wins
        let (max_fee, priority) = compute_stuck_tx_fees(
            None,
            600_000_000_000, // 600 gwei floor > 500 gwei cap
            100_000_000_000, // 100 gwei
            1_000_000_000,   // 1 gwei
        );
        assert_eq!(max_fee, 600_000_000_000); // floor wins
        assert_eq!(priority, 10_000_000_000); // 1g * 10, under cap
    }

    #[test]
    fn test_stuck_fees_zero_stuck_values() {
        // Stuck tx with zero gas → base_fee_floor and default_priority win
        let (max_fee, priority) =
            compute_stuck_tx_fees(Some((0, 0)), 5_000_000_000, 1_000_000_000, 500_000_000);
        assert_eq!(max_fee, 5_000_000_000); // floor wins over 0*2
        assert_eq!(priority, 500_000_000); // default wins over 0*2
    }

    #[test]
    fn test_stuck_fees_large_stuck_values() {
        // Very large stuck tx gas — no overflow, 2x works
        let large = u128::MAX / 4; // safe to multiply by 2
        let (max_fee, priority) = compute_stuck_tx_fees(
            Some((large, large)),
            1_000_000_000,
            1_000_000_000,
            1_000_000_000,
        );
        assert_eq!(max_fee, large * 2);
        assert_eq!(priority, large * 2);
    }

    #[test]
    fn test_stuck_fees_no_stuck_tx_zero_defaults() {
        // Zero defaults → 10x is still 0, but base_fee_floor applies for max_fee
        let (max_fee, priority) = compute_stuck_tx_fees(None, 5_000_000_000, 0, 0);
        assert_eq!(max_fee, 5_000_000_000); // floor wins
        assert_eq!(priority, 0); // 0 * 10 = 0
    }

    // ── compute_fees tests ────────────────────────────────────────────

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
