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

/// Compute the required amount including slippage.
pub(crate) fn amount_with_slippage(required_amount: U256) -> U256 {
    let slippage = required_amount * U256::from(SWAP_SLIPPAGE_BPS) / U256::from(BPS_DENOMINATOR);
    required_amount + slippage
}

/// Select a swap source from candidates with precomputed balances and spending limits.
///
/// This is the pure selection logic extracted from `find_swap_source` for testability.
/// Each candidate entry is `(candidate, balance, spending_limit)` where:
/// - `balance` is the token balance (or `None` if the balance query failed)
/// - `spending_limit` is the effective spending limit (`None` = unlimited, `Some(limit)` = capped)
///
/// When `use_keychain` is true, candidates are filtered by spending limit >= threshold
/// and sorted by limit descending before checking balances.
pub(crate) fn select_swap_source(
    entries: &[(SwapCandidate, Option<U256>, Option<U256>)],
    required_token: Address,
    threshold: U256,
    use_keychain: bool,
) -> Option<SwapSource> {
    // Filter out the required token
    let filtered: Vec<_> = entries
        .iter()
        .filter(|(c, _, _)| c.address != required_token)
        .collect();

    if use_keychain {
        // With keychain: filter by spending limit, sort descending, then check balances.
        let mut eligible: Vec<_> = filtered
            .iter()
            .filter_map(|(c, bal, limit)| {
                let effective = match limit {
                    None => U256::MAX, // unlimited
                    Some(l) if *l >= threshold => *l,
                    Some(_) => return None, // limit too low
                };
                Some((c, bal, effective))
            })
            .collect();

        eligible.sort_by(|a, b| b.2.cmp(&a.2));

        for (candidate, balance, _) in eligible {
            if let Some(bal) = balance {
                if *bal >= threshold {
                    return Some(SwapSource {
                        token_address: candidate.address,
                        symbol: candidate.symbol.clone(),
                    });
                }
            }
        }
    } else {
        // Without keychain: check balances in order.
        for (candidate, balance, _) in &filtered {
            if let Some(bal) = balance {
                if *bal >= threshold {
                    return Some(SwapSource {
                        token_address: candidate.address,
                        symbol: candidate.symbol.clone(),
                    });
                }
            }
        }
    }

    None
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
    let threshold = amount_with_slippage(required_amount);

    // Build entries with balances and spending limits
    let mut entries: Vec<(SwapCandidate, Option<U256>, Option<U256>)> = Vec::new();

    let use_keychain = keychain_info.is_some();

    for candidate in candidates {
        if candidate.address == required_token {
            entries.push((candidate.clone(), None, None));
            continue;
        }

        let balance = query_token_balance(provider, candidate.address, account)
            .await
            .ok();

        let spending_limit = if let Some((wallet_addr, key_addr)) = keychain_info {
            match query_key_spending_limit(provider, wallet_addr, key_addr, candidate.address).await
            {
                Ok(None) => None,       // unlimited
                Ok(Some(l)) => Some(l), // capped
                Err(_) if local_auth.is_some() => {
                    local_key_spending_limit(local_auth.unwrap(), candidate.address)
                }
                Err(_) => Some(U256::ZERO), // error, no local auth → treat as zero
            }
        } else {
            None // no keychain → unlimited
        };

        entries.push((candidate.clone(), balance, spending_limit));
    }

    Ok(select_swap_source(
        &entries,
        required_token,
        threshold,
        use_keychain,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(byte: u8, symbol: &str) -> SwapCandidate {
        SwapCandidate {
            address: Address::repeat_byte(byte),
            symbol: symbol.to_string(),
        }
    }

    // --- struct field tests ---

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

    // --- amount_with_slippage tests ---

    #[test]
    fn test_amount_with_slippage_basic() {
        // 1_000_000 * 50 / 10000 = 5_000 slippage
        let result = amount_with_slippage(U256::from(1_000_000u64));
        assert_eq!(result, U256::from(1_005_000u64));
    }

    #[test]
    fn test_amount_with_slippage_zero() {
        assert_eq!(amount_with_slippage(U256::ZERO), U256::ZERO);
    }

    #[test]
    fn test_amount_with_slippage_rounds_down() {
        // 1 * 50 / 10000 = 0 (floors), so result = 1
        assert_eq!(amount_with_slippage(U256::from(1u64)), U256::from(1u64));
        // 199 * 50 / 10000 = 0 (floors), so result = 199
        assert_eq!(amount_with_slippage(U256::from(199u64)), U256::from(199u64));
        // 200 * 50 / 10000 = 1, so result = 201
        assert_eq!(amount_with_slippage(U256::from(200u64)), U256::from(201u64));
    }

    // --- select_swap_source: no keychain path ---

    #[test]
    fn test_select_no_keychain_picks_first_with_balance() {
        let threshold = U256::from(1_005_000u64);
        let entries = vec![
            (candidate(0x01, "A"), Some(U256::from(500_000u64)), None), // too low
            (candidate(0x02, "B"), Some(U256::from(2_000_000u64)), None), // sufficient
            (candidate(0x03, "C"), Some(U256::from(3_000_000u64)), None), // also sufficient
        ];
        let result = select_swap_source(&entries, Address::repeat_byte(0xFF), threshold, false);
        let src = result.unwrap();
        assert_eq!(src.token_address, Address::repeat_byte(0x02));
        assert_eq!(src.symbol, "B");
    }

    #[test]
    fn test_select_no_keychain_none_when_all_too_low() {
        let threshold = U256::from(1_005_000u64);
        let entries = vec![
            (candidate(0x01, "A"), Some(U256::from(500_000u64)), None),
            (candidate(0x02, "B"), Some(U256::from(1_000_000u64)), None),
        ];
        assert!(
            select_swap_source(&entries, Address::repeat_byte(0xFF), threshold, false).is_none()
        );
    }

    #[test]
    fn test_select_no_keychain_skips_balance_errors() {
        let threshold = U256::from(1_000u64);
        let entries = vec![
            (candidate(0x01, "A"), None, None), // balance error
            (candidate(0x02, "B"), Some(U256::from(2_000u64)), None), // ok
        ];
        let result = select_swap_source(&entries, Address::repeat_byte(0xFF), threshold, false);
        let src = result.unwrap();
        assert_eq!(src.token_address, Address::repeat_byte(0x02));
    }

    #[test]
    fn test_select_excludes_required_token() {
        let required = Address::repeat_byte(0x01);
        let threshold = U256::from(100u64);
        let entries = vec![
            (candidate(0x01, "REQ"), Some(U256::from(999_999u64)), None), // is required token
            (candidate(0x02, "B"), Some(U256::from(200u64)), None),
        ];
        let result = select_swap_source(&entries, required, threshold, false);
        let src = result.unwrap();
        assert_eq!(src.token_address, Address::repeat_byte(0x02));
    }

    #[test]
    fn test_select_all_are_required_token() {
        let required = Address::repeat_byte(0x01);
        let threshold = U256::from(100u64);
        let entries = vec![(candidate(0x01, "REQ"), Some(U256::from(999_999u64)), None)];
        assert!(select_swap_source(&entries, required, threshold, false).is_none());
    }

    #[test]
    fn test_select_empty_candidates() {
        let threshold = U256::from(100u64);
        assert!(select_swap_source(&[], Address::repeat_byte(0xFF), threshold, false).is_none());
    }

    #[test]
    fn test_select_balance_exactly_at_threshold() {
        let threshold = U256::from(1_000u64);
        let entries = vec![
            (candidate(0x01, "A"), Some(U256::from(1_000u64)), None), // exactly at threshold
        ];
        let result = select_swap_source(&entries, Address::repeat_byte(0xFF), threshold, false);
        assert!(result.is_some());
    }

    #[test]
    fn test_select_balance_one_below_threshold() {
        let threshold = U256::from(1_000u64);
        let entries = vec![(candidate(0x01, "A"), Some(U256::from(999u64)), None)];
        assert!(
            select_swap_source(&entries, Address::repeat_byte(0xFF), threshold, false).is_none()
        );
    }

    // --- select_swap_source: keychain path ---

    #[test]
    fn test_select_keychain_unlimited_spending_limit() {
        let threshold = U256::from(1_000u64);
        // None spending limit = unlimited
        let entries = vec![(candidate(0x01, "A"), Some(U256::from(2_000u64)), None)];
        let result = select_swap_source(&entries, Address::repeat_byte(0xFF), threshold, true);
        assert!(result.is_some());
    }

    #[test]
    fn test_select_keychain_limit_below_threshold_excluded() {
        let threshold = U256::from(1_000u64);
        let entries = vec![(
            candidate(0x01, "A"),
            Some(U256::from(2_000u64)),
            Some(U256::from(500u64)),
        )];
        assert!(
            select_swap_source(&entries, Address::repeat_byte(0xFF), threshold, true).is_none()
        );
    }

    #[test]
    fn test_select_keychain_limit_at_threshold_included() {
        let threshold = U256::from(1_000u64);
        let entries = vec![(
            candidate(0x01, "A"),
            Some(U256::from(2_000u64)),
            Some(U256::from(1_000u64)),
        )];
        let result = select_swap_source(&entries, Address::repeat_byte(0xFF), threshold, true);
        assert!(result.is_some());
    }

    #[test]
    fn test_select_keychain_sorts_by_limit_descending() {
        let threshold = U256::from(1_000u64);
        // Token B has higher limit, even though it appears second.
        // Both have sufficient balance; B should be selected first.
        let entries = vec![
            (
                candidate(0x01, "A"),
                Some(U256::from(5_000u64)),
                Some(U256::from(2_000u64)),
            ),
            (
                candidate(0x02, "B"),
                Some(U256::from(5_000u64)),
                Some(U256::from(9_000u64)),
            ),
        ];
        let result = select_swap_source(&entries, Address::repeat_byte(0xFF), threshold, true);
        let src = result.unwrap();
        assert_eq!(src.token_address, Address::repeat_byte(0x02));
        assert_eq!(src.symbol, "B");
    }

    #[test]
    fn test_select_keychain_highest_limit_insufficient_balance_falls_to_next() {
        let threshold = U256::from(1_000u64);
        // B has higher limit but insufficient balance; A should be selected.
        let entries = vec![
            (
                candidate(0x01, "A"),
                Some(U256::from(5_000u64)),
                Some(U256::from(2_000u64)),
            ),
            (
                candidate(0x02, "B"),
                Some(U256::from(500u64)),
                Some(U256::from(9_000u64)),
            ),
        ];
        let result = select_swap_source(&entries, Address::repeat_byte(0xFF), threshold, true);
        let src = result.unwrap();
        assert_eq!(src.token_address, Address::repeat_byte(0x01));
        assert_eq!(src.symbol, "A");
    }

    #[test]
    fn test_select_keychain_balance_error_skipped() {
        let threshold = U256::from(1_000u64);
        let entries = vec![
            (candidate(0x01, "A"), None, Some(U256::from(5_000u64))), // balance error
            (
                candidate(0x02, "B"),
                Some(U256::from(2_000u64)),
                Some(U256::from(3_000u64)),
            ),
        ];
        let result = select_swap_source(&entries, Address::repeat_byte(0xFF), threshold, true);
        let src = result.unwrap();
        assert_eq!(src.token_address, Address::repeat_byte(0x02));
    }

    #[test]
    fn test_select_keychain_zero_limit_excluded() {
        let threshold = U256::from(1_000u64);
        let entries = vec![(
            candidate(0x01, "A"),
            Some(U256::from(5_000u64)),
            Some(U256::ZERO),
        )];
        assert!(
            select_swap_source(&entries, Address::repeat_byte(0xFF), threshold, true).is_none()
        );
    }

    #[test]
    fn test_select_keychain_mixed_eligible_and_ineligible() {
        let threshold = U256::from(1_000u64);
        let entries = vec![
            (
                candidate(0x01, "A"),
                Some(U256::from(5_000u64)),
                Some(U256::from(500u64)),
            ), // limit too low
            (candidate(0x02, "B"), Some(U256::from(200u64)), None), // unlimited but low balance
            (
                candidate(0x03, "C"),
                Some(U256::from(5_000u64)),
                Some(U256::from(5_000u64)),
            ), // eligible
        ];
        let result = select_swap_source(&entries, Address::repeat_byte(0xFF), threshold, true);
        let src = result.unwrap();
        assert_eq!(src.token_address, Address::repeat_byte(0x03));
    }
}
