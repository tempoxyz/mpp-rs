//! Transfer computation for split payments.
//!
//! Provides [`get_transfers`] which computes the list of transfers for a charge,
//! handling both simple (single-recipient) and split (multi-recipient) payments.

use alloy::primitives::{Address, U256};

use super::charge::{parse_memo_bytes_checked, parse_split_memo_bytes, TempoChargeExt};
use super::types::Split;
use crate::error::MppError;
use crate::evm::{parse_address, parse_amount};
use crate::protocol::intents::ChargeRequest;

/// Maximum number of splits allowed (primary + splits ≤ 11 calls).
pub const MAX_SPLITS: usize = 10;

/// A single transfer in a charge (primary or split).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    /// Amount to transfer (in base units).
    pub amount: U256,
    /// Recipient address.
    pub recipient: Address,
    /// Optional 32-byte memo.
    pub memo: Option<[u8; 32]>,
}

/// Compute the validated transfer plan for a charge request.
pub fn get_request_transfers(charge: &ChargeRequest) -> Result<Vec<Transfer>, MppError> {
    let recipient = charge.recipient_address()?;
    let amount = charge.amount_u256()?;
    let details = charge.tempo_method_details()?;
    let memo = parse_memo_bytes_checked(details.memo.as_deref())?;

    get_transfers(amount, recipient, memo, details.splits.as_deref())
}

/// Compute the ordered list of transfers for a charge.
///
/// - The **primary** transfer receives `total_amount - sum(splits)` and inherits the
///   top-level `memo`.
/// - **Split** transfers follow the primary in declaration order.
///
/// # Errors
///
/// Returns an error if:
/// - `splits` is present but empty
/// - More than [`MAX_SPLITS`] splits are provided
/// - Any split has a zero or invalid amount
/// - Any split has an invalid recipient address
/// - `sum(splits) >= total_amount` (primary must receive a positive amount)
pub fn get_transfers(
    total_amount: U256,
    primary_recipient: Address,
    primary_memo: Option<[u8; 32]>,
    splits: Option<&[Split]>,
) -> Result<Vec<Transfer>, MppError> {
    let splits = match splits {
        Some([]) => {
            return Err(MppError::invalid_challenge_reason(
                "Splits must not be empty".to_string(),
            ));
        }
        Some(s) => s,
        None => {
            return Ok(vec![Transfer {
                amount: total_amount,
                recipient: primary_recipient,
                memo: primary_memo,
            }]);
        }
    };

    if splits.len() > MAX_SPLITS {
        return Err(MppError::invalid_challenge_reason(format!(
            "Too many splits: {} (max {})",
            splits.len(),
            MAX_SPLITS
        )));
    }

    let mut split_sum = U256::ZERO;
    let mut split_transfers = Vec::with_capacity(splits.len());

    for split in splits {
        let amount = parse_amount(&split.amount).map_err(|_| {
            MppError::invalid_challenge_reason(format!("Invalid split amount: {}", split.amount))
        })?;

        if amount.is_zero() {
            return Err(MppError::invalid_challenge_reason(
                "Split amount must be greater than zero".to_string(),
            ));
        }

        let recipient = parse_address(&split.recipient)?;
        let memo = parse_split_memo_bytes(split.memo.as_deref())?;

        split_sum = split_sum.checked_add(amount).ok_or_else(|| {
            MppError::invalid_challenge_reason("Split amounts overflow".to_string())
        })?;

        split_transfers.push(Transfer {
            amount,
            recipient,
            memo,
        });
    }

    if split_sum >= total_amount {
        return Err(MppError::invalid_challenge_reason(format!(
            "Sum of splits ({}) must be less than total amount ({})",
            split_sum, total_amount
        )));
    }

    let primary_amount = total_amount - split_sum;

    let mut transfers = Vec::with_capacity(1 + split_transfers.len());
    transfers.push(Transfer {
        amount: primary_amount,
        recipient: primary_recipient,
        memo: primary_memo,
    });
    transfers.extend(split_transfers);

    Ok(transfers)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::repeat_byte(byte)
    }

    #[test]
    fn test_no_splits_returns_single_transfer() {
        let transfers = get_transfers(U256::from(1_000_000u64), addr(0x01), None, None).unwrap();

        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].amount, U256::from(1_000_000u64));
        assert_eq!(transfers[0].recipient, addr(0x01));
        assert!(transfers[0].memo.is_none());
    }

    #[test]
    fn test_empty_splits_rejected() {
        let error =
            get_transfers(U256::from(1_000_000u64), addr(0x01), None, Some(&[])).unwrap_err();

        assert!(error.to_string().contains("Splits must not be empty"));
    }

    #[test]
    fn test_single_split() {
        let splits = vec![Split {
            amount: "300000".to_string(),
            recipient: format!("{:#x}", addr(0x02)),
            memo: None,
        }];

        let transfers =
            get_transfers(U256::from(1_000_000u64), addr(0x01), None, Some(&splits)).unwrap();

        assert_eq!(transfers.len(), 2);
        // Primary gets remainder
        assert_eq!(transfers[0].amount, U256::from(700_000u64));
        assert_eq!(transfers[0].recipient, addr(0x01));
        // Split gets its amount
        assert_eq!(transfers[1].amount, U256::from(300_000u64));
        assert_eq!(transfers[1].recipient, addr(0x02));
    }

    #[test]
    fn test_primary_inherits_memo() {
        let memo = [0xABu8; 32];
        let splits = vec![Split {
            amount: "100000".to_string(),
            recipient: format!("{:#x}", addr(0x02)),
            memo: None,
        }];

        let transfers = get_transfers(
            U256::from(1_000_000u64),
            addr(0x01),
            Some(memo),
            Some(&splits),
        )
        .unwrap();

        assert_eq!(transfers[0].memo, Some(memo));
        assert!(transfers[1].memo.is_none());
    }

    #[test]
    fn test_split_with_memo() {
        let split_memo_hex =
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string();
        let splits = vec![Split {
            amount: "100000".to_string(),
            recipient: format!("{:#x}", addr(0x02)),
            memo: Some(split_memo_hex),
        }];

        let transfers =
            get_transfers(U256::from(1_000_000u64), addr(0x01), None, Some(&splits)).unwrap();

        assert!(transfers[1].memo.is_some());
        assert_eq!(transfers[1].memo.unwrap()[0], 0x12);
    }

    #[test]
    fn test_rejects_invalid_split_memo() {
        let splits = vec![Split {
            amount: "100000".to_string(),
            recipient: format!("{:#x}", addr(0x02)),
            memo: Some("0x1234".to_string()),
        }];

        let error =
            get_transfers(U256::from(1_000_000u64), addr(0x01), None, Some(&splits)).unwrap_err();
        assert!(error.to_string().contains("Invalid split memo"));
    }

    #[test]
    fn test_multiple_splits_preserve_order() {
        let splits = vec![
            Split {
                amount: "100000".to_string(),
                recipient: format!("{:#x}", addr(0x02)),
                memo: None,
            },
            Split {
                amount: "200000".to_string(),
                recipient: format!("{:#x}", addr(0x03)),
                memo: None,
            },
            Split {
                amount: "50000".to_string(),
                recipient: format!("{:#x}", addr(0x04)),
                memo: None,
            },
        ];

        let transfers =
            get_transfers(U256::from(1_000_000u64), addr(0x01), None, Some(&splits)).unwrap();

        assert_eq!(transfers.len(), 4);
        assert_eq!(transfers[0].amount, U256::from(650_000u64)); // primary
        assert_eq!(transfers[1].amount, U256::from(100_000u64));
        assert_eq!(transfers[1].recipient, addr(0x02));
        assert_eq!(transfers[2].amount, U256::from(200_000u64));
        assert_eq!(transfers[2].recipient, addr(0x03));
        assert_eq!(transfers[3].amount, U256::from(50_000u64));
        assert_eq!(transfers[3].recipient, addr(0x04));
    }

    #[test]
    fn test_rejects_sum_equals_total() {
        let splits = vec![Split {
            amount: "1000000".to_string(),
            recipient: format!("{:#x}", addr(0x02)),
            memo: None,
        }];

        let result = get_transfers(U256::from(1_000_000u64), addr(0x01), None, Some(&splits));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must be less than"));
    }

    #[test]
    fn test_rejects_sum_exceeds_total() {
        let splits = vec![Split {
            amount: "1500000".to_string(),
            recipient: format!("{:#x}", addr(0x02)),
            memo: None,
        }];

        let result = get_transfers(U256::from(1_000_000u64), addr(0x01), None, Some(&splits));
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_zero_split_amount() {
        let splits = vec![Split {
            amount: "0".to_string(),
            recipient: format!("{:#x}", addr(0x02)),
            memo: None,
        }];

        let result = get_transfers(U256::from(1_000_000u64), addr(0x01), None, Some(&splits));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("greater than zero"));
    }

    #[test]
    fn test_rejects_too_many_splits() {
        let splits: Vec<Split> = (0..11)
            .map(|i| Split {
                amount: "1000".to_string(),
                recipient: format!("{:#x}", addr(i as u8 + 2)),
                memo: None,
            })
            .collect();

        let result = get_transfers(U256::from(1_000_000u64), addr(0x01), None, Some(&splits));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Too many splits"));
    }

    #[test]
    fn test_max_splits_allowed() {
        let splits: Vec<Split> = (0..10)
            .map(|i| Split {
                amount: "1000".to_string(),
                recipient: format!("{:#x}", addr(i as u8 + 2)),
                memo: None,
            })
            .collect();

        let transfers =
            get_transfers(U256::from(1_000_000u64), addr(0x01), None, Some(&splits)).unwrap();
        assert_eq!(transfers.len(), 11);
        // Primary gets 1_000_000 - 10*1000 = 990_000
        assert_eq!(transfers[0].amount, U256::from(990_000u64));
    }

    #[test]
    fn test_get_request_transfers_rejects_invalid_top_level_memo() {
        let request = ChargeRequest {
            amount: "1000000".to_string(),
            currency: format!("{:#x}", addr(0x20)),
            recipient: Some(format!("{:#x}", addr(0x01))),
            method_details: Some(serde_json::json!({
                "memo": "0x1234",
            })),
            ..Default::default()
        };

        let error = get_request_transfers(&request).unwrap_err();
        assert!(error.to_string().contains("Invalid memo"));
    }

    #[test]
    fn test_get_request_transfers_rejects_empty_splits() {
        let request = ChargeRequest {
            amount: "1000000".to_string(),
            currency: format!("{:#x}", addr(0x20)),
            recipient: Some(format!("{:#x}", addr(0x01))),
            method_details: Some(serde_json::json!({
                "splits": [],
            })),
            ..Default::default()
        };

        let error = get_request_transfers(&request).unwrap_err();
        assert!(error.to_string().contains("Splits must not be empty"));
    }
}
