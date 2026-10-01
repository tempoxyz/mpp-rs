//! Matching the TIP-20 transfers of a transaction against the transfers a
//! charge expects.

use alloy::primitives::{Address, U256};

use crate::protocol::traits::VerificationError;

use super::super::transfers::Transfer;
use super::receipt_logs::ReceiptSenderPolicy;

/// A TIP-20 transfer made by a transaction, read from one of its calls or
/// from its receipt logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TransferEffect {
    pub(super) token: Address,
    /// The sender. Only a receipt log names one: a call is made by whoever
    /// signed the transaction.
    pub(super) from: Option<Address>,
    pub(super) to: Address,
    pub(super) amount: U256,
    pub(super) memo: Option<[u8; 32]>,
}

/// Where the transfers given to [`match_transfers`] were read from.
pub(super) enum TransferSource<'a> {
    /// The calls of a transaction that is not broadcast yet. An expected
    /// transfer without a memo takes the first matching call.
    Calls,
    /// The receipt logs. An expected transfer without a memo takes a memo
    /// transfer before a plain one, and the sender of every matched transfer
    /// must satisfy the policy.
    ReceiptLogs(ReceiptSenderPolicy<'a>),
}

impl TransferSource<'_> {
    fn allows_sender(&self, transfer: &TransferEffect) -> bool {
        match self {
            Self::Calls => true,
            Self::ReceiptLogs(policy) => transfer.from.is_some_and(|from| policy.allows(from)),
        }
    }
}

/// Assign each expected transfer a distinct transfer of the transaction and
/// return the memos of the assigned transfers.
///
/// A transfer matches when token, recipient and amount are equal and, if the
/// expected transfer names a memo, the memo is equal too. Expected transfers
/// with a memo are assigned first, so that one without a memo cannot take the
/// transfer another one needs.
pub(super) fn match_transfers(
    transfers: &[TransferEffect],
    source: TransferSource<'_>,
    currency: Address,
    expected: &[Transfer],
) -> Result<Vec<Option<[u8; 32]>>, VerificationError> {
    let mut sorted_expected: Vec<&Transfer> = expected.iter().collect();
    sorted_expected.sort_by_key(|t| if t.memo.is_some() { 0 } else { 1 });

    let mut used = vec![false; transfers.len()];
    let mut matched_memos = Vec::with_capacity(expected.len());

    for expected in sorted_expected {
        if expected.amount.is_zero() {
            return Err(VerificationError::new(
                "Invalid amount: expected_amount must be greater than zero".to_string(),
            ));
        }
        if expected.recipient.is_zero() {
            return Err(VerificationError::new(
                "Invalid recipient: expected_recipient cannot be the zero address".to_string(),
            ));
        }

        // `with_memo` narrows an expected transfer without a memo to
        // transfers that carry one (`Some(true)`) or do not (`Some(false)`).
        let find = |with_memo: Option<bool>| {
            transfers.iter().enumerate().position(|(index, transfer)| {
                !used[index]
                    && transfer.token == currency
                    && transfer.to == expected.recipient
                    && transfer.amount == expected.amount
                    && match expected.memo {
                        Some(memo) => transfer.memo == Some(memo),
                        None => with_memo.is_none_or(|with_memo| transfer.memo.is_some() == with_memo),
                    }
                    // Last, so that `validate_sender` only sees transfers that
                    // match otherwise.
                    && source.allows_sender(transfer)
            })
        };

        let index = match source {
            TransferSource::ReceiptLogs(_) if expected.memo.is_none() => {
                find(Some(true)).or_else(|| find(Some(false)))
            }
            _ => find(None),
        };

        let Some(index) = index else {
            let memo = if expected.memo.is_some() {
                " with memo"
            } else {
                ""
            };
            return Err(VerificationError::new(match source {
                TransferSource::Calls => format!(
                    "Invalid transaction: no matching transfer call found for {} to {}{memo}",
                    expected.amount, expected.recipient
                ),
                TransferSource::ReceiptLogs(_) => format!(
                    "No matching transfer event found for {} to {}{memo}",
                    expected.amount, expected.recipient
                ),
            }));
        };

        used[index] = true;
        matched_memos.push(transfers[index].memo);
    }

    Ok(matched_memos)
}
