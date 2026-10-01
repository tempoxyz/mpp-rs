//! Matching the TIP-20 transfer logs of a receipt against the expected transfers.

use alloy::primitives::{Address, U256};
use alloy::rpc::types::Log;
use alloy::sol_types::SolEvent;
use tempo_alloy::contracts::precompiles::ITIP20;

use crate::protocol::traits::VerificationError;

use super::super::transfers::Transfer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MatchedTransferLog {
    Transfer,
    Memo([u8; 32]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParsedTransferLog {
    Transfer {
        address: Address,
        amount: U256,
        from: Address,
        to: Address,
    },
    Memo {
        address: Address,
        amount: U256,
        from: Address,
        memo: [u8; 32],
        to: Address,
    },
}

pub(super) struct ReceiptSenderPolicy<'a> {
    pub(super) expected_sender: Address,
    pub(super) source: Option<&'a str>,
    pub(super) validate_sender: Option<&'a ValidateSenderCallback>,
    pub(super) transaction_sender: Address,
    pub(super) settlement_senders: &'a [Address],
}

impl ParsedTransferLog {
    fn address(&self) -> Address {
        match self {
            Self::Transfer { address, .. } | Self::Memo { address, .. } => *address,
        }
    }

    fn amount(&self) -> U256 {
        match self {
            Self::Transfer { amount, .. } | Self::Memo { amount, .. } => *amount,
        }
    }

    fn from(&self) -> Address {
        match self {
            Self::Transfer { from, .. } | Self::Memo { from, .. } => *from,
        }
    }

    fn matched(&self) -> MatchedTransferLog {
        match self {
            Self::Transfer { .. } => MatchedTransferLog::Transfer,
            Self::Memo { memo, .. } => MatchedTransferLog::Memo(*memo),
        }
    }

    fn memo(&self) -> Option<[u8; 32]> {
        match self {
            Self::Transfer { .. } => None,
            Self::Memo { memo, .. } => Some(*memo),
        }
    }

    fn to(&self) -> Address {
        match self {
            Self::Transfer { to, .. } | Self::Memo { to, .. } => *to,
        }
    }

    /// Whether `self` and `other` are the `Transfer` and `TransferWithMemo`
    /// events of the same transfer.
    fn is_twin_of(&self, other: &Self) -> bool {
        self.memo().is_some() != other.memo().is_some()
            && self.address() == other.address()
            && self.from() == other.from()
            && self.to() == other.to()
            && self.amount() == other.amount()
    }
}

fn parse_receipt_transfer_log(log: &Log) -> Option<ParsedTransferLog> {
    let address = log.address();
    if let Ok(transfer) = ITIP20::Transfer::decode_log_data(log.data()) {
        return Some(ParsedTransferLog::Transfer {
            address,
            amount: transfer.amount,
            from: transfer.from,
            to: transfer.to,
        });
    }

    let transfer = ITIP20::TransferWithMemo::decode_log_data(log.data()).ok()?;
    Some(ParsedTransferLog::Memo {
        address,
        amount: transfer.amount,
        from: transfer.from,
        memo: transfer.memo.0,
        to: transfer.to,
    })
}

/// Parse receipt logs into transfer effects, one per token transfer.
///
/// TIP-20 `transferWithMemo` emits `Transfer` immediately followed by
/// `TransferWithMemo` for the same transfer. Such adjacent pairs are merged
/// into one memo effect so a single transfer cannot satisfy two expected
/// transfers.
fn receipt_transfer_effects(logs: &[Log]) -> Vec<ParsedTransferLog> {
    let mut parsed = logs.iter().map(parse_receipt_transfer_log).peekable();
    let mut effects = Vec::new();

    while let Some(log) = parsed.next() {
        let Some(log) = log else {
            continue;
        };
        let twin = parsed
            .peek()
            .and_then(|next| next.filter(|next| log.is_twin_of(next)));
        if let Some(twin) = twin {
            parsed.next();
            effects.push(if log.memo().is_some() { log } else { twin });
        } else {
            effects.push(log);
        }
    }

    effects
}

/// Verify that all expected transfers are present in the receipt logs.
///
/// Uses order-insensitive matching: sorts expected transfers by memo-specificity
/// (transfers with memos matched first) and uses a `used` set to prevent
/// double-matching.
pub(super) fn match_receipt_transfer_logs_with_settlement(
    logs: &[Log],
    currency: Address,
    expected: &[Transfer],
    sender_policy: ReceiptSenderPolicy<'_>,
) -> Result<Vec<MatchedTransferLog>, VerificationError> {
    let mut sorted_expected: Vec<(usize, &Transfer)> = expected.iter().enumerate().collect();
    sorted_expected.sort_by_key(|(_, t)| if t.memo.is_some() { 0 } else { 1 });

    let parsed_logs = receipt_transfer_effects(logs);
    let mut used_logs: Vec<bool> = vec![false; parsed_logs.len()];
    let mut matched_logs = Vec::with_capacity(expected.len());

    for (_, transfer) in &sorted_expected {
        if transfer.amount.is_zero() {
            return Err(VerificationError::new(
                "Invalid amount: expected_amount must be greater than zero".to_string(),
            ));
        }
        if transfer.recipient.is_zero() {
            return Err(VerificationError::new(
                "Invalid recipient: expected_recipient cannot be the zero address".to_string(),
            ));
        }

        let find_match = |prefer_memo: bool| {
            for (log_idx, parsed) in parsed_logs.iter().enumerate() {
                if used_logs[log_idx] {
                    continue;
                }

                if parsed.address() != currency
                    || parsed.to() != transfer.recipient
                    || parsed.amount() != transfer.amount
                {
                    continue;
                }

                if let Some(exp_memo) = transfer.memo {
                    if parsed.memo() != Some(exp_memo) {
                        continue;
                    }
                } else if prefer_memo != parsed.memo().is_some() {
                    continue;
                }

                // On a sender mismatch, validate_sender may authorize the log.
                let sender = parsed.from();
                if sender != sender_policy.expected_sender {
                    let authorized = (sender_policy.transaction_sender
                        == sender_policy.expected_sender
                        && sender_policy.settlement_senders.contains(&sender))
                        || sender_policy.validate_sender.is_some_and(|cb| {
                            cb(SenderValidation {
                                expected_sender: sender_policy.expected_sender,
                                sender,
                                source: sender_policy.source,
                            })
                        });
                    if !authorized {
                        continue;
                    }
                }

                return Some((log_idx, parsed.matched()));
            }

            None
        };

        let matched = if transfer.memo.is_some() {
            find_match(true)
        } else {
            find_match(true).or_else(|| find_match(false))
        };

        let Some((log_idx, matched_log)) = matched else {
            return Err(VerificationError::new(format!(
                "No matching transfer event found for {} to {}{}",
                transfer.amount,
                transfer.recipient,
                if transfer.memo.is_some() {
                    " with memo"
                } else {
                    ""
                }
            )));
        };

        used_logs[log_idx] = true;
        matched_logs.push(matched_log);
    }

    Ok(matched_logs)
}

/// Arguments passed to a [`ValidateSenderCallback`] on a sender mismatch.
#[derive(Debug, Clone, Copy)]
pub struct SenderValidation<'a> {
    /// The expected sender (source address, or receipt sender if no source).
    pub expected_sender: Address,
    /// The actual `from` address on the transfer log.
    pub sender: Address,
    /// The raw credential source DID, if provided.
    pub source: Option<&'a str>,
}

/// Authorizes a transfer whose sender differs from the expected sender;
/// return `true` to accept.
pub type ValidateSenderCallback =
    dyn for<'a> Fn(SenderValidation<'a>) -> bool + Send + Sync + 'static;
