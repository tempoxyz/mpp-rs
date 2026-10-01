//! Matching the TIP-20 transfer logs of a receipt against the expected transfers.

use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use tempo_alloy::TempoNetwork;

use crate::protocol::traits::VerificationError;

use super::super::transfers::Transfer;
use super::ChargeMethod;

/// TIP-20 Transfer event topic: keccak256("Transfer(address,address,uint256)")
/// TIP-20 is Tempo's token standard (compatible with ERC-20 Transfer events).
pub(super) const TRANSFER_EVENT_TOPIC: B256 =
    alloy::primitives::b256!("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");

/// TIP-20 TransferWithMemo event topic: keccak256("TransferWithMemo(address,address,uint256,bytes32)")
pub(super) const TRANSFER_WITH_MEMO_EVENT_TOPIC: B256 =
    alloy::primitives::b256!("57bc7354aa85aed339e000bccffabbc529466af35f0772c8f8ee1145927de7f0");

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

fn parse_receipt_transfer_log(log: &serde_json::Value) -> Option<ParsedTransferLog> {
    let address = log
        .get("address")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<Address>().ok())?;

    let topics: Vec<&str> = log
        .get("topics")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())?;
    if topics.len() < 3 {
        return None;
    }

    let topic0 = topics[0].parse::<B256>().ok()?;
    let from = topics[1]
        .parse::<B256>()
        .ok()
        .map(|b| Address::from_slice(&b[12..]))?;
    let to = topics[2]
        .parse::<B256>()
        .ok()
        .map(|b| Address::from_slice(&b[12..]))?;

    let data = log.get("data").and_then(|v| v.as_str()).unwrap_or("0x");
    if topic0 == TRANSFER_EVENT_TOPIC {
        if data.len() < 66 {
            return None;
        }

        let amount = U256::from_str_radix(&data[2..66], 16).ok()?;
        return Some(ParsedTransferLog::Transfer {
            address,
            amount,
            from,
            to,
        });
    }

    if topic0 == TRANSFER_WITH_MEMO_EVENT_TOPIC {
        if topics.len() < 4 || data.len() < 66 {
            return None;
        }

        let amount = U256::from_str_radix(&data[2..66], 16).ok()?;
        let memo = topics[3].parse::<B256>().ok().map(|bytes| bytes.0)?;
        return Some(ParsedTransferLog::Memo {
            address,
            amount,
            from,
            memo,
            to,
        });
    }

    None
}

/// Parse receipt logs into transfer effects, one per token transfer.
///
/// TIP-20 `transferWithMemo` emits `Transfer` immediately followed by
/// `TransferWithMemo` for the same transfer. Such adjacent pairs are merged
/// into one memo effect so a single transfer cannot satisfy two expected
/// transfers.
fn receipt_transfer_effects(logs: &[serde_json::Value]) -> Vec<ParsedTransferLog> {
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

#[cfg(test)]
pub(super) fn match_receipt_transfer_logs(
    logs: &[serde_json::Value],
    expected_sender: Address,
    currency: Address,
    expected: &[Transfer],
    source: Option<&str>,
    validate_sender: Option<&ValidateSenderCallback>,
) -> Result<Vec<MatchedTransferLog>, VerificationError> {
    match_receipt_transfer_logs_with_settlement(
        logs,
        currency,
        expected,
        ReceiptSenderPolicy {
            expected_sender,
            source,
            validate_sender,
            transaction_sender: expected_sender,
            settlement_senders: &[],
        },
    )
}

pub(super) fn match_receipt_transfer_logs_with_settlement(
    logs: &[serde_json::Value],
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

impl<P> ChargeMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    /// Verify that all expected transfers are present in the receipt logs.
    ///
    /// Uses order-insensitive matching: sorts expected transfers by memo-specificity
    /// (transfers with memos matched first) and uses a `used` set to prevent
    /// double-matching.
    pub(super) fn verify_tip20_transfers(
        &self,
        receipt: &<TempoNetwork as alloy::network::Network>::ReceiptResponse,
        currency: Address,
        expected: &[Transfer],
        sender_policy: ReceiptSenderPolicy<'_>,
    ) -> Result<Vec<MatchedTransferLog>, VerificationError> {
        let receipt_json = serde_json::to_value(receipt).map_err(|e| {
            VerificationError::internal(format!("Failed to serialize receipt: {}", e))
        })?;

        let logs = receipt_json
            .get("logs")
            .and_then(|v| v.as_array())
            .ok_or_else(|| VerificationError::new("Receipt has no logs".to_string()))?;

        match_receipt_transfer_logs_with_settlement(logs, currency, expected, sender_policy)
    }
}
