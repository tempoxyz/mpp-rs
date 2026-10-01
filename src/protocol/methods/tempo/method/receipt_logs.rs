//! Matching the TIP-20 transfer logs of a receipt against the expected transfers.

use alloy::primitives::Address;
use alloy::rpc::types::Log;
use alloy::sol_types::SolEvent;
use tempo_alloy::contracts::precompiles::ITIP20;

use crate::protocol::traits::VerificationError;

use super::super::transfers::Transfer;
use super::matching::{match_transfers, TransferEffect, TransferSource};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MatchedTransferLog {
    Transfer,
    Memo([u8; 32]),
}

pub(super) struct ReceiptSenderPolicy<'a> {
    pub(super) expected_sender: Address,
    pub(super) source: Option<&'a str>,
    pub(super) validate_sender: Option<&'a ValidateSenderCallback>,
    pub(super) transaction_sender: Address,
    pub(super) settlement_senders: &'a [Address],
}

impl ReceiptSenderPolicy<'_> {
    /// Whether a transfer sent by `sender` counts towards the payment: the
    /// expected sender, a settlement sender acting for it, or a sender
    /// `validate_sender` authorizes.
    pub(super) fn allows(&self, sender: Address) -> bool {
        sender == self.expected_sender
            || (self.transaction_sender == self.expected_sender
                && self.settlement_senders.contains(&sender))
            || self.validate_sender.is_some_and(|cb| {
                cb(SenderValidation {
                    expected_sender: self.expected_sender,
                    sender,
                    source: self.source,
                })
            })
    }
}

/// Whether `a` and `b` are the `Transfer` and `TransferWithMemo` events of
/// the same transfer.
fn is_twin(a: &TransferEffect, b: &TransferEffect) -> bool {
    a.memo.is_some() != b.memo.is_some()
        && a.token == b.token
        && a.from == b.from
        && a.to == b.to
        && a.amount == b.amount
}

fn parse_receipt_transfer_log(log: &Log) -> Option<TransferEffect> {
    let token = log.address();
    if let Ok(transfer) = ITIP20::Transfer::decode_log_data(log.data()) {
        return Some(TransferEffect {
            token,
            from: Some(transfer.from),
            to: transfer.to,
            amount: transfer.amount,
            memo: None,
        });
    }

    let transfer = ITIP20::TransferWithMemo::decode_log_data(log.data()).ok()?;
    Some(TransferEffect {
        token,
        from: Some(transfer.from),
        to: transfer.to,
        amount: transfer.amount,
        memo: Some(transfer.memo.0),
    })
}

/// Parse receipt logs into transfer effects, one per token transfer.
///
/// TIP-20 `transferWithMemo` emits `Transfer` immediately followed by
/// `TransferWithMemo` for the same transfer. Such adjacent pairs are merged
/// into one memo effect so a single transfer cannot satisfy two expected
/// transfers.
fn receipt_transfer_effects(logs: &[Log]) -> Vec<TransferEffect> {
    let mut parsed = logs.iter().map(parse_receipt_transfer_log).peekable();
    let mut effects = Vec::new();

    while let Some(log) = parsed.next() {
        let Some(log) = log else {
            continue;
        };
        let twin = parsed
            .peek()
            .and_then(|next| next.filter(|next| is_twin(&log, next)));
        if let Some(twin) = twin {
            parsed.next();
            effects.push(if log.memo.is_some() { log } else { twin });
        } else {
            effects.push(log);
        }
    }

    effects
}

/// Verify that all expected transfers are present in the receipt logs.
pub(super) fn match_receipt_transfer_logs_with_settlement(
    logs: &[Log],
    currency: Address,
    expected: &[Transfer],
    sender_policy: ReceiptSenderPolicy<'_>,
) -> Result<Vec<MatchedTransferLog>, VerificationError> {
    let matched = match_transfers(
        &receipt_transfer_effects(logs),
        TransferSource::ReceiptLogs(sender_policy),
        currency,
        expected,
    )?;

    Ok(matched
        .into_iter()
        .map(|memo| memo.map_or(MatchedTransferLog::Transfer, MatchedTransferLog::Memo))
        .collect())
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
