//! Channel state transitions.
//!
//! Each transition takes the recorded [`ChannelState`] and returns the state
//! to store next, or the reason it is refused. The handlers run them inside
//! [`ChannelStore::update_channel`](super::ChannelStore::update_channel), so
//! every check is made on the state that is being replaced.

use alloy::primitives::Address;

use super::chain::OnChainChannel;
use super::receipt::now_iso8601;
use super::ChannelState;
use crate::protocol::methods::tempo::session::SettlementRoute;
use crate::protocol::traits::VerificationError;

/// What an accepted `open` credential records besides the on-chain channel.
pub(super) struct Opening {
    pub(super) channel_id: String,
    pub(super) chain_id: u64,
    pub(super) escrow_contract: Address,
    pub(super) authorized_signer: Address,
    pub(super) settlement_route: Option<SettlementRoute>,
    pub(super) cumulative_amount: u128,
    pub(super) signature: Vec<u8>,
}

impl ChannelState {
    /// State after an `open`: a new channel, or the recorded one refreshed
    /// from chain and raised to the open's voucher if that is higher.
    pub(super) fn open(
        existing: Option<Self>,
        on_chain: &OnChainChannel,
        opening: Opening,
    ) -> Self {
        let Opening {
            channel_id,
            chain_id,
            escrow_contract,
            authorized_signer,
            settlement_route,
            cumulative_amount,
            signature,
        } = opening;

        if let Some(existing) = existing {
            let settled_on_chain = std::cmp::max(on_chain.settled, existing.settled_on_chain);
            let spent = std::cmp::max(settled_on_chain, existing.spent);

            // Channel already exists — update if higher.
            if cumulative_amount > existing.highest_voucher_amount {
                Self {
                    settlement_route: existing.settlement_route.or(settlement_route),
                    deposit: on_chain.deposit,
                    settled_on_chain,
                    spent,
                    highest_voucher_amount: cumulative_amount,
                    highest_voucher_signature: Some(signature),
                    authorized_signer,
                    close_requested_at: on_chain.close_requested_at,
                    ..existing
                }
            } else {
                Self {
                    deposit: on_chain.deposit,
                    settled_on_chain,
                    spent,
                    authorized_signer,
                    close_requested_at: on_chain.close_requested_at,
                    ..existing
                }
            }
        } else {
            // New channel (or cold-start reopen after local state was lost).
            // Initialize settled_on_chain and spent from on-chain state so
            // we don't overstate available balance when on_chain.settled > 0.
            Self {
                channel_id,
                chain_id,
                escrow_contract,
                payer: on_chain.payer,
                payee: on_chain.payee,
                token: on_chain.token,
                settlement_route,
                authorized_signer,
                deposit: on_chain.deposit,
                settled_on_chain: on_chain.settled,
                highest_voucher_amount: cumulative_amount,
                highest_voucher_signature: Some(signature),
                spent: on_chain.settled,
                units: 0,
                finalized: false,
                closing: false,
                close_requested_at: on_chain.close_requested_at,
                created_at: now_iso8601(),
            }
        }
    }

    /// Merge an on-chain read into the recorded state.
    ///
    /// The read can be older than what is recorded, so the deposit, the
    /// settled amount and `spent` never go down.
    pub(super) fn refresh_on_chain(self, on_chain: &OnChainChannel) -> Self {
        let settled_on_chain = std::cmp::max(on_chain.settled, self.settled_on_chain);
        let spent = std::cmp::max(settled_on_chain, self.spent);
        Self {
            deposit: std::cmp::max(on_chain.deposit, self.deposit),
            settled_on_chain,
            spent,
            close_requested_at: on_chain.close_requested_at,
            ..self
        }
    }

    /// Record a voucher that raises the accepted amount by at least `min_delta`.
    pub(super) fn accept_voucher(
        self,
        cumulative_amount: u128,
        signature: Vec<u8>,
        min_delta: u128,
    ) -> Result<Self, VerificationError> {
        if cumulative_amount <= self.highest_voucher_amount {
            return Err(VerificationError::delta_too_small(
                "voucher does not add new funds",
            ));
        }
        let delta = cumulative_amount - self.highest_voucher_amount;
        if delta < min_delta {
            return Err(VerificationError::delta_too_small(format!(
                "voucher delta {} below minimum {}",
                delta, min_delta
            )));
        }
        Ok(Self {
            highest_voucher_amount: cumulative_amount,
            highest_voucher_signature: Some(signature),
            ..self
        })
    }

    /// Charge `amount` against the accepted balance.
    pub(super) fn deduct(self, amount: u128) -> Result<Self, VerificationError> {
        if self.finalized {
            return Err(VerificationError::channel_closed("channel is finalized"));
        }
        if self.closing {
            return Err(VerificationError::channel_closed("channel is closing"));
        }
        let available = self.highest_voucher_amount.saturating_sub(self.spent);
        if available >= amount {
            Ok(Self {
                spent: self.spent + amount,
                units: self.units + 1,
                ..self
            })
        } else {
            Err(VerificationError::insufficient_balance(format!(
                "requested {}, available {}",
                amount, available
            )))
        }
    }

    /// Mark the channel as closing at `cumulative_amount`, which stops
    /// further vouchers and deductions while the close is submitted.
    pub(super) fn mark_pending_close(
        self,
        cumulative_amount: u128,
    ) -> Result<Self, VerificationError> {
        if self.finalized {
            return Err(VerificationError::channel_closed("channel is finalized"));
        }
        if self.closing {
            return Err(VerificationError::channel_closed("channel is closing"));
        }
        // `spent` can still grow until `closing` is set, so the amount
        // validated against an earlier snapshot may no longer cover it.
        if cumulative_amount < self.spent {
            return Err(VerificationError::new(format!(
                "close voucher amount must be >= {} (spent)",
                self.spent,
            )));
        }
        Ok(Self {
            closing: true,
            ..self
        })
    }

    /// Undo [`mark_pending_close`](Self::mark_pending_close) after the close
    /// was not settled on-chain.
    pub(super) fn clear_pending_close(self) -> Self {
        if self.finalized {
            return self;
        }
        Self {
            closing: false,
            ..self
        }
    }

    /// Record a close that was settled on-chain at `cumulative_amount`.
    pub(super) fn finalize_close(
        self,
        cumulative_amount: u128,
        signature: Vec<u8>,
        on_chain_deposit: u128,
    ) -> Self {
        let update_voucher = cumulative_amount > self.highest_voucher_amount;
        Self {
            deposit: on_chain_deposit,
            highest_voucher_amount: if update_voucher {
                cumulative_amount
            } else {
                self.highest_voucher_amount
            },
            highest_voucher_signature: if update_voucher {
                Some(signature)
            } else {
                self.highest_voucher_signature
            },
            finalized: true,
            closing: false,
            ..self
        }
    }
}
