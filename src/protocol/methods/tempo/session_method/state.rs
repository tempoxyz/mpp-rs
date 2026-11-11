//! Channel state transitions.
//!
//! Each transition takes the recorded [`ChannelState`] and returns the state
//! to store next, or the reason it is refused. The handlers run them inside
//! [`ChannelStore::update_channel`](super::ChannelStore::update_channel), so
//! every check is made on the state that is being replaced.

use alloy::primitives::Address;

use super::chain::OnChainChannel;
use super::receipt::now_iso8601;
use super::{ChannelState, VoucherWindow};
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
            // The read can be older than what is recorded, as in `refresh_on_chain`.
            let deposit = std::cmp::max(on_chain.deposit, existing.deposit);
            let settled_on_chain = std::cmp::max(on_chain.settled, existing.settled_on_chain);
            let spent = std::cmp::max(settled_on_chain, existing.spent);

            // Channel already exists — update if higher.
            if cumulative_amount > existing.highest_voucher_amount {
                Self {
                    settlement_route: existing.settlement_route.or(settlement_route),
                    deposit,
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
                    deposit,
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
                pending_close: None,
                close_requested_at: on_chain.close_requested_at,
                created_at: now_iso8601(),
                window: None,
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

    /// Record a voucher accepted within a reorder window of `window_ms`, at
    /// `now_ms` (Unix milliseconds): out of order, but each increment once.
    ///
    /// `after` is the cumulative amount the client counted before this
    /// voucher, so `(after, cumulative_amount]` is its own increment. Without
    /// it, a voucher above the accepted amount covers the gap from it, and a
    /// late one covers one base unit. A voucher at or below the window's
    /// floor is refused as stale and one overlapping an accepted increment as
    /// seen. Only a voucher above the accepted amount raises it: a late one
    /// adds no funds, since requests are charged from the accepted amount.
    pub(super) fn accept_voucher_in_window(
        self,
        cumulative_amount: u128,
        after: Option<u128>,
        signature: Vec<u8>,
        min_delta: u128,
        now_ms: u64,
        window_ms: u64,
    ) -> Result<Self, VerificationError> {
        let highest = self.highest_voucher_amount;
        // The window tracks vouchers up to the highest one. A channel that
        // has none yet, or whose highest voucher was raised outside it (an
        // open, or vouchers accepted while no window was configured), starts
        // one with every voucher up to the highest below its floor, so none
        // of them can be replayed.
        let mut window = match self.window.clone() {
            Some(window)
                if window
                    .runs
                    .last()
                    .map_or(window.floor, |run| run.to.max(window.floor))
                    == highest =>
            {
                window
            }
            _ => VoucherWindow {
                floor: highest,
                runs: Vec::new(),
            },
        };
        window.prune(now_ms.saturating_sub(window_ms));

        if after.is_some_and(|after| after >= cumulative_amount) {
            return Err(VerificationError::invalid_payload(
                "voucher after must be below cumulativeAmount",
            ));
        }
        let resync = |reason: &str| {
            VerificationError::delta_too_small(format!(
                "{reason}; acceptedCumulative {highest}, requiredCumulative {}",
                highest.saturating_add(min_delta.max(1)),
            ))
        };
        if cumulative_amount <= window.floor {
            return Err(resync("voucher is older than the reorder window (stale)"));
        }
        // A voucher above the highest one adds funds and cannot be a replay:
        // it covers what lies above the highest voucher (and above `after`,
        // leaving a hole below it for a voucher still in flight). A late one
        // covers its own increment, and only once.
        let lo = if cumulative_amount > highest {
            after.unwrap_or(highest).max(highest)
        } else {
            after.unwrap_or(cumulative_amount - 1).max(window.floor)
        };
        if cumulative_amount <= highest && window.overlaps(lo, cumulative_amount) {
            return Err(resync("voucher was already accepted (seen)"));
        }
        let delta = cumulative_amount - lo;
        if delta < min_delta {
            return Err(resync(&format!(
                "voucher delta {delta} below minimum {min_delta}"
            )));
        }
        window.insert(lo, cumulative_amount, now_ms);

        let raises = cumulative_amount > highest;
        Ok(Self {
            highest_voucher_amount: if raises { cumulative_amount } else { highest },
            highest_voucher_signature: if raises {
                Some(signature)
            } else {
                self.highest_voucher_signature
            },
            window: Some(window),
            ..self
        })
    }

    /// The link where the payer buys the MACH that a deposit too small to
    /// cover `amount` lacks, for a MACH channel on a chain that sells MACH.
    /// The payer may already hold it, so the link names the deposit's
    /// shortfall rather than a wallet balance.
    fn machine_token_top_up_url(&self, amount: u128) -> Option<String> {
        use crate::protocol::methods::tempo::machine_token;

        if machine_token::token(self.chain_id) != Some(self.token) {
            return None;
        }
        let unspent_deposit = self.deposit.saturating_sub(self.spent);
        let shortfall = amount.checked_sub(unspent_deposit).filter(|s| *s > 0)?;
        machine_token::funding_url(self.chain_id, Some(self.payer), Some(shortfall))
    }

    /// Charge `amount` against the accepted balance.
    pub(super) fn deduct(self, amount: u128) -> Result<Self, VerificationError> {
        if self.finalized {
            return Err(VerificationError::channel_closed("channel is finalized"));
        }
        if self.closing {
            return Err(VerificationError::channel_closed("channel is closing"));
        }
        if self.close_requested_at != 0 {
            return Err(VerificationError::channel_closed(
                "channel has a pending close request",
            ));
        }
        let available = self.highest_voucher_amount.saturating_sub(self.spent);
        if available >= amount {
            Ok(Self {
                spent: self.spent + amount,
                units: self.units + 1,
                ..self
            })
        } else {
            let mut message = format!("requested {}, available {}", amount, available);
            if let Some(url) = self.machine_token_top_up_url(amount) {
                message.push_str(&format!("; top up the channel with MACH from {url}"));
            }
            Err(VerificationError::insufficient_balance(message))
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
            pending_close: None,
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
            pending_close: None,
            ..self
        }
    }
}
