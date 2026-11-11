//! The `voucher` action.

use alloy::primitives::Address;
use alloy::providers::Provider;
use tempo_alloy::TempoNetwork;

use super::chain::OnChainChannel;
use super::payload::validate_settlement_route;
use super::precompile;
use super::receipt::session_receipt;
use super::{normalize_channel_id, ChannelState, SessionMethod};
use crate::protocol::core::{PaymentCredential, Receipt};
use crate::protocol::methods::tempo::session::{
    SessionCredentialPayload, TempoSessionMethodDetails,
};
use crate::protocol::traits::{ErrorCode, VerificationError};

impl<P> SessionMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    /// Handle 'voucher' action.
    pub(super) async fn handle_voucher(
        &self,
        credential: &PaymentCredential,
        payload: &SessionCredentialPayload,
        details: &TempoSessionMethodDetails,
        expected_payee: Address,
        expected_token: Address,
    ) -> Result<Receipt, VerificationError> {
        let (
            channel_id_str,
            descriptor,
            settlement_route,
            cumulative_amount_str,
            after_str,
            signature_str,
        ) = match payload {
            SessionCredentialPayload::Voucher {
                channel_id,
                descriptor,
                settlement_route,
                cumulative_amount,
                after,
                signature,
            } => (
                channel_id,
                descriptor.as_ref(),
                settlement_route.as_ref(),
                cumulative_amount,
                after.as_ref(),
                signature,
            ),
            _ => unreachable!(),
        };
        let channel_id_str = &normalize_channel_id(channel_id_str);

        // The on-chain read does not depend on the stored channel, so it
        // overlaps the store read. Every stored-channel check still takes
        // precedence over a failed on-chain read: the chain branch never
        // short-circuits the join, and a stored-channel error drops it.
        let read_on_chain = async {
            let escrow = self.resolve_escrow(details)?;
            let channel_id_b256 = Self::parse_channel_id(channel_id_str)?;
            let precompile_descriptor = if precompile::is_precompile(escrow) {
                Some(precompile::validate_descriptor(
                    descriptor,
                    channel_id_b256,
                    escrow,
                    self.resolve_chain_id(details),
                    expected_payee,
                    expected_token,
                    Self::resolve_operator(details)?,
                )?)
            } else {
                None
            };
            self.read_channel(escrow, channel_id_b256, precompile_descriptor.as_ref())
                .await
        };
        let check_stored = async {
            let channel = self
                .store
                .get_channel(channel_id_str)
                .await?
                .ok_or_else(|| VerificationError::channel_not_found("channel not found"))?;

            if channel.payee != expected_payee {
                return Err(VerificationError::credential_mismatch(
                    "channel payee does not match session recipient",
                ));
            }
            if channel.token != expected_token {
                return Err(VerificationError::credential_mismatch(
                    "channel token does not match session currency",
                ));
            }
            validate_settlement_route(&channel, details, settlement_route)?;

            if channel.finalized {
                return Err(VerificationError::channel_closed("channel is finalized"));
            }
            if channel.closing {
                return Err(VerificationError::channel_closed("channel is closing"));
            }

            let cumulative_amount = Self::parse_amount(cumulative_amount_str, "cumulativeAmount")?;
            // `after` only matters to a server that accepts vouchers out of
            // order; any other ignores it, as it did before the field existed.
            let after = match (self.reorder_window, after_str) {
                (Some(_), Some(after)) => Some(Self::parse_amount(after, "after")?),
                _ => None,
            };

            let escrow = self.resolve_escrow(details)?;
            let chain_id = self.resolve_chain_id(details);

            if channel.chain_id != chain_id {
                return Err(VerificationError::credential_mismatch(
                    "channel chain_id does not match session chain_id",
                ));
            }
            if channel.escrow_contract != escrow {
                return Err(VerificationError::credential_mismatch(
                    "channel escrow does not match session escrow",
                ));
            }
            Ok((cumulative_amount, after))
        };
        let ((cumulative_amount, after), on_chain) =
            tokio::try_join!(check_stored, async { Ok(read_on_chain.await) })?;
        let on_chain = on_chain?;
        let min_delta = self.resolve_min_delta(details);
        let escrow = self.resolve_escrow(details)?;

        // A TIP-1034 channel that reads back unfunded was closed or withdrawn (or the RPC has
        // not seen it yet): reject this voucher without recording anything, so a stale read
        // cannot lock the payee out of a live channel.
        if precompile::is_precompile(escrow) && on_chain.deposit == 0 {
            return Err(VerificationError::channel_closed(
                "channel is not funded on-chain",
            ));
        }
        if on_chain.payee != expected_payee {
            return Err(VerificationError::credential_mismatch(
                "on-chain channel payee does not match session recipient",
            ));
        }
        if on_chain.token != expected_token {
            return Err(VerificationError::credential_mismatch(
                "on-chain channel token does not match session currency",
            ));
        }

        let state = self
            .verify_and_accept_voucher(
                channel_id_str,
                Some(on_chain),
                cumulative_amount,
                after,
                signature_str,
                min_delta,
            )
            .await?;

        Ok(session_receipt(&credential.challenge.id, &state, None))
    }

    /// Authenticate and accept a voucher in the same atomic transition as any
    /// on-chain refresh. Rejected vouchers leave accounting untouched, but
    /// authoritative closure flags must still block further metered delivery.
    pub(super) async fn verify_and_accept_voucher(
        &self,
        channel_id_str: &str,
        on_chain: Option<OnChainChannel>,
        cumulative_amount: u128,
        after: Option<u128>,
        signature_str: &str,
        min_delta: u128,
    ) -> Result<ChannelState, VerificationError> {
        if let Some(ref on_chain) = on_chain {
            if on_chain.finalized || on_chain.close_requested_at != 0 {
                let finalized = on_chain.finalized;
                let close_requested_at = on_chain.close_requested_at;
                self.store
                    .update_channel(
                        channel_id_str,
                        Box::new(move |current| {
                            let mut state = current.ok_or_else(|| {
                                VerificationError::channel_not_found("channel not found")
                            })?;
                            // These trusted flags only restrict delivery; do not refresh
                            // deposits, settlement, or spent credit for a rejected voucher.
                            state.finalized |= finalized;
                            state.close_requested_at =
                                state.close_requested_at.max(close_requested_at);
                            Ok(Some(state))
                        }),
                    )
                    .await?;
                return Err(VerificationError::channel_closed(if finalized {
                    "channel is finalized on-chain"
                } else {
                    "channel has a pending close request"
                }));
            }
        }
        let window = self.reorder_window.map(|window| VoucherAcceptance {
            after,
            window_ms: u64::try_from(window.as_millis()).unwrap_or(u64::MAX),
            now_ms: now_ms(),
        });
        // Vouchers inside a reorder window arrive concurrently by design, so
        // on a store shared by several server instances a lost
        // compare-exchange is routine: apply the voucher again against the
        // fresh state rather than failing the request.
        let attempts = if window.is_some() {
            MAX_VOUCHER_UPDATE_ATTEMPTS
        } else {
            1
        };
        let mut attempt = 1;
        loop {
            let channel_id = channel_id_str.to_owned();
            let signature = signature_str.to_owned();
            let on_chain = on_chain.clone();
            let result = self
                .store
                .update_channel(
                    channel_id_str,
                    Box::new(move |current| {
                        let state = current.ok_or_else(|| {
                            VerificationError::channel_not_found("channel not found")
                        })?;
                        let state = match on_chain {
                            Some(on_chain) => ChannelState {
                                finalized: state.finalized || on_chain.finalized,
                                ..state.refresh_on_chain(&on_chain)
                            },
                            None => state,
                        };
                        Self::accept_authenticated_voucher(
                            state,
                            &channel_id,
                            cumulative_amount,
                            &signature,
                            min_delta,
                            window,
                        )
                        .map(Some)
                    }),
                )
                .await;
            match result {
                Err(err) if err.code == Some(ErrorCode::ConcurrentUpdate) && attempt < attempts => {
                    attempt += 1;
                }
                result => {
                    return result?
                        .ok_or_else(|| VerificationError::channel_not_found("channel not found"))
                }
            }
        }
    }

    fn accept_authenticated_voucher(
        channel: ChannelState,
        channel_id_str: &str,
        cumulative_amount: u128,
        signature_str: &str,
        min_delta: u128,
        window: Option<VoucherAcceptance>,
    ) -> Result<ChannelState, VerificationError> {
        if channel.closing {
            return Err(VerificationError::channel_closed("channel is closing"));
        }
        if channel.finalized {
            return Err(VerificationError::channel_closed(
                "channel is finalized on-chain",
            ));
        }
        if channel.close_requested_at != 0 {
            return Err(VerificationError::channel_closed(
                "channel has a pending close request",
            ));
        }
        // Authenticate the voucher before comparing it against the channel:
        // the delta check reports how far it is above the accepted amount,
        // which only the payer may learn. An exact replay of the stored
        // voucher was verified when it was accepted.
        let sig_bytes =
            precompile::parse_signature_for::<P>(channel.escrow_contract, signature_str)?;
        let is_exact_replay = cumulative_amount == channel.highest_voucher_amount
            && channel.highest_voucher_signature.as_ref() == Some(&sig_bytes);
        if !is_exact_replay {
            let channel_id_b256 = Self::parse_channel_id(channel_id_str)?;
            let is_valid = precompile::verify_voucher_for(
                channel.escrow_contract,
                channel.chain_id,
                channel_id_b256,
                cumulative_amount,
                &sig_bytes,
                channel.authorized_signer,
            );
            if !is_valid {
                return Err(VerificationError::invalid_signature(
                    "invalid voucher signature",
                ));
            }
        }

        // Within a reorder window a late voucher adds no funds of its own:
        // requests are charged from the highest voucher, so only a voucher
        // that raises it must be above the settled amount.
        let raises = cumulative_amount > channel.highest_voucher_amount;
        if cumulative_amount < channel.settled_on_chain && (window.is_none() || raises) {
            return Err(VerificationError::new(
                "voucher cumulativeAmount is below on-chain settled amount",
            ));
        }
        if cumulative_amount > channel.deposit {
            return Err(VerificationError::amount_exceeds_deposit(
                "voucher amount exceeds on-chain deposit",
            ));
        }

        match window {
            Some(window) => channel.accept_voucher_in_window(
                cumulative_amount,
                window.after,
                sig_bytes,
                min_delta,
                window.now_ms,
                window.window_ms,
            ),
            None => channel.accept_voucher(cumulative_amount, sig_bytes, min_delta),
        }
    }
}

/// Most times a session method with a reorder window applies one voucher to
/// a channel whose store write lost a race (see
/// [`ErrorCode::ConcurrentUpdate`]).
///
/// The bound comes from the store: within one process the channel store
/// serializes updates to a channel (as `ChannelStoreAdapter`'s per-channel lock
/// does), so a write loses only to another instance sharing the store that
/// committed between this attempt's read and its write. Eight attempts carry
/// a voucher through contention from several instances on one channel while
/// keeping the store round trips one request can make small; past them the
/// conflict is returned with its own code.
pub(super) const MAX_VOUCHER_UPDATE_ATTEMPTS: usize = 8;

/// How a session method with a reorder window accepts one voucher.
#[derive(Clone, Copy)]
struct VoucherAcceptance {
    after: Option<u128>,
    window_ms: u64,
    now_ms: u64,
}

/// The current time in Unix milliseconds.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}
