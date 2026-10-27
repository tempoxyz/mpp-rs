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
use crate::protocol::traits::VerificationError;

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
        let (channel_id_str, descriptor, settlement_route, cumulative_amount_str, signature_str) =
            match payload {
                SessionCredentialPayload::Voucher {
                    channel_id,
                    descriptor,
                    settlement_route,
                    cumulative_amount,
                    signature,
                    ..
                } => (
                    channel_id,
                    descriptor.as_ref(),
                    settlement_route.as_ref(),
                    cumulative_amount,
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
            Ok(cumulative_amount)
        };
        let (cumulative_amount, on_chain) =
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
                signature_str,
                min_delta,
            )
            .await?;

        Ok(session_receipt(&credential.challenge.id, &state, None))
    }

    /// Authenticate and accept a voucher in the same atomic transition as any
    /// on-chain refresh. Rejected vouchers must leave all accounting untouched.
    pub(super) async fn verify_and_accept_voucher(
        &self,
        channel_id_str: &str,
        on_chain: Option<OnChainChannel>,
        cumulative_amount: u128,
        signature_str: &str,
        min_delta: u128,
    ) -> Result<ChannelState, VerificationError> {
        let channel_id = channel_id_str.to_owned();
        let signature = signature_str.to_owned();
        self.store
            .update_channel(
                channel_id_str,
                Box::new(move |current| {
                    let state = current
                        .ok_or_else(|| VerificationError::channel_not_found("channel not found"))?;
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
                    )
                    .map(Some)
                }),
            )
            .await?
            .ok_or_else(|| VerificationError::channel_not_found("channel not found"))
    }

    fn accept_authenticated_voucher(
        channel: ChannelState,
        channel_id_str: &str,
        cumulative_amount: u128,
        signature_str: &str,
        min_delta: u128,
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

        if cumulative_amount < channel.settled_on_chain {
            return Err(VerificationError::new(
                "voucher cumulativeAmount is below on-chain settled amount",
            ));
        }
        if cumulative_amount > channel.deposit {
            return Err(VerificationError::amount_exceeds_deposit(
                "voucher amount exceeds on-chain deposit",
            ));
        }

        channel.accept_voucher(cumulative_amount, sig_bytes, min_delta)
    }
}
