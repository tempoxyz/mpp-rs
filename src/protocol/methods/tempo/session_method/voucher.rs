//! The `voucher` action.

use alloy::primitives::Address;
use alloy::providers::Provider;
use tempo_alloy::TempoNetwork;

use super::chain::get_on_chain_channel;
use super::payload::validate_settlement_route;
use super::receipt::session_receipt;
use super::{normalize_channel_id, ChannelState, SessionMethod};
use crate::protocol::core::{PaymentCredential, Receipt};
use crate::protocol::methods::tempo::session::{
    SessionCredentialPayload, TempoSessionMethodDetails,
};
use crate::protocol::methods::tempo::voucher::verify_voucher;
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
        let (channel_id_str, settlement_route, cumulative_amount_str, signature_str) = match payload
        {
            SessionCredentialPayload::Voucher {
                channel_id,
                settlement_route,
                cumulative_amount,
                signature,
                ..
            } => (
                channel_id,
                settlement_route.as_ref(),
                cumulative_amount,
                signature,
            ),
            _ => unreachable!(),
        };
        let channel_id_str = &normalize_channel_id(channel_id_str);

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
        let min_delta = self.resolve_min_delta(details);
        let channel_id_b256 = Self::parse_channel_id(channel_id_str)?;
        let on_chain = get_on_chain_channel(&*self.provider, escrow, channel_id_b256).await?;

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

        let refreshed = self
            .store
            .update_channel(
                channel_id_str,
                Box::new(move |current| {
                    let state = current
                        .ok_or_else(|| VerificationError::channel_not_found("channel not found"))?;
                    Ok(Some(ChannelState {
                        finalized: state.finalized || on_chain.finalized,
                        ..state.refresh_on_chain(&on_chain)
                    }))
                }),
            )
            .await?
            .ok_or_else(|| VerificationError::channel_not_found("channel not found"))?;

        let state = self
            .verify_and_accept_voucher(
                channel_id_str,
                &refreshed,
                cumulative_amount,
                signature_str,
                min_delta,
            )
            .await?;

        Ok(session_receipt(&credential.challenge.id, &state, None))
    }

    /// Check a voucher against `channel`, the state as last refreshed from
    /// chain, and record it.
    ///
    /// The signature is verified for the channel's own escrow and chain; the
    /// caller has checked that the challenge names the same ones.
    ///
    /// Returns the channel state with the voucher applied.
    pub(super) async fn verify_and_accept_voucher(
        &self,
        channel_id_str: &str,
        channel: &ChannelState,
        cumulative_amount: u128,
        signature_str: &str,
        min_delta: u128,
    ) -> Result<ChannelState, VerificationError> {
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

        // If voucher is not higher than what we already have, verify the
        // signature and reject it as a replay. A successful voucher must add new
        // funds for the current metered request.
        if cumulative_amount <= channel.highest_voucher_amount {
            let sig_bytes = Self::parse_signature(signature_str)?;
            let is_exact_replay =
                channel
                    .highest_voucher_signature
                    .as_ref()
                    .is_some_and(|stored_sig| {
                        stored_sig == &sig_bytes
                            && cumulative_amount == channel.highest_voucher_amount
                    });
            if !is_exact_replay {
                let channel_id_b256 = Self::parse_channel_id(channel_id_str)?;
                let is_valid = verify_voucher(
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
            return Err(VerificationError::delta_too_small(
                "voucher does not add new funds",
            ));
        }

        let delta = cumulative_amount - channel.highest_voucher_amount;
        if delta < min_delta {
            return Err(VerificationError::delta_too_small(format!(
                "voucher delta {} below minimum {}",
                delta, min_delta
            )));
        }

        let channel_id_b256 = Self::parse_channel_id(channel_id_str)?;
        let sig_bytes = Self::parse_signature(signature_str)?;

        let is_valid = verify_voucher(
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

        // Update store with new highest voucher.
        let updated = self
            .store
            .update_channel(
                channel_id_str,
                Box::new(move |current| {
                    let state = current
                        .ok_or_else(|| VerificationError::channel_not_found("channel not found"))?;
                    state
                        .accept_voucher(cumulative_amount, sig_bytes, min_delta)
                        .map(Some)
                }),
            )
            .await?;

        updated.ok_or_else(|| VerificationError::channel_not_found("channel not found"))
    }
}
