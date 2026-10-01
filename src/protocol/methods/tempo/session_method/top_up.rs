//! The `topUp` action.

use alloy::network::ReceiptResponse;
use alloy::primitives::{Address, Bytes, B256};
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
use crate::protocol::traits::VerificationError;

impl<P> SessionMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    /// Verify that the topUp transaction tops up the claimed channel by the
    /// declared amount.
    pub(super) fn verify_top_up_transaction(
        tx_bytes: &[u8],
        claimed_channel_id: B256,
        escrow: Address,
        additional_deposit: u128,
    ) -> Result<(), VerificationError> {
        use alloy::sol_types::SolCall;

        alloy::sol! {
            interface IEscrowTopUp {
                function topUp(bytes32 channelId, uint256 additionalDeposit) external;
            }
        }

        let (_, input) = Self::decode_escrow_call(
            tx_bytes,
            escrow,
            <IEscrowTopUp::topUpCall as SolCall>::SELECTOR,
            "topUp",
        )?;

        let decoded = IEscrowTopUp::topUpCall::abi_decode(&input).map_err(|e| {
            VerificationError::invalid_payload(format!(
                "failed to decode escrow.topUp() calldata: {e}"
            ))
        })?;

        if decoded.channelId != claimed_channel_id {
            return Err(VerificationError::new(
                "topUp transaction does not match claimed channelId",
            ));
        }
        if decoded.additionalDeposit != alloy::primitives::U256::from(additional_deposit) {
            return Err(VerificationError::new(
                "topUp transaction amount does not match additionalDeposit",
            ));
        }

        Ok(())
    }

    /// Handle 'topUp' action.
    pub(super) async fn handle_top_up(
        &self,
        credential: &PaymentCredential,
        payload: &SessionCredentialPayload,
        details: &TempoSessionMethodDetails,
        expected_payee: Address,
        expected_token: Address,
    ) -> Result<Receipt, VerificationError> {
        let (channel_id_str, settlement_route, additional_deposit_str, transaction_str) =
            match payload {
                SessionCredentialPayload::TopUp {
                    channel_id,
                    settlement_route,
                    additional_deposit,
                    transaction,
                    ..
                } => (
                    channel_id,
                    settlement_route.as_ref(),
                    additional_deposit,
                    transaction,
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

        let channel_id_b256 = Self::parse_channel_id(channel_id_str)?;
        let escrow = self.resolve_escrow(details)?;

        let additional_deposit = Self::parse_amount(additional_deposit_str, "additionalDeposit")?;

        // Broadcast the client's signed topUp transaction.
        let tx_bytes: Bytes = transaction_str.parse().map_err(|e| {
            VerificationError::invalid_payload(format!("invalid topUp transaction hex: {}", e))
        })?;
        Self::verify_top_up_transaction(&tx_bytes, channel_id_b256, escrow, additional_deposit)?;

        let pending = self
            .provider
            .send_raw_transaction(&tx_bytes)
            .await
            .map_err(|e| {
                VerificationError::network_error(format!("failed to broadcast topUp tx: {}", e))
            })?;
        let tx_receipt = pending
            .get_receipt()
            .await
            .map_err(|e| VerificationError::network_error(format!("topUp tx failed: {}", e)))?;
        if !tx_receipt.status() {
            return Err(VerificationError::transaction_failed(
                "topUp transaction reverted",
            ));
        }
        let top_up_tx_hash = tx_receipt.transaction_hash().to_string();

        // Re-read on-chain state after topUp tx is broadcast.
        let on_chain = get_on_chain_channel(&*self.provider, escrow, channel_id_b256).await?;

        if on_chain.deposit <= channel.deposit {
            return Err(VerificationError::new(
                "channel deposit did not increase after topUp",
            ));
        }

        // Update store with full on-chain snapshot (deposit, settled, close state).
        let on_chain_deposit = on_chain.deposit;
        let on_chain_settled = on_chain.settled;
        let on_chain_close_requested_at = on_chain.close_requested_at;
        let channel_id_owned = channel_id_str.clone();
        let updated = self
            .store
            .update_channel(
                &channel_id_owned,
                Box::new(move |current| {
                    let state = current
                        .ok_or_else(|| VerificationError::channel_not_found("channel not found"))?;
                    let settled_on_chain = std::cmp::max(on_chain_settled, state.settled_on_chain);
                    let spent = std::cmp::max(settled_on_chain, state.spent);
                    Ok(Some(ChannelState {
                        deposit: std::cmp::max(on_chain_deposit, state.deposit),
                        settled_on_chain,
                        spent,
                        close_requested_at: on_chain_close_requested_at,
                        ..state
                    }))
                }),
            )
            .await?;

        let state = updated.unwrap_or(channel);
        Ok(session_receipt(
            &credential.challenge.id,
            &state,
            Some(top_up_tx_hash),
        ))
    }
}
