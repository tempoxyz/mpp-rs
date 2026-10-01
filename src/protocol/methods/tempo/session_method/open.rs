//! The `open` action.

use alloy::network::ReceiptResponse;
use alloy::primitives::{Address, Bytes, B256};
use alloy::providers::Provider;
use tempo_alloy::TempoNetwork;

use super::chain::get_on_chain_channel;
use super::receipt::{now_iso8601, session_receipt};
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
    /// Verify that the open transaction's derived channel ID matches the claimed channelId.
    ///
    /// Returns the address that signs the channel's vouchers and the deposit
    /// the transaction opens it with.
    pub(super) fn verify_open_channel_id_binding(
        tx_bytes: &[u8],
        claimed_channel_id: B256,
        escrow: Address,
        chain_id: u64,
        expected_payee: Address,
        expected_token: Address,
    ) -> Result<(Address, u128), VerificationError> {
        use alloy::consensus::transaction::SignerRecoverable;
        use alloy::sol_types::SolCall;

        alloy::sol! {
            interface IEscrowOpen {
                function open(address payee, address token, uint128 deposit, bytes32 salt, address authorizedSigner) external;
            }
        }

        let (signed, input) = Self::decode_escrow_call(
            tx_bytes,
            escrow,
            <IEscrowOpen::openCall as SolCall>::SELECTOR,
            "open",
        )?;

        let sender = signed
            .recover_signer()
            .map_err(|e| VerificationError::new(format!("failed to recover sender: {e}")))?;

        let decoded = IEscrowOpen::openCall::abi_decode(&input).map_err(|e| {
            VerificationError::invalid_payload(format!(
                "failed to decode escrow.open() calldata: {e}"
            ))
        })?;

        if decoded.payee != expected_payee {
            return Err(VerificationError::credential_mismatch(
                "open transaction payee does not match session recipient",
            ));
        }
        if decoded.token != expected_token {
            return Err(VerificationError::credential_mismatch(
                "open transaction token does not match session currency",
            ));
        }

        let derived = crate::protocol::methods::tempo::voucher::compute_channel_id(
            sender,
            decoded.payee,
            decoded.token,
            decoded.salt,
            decoded.authorizedSigner,
            escrow,
            chain_id,
        );

        if derived != claimed_channel_id {
            return Err(VerificationError::new(
                "open transaction does not match claimed channelId",
            ));
        }

        let voucher_signer = if decoded.authorizedSigner == Address::ZERO {
            sender
        } else {
            decoded.authorizedSigner
        };

        Ok((voucher_signer, decoded.deposit))
    }

    /// Handle 'open' action.
    pub(super) async fn handle_open(
        &self,
        credential: &PaymentCredential,
        payload: &SessionCredentialPayload,
        details: &TempoSessionMethodDetails,
        expected_payee: Address,
        expected_token: Address,
        amount: u128,
    ) -> Result<Receipt, VerificationError> {
        let (
            channel_id_str,
            descriptor,
            settlement_route,
            cumulative_amount_str,
            signature_str,
            _authorized_signer_str,
            transaction_str,
        ) = match payload {
            SessionCredentialPayload::Open {
                channel_id,
                descriptor,
                settlement_route,
                cumulative_amount,
                signature,
                authorized_signer,
                transaction,
                ..
            } => (
                channel_id,
                descriptor.as_ref(),
                settlement_route.as_ref(),
                cumulative_amount,
                signature,
                authorized_signer,
                transaction,
            ),
            _ => unreachable!(),
        };
        let channel_id_str = &normalize_channel_id(channel_id_str);

        let channel_id_b256 = Self::parse_channel_id(channel_id_str)?;
        let escrow = self.resolve_escrow(details)?;
        let chain_id = self.resolve_chain_id(details);

        if details.machine_token_enabled == Some(true) {
            let descriptor = descriptor.ok_or_else(|| {
                VerificationError::invalid_payload(
                    "machine-token open credential is missing its channel descriptor",
                )
            })?;
            let route = settlement_route.ok_or_else(|| {
                VerificationError::invalid_payload(
                    "machine-token open credential is missing its settlement route",
                )
            })?;
            let recipient = Self::parse_address(&route.recipient)?;
            let target_token = Self::parse_address(&route.target_token)?;
            let route_salt = route
                .route_salt
                .parse()
                .map_err(|_| VerificationError::invalid_payload("invalid settlement routeSalt"))?;
            let expected_salt =
                crate::protocol::methods::tempo::machine_token::compute_session_salt(
                    recipient,
                    target_token,
                    route_salt,
                );
            if descriptor.salt != expected_salt.to_string()
                || details.settlement_adapter.as_deref() != Some(&route.adapter)
                || details.settlement_recipient.as_deref() != Some(&route.recipient)
                || details.settlement_token.as_deref() != Some(&route.target_token)
            {
                return Err(VerificationError::credential_mismatch(
                    "machine-token settlement route is not bound to the descriptor",
                ));
            }
        }
        let accepted_settlement_route = settlement_route.cloned();

        // Broadcast the client's signed open transaction (approve + escrow.open).
        let tx_bytes: Bytes = transaction_str.parse().map_err(|e| {
            VerificationError::invalid_payload(format!("invalid open transaction hex: {}", e))
        })?;

        // Verify the open transaction's derived channel ID matches the claimed channelId
        let (voucher_signer, open_deposit) = Self::verify_open_channel_id_binding(
            &tx_bytes,
            channel_id_b256,
            escrow,
            chain_id,
            expected_payee,
            expected_token,
        )?;

        // Check the voucher against the transaction before broadcasting it:
        // once the channel is funded, rejecting the credential would leave the
        // deposit in a channel the server never recorded.
        let cumulative_amount = Self::parse_amount(cumulative_amount_str, "cumulativeAmount")?;
        if cumulative_amount > open_deposit {
            return Err(VerificationError::amount_exceeds_deposit(
                "voucher amount exceeds open deposit",
            ));
        }
        if open_deposit < amount {
            return Err(VerificationError::insufficient_balance(
                "open deposit is less than the session amount",
            ));
        }
        let sig_bytes = Self::parse_signature(signature_str)?;
        if !verify_voucher(
            escrow,
            chain_id,
            channel_id_b256,
            cumulative_amount,
            &sig_bytes,
            voucher_signer,
        ) {
            return Err(VerificationError::invalid_signature(
                "invalid voucher signature",
            ));
        }

        let pending = self
            .provider
            .send_raw_transaction(&tx_bytes)
            .await
            .map_err(|e| {
                VerificationError::network_error(format!("failed to broadcast open tx: {}", e))
            })?;
        let tx_receipt = pending
            .get_receipt()
            .await
            .map_err(|e| VerificationError::network_error(format!("open tx failed: {}", e)))?;
        if !tx_receipt.status() {
            return Err(VerificationError::transaction_failed(format!(
                "open transaction reverted (tx: {})",
                tx_receipt.transaction_hash()
            )));
        }
        let open_tx_hash = tx_receipt.transaction_hash().to_string();

        let on_chain = get_on_chain_channel(&*self.provider, escrow, channel_id_b256).await?;

        if on_chain.payee != expected_payee {
            return Err(VerificationError::credential_mismatch(
                "channel payee does not match session recipient",
            ));
        }
        if on_chain.token != expected_token {
            return Err(VerificationError::credential_mismatch(
                "channel token does not match session currency",
            ));
        }

        // Validate on-chain state.
        if on_chain.deposit == 0 {
            return Err(VerificationError::channel_not_found(
                "channel not funded on-chain",
            ));
        }
        if on_chain.finalized {
            return Err(VerificationError::channel_closed(
                "channel is finalized on-chain",
            ));
        }
        if on_chain.close_requested_at != 0 {
            return Err(VerificationError::channel_closed(
                "channel has a pending close request",
            ));
        }
        if on_chain.deposit.saturating_sub(on_chain.settled) < amount {
            return Err(VerificationError::insufficient_balance(
                "channel available balance is less than the session amount",
            ));
        }

        let authorized_signer = if on_chain.authorized_signer == Address::ZERO {
            on_chain.payer
        } else {
            on_chain.authorized_signer
        };

        if cumulative_amount > on_chain.deposit {
            return Err(VerificationError::amount_exceeds_deposit(
                "voucher amount exceeds on-chain deposit",
            ));
        }
        if cumulative_amount < on_chain.settled {
            return Err(VerificationError::new(
                "voucher cumulativeAmount is below on-chain settled amount",
            ));
        }

        // The signature was verified against the transaction's signer above;
        // only a channel that reports a different one needs another check.
        if authorized_signer != voucher_signer
            && !verify_voucher(
                escrow,
                chain_id,
                channel_id_b256,
                cumulative_amount,
                &sig_bytes,
                authorized_signer,
            )
        {
            return Err(VerificationError::invalid_signature(
                "invalid voucher signature",
            ));
        }

        // Create or update channel in store.
        let channel_id_for_key = channel_id_str.clone();
        let channel_id_for_state = channel_id_str.clone();
        let updated = self
            .store
            .update_channel(
                &channel_id_for_key,
                Box::new(move |existing| {
                    if let Some(existing) = existing {
                        let settled_on_chain =
                            std::cmp::max(on_chain.settled, existing.settled_on_chain);
                        let spent = std::cmp::max(settled_on_chain, existing.spent);

                        // Channel already exists — update if higher.
                        if cumulative_amount > existing.highest_voucher_amount {
                            Ok(Some(ChannelState {
                                settlement_route: existing
                                    .settlement_route
                                    .or_else(|| accepted_settlement_route.clone()),
                                deposit: on_chain.deposit,
                                settled_on_chain,
                                spent,
                                highest_voucher_amount: cumulative_amount,
                                highest_voucher_signature: Some(sig_bytes),
                                authorized_signer,
                                close_requested_at: on_chain.close_requested_at,
                                ..existing
                            }))
                        } else {
                            Ok(Some(ChannelState {
                                deposit: on_chain.deposit,
                                settled_on_chain,
                                spent,
                                authorized_signer,
                                close_requested_at: on_chain.close_requested_at,
                                ..existing
                            }))
                        }
                    } else {
                        // New channel (or cold-start reopen after local state was lost).
                        // Initialize settled_on_chain and spent from on-chain state so
                        // we don't overstate available balance when on_chain.settled > 0.
                        Ok(Some(ChannelState {
                            channel_id: channel_id_for_state,
                            chain_id,
                            escrow_contract: escrow,
                            payer: on_chain.payer,
                            payee: on_chain.payee,
                            token: on_chain.token,
                            settlement_route: accepted_settlement_route,
                            authorized_signer,
                            deposit: on_chain.deposit,
                            settled_on_chain: on_chain.settled,
                            highest_voucher_amount: cumulative_amount,
                            highest_voucher_signature: Some(sig_bytes),
                            spent: on_chain.settled,
                            units: 0,
                            finalized: false,
                            closing: false,
                            close_requested_at: on_chain.close_requested_at,
                            created_at: now_iso8601(),
                        }))
                    }
                }),
            )
            .await?;

        let state =
            updated.ok_or_else(|| VerificationError::internal("failed to create channel"))?;

        Ok(session_receipt(
            &credential.challenge.id,
            &state,
            Some(open_tx_hash),
        ))
    }
}
