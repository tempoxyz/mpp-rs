//! The `close` action.

use alloy::network::ReceiptResponse;
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

/// Validate the close voucher amount against spent, on-chain settled, and deposit.
/// Matches mppx handleClose:
/// https://github.com/wevm/mppx/blob/c526ea6/src/tempo/server/Session.ts#L837-L846
///
/// The amount must exceed the on-chain settled amount: a settled voucher is
/// public on-chain and must not close the channel when presented again
/// (GHSA-mv9j-8jvg-j8mr). The one exception is a funded channel nothing was
/// ever settled on, which can be closed at zero to refund the payer.
pub(super) fn validate_close_amount(
    cumulative_amount: u128,
    spent: u128,
    on_chain_settled: u128,
    on_chain_deposit: u128,
) -> Result<(), VerificationError> {
    if cumulative_amount < spent {
        return Err(VerificationError::new(format!(
            "close voucher amount must be >= {} (spent)",
            spent,
        )));
    }
    let refunds_untouched = cumulative_amount == 0 && on_chain_settled == 0 && on_chain_deposit > 0;
    if cumulative_amount <= on_chain_settled && !refunds_untouched {
        return Err(VerificationError::new(format!(
            "close voucher amount must be > {} (on-chain settled)",
            on_chain_settled,
        )));
    }
    if cumulative_amount > on_chain_deposit {
        return Err(VerificationError::amount_exceeds_deposit(
            "close voucher amount exceeds on-chain deposit",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn machine_session_close_calls(
    chain_id: u64,
    escrow: Address,
    descriptor: &crate::protocol::methods::tempo::session::ChannelDescriptor,
    route: &crate::protocol::methods::tempo::session::SettlementRoute,
    cumulative_amount: u128,
    deposit: u128,
    settled: u128,
    signature: &[u8],
) -> Result<Vec<tempo_alloy::primitives::transaction::Call>, VerificationError> {
    use alloy::{
        primitives::{Bytes, TxKind, U256},
        sol_types::SolCall,
    };
    if cumulative_amount != deposit {
        return Err(VerificationError::invalid_payload(
            "machine-token sessions cannot close with a nonzero refund",
        ));
    }
    let cumulative_amount = alloy::primitives::Uint::<96, 2>::from(cumulative_amount);
    let parse_address = |value: &str| {
        value
            .parse::<Address>()
            .map_err(|_| VerificationError::invalid_payload("invalid channel descriptor address"))
    };
    let descriptor_wire =
        tempo_alloy::contracts::precompiles::ITIP20ChannelReserve::ChannelDescriptor {
            payer: parse_address(&descriptor.payer)?,
            payee: parse_address(&descriptor.payee)?,
            operator: parse_address(&descriptor.operator)?,
            token: parse_address(&descriptor.token)?,
            salt: descriptor
                .salt
                .parse()
                .map_err(|_| VerificationError::invalid_payload("invalid descriptor salt"))?,
            authorizedSigner: parse_address(&descriptor.authorized_signer)?,
            expiringNonceHash: descriptor.expiring_nonce_hash.parse().map_err(|_| {
                VerificationError::invalid_payload("invalid descriptor expiringNonceHash")
            })?,
        };
    let settle = tempo_alloy::contracts::precompiles::ITIP20ChannelReserve::settleCall::new((
        descriptor_wire.clone(),
        cumulative_amount,
        Bytes::copy_from_slice(signature),
    ));
    let close = tempo_alloy::contracts::precompiles::ITIP20ChannelReserve::closeCall::new((
        descriptor_wire,
        cumulative_amount,
        cumulative_amount,
        Bytes::copy_from_slice(signature),
    ));
    let swap = crate::protocol::methods::tempo::machine_token::settle_session_call(
        chain_id, descriptor, route,
    )
    .map_err(|error| VerificationError::invalid_payload(error.to_string()))?;
    let close_call = tempo_alloy::primitives::transaction::Call {
        to: TxKind::Call(escrow),
        value: U256::ZERO,
        input: Bytes::from(close.abi_encode()),
    };
    if settled == deposit {
        return Ok(vec![close_call]);
    }
    Ok(vec![
        tempo_alloy::primitives::transaction::Call {
            to: TxKind::Call(escrow),
            value: U256::ZERO,
            input: Bytes::from(settle.abi_encode()),
        },
        swap,
        close_call,
    ])
}

impl<P> SessionMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    /// Handle 'close' action.
    pub(super) async fn handle_close(
        &self,
        credential: &PaymentCredential,
        payload: &SessionCredentialPayload,
        details: &TempoSessionMethodDetails,
        expected_payee: Address,
        expected_token: Address,
    ) -> Result<Receipt, VerificationError> {
        let (channel_id_str, descriptor, settlement_route, cumulative_amount_str, signature_str) =
            match payload {
                SessionCredentialPayload::Close {
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
            return Err(VerificationError::channel_closed(
                "channel is already finalized",
            ));
        }

        let cumulative_amount = Self::parse_amount(cumulative_amount_str, "cumulativeAmount")?;

        let channel_id_b256 = Self::parse_channel_id(channel_id_str)?;
        let escrow = self.resolve_escrow(details)?;
        let chain_id = self.resolve_chain_id(details);

        // For close, always re-read on-chain state.
        let on_chain = get_on_chain_channel(&*self.provider, escrow, channel_id_b256).await?;

        if on_chain.finalized {
            return Err(VerificationError::channel_closed(
                "channel is finalized on-chain",
            ));
        }

        validate_close_amount(
            cumulative_amount,
            channel.spent,
            on_chain.settled,
            on_chain.deposit,
        )?;

        let sig_bytes = Self::parse_signature(signature_str)?;
        let is_valid = verify_voucher(
            escrow,
            chain_id,
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

        let signer = self.close_signer.as_ref().ok_or_else(|| {
            VerificationError::new(
                "cannot close channel: no close signer configured (see `with_close_signer`)",
            )
        })?;

        self.store
            .update_channel(
                channel_id_str,
                Box::new(move |current| {
                    let state = current
                        .ok_or_else(|| VerificationError::channel_not_found("channel not found"))?;
                    state.mark_pending_close(cumulative_amount).map(Some)
                }),
            )
            .await?;

        // Submit the close transaction on-chain. Failures are collected so the
        // `closing` flag can be reset below.
        let close_tx_result: Result<String, VerificationError> = async {
            use alloy::eips::Encodable2718;
            use alloy::primitives::Bytes;
            use alloy::sol_types::SolCall;
            use tempo_alloy::primitives::transaction::Call;
            use tempo_alloy::primitives::TempoTransaction;

            alloy::sol! {
                interface IEscrowClose {
                    function close(bytes32 channelId, uint128 cumulativeAmount, bytes calldata signature) external;
                }
            }

            let close_data = IEscrowClose::closeCall::new((
                channel_id_b256,
                cumulative_amount,
                Bytes::from(sig_bytes.clone()),
            ))
            .abi_encode();

            let nonce = self
                .provider
                .get_transaction_count(signer.address())
                .await
                .map_err(|e| {
                    VerificationError::network_error(format!("failed to get nonce: {}", e))
                })?;
            let gas_price = self.provider.get_gas_price().await.map_err(|e| {
                VerificationError::network_error(format!("failed to get gas price: {}", e))
            })?;

            let mut calls = vec![Call {
                to: alloy::primitives::TxKind::Call(escrow),
                value: alloy::primitives::U256::ZERO,
                input: Bytes::from(close_data),
            }];
            if details.machine_token_enabled == Some(true) {
                let descriptor = descriptor.ok_or_else(|| {
                    VerificationError::invalid_payload(
                        "machine-token close credential is missing its channel descriptor",
                    )
                })?;
                let route = settlement_route.ok_or_else(|| {
                    VerificationError::invalid_payload(
                        "machine-token close credential is missing its settlement route",
                    )
                })?;
                calls = machine_session_close_calls(
                    chain_id,
                    escrow,
                    descriptor,
                    route,
                    cumulative_amount,
                    on_chain.deposit,
                    on_chain.settled,
                    &sig_bytes,
                )?;
            }

            let tempo_tx = TempoTransaction {
                chain_id,
                nonce,
                gas_limit: 2_000_000,
                max_fee_per_gas: gas_price,
                max_priority_fee_per_gas: gas_price,
                calls,
                ..Default::default()
            };

            let sig_hash = tempo_tx.signature_hash();
            let signature = signer.sign_hash(&sig_hash).await.map_err(|e| {
                VerificationError::network_error(format!("failed to sign close tx: {}", e))
            })?;
            let signed_tx = tempo_tx.into_signed(signature.into());
            let tx_bytes = Bytes::from(signed_tx.encoded_2718());

            let pending = self
                .provider
                .send_raw_transaction(&tx_bytes)
                .await
                .map_err(|e| {
                    VerificationError::network_error(format!("failed to send close tx: {}", e))
                })?;
            let receipt = pending
                .get_receipt()
                .await
                .map_err(|e| VerificationError::network_error(format!("close tx failed: {}", e)))?;
            if !receipt.status() {
                return Err(VerificationError::transaction_failed(format!(
                    "close transaction reverted (tx: {})",
                    receipt.transaction_hash()
                )));
            }

            Ok(receipt.transaction_hash().to_string())
        }
        .await;

        let close_tx_hash = match close_tx_result {
            Ok(hash) => hash,
            Err(err) => {
                let _ = self
                    .store
                    .update_channel(
                        channel_id_str,
                        Box::new(|current| Ok(current.map(ChannelState::clear_pending_close))),
                    )
                    .await;
                return Err(err);
            }
        };

        // Finalize in store.
        let finalized = self
            .store
            .update_channel(
                channel_id_str,
                Box::new(move |current| {
                    Ok(current.map(|state| {
                        state.finalize_close(cumulative_amount, sig_bytes, on_chain.deposit)
                    }))
                }),
            )
            .await?;

        Ok(session_receipt(
            &credential.challenge.id,
            finalized.as_ref().unwrap_or(&channel),
            Some(close_tx_hash),
        ))
    }
}
