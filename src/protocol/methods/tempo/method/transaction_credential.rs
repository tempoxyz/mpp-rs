//! Transaction credentials (pull mode): the server validates and broadcasts
//! the client's signed transaction.

use alloy::consensus::transaction::SignerRecoverable;
use alloy::eips::Decodable2718;
use alloy::network::ReceiptResponse;
use alloy::primitives::{keccak256, Address, Bytes, TxKind, B256, U256};
use alloy::providers::Provider;
use tempo_alloy::TempoNetwork;

use crate::protocol::intents::ChargeRequest;
use crate::protocol::traits::VerificationError;

use super::super::transfers::Transfer;
use super::super::{proof, TempoChargeExt};
use super::calls::{
    get_transfer_calls, validate_fee_payer_calls, TRANSFER_SELECTOR, TRANSFER_WITH_MEMO_SELECTOR,
};
use super::fee_payer::FeePayerPolicy;
use super::memo::{
    assert_challenge_bound_memo, assert_challenge_bound_memos, challenge_bound_memo_error,
    is_challenge_bound_memo,
};
use super::receipt_logs::{match_receipt_transfer_logs_with_settlement, ReceiptSenderPolicy};
use super::ChargeMethod;

/// Check a transaction credential `source` against the recovered transaction
/// sender: `Ok` if absent or a `did:pkh:eip155` DID for `expected_chain_id`
/// naming `sender`, else `Err`.
pub(super) fn ensure_transaction_credential_source(
    source: Option<&str>,
    sender: Address,
    expected_chain_id: u64,
) -> Result<(), VerificationError> {
    let Some(source) = source else {
        return Ok(());
    };

    let invalid = || VerificationError::new("Transaction credential source is invalid.");

    let parsed = proof::parse_proof_source(source).map_err(|_| invalid())?;
    if parsed.chain_id != expected_chain_id {
        return Err(invalid());
    }
    if parsed.address != sender {
        return Err(VerificationError::new(
            "Transaction credential source does not match the transaction sender.",
        ));
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct TransactionValidationOptions<'a> {
    pub(super) require_exact_calls: bool,
    pub(super) machine_token_enabled: bool,
    pub(super) challenge_binding: Option<(&'a str, &'a str)>,
}

impl<P> ChargeMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    /// Validate that a transaction contains all expected payment calls (supports splits).
    ///
    /// Uses order-insensitive matching with memo-specificity sorting.
    #[cfg(test)]
    pub(super) fn validate_transaction_transfers(
        &self,
        tx_bytes: &[u8],
        currency: Address,
        expected: &[Transfer],
        expected_chain_id: u64,
        require_exact_calls: bool,
    ) -> Result<(), VerificationError> {
        self.validate_transaction_transfers_with_machine_token(
            tx_bytes,
            currency,
            expected,
            expected_chain_id,
            TransactionValidationOptions {
                require_exact_calls,
                ..Default::default()
            },
        )
        .map(|_| ())
    }

    pub(super) fn validate_transaction_transfers_with_machine_token(
        &self,
        tx_bytes: &[u8],
        currency: Address,
        expected: &[Transfer],
        expected_chain_id: u64,
        options: TransactionValidationOptions<'_>,
    ) -> Result<Option<Address>, VerificationError> {
        let TransactionValidationOptions {
            require_exact_calls,
            machine_token_enabled,
            challenge_binding,
        } = options;

        if currency.is_zero() {
            return Err(VerificationError::new(
                "Invalid currency: currency cannot be the zero address".to_string(),
            ));
        }

        // Skip type byte (0x76) for Tempo transactions
        let tx_data = if !tx_bytes.is_empty()
            && tx_bytes[0] == tempo_alloy::primitives::transaction::TEMPO_TX_TYPE_ID
        {
            &tx_bytes[1..]
        } else {
            tx_bytes
        };

        let signed = tempo_alloy::primitives::AASigned::rlp_decode(&mut &tx_data[..])
            .map_err(|e| VerificationError::new(format!("Failed to decode transaction: {}", e)))?;
        let tx = signed.tx();

        if tx.chain_id != expected_chain_id {
            return Err(VerificationError::new(format!(
                "Transaction chain_id mismatch: expected {}, got {}",
                expected_chain_id, tx.chain_id
            )));
        }

        let policy =
            FeePayerPolicy::resolve(expected_chain_id, self.fee_payer_policy_override.as_ref());

        if require_exact_calls && tx.gas_limit > policy.max_gas {
            return Err(VerificationError::new(format!(
                "Fee-sponsored transaction gas limit {} exceeds maximum {}",
                tx.gas_limit, policy.max_gas
            )));
        }

        let machine_token_route = machine_token_enabled
            .then(|| {
                super::super::machine_token::match_route(
                    &tx.calls,
                    expected_chain_id,
                    currency,
                    expected,
                )
            })
            .flatten();

        if let Some(route) = machine_token_route {
            if let Some((challenge_id, realm)) = challenge_binding {
                let memo = route.transfer.memo.ok_or_else(challenge_bound_memo_error)?;
                if !is_challenge_bound_memo(&memo, challenge_id, realm) {
                    return Err(challenge_bound_memo_error());
                }
            }
            return Ok(Some(route.settlement_sender));
        }

        let transfer_calls = get_transfer_calls(&tx.calls)?;

        if require_exact_calls {
            validate_fee_payer_calls(&tx.calls, currency, expected)?;
        }

        // Sort expected transfers: memo-bearing first for greedy-safe matching
        let mut sorted_expected: Vec<(usize, &Transfer)> = expected.iter().enumerate().collect();
        sorted_expected.sort_by_key(|(_, t)| if t.memo.is_some() { 0 } else { 1 });

        let mut used_calls: Vec<bool> = vec![false; transfer_calls.len()];
        let mut matched_memos: Vec<[u8; 32]> = Vec::new();

        if require_exact_calls && transfer_calls.len() != expected.len() {
            return Err(VerificationError::new(format!(
                "Invalid transaction: no matching payment call found (expected {} transfer calls, got {})",
                expected.len(),
                transfer_calls.len()
            )));
        }

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

            let mut found = false;

            for (call_idx, call) in transfer_calls.iter().enumerate() {
                if used_calls[call_idx] {
                    continue;
                }

                let call_to = match &call.to {
                    TxKind::Call(addr) => addr,
                    TxKind::Create => continue,
                };
                if call_to != &currency {
                    continue;
                }

                let data = &call.input;
                if data.len() < 4 {
                    continue;
                }

                let selector: [u8; 4] = data[..4].try_into().unwrap_or([0; 4]);

                if let Some(exp_memo) = &transfer.memo {
                    if selector == TRANSFER_WITH_MEMO_SELECTOR && data.len() == 100 {
                        let to = Address::from_slice(&data[16..36]);
                        let amount = U256::from_be_slice(&data[36..68]);
                        let memo_bytes = B256::from_slice(&data[68..100]);

                        if to == transfer.recipient
                            && amount == transfer.amount
                            && memo_bytes == B256::from(*exp_memo)
                        {
                            used_calls[call_idx] = true;
                            matched_memos.push(*exp_memo);
                            found = true;
                            break;
                        }
                    }
                } else {
                    // No memo — accept transfer or transferWithMemo
                    if selector == TRANSFER_SELECTOR && data.len() == 68 {
                        let to = Address::from_slice(&data[16..36]);
                        let amount = U256::from_be_slice(&data[36..68]);

                        if to == transfer.recipient && amount == transfer.amount {
                            used_calls[call_idx] = true;
                            found = true;
                            break;
                        }
                    }
                    if !found && selector == TRANSFER_WITH_MEMO_SELECTOR && data.len() == 100 {
                        let to = Address::from_slice(&data[16..36]);
                        let amount = U256::from_be_slice(&data[36..68]);
                        let memo = B256::from_slice(&data[68..100]);

                        if to == transfer.recipient && amount == transfer.amount {
                            used_calls[call_idx] = true;
                            matched_memos.push(memo.0);
                            found = true;
                            break;
                        }
                    }
                }
            }

            if !found {
                return Err(VerificationError::new(format!(
                    "Invalid transaction: no matching transfer call found for {} to {}{}",
                    transfer.amount,
                    transfer.recipient,
                    if transfer.memo.is_some() {
                        " with memo"
                    } else {
                        ""
                    }
                )));
            }
        }

        if require_exact_calls && !used_calls.iter().all(|used| *used) {
            return Err(VerificationError::new(
                "Fee-sponsored transaction contains unexpected calls".to_string(),
            ));
        }

        if let Some((challenge_id, realm)) = challenge_binding {
            assert_challenge_bound_memos(&matched_memos, challenge_id, realm)?;
        }

        Ok(None)
    }

    pub(super) fn validate_transaction_credential(
        &self,
        signed_tx: &str,
        charge: &ChargeRequest,
        expected_chain_id: u64,
        challenge_id: &str,
        realm: &str,
    ) -> Result<Address, VerificationError> {
        use alloy::eips::Encodable2718;

        let tx_bytes = signed_tx
            .parse::<Bytes>()
            .map_err(|e| VerificationError::new(format!("Invalid transaction bytes: {e}")))?;
        let currency = charge.currency_address().map_err(|e| {
            VerificationError::new(format!("Invalid currency address in request: {e}"))
        })?;
        let expected = Self::expected_transfers(charge)?;

        if charge.fee_payer() {
            if self.fee_payer_signer.is_none() {
                return Err(VerificationError::new(
                    "feePayer requested but fee sponsorship is not configured on this server",
                ));
            }
            // The sponsor fee token is chosen at co-sign time and is independent
            // of the charge currency; only a configured fee token is known here.
            let (signed, sender) =
                self.validate_fee_payer_transaction(&tx_bytes, self.fee_payer_fee_token)?;
            self.validate_transaction_transfers_with_machine_token(
                &signed.encoded_2718(),
                currency,
                &expected,
                expected_chain_id,
                TransactionValidationOptions {
                    require_exact_calls: true,
                    machine_token_enabled: charge.machine_token_enabled(),
                    challenge_binding: Some((challenge_id, realm)),
                },
            )?;
            return Ok(sender);
        }

        self.validate_transaction_transfers_with_machine_token(
            &tx_bytes,
            currency,
            &expected,
            expected_chain_id,
            TransactionValidationOptions {
                machine_token_enabled: charge.machine_token_enabled(),
                challenge_binding: Some((challenge_id, realm)),
                ..Default::default()
            },
        )?;
        let signed = tempo_alloy::primitives::AASigned::decode_2718(&mut &tx_bytes[..])
            .map_err(|e| VerificationError::new(format!("Failed to decode transaction: {e}")))?;
        signed
            .recover_signer()
            .map_err(|e| VerificationError::new(format!("Failed to recover sender: {e}")))
    }

    pub(super) async fn broadcast_transaction(
        &self,
        signed_tx: &str,
        charge: &ChargeRequest,
        source: Option<&str>,
        expected_chain_id: u64,
        challenge_id: &str,
        realm: &str,
    ) -> Result<B256, VerificationError> {
        let tx_bytes = signed_tx
            .parse::<Bytes>()
            .map_err(|e| VerificationError::new(format!("Invalid transaction bytes: {}", e)))?;

        let currency = charge.currency_address().map_err(|e| {
            VerificationError::new(format!("Invalid currency address in request: {}", e))
        })?;
        let expected = Self::expected_transfers(charge)?;

        // Reject an invalid client envelope before adding the server's sponsor
        // signature, and a source that is not the sender before broadcasting.
        // The final signed transaction is validated again below.
        if charge.fee_payer() || source.is_some() {
            let sender = self.validate_transaction_credential(
                signed_tx,
                charge,
                expected_chain_id,
                challenge_id,
                realm,
            )?;
            ensure_transaction_credential_source(source, sender, expected_chain_id)?;
        }

        // Fee payer co-signing replaces the placeholder fee_payer_signature
        // with a real co-signature and sets the fee_token.
        let final_tx_bytes = if charge.fee_payer() {
            let fee_payer_signer = self.fee_payer_signer.as_ref().ok_or_else(|| {
                VerificationError::new(
                    "feePayer requested but fee sponsorship is not configured on this server"
                        .to_string(),
                )
            })?;

            let fee_token = self
                .resolve_fee_payer_fee_token(expected_chain_id, fee_payer_signer.address())
                .await?;
            self.cosign_fee_payer_transaction(&tx_bytes, fee_payer_signer.as_ref(), fee_token)
                .await?
        } else {
            tx_bytes.to_vec()
        };

        let settlement_sender = self.validate_transaction_transfers_with_machine_token(
            &final_tx_bytes,
            currency,
            &expected,
            expected_chain_id,
            TransactionValidationOptions {
                require_exact_calls: charge.fee_payer(),
                machine_token_enabled: charge.machine_token_enabled(),
                challenge_binding: Some((challenge_id, realm)),
            },
        )?;

        // The sponsor pays the gas here, so simulate first and bail if the tx
        // would revert. Static validation above only checks call shape, not
        // execution. Fails closed: no simulation, no broadcast.
        if charge.fee_payer() {
            self.simulate_before_broadcast(&final_tx_bytes).await?;
        }

        // Pre-broadcast dedup of the final tx bytes. Separate namespace from
        // the post-broadcast hash dedup in verify_hash.
        if let Some(store) = &self.store {
            let tx_hash_pre = keccak256(&final_tx_bytes);
            let dedup_key = format!("mpp:charge:submission:{:#x}", tx_hash_pre);
            // Atomically reserve before broadcasting.
            let claimed = store
                .put_if_absent(&dedup_key, serde_json::Value::Bool(true))
                .await
                .map_err(|e| VerificationError::internal(format!("Failed to record tx: {e}")))?;
            if !claimed {
                return Err(VerificationError::new(
                    "Transaction has already been submitted.",
                ));
            }
        }

        // Use eth_sendRawTransactionSync (EIP-7966) for single-call broadcast +
        // receipt. The Tempo node holds the connection open until the transaction
        // is mined/pre-confirmed and returns the full receipt, avoiding the
        // client-side polling loop of send_raw_transaction + get_receipt.
        let raw_hex = alloy::hex::encode_prefixed(&final_tx_bytes);
        let receipt: <TempoNetwork as alloy::network::Network>::ReceiptResponse = self
            .provider
            .raw_request("eth_sendRawTransactionSync".into(), [raw_hex])
            .await
            .map_err(|e| VerificationError::network_error(format!("Failed to broadcast: {}", e)))?;

        if !receipt.status() {
            return Err(VerificationError::transaction_failed(format!(
                "Transaction {} reverted",
                receipt.transaction_hash()
            )));
        }

        // Verify the receipt contains the expected TIP-20 transfer(s).
        let settlement_senders = settlement_sender.into_iter().collect::<Vec<_>>();
        let matched_logs = match_receipt_transfer_logs_with_settlement(
            receipt.logs(),
            currency,
            &expected,
            ReceiptSenderPolicy {
                expected_sender: receipt.from(),
                source: None,
                validate_sender: None,
                transaction_sender: receipt.from(),
                settlement_senders: &settlement_senders,
            },
        )?;
        assert_challenge_bound_memo(&matched_logs, challenge_id, realm)?;

        // Record the on-chain tx hash for hash-based replay protection. Use the
        // atomic claim so a concurrent hash credential for the same tx cannot
        // also succeed.
        if let Some(store) = &self.store {
            let replay_key = format!("mpp:charge:{:#x}", receipt.transaction_hash());
            let claimed = store
                .put_if_absent(&replay_key, serde_json::Value::Bool(true))
                .await
                .map_err(|e| {
                    VerificationError::internal(format!("Failed to record tx hash: {e}"))
                })?;
            if !claimed {
                return Err(VerificationError::new(
                    "Transaction hash has already been used.",
                ));
            }
        }

        Ok(receipt.transaction_hash())
    }
}
