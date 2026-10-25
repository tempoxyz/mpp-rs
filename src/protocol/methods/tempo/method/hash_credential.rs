//! Hash credentials (push mode): the client broadcast the transaction itself.

use alloy::network::ReceiptResponse;
use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use tempo_alloy::primitives::transaction::Call;
use tempo_alloy::TempoNetwork;

use crate::protocol::core::{ChallengeEcho, Receipt};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::traits::VerificationError;

use super::super::{proof, TempoChargeExt, METHOD_NAME};
use super::memo::assert_challenge_bound_memos;
use super::receipt_logs::{match_receipt_transfers, ReceiptSenderPolicy};
use super::transaction_credential::funding_currency;
use super::ChargeMethod;

/// Parse a hash credential `source`: `Ok(None)` if absent, `Ok(Some(address))`
/// for a `did:pkh:eip155` DID matching `expected_chain_id`, else `Err`.
pub(super) fn parse_hash_credential_source(
    source: Option<&str>,
    expected_chain_id: u64,
) -> Result<Option<Address>, VerificationError> {
    let Some(source) = source else {
        return Ok(None);
    };

    let invalid = || VerificationError::new("Hash credential source is invalid.");

    let parsed = proof::parse_proof_source(source).map_err(|_| invalid())?;
    if parsed.chain_id != expected_chain_id {
        return Err(invalid());
    }

    Ok(Some(parsed.address))
}

fn request_settlement_senders(charge: &ChargeRequest, chain_id: u64) -> Vec<Address> {
    if charge.machine_token_enabled() {
        super::super::machine_token::settlement_sender(chain_id)
            .into_iter()
            .collect()
    } else {
        Vec::new()
    }
}

impl<P> ChargeMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    pub(super) async fn verify_hash(
        &self,
        tx_hash: &str,
        charge: &ChargeRequest,
        source: Option<&str>,
        expected_chain_id: u64,
        challenge: &ChallengeEcho,
        reserve: bool,
    ) -> Result<(Receipt, Option<Address>), VerificationError> {
        // Validate the source before reserving the hash.
        let source_address = parse_hash_credential_source(source, expected_chain_id)?;

        let hash = tx_hash
            .parse::<B256>()
            .map_err(|e| VerificationError::new(format!("Invalid transaction hash: {}", e)))?;

        let replay_key = format!("mpp:charge:{:#x}", hash);

        let receipt = self
            .provider
            .get_transaction_receipt(hash)
            .await
            .map_err(|e| {
                VerificationError::network_error(format!("Failed to fetch receipt: {}", e))
            })?
            .ok_or_else(|| {
                VerificationError::pending(format!(
                    "Transaction {} not found or not yet mined",
                    tx_hash
                ))
            })?;

        if !receipt.status() {
            return Err(VerificationError::transaction_failed(format!(
                "Transaction {} reverted",
                tx_hash
            )));
        }

        let currency = charge.currency_address().map_err(|e| {
            VerificationError::new(format!("Invalid currency address in request: {}", e))
        })?;
        let expected = Self::expected_transfers(charge)?;

        // Use the source address if present, otherwise the receipt sender.
        let expected_sender = source_address.unwrap_or_else(|| receipt.from());

        // Tempo uses TIP-20 tokens exclusively (no native token transfers)
        let settlement_senders = request_settlement_senders(charge, expected_chain_id);
        let matched = match_receipt_transfers(
            receipt.logs(),
            currency,
            &expected,
            ReceiptSenderPolicy {
                expected_sender,
                source,
                validate_sender: self.validate_sender.as_deref(),
                transaction_sender: receipt.from(),
                settlement_senders: &settlement_senders,
            },
        )?;

        // The receipt is settled, so a memo that is not bound to this
        // challenge is final: answer it as a replay, not a retryable failure.
        assert_challenge_bound_memos(
            matched.iter().filter_map(|transfer| transfer.memo.as_ref()),
            &challenge.id,
            &challenge.realm,
        )
        .map_err(|error| VerificationError::credential_replayed(error.message))?;

        // The payer is the account the matched transfers debited, not the
        // submitter. Settlement-contract transfers are funded by the
        // transaction sender. Unset when the matched senders differ.
        let mut payers = matched.iter().filter_map(|transfer| {
            transfer.from.map(|from| {
                if settlement_senders.contains(&from) {
                    receipt.from()
                } else {
                    from
                }
            })
        });
        let first = payers.next();
        let payer = first.filter(|first| payers.all(|payer| payer == *first));

        // Only a final receipt is labelled; validation stays receipt-only. The
        // lookup runs before the hash is claimed, so a slow or cancelled RPC can
        // never strand a reserved payment without its receipt.
        let funding_currency = if reserve {
            self.hash_funding_currency(hash, expected_sender, charge, expected_chain_id)
                .await
        } else {
            None
        };

        if let Some(store) = &self.store {
            if reserve {
                let claimed = store
                    .put_if_absent(&replay_key, serde_json::Value::Bool(true))
                    .await
                    .map_err(|e| {
                        VerificationError::internal(format!("Failed to record tx hash: {e}"))
                    })?;
                if !claimed {
                    return Err(VerificationError::credential_replayed(
                        "Transaction hash has already been used.",
                    ));
                }
            } else if store
                .get(&replay_key)
                .await
                .map_err(|e| VerificationError::internal(format!("Failed to check tx hash: {e}")))?
                .is_some()
            {
                return Err(VerificationError::credential_replayed(
                    "Transaction hash has already been used.",
                ));
            }
        }

        let receipt = Receipt::success(METHOD_NAME, format!("{hash:#x}"));
        let receipt = match funding_currency {
            Some(token) => receipt.with_funding_currency(token.to_checksum(None)),
            None => receipt,
        };
        Ok((receipt, payer))
    }

    /// The token `sender` spent on the payment route of transaction `hash`,
    /// if it is a recognized route. Lookup failures leave the already verified
    /// payment unlabelled.
    async fn hash_funding_currency(
        &self,
        hash: B256,
        sender: Address,
        charge: &ChargeRequest,
        chain_id: u64,
    ) -> Option<Address> {
        let transaction = self
            .provider
            .get_transaction_by_hash(hash)
            .await
            .ok()
            .flatten()?;
        if transaction.inner.signer() != sender {
            return None;
        }
        let calls: Vec<Call> = transaction
            .inner
            .inner()
            .calls()
            .map(|(to, input)| Call {
                to,
                value: U256::ZERO,
                input: input.clone(),
            })
            .collect();
        funding_currency(
            &calls,
            chain_id,
            charge.currency_address().ok()?,
            &Self::expected_transfers(charge).ok()?,
            charge.machine_token_enabled(),
        )
    }
}
