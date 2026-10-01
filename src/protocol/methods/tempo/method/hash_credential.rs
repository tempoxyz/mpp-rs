//! Hash credentials (push mode): the client broadcast the transaction itself.

use alloy::network::ReceiptResponse;
use alloy::primitives::{Address, B256};
use alloy::providers::Provider;
use tempo_alloy::TempoNetwork;

use crate::protocol::core::{ChallengeEcho, Receipt};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::traits::VerificationError;

use super::super::{proof, TempoChargeExt, METHOD_NAME};
use super::memo::assert_challenge_bound_memo;
use super::receipt_logs::ReceiptSenderPolicy;
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
    ) -> Result<Receipt, VerificationError> {
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
        let matched_logs = self.verify_tip20_transfers(
            &receipt,
            currency,
            &expected,
            ReceiptSenderPolicy {
                expected_sender,
                source,
                validate_sender: self.validate_sender.as_deref(),
                transaction_sender: receipt.from(),
                settlement_senders: &request_settlement_senders(charge, expected_chain_id),
            },
        )?;

        assert_challenge_bound_memo(&matched_logs, &challenge.id, &challenge.realm)?;

        if let Some(store) = &self.store {
            if reserve {
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
            } else if store
                .get(&replay_key)
                .await
                .map_err(|e| VerificationError::internal(format!("Failed to check tx hash: {e}")))?
                .is_some()
            {
                return Err(VerificationError::new(
                    "Transaction hash has already been used.",
                ));
            }
        }

        Ok(Receipt::success(METHOD_NAME, format!("{hash:#x}")))
    }
}
