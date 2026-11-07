//! Zone credentials (push mode): a Zone withdrawal settled on Tempo paid the
//! recipient, as mppx's `validateZoneCredential`.

use alloy::network::ReceiptResponse;
use alloy::primitives::{B256, U256};
use alloy::providers::Provider;
use tempo_alloy::TempoNetwork;

use crate::protocol::core::{ChallengeEcho, PaymentPayload, Receipt};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::traits::{ErrorCode, VerificationError};

use super::super::{zone, TempoChargeExt, METHOD_NAME};
use super::memo::assert_challenge_bound_memos;
use super::ChargeMethod;

/// Store key that makes a Zone withdrawal single-use, keyed by portal and
/// sender tag like mppx's `mppx:charge:zone:<portal>:<senderTag>`.
fn zone_replay_key(portal: alloy::primitives::Address, sender_tag: B256) -> String {
    format!("mpp:charge:zone:{portal:#x}:{sender_tag:#x}")
}

fn parse_b256(value: Option<&str>, field: &str) -> Result<B256, VerificationError> {
    let value = value.unwrap_or_default();
    let hex = value.strip_prefix("0x").ok_or_else(|| {
        VerificationError::with_code(
            format!("Invalid Zone credential {field}."),
            ErrorCode::InvalidCredential,
        )
    })?;
    if hex.len() != 64 {
        return Err(VerificationError::with_code(
            format!("Invalid Zone credential {field}."),
            ErrorCode::InvalidCredential,
        ));
    }
    value.parse::<B256>().map_err(|_| {
        VerificationError::with_code(
            format!("Invalid Zone credential {field}."),
            ErrorCode::InvalidCredential,
        )
    })
}

/// Reject a Zone credential that claims a source, as mpp-go does: nothing
/// ties a Zone withdrawal's payer to a source DID on Tempo, so an unchecked
/// one must not reach the receipt or [`ChargeValidation`](crate::protocol::traits::ChargeValidation).
pub(super) fn ensure_zone_credential_has_no_source(
    source: Option<&str>,
) -> Result<(), VerificationError> {
    if source.is_some() {
        return Err(VerificationError::with_code(
            "Zone credentials must not carry a source.",
            ErrorCode::InvalidCredential,
        ));
    }
    Ok(())
}

fn zone_withdrawal_not_found() -> VerificationError {
    VerificationError::new("Payment verification failed: Zone withdrawal not found.")
}

impl<P> ChargeMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    /// Verify a payment that a Zone withdrawal settled on Tempo: the portal's
    /// `WithdrawalProcessed` event pays the recipient, and the withdrawal's
    /// memo in the `processWithdrawals` calldata binds it to this challenge.
    ///
    /// With `reserve`, the withdrawal's sender tag is claimed in the store so
    /// it pays for one challenge only; without it, a claimed one is rejected.
    pub(super) async fn verify_zone(
        &self,
        payload: &PaymentPayload,
        charge: &ChargeRequest,
        challenge: &ChallengeEcho,
        reserve: bool,
    ) -> Result<Receipt, VerificationError> {
        let hash = parse_b256(Some(payload.data()), "hash")?;
        let sender_tag = parse_b256(payload.zone_sender_tag(), "senderTag")?;
        let zone_id = payload
            .zone_id()
            .filter(|id| zone::is_id(u64::from(*id)))
            .ok_or_else(|| {
                VerificationError::with_code("Invalid Zone ID.", ErrorCode::InvalidCredential)
            })?;

        let details = charge
            .tempo_method_details()
            .map_err(|e| VerificationError::new(format!("Invalid charge request: {e}")))?;
        if !zone::is_accepted(details.zones.as_ref(), zone_id) {
            return Err(VerificationError::new(format!(
                "Payment verification failed: Zone is not accepted for this challenge (zoneId {zone_id})."
            )));
        }
        if details.splits.is_some() {
            return Err(VerificationError::new(
                "Payment verification failed: Zone credentials do not support split payments.",
            ));
        }

        let recipient = charge.recipient_address().map_err(|e| {
            VerificationError::new(format!("Invalid recipient address in request: {e}"))
        })?;
        let currency = charge.currency_address().map_err(|e| {
            VerificationError::new(format!("Invalid currency address in request: {e}"))
        })?;
        let amount = charge
            .amount_u256()
            .map_err(|e| VerificationError::new(format!("Invalid amount in request: {e}")))?;

        let portal = zone::portal_address(zone_id);
        let receipt = self
            .provider
            .get_transaction_receipt(hash)
            .await
            .map_err(|e| VerificationError::network_error(format!("Failed to fetch receipt: {e}")))?
            .ok_or_else(|| {
                VerificationError::pending(format!(
                    "Transaction {hash:#x} not found or not yet mined"
                ))
            })?;
        if !receipt.status() {
            return Err(VerificationError::transaction_failed(
                "Payment verification failed: settlement transaction reverted.",
            ));
        }

        let event = zone::find_processed_event(
            receipt.logs().iter().map(|log| &log.inner),
            portal,
            sender_tag,
        )
        .ok_or_else(|| {
            VerificationError::new("Payment verification failed: Zone withdrawal not settled.")
        })?;
        if !event.callbackSuccess {
            return Err(VerificationError::new(
                "Payment verification failed: Zone withdrawal bounced.",
            ));
        }

        // The event has no memo, so the calldata's withdrawal shows what was
        // paid and for which challenge.
        let transaction = self
            .provider
            .get_transaction_by_hash(hash)
            .await
            .map_err(|e| {
                VerificationError::network_error(format!("Failed to fetch transaction: {e}"))
            })?
            .ok_or_else(zone_withdrawal_not_found)?;
        let withdrawal =
            zone::find_withdrawal(transaction.inner.inner().calls(), portal, sender_tag)
                .ok_or_else(zone_withdrawal_not_found)?;
        if withdrawal.gasLimit != 0
            || withdrawal.to != recipient
            || withdrawal.token != currency
            || U256::from(withdrawal.amount) != amount
        {
            return Err(zone_withdrawal_not_found());
        }
        // The withdrawal already settled to the recipient, so another payment
        // would not help: an unbound memo is a replay, as for hash credentials.
        assert_challenge_bound_memos([&withdrawal.memo.0], &challenge.id, &challenge.realm)
            .map_err(|error| VerificationError::credential_replayed(error.message))?;

        if let Some(store) = &self.store {
            let replay_key = zone_replay_key(portal, sender_tag);
            let used = if reserve {
                !store
                    .put_if_absent(&replay_key, serde_json::Value::Bool(true))
                    .await
                    .map_err(|e| {
                        VerificationError::internal(format!(
                            "Failed to record Zone withdrawal: {e}"
                        ))
                    })?
            } else {
                store
                    .get(&replay_key)
                    .await
                    .map_err(|e| {
                        VerificationError::internal(format!("Failed to check Zone withdrawal: {e}"))
                    })?
                    .is_some()
            };
            if used {
                return Err(VerificationError::credential_replayed(
                    "Zone withdrawal has already been used.",
                ));
            }
        }

        Ok(Receipt::success(
            METHOD_NAME,
            format!("{:#x}", receipt.transaction_hash()),
        ))
    }
}
