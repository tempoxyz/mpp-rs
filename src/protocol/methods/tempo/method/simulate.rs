//! Pre-broadcast simulation of fee-sponsored transactions.
//!
//! As mppx's `FeePayer.preflightSponsorship`, a sponsored transaction is
//! simulated with two `eth_call`s: first the sender's calls alone, without fee
//! fields or signatures, before any sponsor signs; then the co-signed
//! transaction with its concrete fee payer and fee token.

use alloy::consensus::transaction::SignerRecoverable;
use alloy::eips::Decodable2718;
use alloy::primitives::{Address, Bytes};
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use tempo_alloy::primitives::transaction::{PrimitiveSignature, TempoSignature};
use tempo_alloy::primitives::AASigned;
use tempo_alloy::rpc::TempoTransactionRequest;
use tempo_alloy::TempoNetwork;

use crate::protocol::traits::VerificationError;

use super::ChargeMethod;

/// Move the last call of an AA batch into `to`/`value`/`input`.
///
/// A request without `to` is read as a contract creation next to the batch.
/// The node rebuilds the batch as `calls ++ [to call]`, so this keeps the
/// batch and its order while giving the request a call target.
fn fold_tail_call(request: &mut TempoTransactionRequest) -> Result<(), VerificationError> {
    let tail = request.calls.pop().ok_or_else(|| {
        VerificationError::new("Cannot simulate Tempo AA transaction with no calls")
    })?;
    request.inner.to = Some(tail.to);
    request.inner.value = Some(tail.value);
    request.inner.input = tail.input.into();
    Ok(())
}

fn request_value(
    request: &TempoTransactionRequest,
) -> Result<serde_json::Value, VerificationError> {
    serde_json::to_value(request).map_err(|e| {
        VerificationError::internal(format!("Failed to encode simulation request: {e}"))
    })
}

impl<P> ChargeMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    /// The sender's calls as an `eth_call` request: only `from` and the calls,
    /// so the sender need not hold a fee token (mppx
    /// `simulationTransaction(tx, { feePayer: true })`).
    pub(super) fn sender_simulation_request(
        signed: &AASigned,
        sender: Address,
    ) -> Result<serde_json::Value, VerificationError> {
        let mut request = TempoTransactionRequest {
            inner: TransactionRequest {
                from: Some(sender),
                ..Default::default()
            },
            calls: signed.tx().calls.clone(),
            ..Default::default()
        };
        fold_tail_call(&mut request)?;
        request_value(&request)
    }

    /// A co-signed `0x76` transaction as an `eth_call` request: every field of
    /// the transaction with its concrete `feePayer` and `feeToken`, and
    /// neither signature (mppx `sponsoredSimulationTransaction`). The node
    /// rejects `feePayer: true` in `eth_call`, so the sponsor is named.
    ///
    /// The sender signature's key type, key data and access key are kept as
    /// `keyType`/`keyData`/`keyId` hints, so the node charges the signature
    /// verification gas and access-key limits the broadcast transaction pays.
    pub(super) fn sponsored_simulation_request(
        final_tx_bytes: &[u8],
        fee_payer: Address,
    ) -> Result<serde_json::Value, VerificationError> {
        let signed = AASigned::decode_2718(&mut &final_tx_bytes[..]).map_err(|e| {
            VerificationError::new(format!("Failed to decode co-signed tx for simulation: {e}"))
        })?;
        let sender = signed.recover_signer().map_err(|e| {
            VerificationError::new(format!("Failed to recover sender for simulation: {e}"))
        })?;

        let (key_id, primitive_sig) = match signed.signature() {
            TempoSignature::Keychain(keychain_sig) => {
                let key_id = keychain_sig.key_id(&signed.signature_hash()).map_err(|e| {
                    VerificationError::new(format!(
                        "Failed to recover keychain access key for simulation: {e}"
                    ))
                })?;
                (Some(key_id), &keychain_sig.signature)
            }
            TempoSignature::Primitive(primitive_sig) => (None, primitive_sig),
        };
        let key_type = primitive_sig.signature_type();
        let key_data = match primitive_sig {
            PrimitiveSignature::WebAuthn(webauthn) => Some(webauthn.webauthn_data.clone()),
            _ => None,
        };

        let mut request: TempoTransactionRequest = signed.into();
        request.inner.from = Some(sender);
        request.fee_payer_signature = None;
        request.key_type = Some(key_type);
        request.key_data = key_data;
        request.key_id = key_id;
        fold_tail_call(&mut request)?;

        let mut value = request_value(&request)?;
        if let Some(object) = value.as_object_mut() {
            object.insert(
                "feePayer".into(),
                serde_json::Value::String(format!("{fee_payer:#x}")),
            );
        }
        Ok(value)
    }

    /// `eth_call` one simulation request and fail closed: a revert is a failed
    /// transaction, and an RPC error is a failed check, not a pass.
    async fn simulate_call(&self, request: serde_json::Value) -> Result<(), VerificationError> {
        // JSON-RPC error code nodes return for a reverted call.
        const JSONRPC_EXECUTION_REVERTED: i64 = 3;

        let result: Result<Bytes, _> = self
            .provider
            .raw_request("eth_call".into(), (request, "latest"))
            .await;
        result.map(|_| ()).map_err(|e| match e.as_error_resp() {
            Some(err) if err.code == JSONRPC_EXECUTION_REVERTED => {
                VerificationError::transaction_failed(format!(
                    "Sponsored transaction would revert in pre-broadcast simulation: {} (code {})",
                    err.message, err.code
                ))
            }
            _ => VerificationError::network_error(format!("Pre-broadcast simulation failed: {e}")),
        })
    }

    /// Simulate a sponsored transaction's calls from its sender, before any
    /// sponsor signs it, so a reverting transaction never reaches a signer or
    /// hosted fee payer.
    pub(super) async fn simulate_sender_calls(
        &self,
        signed: &AASigned,
        sender: Address,
    ) -> Result<(), VerificationError> {
        self.simulate_call(Self::sender_simulation_request(signed, sender)?)
            .await
    }

    /// Simulate the co-signed transaction the sponsor will pay for, right
    /// before broadcasting it.
    pub(super) async fn simulate_sponsored_transaction(
        &self,
        final_tx_bytes: &[u8],
        fee_payer: Address,
    ) -> Result<(), VerificationError> {
        self.simulate_call(Self::sponsored_simulation_request(
            final_tx_bytes,
            fee_payer,
        )?)
        .await
    }
}
