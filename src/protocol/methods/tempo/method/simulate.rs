//! Pre-broadcast simulation of fee-sponsored transactions.

use alloy::consensus::transaction::SignerRecoverable;
use alloy::eips::Decodable2718;
use alloy::providers::Provider;
use alloy::rpc::types::simulate::{SimBlock, SimCallResult, SimulatePayload};
use alloy::rpc::types::TransactionRequest;
use tempo_alloy::primitives::transaction::{PrimitiveSignature, TempoSignature};
use tempo_alloy::rpc::TempoTransactionRequest;
use tempo_alloy::TempoNetwork;

use crate::protocol::traits::VerificationError;

use super::ChargeMethod;

/// `tempo_simulateV1` response; we only read the per-call status.
#[derive(Debug, Clone, serde::Deserialize)]
struct TempoSimulateResponse {
    #[serde(default)]
    blocks: Vec<TempoSimulateBlock>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct TempoSimulateBlock {
    #[serde(default)]
    calls: Vec<SimCallResult>,
}

impl<P> ChargeMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    /// Decode a co-signed `0x76` tx and build the equivalent
    /// `tempo_simulateV1` request.
    pub(super) fn build_simulate_payload(
        final_tx_bytes: &[u8],
    ) -> Result<SimulatePayload<TempoTransactionRequest>, VerificationError> {
        let signed = tempo_alloy::primitives::AASigned::decode_2718(&mut &final_tx_bytes[..])
            .map_err(|e| {
                VerificationError::new(format!("Failed to decode co-signed tx for simulation: {e}"))
            })?;
        let sender = signed.recover_signer().map_err(|e| {
            VerificationError::new(format!("Failed to recover sender for simulation: {e}"))
        })?;

        // Extract auth metadata before `into()` discards the signature: the
        // node sizes signature gas from `keyType`/`keyData` (primitive
        // p256/webauthn included) and selects the keychain key via `keyId`.
        let (key_id, key_type, key_data) = {
            let (key_id, primitive_sig) =
                if let TempoSignature::Keychain(keychain_sig) = signed.signature() {
                    let key_id = keychain_sig.key_id(&signed.signature_hash()).map_err(|e| {
                        VerificationError::new(format!(
                            "Failed to recover keychain access key for simulation: {e}"
                        ))
                    })?;
                    (Some(key_id), Some(&keychain_sig.signature))
                } else if let TempoSignature::Primitive(primitive_sig) = signed.signature() {
                    (None, Some(primitive_sig))
                } else {
                    (None, None)
                };
            let (key_type, key_data) = if let Some(primitive_sig) = primitive_sig {
                let key_data = match primitive_sig {
                    PrimitiveSignature::WebAuthn(webauthn) => Some(webauthn.webauthn_data.clone()),
                    _ => None,
                };
                (Some(primitive_sig.signature_type()), key_data)
            } else {
                (None, None)
            };
            (key_id, key_type, key_data)
        };

        let mut req: TempoTransactionRequest = signed.into();
        req.inner.from = Some(sender);

        // `From<AASigned>` leaves `inner.to` unset, which the node reads as a
        // contract CREATE and rejects alongside the AA batch. The node rebuilds
        // the batch as `calls ++ [inner.to call]`, so fold the last sub-call
        // into `inner.to/value/input`: same resulting batch (order and
        // fee-payer signature preserved) with a real call target.
        let tail = req.calls.pop().ok_or_else(|| {
            VerificationError::new("Cannot simulate Tempo AA transaction with no calls")
        })?;
        req.inner.to = Some(tail.to);
        req.inner.value = Some(tail.value);
        req.inner.input = tail.input.into();

        req.key_type = key_type;
        req.key_data = key_data;
        if let Some(key_id) = key_id {
            req.key_id = Some(key_id);
        }

        Ok(SimulatePayload {
            block_state_calls: vec![SimBlock {
                block_overrides: None,
                state_overrides: None,
                calls: vec![req],
            }],
            // We only care about execution outcome, not mempool admission.
            validation: false,
            trace_transfers: false,
            return_full_transactions: false,
        })
    }

    /// Simulate a co-signed `0x76` tx and error if it would revert. Fails
    /// closed: an RPC error is treated as a failed check, not a pass. Nodes
    /// without `tempo_simulateV1` (JSON-RPC -32601) are asked to `eth_call`
    /// the transaction's calls instead.
    pub(super) async fn simulate_before_broadcast(
        &self,
        final_tx_bytes: &[u8],
    ) -> Result<(), VerificationError> {
        // Standard JSON-RPC "method not found" code.
        const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;

        let payload = Self::build_simulate_payload(final_tx_bytes)?;

        // tempo_simulateV1(payload, block?) — omit block to use the latest state.
        let response: TempoSimulateResponse = match self
            .provider
            .raw_request("tempo_simulateV1".into(), (&payload,))
            .await
        {
            Ok(response) => response,
            Err(e) => {
                if e.as_error_resp()
                    .is_some_and(|err| err.code == JSONRPC_METHOD_NOT_FOUND)
                {
                    return self.simulate_with_eth_call(payload).await;
                }
                return Err(VerificationError::network_error(format!(
                    "Pre-broadcast simulation failed: {e}"
                )));
            }
        };

        let call: &SimCallResult = response
            .blocks
            .first()
            .and_then(|block| block.calls.first())
            .ok_or_else(|| {
                VerificationError::internal("Pre-broadcast simulation returned no call results")
            })?;

        if !call.status {
            let detail = match &call.error {
                Some(err) => format!("{} (code {})", err.message, err.code),
                None if !call.return_data.is_empty() => {
                    format!(
                        "revert data {}",
                        alloy::hex::encode_prefixed(&call.return_data)
                    )
                }
                None => "no revert reason returned".to_string(),
            };
            return Err(VerificationError::transaction_failed(format!(
                "Sponsored transaction would revert in pre-broadcast simulation: {detail}"
            )));
        }

        Ok(())
    }

    /// Preserve the signed gas limit alongside the sender and calls. Without fee
    /// fields or signatures the node only checks call execution, so the
    /// sender does not need to hold a fee token (mppx simulates the same way).
    pub(super) fn sender_call_request(request: TempoTransactionRequest) -> TempoTransactionRequest {
        TempoTransactionRequest {
            inner: TransactionRequest {
                from: request.inner.from,
                to: request.inner.to,
                value: request.inner.value,
                input: request.inner.input,
                gas: request.inner.gas,
                ..Default::default()
            },
            calls: request.calls,
            ..Default::default()
        }
    }

    /// `eth_call` fallback for [`Self::simulate_before_broadcast`].
    async fn simulate_with_eth_call(
        &self,
        payload: SimulatePayload<TempoTransactionRequest>,
    ) -> Result<(), VerificationError> {
        // JSON-RPC error code nodes return for a reverted call.
        const JSONRPC_EXECUTION_REVERTED: i64 = 3;

        let requests = payload
            .block_state_calls
            .into_iter()
            .flat_map(|block| block.calls);
        for request in requests {
            if let Err(e) = self.provider.call(Self::sender_call_request(request)).await {
                return Err(match e.as_error_resp() {
                    Some(err) if err.code == JSONRPC_EXECUTION_REVERTED => {
                        VerificationError::transaction_failed(format!(
                            "Sponsored transaction would revert in pre-broadcast simulation: {} (code {})",
                            err.message, err.code
                        ))
                    }
                    _ => VerificationError::network_error(format!(
                        "Pre-broadcast simulation failed: {e}"
                    )),
                });
            }
        }

        Ok(())
    }
}
