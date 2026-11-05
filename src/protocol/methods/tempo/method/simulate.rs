//! Pre-broadcast simulation of fee-sponsored transactions.
//!
//! As mppx's `FeePayer.preflightSponsorship`, a sponsored transaction is
//! simulated with two `eth_call`s: first the sender's transaction without fee
//! fields, fee payer or signatures, before any sponsor signs; then the
//! co-signed transaction with its concrete fee payer, fee token and fee payer
//! signature.
//!
//! Tempo nodes (v1.18 and later) check the fee payer's fee-token balance in
//! `eth_call` too, and recover the fee payer only from `feePayerSignature`: a
//! bare `feePayer` address is ignored and the sender is billed instead. The
//! final simulation therefore carries the sponsor's signature, so it passes
//! when the sender holds none of the sponsor's fee token. The sender's own
//! signature is never sent.
//!
//! The first simulation is the gas bound: it runs at the exact gas limit the
//! sponsor broadcasts, with no fee fields, so the node charges the sender
//! nothing and checks no fee-token balance, and an under-gassed transaction
//! fails there (out of gas, or intrinsic gas too low) before any sponsor
//! signs. It keeps the transaction's nonce key, validity window, key
//! authorization and sender key hints, because the node prices intrinsic gas
//! from them: without the expiring nonce key a request is charged about
//! 250,000 more gas, as a fresh 2D nonce.

use alloy::consensus::transaction::SignerRecoverable;
use alloy::eips::Decodable2718;
use alloy::primitives::{Address, Bytes, Signature};
use alloy::providers::Provider;
use alloy::transports::{RpcError, TransportErrorKind};
use tempo_alloy::primitives::transaction::{PrimitiveSignature, TempoSignature};
use tempo_alloy::primitives::AASigned;
use tempo_alloy::rpc::TempoTransactionRequest;
use tempo_alloy::TempoNetwork;

use crate::protocol::traits::VerificationError;

use super::ChargeMethod;

/// Extra gas a local fee payer signs into its simulation-only copy of a
/// sponsored transaction, as mppx's `sponsoredSimulationGasBuffer`.
///
/// The fee payer signature binds the gas limit, and Tempo's sponsored
/// `eth_call` charges more gas than the same transaction uses when mined
/// (about 6,000 for a session top-up on v1.18.1: mined 63,645 of a 67,894
/// limit, simulated 69,645), so simulating at the signed limit would reject
/// transactions that succeed onchain. The broadcast transaction keeps its own
/// gas limit, which the sender simulation bounds. The padding is clamped to
/// the fee payer policy (`max_gas` and `max_total_fee`), so the fee payer
/// never signs a copy its policy would refuse.
///
/// A hosted fee payer's signature binds the broadcast gas limit and cannot be
/// padded. That simulation, and a local copy whose padding the policy clamped,
/// may fail only for this overhead: such a gas-limit-only failure is
/// tolerated (see [`is_gas_limit_error`]), because the sender simulation
/// already passed at the broadcast gas limit. Any other failure stays fatal.
pub(super) const SPONSORED_SIMULATION_GAS_BUFFER: u64 = 10_000;

/// A fee payer signature over a simulation-only copy of a sponsored
/// transaction whose gas limit is `gas_limit`, used in the final simulation
/// in place of the broadcast transaction's own signature and gas limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FeePayerSimulation {
    /// The simulation copy's gas limit: the broadcast gas limit plus
    /// [`SPONSORED_SIMULATION_GAS_BUFFER`], clamped to the fee payer policy.
    pub(super) gas_limit: u64,
    /// Gas the copy adds over the broadcast gas limit: less than
    /// [`SPONSORED_SIMULATION_GAS_BUFFER`] when the policy clamped it.
    pub(super) gas_buffer: u64,
    /// The fee payer's signature over the simulation copy.
    pub(super) fee_payer_signature: Signature,
}

/// A signature in JSON-RPC form (`r`, `s` and `yParity` as hex quantities),
/// as ox's `Signature.toRpc`.
pub(super) fn rpc_signature(signature: &Signature) -> serde_json::Value {
    serde_json::json!({
        "r": format!("{:#x}", signature.r()),
        "s": format!("{:#x}", signature.s()),
        "yParity": format!("{:#x}", u8::from(signature.v())),
    })
}

/// JSON-RPC error code nodes return for a reverted call.
const JSONRPC_EXECUTION_REVERTED: i64 = 3;

/// Whether a failed `eth_call` failed only for its gas limit, as mppx's
/// `isOutOfGasError`. Tempo v1.18.1 reports gas exhaustion as
/// `{"code":-32003,"message":"out of gas: gas exhausted during precompiled
/// contract execution: 40960"}` or `{"code":-32000,"message":"intrinsic gas
/// too low"}`, with no `data`.
///
/// Only the node's own JSON-RPC error counts, never a wrapper's text, and only
/// a message that starts with "out of gas" or "intrinsic gas too low" followed
/// by `:` or its end: -32003 is shared with the fee-token balance error, so
/// the code alone cannot tell them apart, and a substring match would let
/// "execution reverted: out of gas" or a wrapper around a balance error pass
/// to broadcast. A revert (code 3) or an error carrying revert data never
/// counts, since the reverting contract chooses that text.
pub(super) fn is_gas_limit_error(error: &RpcError<TransportErrorKind>) -> bool {
    let Some(payload) = error.as_error_resp() else {
        return false;
    };
    // Revert data: a `data` field other than null, `""` or `"0x"`.
    let has_revert_data = payload.data.as_ref().is_some_and(|data| {
        let data = data.get().trim();
        data != "null"
            && !matches!(
                serde_json::from_str::<String>(data).as_deref(),
                Ok("" | "0x")
            )
    });
    if payload.code == JSONRPC_EXECUTION_REVERTED || has_revert_data {
        return false;
    }
    let message = payload.message.trim().to_ascii_lowercase();
    ["out of gas", "intrinsic gas too low"]
        .iter()
        .any(|prefix| {
            message
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(':'))
        })
}

/// Bytes a keychain envelope puts before its approval: the type byte and the
/// 20-byte user address.
const KEYCHAIN_ENVELOPE_PREFIX_LEN: usize = 1 + 20;

/// The primitive signature that approves a keychain envelope, or None when
/// the approval is not primitive (a configurable account's owner quorum).
///
/// Decoded from the envelope's wire bytes (`type | user_address | approval`)
/// rather than read from `KeychainSignature::signature`, whose Rust type is
/// `PrimitiveSignature` before T14 and `AccountSignature` from T14, so this
/// builds against both tempo-primitives versions.
fn keychain_primitive_approval(signature: &TempoSignature) -> Option<PrimitiveSignature> {
    let bytes = signature.to_bytes();
    PrimitiveSignature::from_bytes(bytes.get(KEYCHAIN_ENVELOPE_PREFIX_LEN..)?).ok()
}

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
    /// A signed `0x76` transaction as an `eth_call` request from its sender,
    /// without the sender's signature or `feePayerSignature`: every other
    /// field of the transaction, with the sender signature's key type, key
    /// data and access key as `keyType`/`keyData`/`keyId` hints, so the node
    /// charges the signature verification gas and access-key limits the
    /// broadcast transaction pays. The tail call is not folded yet.
    fn simulation_request_base(
        signed: &AASigned,
        sender: Address,
    ) -> Result<TempoTransactionRequest, VerificationError> {
        let (key_id, key_type, approval) = match signed.signature() {
            TempoSignature::Keychain(keychain_sig) => {
                let key_id = keychain_sig.key_id(&signed.signature_hash()).map_err(|e| {
                    VerificationError::new(format!(
                        "Failed to recover keychain access key for simulation: {e}"
                    ))
                })?;
                (
                    Some(key_id),
                    keychain_sig.signature.signature_type(),
                    keychain_primitive_approval(signed.signature()),
                )
            }
            TempoSignature::Primitive(primitive_sig) => (
                None,
                primitive_sig.signature_type(),
                Some(primitive_sig.clone()),
            ),
            // Signatures newer tempo-primitives versions add (a configurable
            // account sender) carry no access-key hints to forward.
            #[allow(unreachable_patterns)]
            _ => {
                return Err(VerificationError::new(
                    "Unsupported sender signature for simulation",
                ))
            }
        };
        let key_data = match approval {
            Some(PrimitiveSignature::WebAuthn(webauthn)) => Some(webauthn.webauthn_data),
            _ => None,
        };

        let mut request: TempoTransactionRequest = signed.clone().into();
        request.inner.from = Some(sender);
        request.fee_payer_signature = None;
        request.key_type = Some(key_type);
        request.key_data = key_data;
        request.key_id = key_id;
        Ok(request)
    }

    /// The sender's transaction as an `eth_call` request, before any sponsor
    /// signs: the transaction at its exact (broadcast) gas limit, with its
    /// nonce key, validity window, key authorization and sender key hints,
    /// but without `feeToken`, `feePayer`, `feePayerSignature` or any fee per
    /// gas, so the node bills the sender nothing and needs no fee-token
    /// balance (mppx `simulationTransaction(tx, { feePayer: true })`). It is
    /// the sponsored transaction's gas bound: a gas limit too low for the
    /// calls fails here.
    pub(super) fn sender_simulation_request(
        signed: &AASigned,
        sender: Address,
    ) -> Result<serde_json::Value, VerificationError> {
        let mut request = Self::simulation_request_base(signed, sender)?;
        request.fee_token = None;
        request.inner.gas_price = None;
        request.inner.max_fee_per_gas = None;
        request.inner.max_priority_fee_per_gas = None;
        fold_tail_call(&mut request)?;
        request_value(&request)
    }

    /// A co-signed `0x76` transaction as an `eth_call` request: every field of
    /// the transaction with its concrete `feePayer`, `feeToken` and
    /// `feePayerSignature`, and without the sender's signature (mppx
    /// `sponsoredSimulationTransaction`). The node rejects `feePayer: true` in
    /// `eth_call`, so the sponsor is named, and it bills the fee payer it
    /// recovers from `feePayerSignature` (the sender when absent), so the
    /// sponsor's signature is sent.
    ///
    /// With `simulation`, its gas limit and fee payer signature replace the
    /// transaction's (a local fee payer's simulation-only copy); otherwise the
    /// transaction's own fee payer signature is sent (a hosted fee payer's).
    /// Key hints are sent as in [`Self::simulation_request_base`].
    pub(super) fn sponsored_simulation_request(
        final_tx_bytes: &[u8],
        fee_payer: Address,
        simulation: Option<&FeePayerSimulation>,
    ) -> Result<serde_json::Value, VerificationError> {
        let signed = AASigned::decode_2718(&mut &final_tx_bytes[..]).map_err(|e| {
            VerificationError::new(format!("Failed to decode co-signed tx for simulation: {e}"))
        })?;
        let sender = signed.recover_signer().map_err(|e| {
            VerificationError::new(format!("Failed to recover sender for simulation: {e}"))
        })?;

        let fee_payer_signature = match simulation {
            Some(simulation) => simulation.fee_payer_signature,
            None => signed.tx().fee_payer_signature.ok_or_else(|| {
                VerificationError::new(
                    "Cannot simulate a sponsored transaction without its fee payer signature",
                )
            })?,
        };

        // `feePayerSignature` is written below in RPC form rather than
        // alloy's serde form.
        let mut request = Self::simulation_request_base(&signed, sender)?;
        if let Some(simulation) = simulation {
            request.inner.gas = Some(simulation.gas_limit);
        }
        fold_tail_call(&mut request)?;

        let mut value = request_value(&request)?;
        if let Some(object) = value.as_object_mut() {
            object.insert(
                "feePayer".into(),
                serde_json::Value::String(format!("{fee_payer:#x}")),
            );
            object.insert(
                "feePayerSignature".into(),
                rpc_signature(&fee_payer_signature),
            );
        }
        Ok(value)
    }

    /// `eth_call` one simulation request and fail closed: a revert is a failed
    /// transaction, and an RPC error is a failed check, not a pass. With
    /// `tolerate_gas_limit`, a gas-limit-only failure ([`is_gas_limit_error`])
    /// passes.
    async fn simulate_call(
        &self,
        request: serde_json::Value,
        tolerate_gas_limit: bool,
    ) -> Result<(), VerificationError> {
        let result: Result<Bytes, _> = self
            .provider
            .raw_request("eth_call".into(), (request, "latest"))
            .await;
        let Err(e) = result else {
            return Ok(());
        };
        match e.as_error_resp() {
            _ if tolerate_gas_limit && is_gas_limit_error(&e) => Ok(()),
            Some(err) if err.code == JSONRPC_EXECUTION_REVERTED => {
                Err(VerificationError::transaction_failed(format!(
                    "Sponsored transaction would revert in pre-broadcast simulation: {} (code {})",
                    err.message, err.code
                )))
            }
            _ => Err(VerificationError::network_error(format!(
                "Pre-broadcast simulation failed: {e}"
            ))),
        }
    }

    /// Simulate a sponsored transaction from its sender at its broadcast gas
    /// limit, before any sponsor signs it, so a reverting or under-gassed
    /// transaction never reaches a signer or hosted fee payer. See
    /// [`Self::sender_simulation_request`].
    pub(super) async fn simulate_sender_calls(
        &self,
        signed: &AASigned,
        sender: Address,
    ) -> Result<(), VerificationError> {
        self.simulate_call(Self::sender_simulation_request(signed, sender)?, false)
            .await
    }

    /// Simulate the co-signed transaction the sponsor will pay for, right
    /// before broadcasting it, with the fee payer signature `simulation`
    /// carries (a local fee payer's) or else the transaction's own (a hosted
    /// fee payer's). See [`Self::sponsored_simulation_request`].
    ///
    /// Call it only after [`Self::simulate_sender_calls`] passed for the same
    /// transaction: when the simulation has less than
    /// [`SPONSORED_SIMULATION_GAS_BUFFER`] of headroom over the broadcast gas
    /// limit (a hosted signature, or a local copy the policy clamped), a
    /// gas-limit-only failure is the node's sponsored-call overhead, which the
    /// mined transaction does not pay, and passes. Fee-balance errors, reverts
    /// and every other failure stay fatal.
    pub(super) async fn simulate_sponsored_transaction(
        &self,
        final_tx_bytes: &[u8],
        fee_payer: Address,
        simulation: Option<&FeePayerSimulation>,
    ) -> Result<(), VerificationError> {
        let tolerate_gas_limit = simulation
            .is_none_or(|simulation| simulation.gas_buffer < SPONSORED_SIMULATION_GAS_BUFFER);
        self.simulate_call(
            Self::sponsored_simulation_request(final_tx_bytes, fee_payer, simulation)?,
            tolerate_gas_limit,
        )
        .await
    }
}
