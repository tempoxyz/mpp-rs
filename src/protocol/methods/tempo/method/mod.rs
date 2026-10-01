//! Tempo charge method for server-side payment verification.
//!
//! This module provides [`ChargeMethod`] which implements the [`ChargeMethod`]
//! trait for **Tempo blockchain** payments using alloy's typed Provider.
//!
//! # Tempo-Specific
//!
//! This verifier is designed specifically for the Tempo network (chain ID 42431).
//! It uses Tempo-specific constants and expects a `TempoNetwork` provider.
//! For other chains (Base, Ethereum mainnet, etc.), use separate method modules.
//!
//! # Example
//!
//! ```ignore
//! use std::sync::Arc;
//! use mpp::server::{tempo_provider, TempoChargeMethod};
//! use mpp::protocol::traits::ChargeMethod as ChargeMethodTrait;
//! use mpp::store::MemoryStore;
//!
//! let provider = tempo_provider("https://rpc.moderato.tempo.xyz");
//! // The store makes credentials single-use; `TempoChargeMethod::new` has none.
//! let method = TempoChargeMethod::new(provider).with_store(Arc::new(MemoryStore::new()));
//!
//! // In your server handler:
//! let receipt = method.verify(&credential, &request).await?;
//! assert!(receipt.is_success());
//! ```

use alloy::primitives::Address;
use alloy::providers::Provider;
use std::future::Future;
use std::sync::Arc;
use tempo_alloy::TempoNetwork;
use tokio::sync::OnceCell;

use crate::protocol::core::{PaymentCredential, PaymentPayload, Receipt};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::traits::{
    ChargeMethod as ChargeMethodTrait, ChargeValidation, VerificationError,
};
use crate::store::Store;

use super::transfers::{get_request_transfers, Transfer};
use super::{
    proof, relay::Relay, RelayConfig, TempoChargeExt, CHAIN_ID, INTENT_CHARGE, METHOD_NAME,
};

mod calls;
mod fee_payer;
mod hash_credential;
mod memo;
mod proof_credential;
mod receipt_logs;
mod simulate;
mod transaction_credential;

pub use fee_payer::{FeePayerPolicy, FeePayerPolicyOverride};
pub use receipt_logs::{SenderValidation, ValidateSenderCallback};

use transaction_credential::ensure_transaction_credential_source;

/// Reject a credential whose submission mode the challenge does not allow.
///
/// `type="hash"` is `push` mode and `type="transaction"` is `pull` mode.
/// `methodDetails.supportedModes`, when present, lists the allowed modes.
/// Proof credentials are exempt: zero-amount charges have no submission mode.
fn ensure_submission_mode_allowed(
    charge: &ChargeRequest,
    payload: &PaymentPayload,
) -> Result<(), VerificationError> {
    let (mode, kind) = if payload.is_hash() {
        ("push", "Hash")
    } else if payload.is_transaction() {
        ("pull", "Transaction")
    } else {
        return Ok(());
    };

    let supported_modes = charge
        .method_details
        .as_ref()
        .and_then(|details| details.get("supportedModes"))
        .filter(|modes| !modes.is_null());
    if let Some(supported_modes) = supported_modes {
        let supported = supported_modes
            .as_array()
            .is_some_and(|modes| modes.iter().any(|m| m.as_str() == Some(mode)));
        if !supported {
            return Err(VerificationError::new(format!(
                "{kind} credentials are not supported for this challenge."
            )));
        }
    }

    Ok(())
}

/// Tempo charge method for one-time payment verification.
///
/// This is a **Tempo-specific** payment verifier. It expects:
/// - `method="tempo"` in the credential
/// - Chain ID 42431 (Tempo Moderato) by default
/// - A provider configured for `TempoNetwork`
///
/// For other chains (Base, Ethereum), use or create separate method modules.
///
/// # Verification Flow
///
/// 1. Parse the credential payload (hash or signed transaction)
/// 2. For transaction credentials: validate call data before broadcasting
/// 3. Fetch the transaction receipt from Tempo RPC
/// 4. Verify transfer amount, recipient, and currency match
///
/// # Credential Types
///
/// - `hash`: Client already broadcast the transaction, provides tx hash
/// - `transaction`: Client provides signed transaction for server to broadcast
///
/// # Example
///
/// ```ignore
/// use std::sync::Arc;
/// use mpp::server::{tempo_provider, TempoChargeMethod};
/// use mpp::protocol::traits::ChargeMethod as ChargeMethodTrait;
/// use mpp::store::MemoryStore;
///
/// let provider = tempo_provider("https://rpc.moderato.tempo.xyz");
/// // The store makes credentials single-use; `TempoChargeMethod::new` has none.
/// let method = TempoChargeMethod::new(provider).with_store(Arc::new(MemoryStore::new()));
///
/// // Verify a payment
/// let receipt = method.verify(&credential, &request).await?;
/// if receipt.is_success() {
///     println!("Payment verified: {}", receipt.reference);
/// }
/// ```
#[derive(Clone)]
pub struct ChargeMethod<P> {
    provider: Arc<P>,
    fee_payer_signer: Option<Arc<super::DynSigner>>,
    store: Option<Arc<dyn Store>>,
    cached_chain_id: Arc<OnceCell<u64>>,
    fee_payer_policy_override: Option<FeePayerPolicyOverride>,
    validate_sender: Option<Arc<ValidateSenderCallback>>,
    fee_payer_allowed_fee_tokens: Option<Vec<Address>>,
    relay: Option<Relay>,
    fee_payer_fee_token: Option<Address>,
    fee_payer_allow_key_authorization: bool,
}

impl<P> ChargeMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    /// Create a new Tempo charge method with the given alloy Provider.
    ///
    /// The provider must be configured for `TempoNetwork`. Use
    /// [`tempo_provider`](crate::server::tempo_provider) to create one.
    ///
    /// No replay store is configured. Until [`with_store`](Self::with_store) is
    /// called, a hash or proof credential is accepted again for as long as its
    /// challenge is valid. [`Mpp::create`](crate::server::Mpp::create) configures
    /// an in-memory store by default.
    pub fn new(provider: P) -> Self {
        Self {
            provider: Arc::new(provider),
            fee_payer_signer: None,
            store: None,
            cached_chain_id: Arc::new(OnceCell::new()),
            fee_payer_policy_override: None,
            validate_sender: None,
            fee_payer_allowed_fee_tokens: None,
            relay: None,
            fee_payer_fee_token: None,
            fee_payer_allow_key_authorization: true,
        }
    }

    /// Delegate credential validation and finalization to a Tempo API relay.
    ///
    /// The relay broadcasts pull credentials and finalizes already-broadcast
    /// push credentials without submitting them again.
    pub fn with_relay(mut self, config: RelayConfig) -> crate::error::Result<Self> {
        self.relay = Some(Relay::new(config)?);
        Ok(self)
    }

    /// Set a callback invoked when a hash-credential transfer's sender differs
    /// from the expected sender; returning `true` accepts the transfer.
    pub fn with_validate_sender<F>(mut self, validate_sender: F) -> Self
    where
        F: for<'a> Fn(SenderValidation<'a>) -> bool + Send + Sync + 'static,
    {
        self.validate_sender = Some(Arc::new(validate_sender));
        self
    }

    /// Override the fee-sponsor policy applied to fee-payer envelopes.
    ///
    /// Each unset field falls back to the per-chain default. Use to raise or
    /// lower `max_gas`, `max_fee_per_gas`, `max_priority_fee_per_gas`,
    /// `max_total_fee`, or `max_validity_window_seconds` per server.
    pub fn with_fee_payer_policy_override(mut self, overrides: FeePayerPolicyOverride) -> Self {
        self.fee_payer_policy_override = Some(overrides);
        self
    }

    /// Replace the default sponsor fee-token allowlist.
    ///
    /// By default, fee-payer co-signing accepts pathUSD and the known default
    /// currency for the transaction chain ID (see
    /// [`FeePayerPolicy::default_allowed_fee_tokens`]). Use this to restrict
    /// or widen the accepted fee tokens for a server.
    pub fn with_fee_payer_allowed_fee_tokens(mut self, allowed_fee_tokens: Vec<Address>) -> Self {
        self.fee_payer_allowed_fee_tokens = Some(allowed_fee_tokens);
        self
    }

    #[cfg(test)]
    pub(crate) fn fee_payer_allowed_fee_tokens(&self) -> Option<&[Address]> {
        self.fee_payer_allowed_fee_tokens.as_deref()
    }

    /// Set the token the local fee payer uses to pay gas.
    ///
    /// When unset, the fee payer uses the first token in the fee-token
    /// allowlist it holds a nonzero balance of, falling back to the first
    /// allowed token. An explicit token must also be in the allowlist.
    pub fn with_fee_payer_fee_token(mut self, fee_token: Address) -> Self {
        self.fee_payer_fee_token = Some(fee_token);
        self
    }

    /// Set whether a sponsored transaction may install an access key.
    ///
    /// Allowed by default, matching mppx. A key authorization adds intrinsic
    /// gas the fee payer pays for; pass `false` to reject sponsored
    /// transactions that carry one.
    pub fn with_fee_payer_allow_key_authorization(mut self, allow: bool) -> Self {
        self.fee_payer_allow_key_authorization = allow;
        self
    }

    /// Configure a store for replay deduplication.
    ///
    /// When set, each verified transaction hash is recorded and subsequent
    /// attempts to replay the same hash are rejected. Zero-amount proof
    /// challenges are likewise made single-use per challenge id.
    ///
    /// The store must support atomic [`Store::put_if_absent`], else verification
    /// fails closed with `StoreError::AtomicUnsupported`.
    pub fn with_store(mut self, store: Arc<dyn Store>) -> Self {
        self.store = Some(store);
        self
    }

    /// Configure a fee payer signer for sponsoring transaction fees.
    ///
    /// When set, requests with `feePayer: true` will be accepted and
    /// broadcast. Without a fee payer signer, such requests are rejected.
    pub fn with_fee_payer<S>(mut self, signer: S) -> Self
    where
        S: alloy::signers::Signer + Send + Sync + 'static,
    {
        self.fee_payer_signer = Some(Arc::new(signer));
        self
    }

    pub(crate) fn with_fee_payer_arc(mut self, signer: Arc<super::DynSigner>) -> Self {
        self.fee_payer_signer = Some(signer);
        self
    }

    /// Get a reference to the underlying provider.
    pub fn provider(&self) -> &P {
        &self.provider
    }

    /// Compute the expected transfers from a charge request (primary + splits).
    fn expected_transfers(charge: &ChargeRequest) -> Result<Vec<Transfer>, VerificationError> {
        get_request_transfers(charge)
            .map_err(|e| VerificationError::new(format!("Invalid charge request: {e}")))
    }

    async fn validate_local(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> Result<ChargeValidation, VerificationError> {
        if credential.challenge.method.as_str() != METHOD_NAME {
            return Err(VerificationError::credential_mismatch(format!(
                "Method mismatch: expected {METHOD_NAME}, got {}",
                credential.challenge.method
            )));
        }
        if credential.challenge.intent.as_str() != INTENT_CHARGE {
            return Err(VerificationError::credential_mismatch(format!(
                "Intent mismatch: expected {INTENT_CHARGE}, got {}",
                credential.challenge.intent
            )));
        }

        let expected_chain_id = request.chain_id().unwrap_or(CHAIN_ID);
        let actual_chain_id = *self
            .cached_chain_id
            .get_or_try_init(|| async {
                self.provider.get_chain_id().await.map_err(|e| {
                    VerificationError::network_error(format!("Failed to fetch chain ID: {e}"))
                })
            })
            .await?;
        if actual_chain_id != expected_chain_id {
            return Err(VerificationError::chain_id_mismatch(format!(
                "Chain ID mismatch: expected {expected_chain_id}, got {actual_chain_id}"
            )));
        }

        let payload = credential.charge_payload().map_err(|e| {
            VerificationError::with_code(
                format!("Expected charge payload: {e}"),
                crate::protocol::traits::ErrorCode::InvalidCredential,
            )
        })?;
        let is_zero_amount = request
            .amount_u256()
            .map_err(|e| VerificationError::new(format!("Invalid amount in request: {e}")))?
            .is_zero();
        if is_zero_amount && !payload.is_proof() {
            return Err(VerificationError::new(
                "Zero-amount challenges require a proof credential.",
            ));
        }
        ensure_submission_mode_allowed(request, &payload)?;

        let mut transaction_sender = None;
        let details = if payload.is_hash() {
            self.verify_hash(
                payload.tx_hash().unwrap(),
                request,
                credential.source.as_deref(),
                expected_chain_id,
                &credential.challenge,
                false,
            )
            .await?;
            serde_json::json!({ "mode": "push" })
        } else if payload.is_proof() {
            if !is_zero_amount {
                return Err(VerificationError::new(
                    "Proof credentials are only valid for zero-amount challenges.",
                ));
            }
            let sender = self
                .validate_proof_credential(
                    credential,
                    payload.proof_signature().unwrap(),
                    expected_chain_id,
                )
                .await?;
            if let Some(store) = &self.store {
                if store
                    .get(&Self::proof_replay_key(credential))
                    .await
                    .map_err(|e| {
                        VerificationError::internal(format!("Failed to check proof: {e}"))
                    })?
                    .is_some()
                {
                    return Err(VerificationError::new(
                        "Proof credential has already been used.",
                    ));
                }
            }
            serde_json::json!({ "mode": "proof", "sender": format!("{sender:#x}") })
        } else {
            let serialized_transaction = payload.signed_tx().unwrap();
            let sender = self.validate_transaction_credential(
                serialized_transaction,
                request,
                expected_chain_id,
                &credential.challenge.id,
                &credential.challenge.realm,
            )?;
            ensure_transaction_credential_source(
                credential.source.as_deref(),
                sender,
                expected_chain_id,
            )?;
            transaction_sender = Some(sender);
            serde_json::json!({
                "mode": "pull",
                "sender": format!("{sender:#x}"),
                "serializedTransaction": serialized_transaction,
            })
        };

        let mut validation = ChargeValidation::new(credential, request, details);
        // Without a claimed source, the transaction sender is the payer.
        if validation.source.is_none() {
            validation.source =
                transaction_sender.map(|sender| proof::proof_source(sender, expected_chain_id));
        }
        Ok(validation)
    }
}

#[allow(clippy::manual_async_fn)]
impl<P> crate::protocol::traits::SessionMethod for ChargeMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    fn method(&self) -> &str {
        METHOD_NAME
    }

    fn verify_session(
        &self,
        _credential: &PaymentCredential,
        _request: &crate::protocol::intents::SessionRequest,
    ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send {
        async {
            Err(VerificationError::new(
                "Session verification not yet implemented — requires on-chain channel state lookup",
            ))
        }
    }
}

impl<P> ChargeMethodTrait for ChargeMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    fn method(&self) -> &str {
        METHOD_NAME
    }

    fn supports_validation(&self) -> bool {
        true
    }

    fn validate(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> impl Future<Output = Result<ChargeValidation, VerificationError>> + Send {
        let relay = self.relay.clone();
        let this = self.clone();
        let credential = credential.clone();
        let request = request.clone();
        async move {
            match relay {
                Some(relay) => relay.validate(&credential, &request).await,
                None => this.validate_local(&credential, &request).await,
            }
        }
    }

    fn broadcast(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send {
        let this = self.clone();
        let credential = credential.clone();
        let request = request.clone();
        async move {
            if let Some(relay) = &this.relay {
                relay.broadcast(&credential, METHOD_NAME).await
            } else {
                ChargeMethodTrait::verify(&this, &credential, &request).await
            }
        }
    }

    fn verify(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send {
        let credential = credential.clone();
        let request = request.clone();
        let provider = Arc::clone(&self.provider);
        let fee_payer_signer = self.fee_payer_signer.clone();
        let store = self.store.clone();
        let cached_chain_id = Arc::clone(&self.cached_chain_id);
        let fee_payer_policy_override = self.fee_payer_policy_override.clone();
        let validate_sender = self.validate_sender.clone();
        let fee_payer_allowed_fee_tokens = self.fee_payer_allowed_fee_tokens.clone();
        let relay = self.relay.clone();
        let fee_payer_fee_token = self.fee_payer_fee_token;
        let fee_payer_allow_key_authorization = self.fee_payer_allow_key_authorization;

        async move {
            if let Some(relay) = relay {
                relay.validate(&credential, &request).await?;
                return relay.broadcast(&credential, METHOD_NAME).await;
            }

            let this = ChargeMethod {
                provider,
                fee_payer_signer,
                store,
                cached_chain_id,
                fee_payer_policy_override,
                validate_sender,
                fee_payer_allowed_fee_tokens,
                relay: None,
                fee_payer_fee_token,
                fee_payer_allow_key_authorization,
            };

            if credential.challenge.method.as_str() != METHOD_NAME {
                return Err(VerificationError::credential_mismatch(format!(
                    "Method mismatch: expected {}, got {}",
                    METHOD_NAME, credential.challenge.method
                )));
            }
            if credential.challenge.intent.as_str() != INTENT_CHARGE {
                return Err(VerificationError::credential_mismatch(format!(
                    "Intent mismatch: expected {}, got {}",
                    INTENT_CHARGE, credential.challenge.intent
                )));
            }

            let expected_chain_id = request.chain_id().unwrap_or(CHAIN_ID);
            let actual_chain_id = *this
                .cached_chain_id
                .get_or_try_init(|| async {
                    this.provider.get_chain_id().await.map_err(|e| {
                        VerificationError::network_error(format!("Failed to fetch chain ID: {}", e))
                    })
                })
                .await?;

            if actual_chain_id != expected_chain_id {
                return Err(VerificationError::chain_id_mismatch(format!(
                    "Chain ID mismatch: expected {}, got {}",
                    expected_chain_id, actual_chain_id
                )));
            }

            let charge_payload = credential.charge_payload().map_err(|e| {
                VerificationError::with_code(
                    format!("Expected charge payload: {}", e),
                    crate::protocol::traits::ErrorCode::InvalidCredential,
                )
            })?;

            let is_zero_amount = request
                .amount_u256()
                .map_err(|e| VerificationError::new(format!("Invalid amount in request: {}", e)))?
                .is_zero();

            if is_zero_amount && !charge_payload.is_proof() {
                return Err(VerificationError::new(
                    "Zero-amount challenges require a proof credential.",
                ));
            }
            ensure_submission_mode_allowed(&request, &charge_payload)?;

            if charge_payload.is_hash() {
                // Client already broadcast the transaction, verify by hash
                this.verify_hash(
                    charge_payload.tx_hash().unwrap(),
                    &request,
                    credential.source.as_deref(),
                    expected_chain_id,
                    &credential.challenge,
                    true,
                )
                .await
            } else if charge_payload.is_proof() {
                if !is_zero_amount {
                    return Err(VerificationError::new(
                        "Proof credentials are only valid for zero-amount challenges.",
                    ));
                }

                let sig_hex = charge_payload.proof_signature().unwrap();
                this.validate_proof_credential(&credential, sig_hex, expected_chain_id)
                    .await?;
                this.reserve_proof_credential(&credential).await?;

                Ok(Receipt::success(METHOD_NAME, &credential.challenge.id))
            } else {
                // Client sent signed transaction, validate and broadcast it.
                // broadcast_transaction already does pre-broadcast dedup and
                // validates the receipt, so we do NOT call verify_hash here
                // (which would self-reject since the tx hash is already marked).
                let tx_hash = this
                    .broadcast_transaction(
                        charge_payload.signed_tx().unwrap(),
                        &request,
                        credential.source.as_deref(),
                        expected_chain_id,
                        &credential.challenge.id,
                        &credential.challenge.realm,
                    )
                    .await?;
                Ok(Receipt::success(METHOD_NAME, format!("{:#x}", tx_hash)))
            }
        }
    }
}

#[cfg(test)]
mod tests;
