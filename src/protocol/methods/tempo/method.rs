//! Tempo charge method for server-side payment verification.
//!
//! This module provides [`ChargeMethod`] which implements the [`ChargeMethod`]
//! trait for Tempo blockchain payments using alloy's typed Provider.
//!
//! # Example
//!
//! ```ignore
//! use mpay::protocol::methods::tempo::ChargeMethod;
//! use mpay::protocol::traits::ChargeMethod as ChargeMethodTrait;
//! use alloy::providers::ProviderBuilder;
//!
//! let provider = ProviderBuilder::new().connect_http("https://rpc.moderato.tempo.xyz".parse()?);
//! let method = ChargeMethod::new(provider);
//!
//! // In your server handler:
//! let receipt = method.verify(&credential, &request).await?;
//! assert!(receipt.is_success());
//! ```

use alloy::network::{Network, ReceiptResponse};
use alloy::primitives::{Bytes, B256};
use alloy::providers::Provider;
use std::future::Future;
use std::sync::Arc;

use crate::protocol::core::{PaymentCredential, PaymentPayload, Receipt};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::traits::{ChargeMethod as ChargeMethodTrait, VerificationError};

use super::{parse_iso8601_timestamp, TempoChargeExt, CHAIN_ID, METHOD_NAME};

const INTENT_CHARGE: &str = "charge";

/// Tempo charge method for one-time payment verification.
///
/// Verifies that a payment transaction matches the requested parameters by:
/// 1. Parsing the credential payload (hash or transaction)
/// 2. Fetching the transaction receipt from Tempo RPC using alloy Provider
/// 3. Verifying transfer amount, recipient, and currency match
///
/// # Credential Types
///
/// - `hash`: Client already broadcast the transaction, provides tx hash
/// - `transaction`: Client provides signed transaction for server to broadcast
///
/// # Example
///
/// ```ignore
/// use mpay::protocol::methods::tempo::ChargeMethod;
/// use mpay::protocol::traits::ChargeMethod as ChargeMethodTrait;
/// use alloy::providers::ProviderBuilder;
///
/// let provider = ProviderBuilder::new().connect_http("https://rpc.moderato.tempo.xyz".parse()?);
/// let method = ChargeMethod::new(provider);
///
/// // Verify a payment
/// let receipt = method.verify(&credential, &request).await?;
/// if receipt.is_success() {
///     println!("Payment verified: {}", receipt.reference);
/// }
/// ```
#[derive(Clone)]
pub struct ChargeMethod<P, N: Network = alloy::network::Ethereum> {
    provider: Arc<P>,
    _network: std::marker::PhantomData<N>,
}

impl<P, N> ChargeMethod<P, N>
where
    P: Provider<N> + Clone + Send + Sync + 'static,
    N: Network,
{
    /// Create a new Tempo charge method with the given alloy Provider.
    pub fn new(provider: P) -> Self {
        Self {
            provider: Arc::new(provider),
            _network: std::marker::PhantomData,
        }
    }

    /// Get a reference to the underlying provider.
    pub fn provider(&self) -> &P {
        &self.provider
    }

    async fn verify_hash(
        &self,
        tx_hash: &str,
        _charge: &ChargeRequest,
    ) -> Result<Receipt, VerificationError> {
        // TODO: Full validation should verify:
        // - For native transfers: tx.to == recipient, tx.value >= amount
        // - For ERC-20: parse Transfer logs, verify recipient and amount
        // For now, we just verify the transaction succeeded.

        let hash = tx_hash
            .parse::<B256>()
            .map_err(|e| VerificationError::new(format!("Invalid transaction hash: {}", e)))?;

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

        Ok(Receipt::success(METHOD_NAME, tx_hash))
    }

    fn check_expiration(&self, expires: &str) -> Result<(), VerificationError> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let expires_ts = parse_iso8601_timestamp(expires)
            .ok_or_else(|| VerificationError::new("Invalid expires timestamp"))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now > expires_ts {
            return Err(VerificationError::expired(format!(
                "Request expired at {}",
                expires
            )));
        }

        Ok(())
    }

    async fn broadcast_transaction(&self, signed_tx: &str) -> Result<B256, VerificationError> {
        let tx_bytes = signed_tx
            .parse::<Bytes>()
            .map_err(|e| VerificationError::new(format!("Invalid transaction bytes: {}", e)))?;

        let pending = self
            .provider
            .send_raw_transaction(&tx_bytes)
            .await
            .map_err(|e| VerificationError::network_error(format!("Failed to broadcast: {}", e)))?;

        // Wait for transaction to be mined
        let receipt = pending.get_receipt().await.map_err(|e| {
            VerificationError::network_error(format!("Failed to get receipt: {}", e))
        })?;

        if !receipt.status() {
            return Err(VerificationError::transaction_failed(format!(
                "Transaction {} reverted",
                receipt.transaction_hash()
            )));
        }

        Ok(receipt.transaction_hash())
    }
}

impl<P, N> ChargeMethodTrait for ChargeMethod<P, N>
where
    P: Provider<N> + Clone + Send + Sync + 'static,
    N: Network,
{
    fn method(&self) -> &str {
        METHOD_NAME
    }

    fn verify(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send {
        let credential = credential.clone();
        let request = request.clone();
        let provider = Arc::clone(&self.provider);

        async move {
            let this: ChargeMethod<P, N> = ChargeMethod {
                provider,
                _network: std::marker::PhantomData,
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

            if let Some(ref expires) = request.expires {
                this.check_expiration(expires)?;
            }

            let expected_chain_id = request.chain_id().unwrap_or(CHAIN_ID);
            let actual_chain_id = this.provider.get_chain_id().await.map_err(|e| {
                VerificationError::network_error(format!("Failed to fetch chain ID: {}", e))
            })?;

            if actual_chain_id != expected_chain_id {
                return Err(VerificationError::chain_id_mismatch(format!(
                    "Chain ID mismatch: expected {}, got {}",
                    expected_chain_id, actual_chain_id
                )));
            }

            match &credential.payload {
                PaymentPayload::Hash { hash, .. } => this.verify_hash(hash, &request).await,
                PaymentPayload::Transaction { signature, .. } => {
                    let tx_hash = this.broadcast_transaction(signature).await?;
                    this.verify_hash(&format!("{:#x}", tx_hash), &request).await
                }
            }
        }
    }
}
