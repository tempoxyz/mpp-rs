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

use alloy::consensus::Transaction;
use alloy::primitives::{Address, Bytes, B256, U256};
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
pub struct ChargeMethod<P> {
    provider: Arc<P>,
}

impl<P> ChargeMethod<P>
where
    P: Provider + Clone + Send + Sync + 'static,
{
    /// Create a new Tempo charge method with the given alloy Provider.
    pub fn new(provider: P) -> Self {
        Self {
            provider: Arc::new(provider),
        }
    }

    /// Get a reference to the underlying provider.
    pub fn provider(&self) -> &P {
        &self.provider
    }

    async fn verify_hash(
        &self,
        tx_hash: &str,
        charge: &ChargeRequest,
    ) -> Result<Receipt, VerificationError> {
        let expected_recipient = charge.recipient_address().map_err(|e| {
            VerificationError::invalid_recipient(format!("Invalid recipient: {}", e))
        })?;

        let expected_amount = charge
            .amount_u256()
            .map_err(|e| VerificationError::invalid_amount(format!("Invalid amount: {}", e)))?;

        let expected_currency = charge
            .currency_address()
            .map_err(|e| VerificationError::new(format!("Invalid currency address: {}", e)))?;

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

        let tx = self
            .provider
            .get_transaction_by_hash(hash)
            .await
            .map_err(|e| {
                VerificationError::network_error(format!("Failed to fetch transaction: {}", e))
            })?
            .ok_or_else(|| {
                VerificationError::pending(format!("Transaction {} not found", tx_hash))
            })?;

        let to_addr = tx.inner.to().ok_or_else(|| {
            VerificationError::invalid_recipient("Transaction has no recipient (contract creation)")
        })?;

        if to_addr != expected_recipient {
            return Err(VerificationError::invalid_recipient(format!(
                "Recipient mismatch: expected {}, got {}",
                expected_recipient, to_addr
            )));
        }

        let value = tx.inner.value();
        if value < expected_amount {
            return Err(VerificationError::invalid_amount(format!(
                "Amount mismatch: expected {}, got {}",
                expected_amount, value
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

        Ok(*pending.tx_hash())
    }
}

impl<P> ChargeMethodTrait for ChargeMethod<P>
where
    P: Provider + Clone + Send + Sync + 'static,
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
            let this = ChargeMethod { provider };

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
