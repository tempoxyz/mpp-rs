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
//! use mpay::server::{tempo_provider, TempoChargeMethod};
//! use mpay::protocol::traits::ChargeMethod as ChargeMethodTrait;
//!
//! let provider = tempo_provider("https://rpc.moderato.tempo.xyz");
//! let method = TempoChargeMethod::new(provider);
//!
//! // In your server handler:
//! let receipt = method.verify(&credential, &request).await?;
//! assert!(receipt.is_success());
//! ```

use alloy::consensus::Transaction;
use alloy::network::ReceiptResponse;
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::Provider;
use std::future::Future;
use std::sync::Arc;
use tempo_alloy::TempoNetwork;

use crate::protocol::core::{PaymentCredential, Receipt};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::traits::{ChargeMethod as ChargeMethodTrait, VerificationError};

use super::{parse_iso8601_timestamp, TempoChargeExt, CHAIN_ID, METHOD_NAME};

/// TIP-20/ERC-20 Transfer event topic: keccak256("Transfer(address,address,uint256)")
/// TIP-20 extends ERC-20, so it uses the same Transfer event signature.
const TRANSFER_EVENT_TOPIC: B256 =
    alloy::primitives::b256!("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");

const INTENT_CHARGE: &str = "charge";

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
/// 2. Fetch the transaction receipt from Tempo RPC
/// 3. Verify transfer amount, recipient, and currency match
///
/// # Credential Types
///
/// - `hash`: Client already broadcast the transaction, provides tx hash
/// - `transaction`: Client provides signed transaction for server to broadcast
///
/// # Example
///
/// ```ignore
/// use mpay::server::{tempo_provider, TempoChargeMethod};
/// use mpay::protocol::traits::ChargeMethod as ChargeMethodTrait;
///
/// let provider = tempo_provider("https://rpc.moderato.tempo.xyz");
/// let method = TempoChargeMethod::new(provider);
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
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    /// Create a new Tempo charge method with the given alloy Provider.
    ///
    /// The provider must be configured for `TempoNetwork`. Use
    /// [`tempo_provider`](crate::server::tempo_provider) to create one.
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

        let expected_recipient = charge.recipient_address().map_err(|e| {
            VerificationError::new(format!("Invalid recipient address in request: {}", e))
        })?;
        let expected_amount = charge
            .amount_u256()
            .map_err(|e| VerificationError::new(format!("Invalid amount in request: {}", e)))?;
        let currency = charge.currency_address().map_err(|e| {
            VerificationError::new(format!("Invalid currency address in request: {}", e))
        })?;

        let is_native = currency == Address::ZERO;

        if is_native {
            let tx = self
                .provider
                .get_transaction_by_hash(hash)
                .await
                .map_err(|e| {
                    VerificationError::network_error(format!("Failed to fetch transaction: {}", e))
                })?
                .ok_or_else(|| {
                    VerificationError::new(format!("Transaction {} not found", tx_hash))
                })?;

            let tx_to = tx.to().ok_or_else(|| {
                VerificationError::new("Native transfer must have a recipient".to_string())
            })?;

            if tx_to != expected_recipient {
                return Err(VerificationError::new(format!(
                    "Recipient mismatch: expected {}, got {}",
                    expected_recipient, tx_to
                )));
            }

            if tx.value() < expected_amount {
                return Err(VerificationError::new(format!(
                    "Amount mismatch: expected at least {}, got {}",
                    expected_amount,
                    tx.value()
                )));
            }
        } else {
            self.verify_erc20_transfer(&receipt, currency, expected_recipient, expected_amount)?;
        }

        Ok(Receipt::success(METHOD_NAME, tx_hash))
    }

    fn verify_erc20_transfer(
        &self,
        receipt: &<TempoNetwork as alloy::network::Network>::ReceiptResponse,
        currency: Address,
        expected_recipient: Address,
        expected_amount: U256,
    ) -> Result<(), VerificationError> {
        let receipt_json = serde_json::to_value(receipt)
            .map_err(|e| VerificationError::new(format!("Failed to serialize receipt: {}", e)))?;

        let logs = receipt_json
            .get("logs")
            .and_then(|v| v.as_array())
            .ok_or_else(|| VerificationError::new("Receipt has no logs".to_string()))?;

        for log in logs {
            let log_address = log
                .get("address")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<Address>().ok());

            if log_address != Some(currency) {
                continue;
            }

            let topics: Vec<&str> = log
                .get("topics")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();

            if topics.len() < 3 {
                continue;
            }

            let topic0 = topics[0].parse::<B256>().unwrap_or_default();

            if topic0 != TRANSFER_EVENT_TOPIC {
                continue;
            }

            let to_topic = topics[2];
            let to_address =
                Address::from_slice(&to_topic.parse::<B256>().unwrap_or_default()[12..]);

            if to_address != expected_recipient {
                continue;
            }

            let data = log.get("data").and_then(|v| v.as_str()).unwrap_or("0x");

            if data.len() >= 66 {
                let amount = U256::from_str_radix(&data[2..], 16).unwrap_or(U256::ZERO);
                if amount >= expected_amount {
                    return Ok(());
                }
            }
        }

        Err(VerificationError::new(format!(
            "No matching Transfer event found: expected {} {} to {}",
            expected_amount, currency, expected_recipient
        )))
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

impl<P> ChargeMethodTrait for ChargeMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
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

            if credential.payload.is_hash() {
                // Client already broadcast the transaction, verify by hash
                this.verify_hash(credential.payload.signature(), &request).await
            } else {
                // Client sent signed transaction, we need to broadcast it
                let tx_hash = this.broadcast_transaction(credential.payload.signature()).await?;
                this.verify_hash(&format!("{:#x}", tx_hash), &request).await
            }
        }
    }
}
