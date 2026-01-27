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
use alloy::rpc::types::Log;
use std::future::Future;
use std::sync::Arc;

use crate::evm::{parse_address, parse_amount};
use crate::protocol::core::{PaymentCredential, PaymentPayload, Receipt};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::traits::{ChargeMethod as ChargeMethodTrait, VerificationError};

use super::{parse_iso8601_timestamp, TempoChargeExt, CHAIN_ID, METHOD_NAME};

/// ERC-20 Transfer(address,address,uint256) event signature.
const TRANSFER_TOPIC: B256 =
    alloy::primitives::b256!("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");

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
        let expected_recipient = charge
            .recipient
            .as_ref()
            .ok_or_else(|| VerificationError::new("No recipient in request"))?;
        let expected_recipient = parse_address(expected_recipient)
            .map_err(|e| VerificationError::new(format!("Invalid recipient address: {}", e)))?;

        let expected_amount = parse_amount(&charge.amount)
            .map_err(|e| VerificationError::new(format!("Invalid amount: {}", e)))?;

        let expected_currency = parse_address(&charge.currency)
            .map_err(|e| VerificationError::new(format!("Invalid currency address: {}", e)))?;

        let hash = tx_hash
            .parse::<B256>()
            .map_err(|e| VerificationError::new(format!("Invalid transaction hash: {}", e)))?;

        let receipt = self
            .provider
            .get_transaction_receipt(hash)
            .await
            .map_err(|e| VerificationError::new(format!("Failed to fetch receipt: {}", e)))?
            .ok_or_else(|| {
                VerificationError::not_found(format!(
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

        let is_native = expected_currency == Address::ZERO;

        if is_native {
            let tx = self
                .provider
                .get_transaction_by_hash(hash)
                .await
                .map_err(|e| VerificationError::new(format!("Failed to fetch transaction: {}", e)))?
                .ok_or_else(|| {
                    VerificationError::not_found(format!("Transaction {} not found", tx_hash))
                })?;

            let to_addr = tx.inner.to().ok_or_else(|| {
                VerificationError::invalid_recipient(
                    "Transaction has no recipient (contract creation)",
                )
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
        } else {
            self.verify_transfer_logs(
                receipt.inner.logs(),
                expected_recipient,
                expected_amount,
                expected_currency,
            )?;
        }

        Ok(Receipt::success(METHOD_NAME, tx_hash))
    }

    fn verify_transfer_logs(
        &self,
        logs: &[Log],
        expected_recipient: Address,
        expected_amount: U256,
        expected_currency: Address,
    ) -> Result<(), VerificationError> {
        for log in logs {
            let topics = log.topics();
            if topics.is_empty() || topics[0] != TRANSFER_TOPIC {
                continue;
            }

            if log.address() != expected_currency {
                continue;
            }

            if topics.len() < 3 {
                continue;
            }

            let to_addr = Address::from_slice(&topics[2].as_slice()[12..32]);

            if to_addr != expected_recipient {
                continue;
            }

            let data = log.data().data.as_ref();
            let amount = if data.len() >= 32 {
                U256::from_be_slice(&data[..32])
            } else if data.is_empty() {
                U256::ZERO
            } else {
                let mut padded = [0u8; 32];
                padded[32 - data.len()..].copy_from_slice(data);
                U256::from_be_slice(&padded)
            };

            if amount >= expected_amount {
                return Ok(());
            }
        }

        Err(VerificationError::not_found(
            "No matching transfer found in logs",
        ))
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
            .map_err(|e| {
                VerificationError::transaction_failed(format!("Failed to broadcast: {}", e))
            })?;

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

            if let Some(ref expires) = request.expires {
                this.check_expiration(expires)?;
            }

            let expected_chain_id = request.chain_id().unwrap_or(CHAIN_ID);
            let actual_chain_id =
                this.provider.get_chain_id().await.map_err(|e| {
                    VerificationError::new(format!("Failed to fetch chain ID: {}", e))
                })?;

            if actual_chain_id != expected_chain_id {
                return Err(VerificationError::with_code(
                    format!(
                        "Chain ID mismatch: expected {}, got {}",
                        expected_chain_id, actual_chain_id
                    ),
                    super::super::super::traits::ErrorCode::NetworkError,
                ));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_topic_constant() {
        assert_eq!(
            format!("{:#x}", TRANSFER_TOPIC),
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        );
    }
}
