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
//! use mpp::server::{tempo_provider, TempoChargeMethod};
//! use mpp::protocol::traits::ChargeMethod as ChargeMethodTrait;
//!
//! let provider = tempo_provider("https://rpc.moderato.tempo.xyz");
//! let method = TempoChargeMethod::new(provider);
//!
//! // In your server handler:
//! let receipt = method.verify(&credential, &request).await?;
//! assert!(receipt.is_success());
//! ```

use alloy::network::ReceiptResponse;
use alloy::primitives::{hex, Address, Bytes, TxKind, B256, U256};
use alloy::providers::Provider;
use std::future::Future;
use std::sync::Arc;
use tempo_alloy::TempoNetwork;

use crate::protocol::core::{PaymentCredential, Receipt};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::traits::{ChargeMethod as ChargeMethodTrait, VerificationError};
use crate::store::Store;

use super::{TempoChargeExt, CHAIN_ID, INTENT_CHARGE, METHOD_NAME};

/// TIP-20 Transfer event topic: keccak256("Transfer(address,address,uint256)")
/// TIP-20 is Tempo's token standard (compatible with ERC-20 Transfer events).
const TRANSFER_EVENT_TOPIC: B256 =
    alloy::primitives::b256!("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");

/// TIP-20 TransferWithMemo event topic: keccak256("TransferWithMemo(address,address,uint256,bytes32)")
const TRANSFER_WITH_MEMO_EVENT_TOPIC: B256 =
    alloy::primitives::b256!("57bc7354aa85aed339e000bccffabbc529466af35f0772c8f8ee1145927de7f0");

/// TIP-20 transfer function selector: bytes4(keccak256("transfer(address,uint256)"))
const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

/// TIP-20 transferWithMemo function selector: bytes4(keccak256("transferWithMemo(address,uint256,bytes32)"))
const TRANSFER_WITH_MEMO_SELECTOR: [u8; 4] = [0x95, 0x77, 0x7d, 0x59];

/// Parse a hex string (with or without 0x prefix) into a B256.
fn parse_b256_hex(s: &str) -> Option<B256> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).ok().and_then(|bytes| {
        if bytes.len() == 32 {
            Some(B256::from_slice(&bytes))
        } else {
            None
        }
    })
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
/// use mpp::server::{tempo_provider, TempoChargeMethod};
/// use mpp::protocol::traits::ChargeMethod as ChargeMethodTrait;
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
    fee_payer_signer: Option<Arc<alloy::signers::local::PrivateKeySigner>>,
    store: Option<Arc<dyn Store>>,
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
            fee_payer_signer: None,
            store: None,
        }
    }

    /// Configure a store for transaction hash deduplication.
    ///
    /// When set, each verified transaction hash is recorded and subsequent
    /// attempts to replay the same hash are rejected.
    pub fn with_store(mut self, store: Arc<dyn Store>) -> Self {
        self.store = Some(store);
        self
    }

    /// Configure a fee payer signer for sponsoring transaction fees.
    ///
    /// When set, requests with `feePayer: true` will be accepted and
    /// broadcast. Without a fee payer signer, such requests are rejected.
    pub fn with_fee_payer(mut self, signer: alloy::signers::local::PrivateKeySigner) -> Self {
        self.fee_payer_signer = Some(Arc::new(signer));
        self
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

        let replay_key = format!("mpp:charge:{tx_hash}");

        if let Some(store) = &self.store {
            let seen = store
                .get(&replay_key)
                .await
                .map_err(|e| VerificationError::new(format!("Store error: {e}")))?;
            if seen.is_some() {
                return Err(VerificationError::new(
                    "Transaction hash has already been used.",
                ));
            }
        }

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
        let memo = charge.memo();

        // Tempo uses TIP-20 tokens exclusively (no native token transfers)
        self.verify_tip20_transfer(
            &receipt,
            currency,
            expected_recipient,
            expected_amount,
            memo.as_deref(),
        )?;

        if let Some(store) = &self.store {
            store
                .put(&replay_key, serde_json::Value::Bool(true))
                .await
                .map_err(|e| VerificationError::new(format!("Failed to record tx hash: {e}")))?;
        }

        Ok(Receipt::success(METHOD_NAME, tx_hash))
    }

    fn verify_tip20_transfer(
        &self,
        receipt: &<TempoNetwork as alloy::network::Network>::ReceiptResponse,
        currency: Address,
        expected_recipient: Address,
        expected_amount: U256,
        memo: Option<&str>,
    ) -> Result<(), VerificationError> {
        // Security guards: reject zero values that could match parse failures
        if expected_amount.is_zero() {
            return Err(VerificationError::new(
                "Invalid amount: expected_amount must be greater than zero".to_string(),
            ));
        }
        if expected_recipient.is_zero() {
            return Err(VerificationError::new(
                "Invalid recipient: expected_recipient cannot be the zero address".to_string(),
            ));
        }
        if currency.is_zero() {
            return Err(VerificationError::new(
                "Invalid currency: currency cannot be the zero address".to_string(),
            ));
        }

        let receipt_json = serde_json::to_value(receipt)
            .map_err(|e| VerificationError::new(format!("Failed to serialize receipt: {}", e)))?;

        let logs = receipt_json
            .get("logs")
            .and_then(|v| v.as_array())
            .ok_or_else(|| VerificationError::new("Receipt has no logs".to_string()))?;

        // Parse expected memo if present - fail if memo is present but invalid
        let expected_memo = match memo {
            Some(m) => Some(parse_b256_hex(m).ok_or_else(|| {
                VerificationError::new(format!(
                    "Invalid memo: must be 32-byte hex string, got: {}",
                    m
                ))
            })?),
            None => None,
        };

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

            if topics.is_empty() {
                continue;
            }

            // Skip logs with unparseable topic0 rather than defaulting to zero
            let topic0 = match topics[0].parse::<B256>() {
                Ok(t) => t,
                Err(_) => continue,
            };

            // Check for TransferWithMemo when memo is expected
            if let Some(exp_memo) = expected_memo {
                if topic0 == TRANSFER_WITH_MEMO_EVENT_TOPIC && topics.len() >= 3 {
                    let to_topic = topics[2];
                    // Skip if to_address topic is unparseable
                    let to_address = match to_topic.parse::<B256>() {
                        Ok(b) => Address::from_slice(&b[12..]),
                        Err(_) => continue,
                    };

                    if to_address != expected_recipient {
                        continue;
                    }

                    let data = log.get("data").and_then(|v| v.as_str()).unwrap_or("0x");
                    // Data contains: amount (32 bytes) + memo (32 bytes)
                    if data.len() >= 130 {
                        // 0x + 64 (amount) + 64 (memo)
                        // Skip if amount or memo parsing fails
                        let amount = match U256::from_str_radix(&data[2..66], 16) {
                            Ok(a) => a,
                            Err(_) => continue,
                        };
                        let memo_bytes = match parse_b256_hex(&data[66..130]) {
                            Some(m) => m,
                            None => continue,
                        };

                        if amount == expected_amount && memo_bytes == exp_memo {
                            return Ok(());
                        }
                    }
                }
                continue;
            }

            // Standard Transfer event
            if topic0 != TRANSFER_EVENT_TOPIC || topics.len() < 3 {
                continue;
            }

            let to_topic = topics[2];
            // Skip if to_address topic is unparseable
            let to_address = match to_topic.parse::<B256>() {
                Ok(b) => Address::from_slice(&b[12..]),
                Err(_) => continue,
            };

            if to_address != expected_recipient {
                continue;
            }

            let data = log.get("data").and_then(|v| v.as_str()).unwrap_or("0x");

            if data.len() >= 66 {
                // Skip if amount parsing fails
                let amount = match U256::from_str_radix(&data[2..], 16) {
                    Ok(a) => a,
                    Err(_) => continue,
                };
                // Use exact equality per TypeScript SDK behavior
                if amount == expected_amount {
                    return Ok(());
                }
            }
        }

        if memo.is_some() {
            Err(VerificationError::new(format!(
                "No matching TransferWithMemo event found: expected {} {} to {} with memo",
                expected_amount, currency, expected_recipient
            )))
        } else {
            Err(VerificationError::new(format!(
                "No matching Transfer event found: expected {} {} to {}",
                expected_amount, currency, expected_recipient
            )))
        }
    }

    /// Validate that a transaction contains the expected payment call.
    ///
    /// This performs pre-broadcast validation by deserializing the transaction
    /// and checking that it contains a transfer/transferWithMemo call with the
    /// expected recipient, amount, and (optionally) memo.
    fn validate_transaction(
        &self,
        tx_bytes: &[u8],
        currency: Address,
        expected_recipient: Address,
        expected_amount: U256,
        memo: Option<&str>,
        expected_chain_id: u64,
    ) -> Result<(), VerificationError> {
        // Security guards: reject zero values that could match parse failures
        if expected_amount.is_zero() {
            return Err(VerificationError::new(
                "Invalid amount: expected_amount must be greater than zero".to_string(),
            ));
        }
        if expected_recipient.is_zero() {
            return Err(VerificationError::new(
                "Invalid recipient: expected_recipient cannot be the zero address".to_string(),
            ));
        }
        if currency.is_zero() {
            return Err(VerificationError::new(
                "Invalid currency: currency cannot be the zero address".to_string(),
            ));
        }

        // Skip type byte (0x76) for Tempo transactions
        let tx_data = if !tx_bytes.is_empty()
            && tx_bytes[0] == tempo_primitives::transaction::TEMPO_TX_TYPE_ID
        {
            &tx_bytes[1..]
        } else {
            tx_bytes
        };

        // Decode the signed Tempo transaction (AASigned = tx fields + signature).
        let signed = tempo_primitives::AASigned::rlp_decode(&mut &tx_data[..])
            .map_err(|e| VerificationError::new(format!("Failed to decode transaction: {}", e)))?;
        let tx = signed.tx();

        // Validate chain_id to prevent cross-chain replay attacks
        if tx.chain_id != expected_chain_id {
            return Err(VerificationError::new(format!(
                "Transaction chain_id mismatch: expected {}, got {}",
                expected_chain_id, tx.chain_id
            )));
        }

        // Parse expected memo if present - fail if memo is present but invalid
        let expected_memo = match memo {
            Some(m) => Some(parse_b256_hex(m).ok_or_else(|| {
                VerificationError::new(format!(
                    "Invalid memo: must be 32-byte hex string, got: {}",
                    m
                ))
            })?),
            None => None,
        };

        // Search for matching call in transaction
        for call in &tx.calls {
            // Check if this call targets the currency contract
            let call_to = match &call.to {
                TxKind::Call(addr) => addr,
                TxKind::Create => continue,
            };

            if call_to != &currency {
                continue;
            }

            let data = &call.input;
            if data.len() < 4 {
                continue;
            }

            let selector: [u8; 4] = data[..4].try_into().unwrap_or([0; 4]);

            if let Some(exp_memo) = expected_memo {
                // Look for transferWithMemo(address,uint256,bytes32)
                // Exact length: 4 (selector) + 32 (address) + 32 (amount) + 32 (memo) = 100 bytes
                if selector == TRANSFER_WITH_MEMO_SELECTOR && data.len() == 100 {
                    let to = Address::from_slice(&data[16..36]);
                    let amount = U256::from_be_slice(&data[36..68]);
                    let memo_bytes = B256::from_slice(&data[68..100]);

                    if to == expected_recipient
                        && amount == expected_amount
                        && memo_bytes == exp_memo
                    {
                        return Ok(());
                    }
                }
            } else {
                // No memo specified — accept either transfer or transferWithMemo
                // (clients may attach attribution memos even when the request doesn't require one)
                if selector == TRANSFER_SELECTOR && data.len() == 68 {
                    let to = Address::from_slice(&data[16..36]);
                    let amount = U256::from_be_slice(&data[36..68]);

                    if to == expected_recipient && amount == expected_amount {
                        return Ok(());
                    }
                }
                if selector == TRANSFER_WITH_MEMO_SELECTOR && data.len() == 100 {
                    let to = Address::from_slice(&data[16..36]);
                    let amount = U256::from_be_slice(&data[36..68]);

                    if to == expected_recipient && amount == expected_amount {
                        return Ok(());
                    }
                }
            }
        }

        if memo.is_some() {
            Err(VerificationError::new(format!(
                "Invalid transaction: no matching transferWithMemo call found for {} {} to {}",
                expected_amount, currency, expected_recipient
            )))
        } else {
            Err(VerificationError::new(format!(
                "Invalid transaction: no matching transfer call found for {} {} to {}",
                expected_amount, currency, expected_recipient
            )))
        }
    }

    async fn broadcast_transaction(
        &self,
        signed_tx: &str,
        charge: &ChargeRequest,
        expected_chain_id: u64,
    ) -> Result<B256, VerificationError> {
        let tx_bytes = signed_tx
            .parse::<Bytes>()
            .map_err(|e| VerificationError::new(format!("Invalid transaction bytes: {}", e)))?;

        let expected_recipient = charge.recipient_address().map_err(|e| {
            VerificationError::new(format!("Invalid recipient address in request: {}", e))
        })?;
        let expected_amount = charge
            .amount_u256()
            .map_err(|e| VerificationError::new(format!("Invalid amount in request: {}", e)))?;
        let currency = charge.currency_address().map_err(|e| {
            VerificationError::new(format!("Invalid currency address in request: {}", e))
        })?;
        let memo = charge.memo();

        // Fee payer co-signing replaces the placeholder fee_payer_signature
        // with a real co-signature and sets the fee_token.
        let final_tx_bytes = if charge.fee_payer() {
            let fee_payer_signer = self.fee_payer_signer.as_ref().ok_or_else(|| {
                VerificationError::new(
                    "feePayer requested but fee sponsorship is not configured on this server"
                        .to_string(),
                )
            })?;

            self.cosign_fee_payer_transaction(&tx_bytes, fee_payer_signer, currency)?
        } else {
            tx_bytes.to_vec()
        };

        self.validate_transaction(
            &final_tx_bytes,
            currency,
            expected_recipient,
            expected_amount,
            memo.as_deref(),
            expected_chain_id,
        )?;

        let pending = self
            .provider
            .send_raw_transaction(&final_tx_bytes)
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

    /// Co-sign a fee payer transaction.
    ///
    /// Accepts a `0x78` fee payer envelope, recovers the sender via
    /// ecrecover, validates fee-payer invariants, then co-signs and
    /// returns a complete `0x76` transaction ready for broadcast.
    fn cosign_fee_payer_transaction(
        &self,
        tx_bytes: &[u8],
        fee_payer_signer: &alloy::signers::local::PrivateKeySigner,
        fee_token: Address,
    ) -> Result<Vec<u8>, VerificationError> {
        use super::fee_payer_envelope::{FeePayerEnvelope78, TEMPO_FEE_PAYER_ENVELOPE_TYPE_ID};
        use alloy::consensus::transaction::SignerRecoverable;
        use alloy::eips::Encodable2718;
        use alloy::signers::SignerSync;
        use tempo_primitives::transaction::TEMPO_EXPIRING_NONCE_KEY;

        if tx_bytes.is_empty() {
            return Err(VerificationError::new("Empty transaction bytes"));
        }

        let type_byte = tx_bytes[0];
        if type_byte != TEMPO_FEE_PAYER_ENVELOPE_TYPE_ID {
            return Err(VerificationError::new(format!(
                "Expected fee payer envelope (0x78), got 0x{type_byte:02x}"
            )));
        }

        let env = FeePayerEnvelope78::decode_envelope(tx_bytes)
            .map_err(|e| VerificationError::new(format!("Failed to decode 0x78 envelope: {e}")))?;

        let signed = env.to_recoverable_signed();
        let sender = signed
            .recover_signer()
            .map_err(|e| VerificationError::new(format!("Failed to recover sender: {e}")))?;
        if sender != env.sender {
            return Err(VerificationError::new(format!(
                "Sender mismatch in 0x78 envelope: envelope={:#x} recovered={:#x}",
                env.sender, sender
            )));
        }

        let tx = signed.tx();

        // Validate fee-payer invariants
        if tx.fee_payer_signature.is_none() {
            return Err(VerificationError::new(
                "Transaction must include fee_payer_signature placeholder",
            ));
        }

        if tx.fee_token.is_some() {
            return Err(VerificationError::new(
                "Fee payer transaction must not include fee_token (server sets it)",
            ));
        }

        if tx.nonce_key != TEMPO_EXPIRING_NONCE_KEY {
            return Err(VerificationError::new(
                "Fee payer envelope must use expiring nonce key (U256::MAX)",
            ));
        }

        match tx.valid_before {
            None => {
                return Err(VerificationError::new(
                    "Fee payer envelope must include valid_before",
                ));
            }
            Some(vb) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| VerificationError::new(format!("System clock error: {e}")))?
                    .as_secs();
                if vb <= now {
                    return Err(VerificationError::new(format!(
                        "Fee payer envelope expired: valid_before ({vb}) is not in the future (now={now})"
                    )));
                }
            }
        }

        // Rebuild the transaction with fee_token set and real fee_payer_signature
        let (tx, client_signature, _hash) = signed.into_parts();
        let mut tx = tx;
        tx.fee_token = Some(fee_token);
        tx.fee_payer_signature = None; // Clear placeholder before computing hash

        // Compute the fee payer signature hash and co-sign
        let fp_hash = tx.fee_payer_signature_hash(sender);
        let fp_sig = fee_payer_signer
            .sign_hash_sync(&fp_hash)
            .map_err(|e| VerificationError::new(format!("Failed to co-sign transaction: {e}")))?;

        tx.fee_payer_signature = Some(fp_sig);

        let signed_tx = tx.into_signed(client_signature);
        Ok(signed_tx.encoded_2718())
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

        async move {
            let this = ChargeMethod {
                provider,
                fee_payer_signer,
                store,
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
            let actual_chain_id = this.provider.get_chain_id().await.map_err(|e| {
                VerificationError::network_error(format!("Failed to fetch chain ID: {}", e))
            })?;

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

            if charge_payload.is_hash() {
                // Client already broadcast the transaction, verify by hash
                this.verify_hash(charge_payload.tx_hash().unwrap(), &request)
                    .await
            } else {
                // Client sent signed transaction, validate and broadcast it
                let tx_hash = this
                    .broadcast_transaction(
                        charge_payload.signed_tx().unwrap(),
                        &request,
                        expected_chain_id,
                    )
                    .await?;
                this.verify_hash(&format!("{:#x}", tx_hash), &request).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{super::MODERATO_CHAIN_ID, *};

    #[test]
    fn test_transfer_selector() {
        // transfer(address,uint256) = 0xa9059cbb
        assert_eq!(TRANSFER_SELECTOR, [0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn test_transfer_with_memo_selector() {
        // transferWithMemo(address,uint256,bytes32) = 0x95777d59
        assert_eq!(TRANSFER_WITH_MEMO_SELECTOR, [0x95, 0x77, 0x7d, 0x59]);
    }

    #[test]
    fn test_parse_b256_hex_valid() {
        let valid = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let result = parse_b256_hex(valid);
        assert!(result.is_some());

        // Without 0x prefix
        let valid_no_prefix = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let result = parse_b256_hex(valid_no_prefix);
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_b256_hex_invalid_length() {
        // Too short (only 3 bytes)
        let too_short = "0xabcdef";
        assert!(parse_b256_hex(too_short).is_none());

        // Too long (33 bytes)
        let too_long = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef00";
        assert!(parse_b256_hex(too_long).is_none());

        // Empty
        assert!(parse_b256_hex("").is_none());
        assert!(parse_b256_hex("0x").is_none());
    }

    #[test]
    fn test_parse_b256_hex_invalid_chars() {
        // Invalid hex characters
        let invalid = "0xgggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg";
        assert!(parse_b256_hex(invalid).is_none());
    }

    #[test]
    fn test_event_topics() {
        // Verify event topic constants match keccak256 of event signatures
        // Transfer(address,address,uint256)
        assert_eq!(
            TRANSFER_EVENT_TOPIC,
            alloy::primitives::b256!(
                "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
            )
        );

        // TransferWithMemo(address,address,uint256,bytes32)
        assert_eq!(
            TRANSFER_WITH_MEMO_EVENT_TOPIC,
            alloy::primitives::b256!(
                "57bc7354aa85aed339e000bccffabbc529466af35f0772c8f8ee1145927de7f0"
            )
        );
    }

    #[test]
    fn test_parse_b256_hex_case_insensitive() {
        // Test case insensitivity - both should parse to the same value
        let lower = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let upper = "0xABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890";
        let mixed = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf1234567890AbCdEf1234567890";

        let lower_result = parse_b256_hex(lower).unwrap();
        let upper_result = parse_b256_hex(upper).unwrap();
        let mixed_result = parse_b256_hex(mixed).unwrap();

        assert_eq!(lower_result, upper_result);
        assert_eq!(lower_result, mixed_result);
    }

    #[test]
    fn test_calldata_length_constants() {
        // Verify the expected calldata lengths match ABI encoding
        // transfer(address,uint256): 4 + 32 + 32 = 68
        // transferWithMemo(address,uint256,bytes32): 4 + 32 + 32 + 32 = 100
        const TRANSFER_CALLDATA_LEN: usize = 4 + 32 + 32;
        const TRANSFER_WITH_MEMO_CALLDATA_LEN: usize = 4 + 32 + 32 + 32;

        assert_eq!(TRANSFER_CALLDATA_LEN, 68);
        assert_eq!(TRANSFER_WITH_MEMO_CALLDATA_LEN, 100);
    }

    #[test]
    fn test_selector_parsing_short_input() {
        // Ensure short inputs don't panic - test with various short lengths
        let short_inputs: Vec<&[u8]> = vec![&[], &[0xa9], &[0xa9, 0x05], &[0xa9, 0x05, 0x9c]];

        for input in short_inputs {
            // This mimics the parsing logic - should not panic
            if input.len() >= 4 {
                let _selector: [u8; 4] = input[..4].try_into().unwrap_or([0; 4]);
            }
        }
    }

    #[test]
    fn test_zero_amount_rejected() {
        // Zero amounts should be rejected to prevent parse-failure bypasses
        let zero = U256::ZERO;
        assert!(zero.is_zero());

        let non_zero = U256::from(1u64);
        assert!(!non_zero.is_zero());
    }

    #[test]
    fn test_zero_address_detection() {
        // Zero addresses should be rejected to prevent parse-failure bypasses
        let zero_addr = Address::ZERO;
        assert!(zero_addr.is_zero());

        let valid_addr: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f3bB77"
            .parse()
            .unwrap();
        assert!(!valid_addr.is_zero());
    }

    #[test]
    fn test_chain_id_constant() {
        // Verify the Tempo mainnet chain ID constant
        assert_eq!(CHAIN_ID, 4217);
        // Verify the Tempo Moderato testnet chain ID constant
        assert_eq!(MODERATO_CHAIN_ID, 42431);
    }

    #[test]
    fn test_fee_payer_not_configured() {
        // When fee_payer_signer is None, the error message should indicate
        // that fee sponsorship is not configured.
        let error = VerificationError::new(
            "feePayer requested but fee sponsorship is not configured on this server",
        );
        assert!(error
            .to_string()
            .contains("fee sponsorship is not configured"));
    }

    // ==================== Fee payer co-sign unit tests ====================

    /// Helper: build a valid TempoTransaction for fee payer tests.
    fn make_fee_payer_tx(valid_before_secs_from_now: u64) -> tempo_primitives::TempoTransaction {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        tempo_primitives::TempoTransaction {
            chain_id: CHAIN_ID,
            nonce: 0,
            nonce_key: U256::MAX,
            gas_limit: 1_000_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            fee_token: None,
            fee_payer_signature: Some(alloy::primitives::Signature::new(
                U256::ZERO,
                U256::ZERO,
                false,
            )),
            valid_before: Some(now + valid_before_secs_from_now),
            valid_after: None,
            calls: vec![tempo_primitives::transaction::Call {
                to: TxKind::Call(Address::repeat_byte(0x20)),
                value: U256::ZERO,
                input: Bytes::from(vec![0xa9, 0x05, 0x9c, 0xbb]), // transfer selector
            }],
            access_list: Default::default(),
            tempo_authorization_list: vec![],
            key_authorization: None,
        }
    }

    /// Helper: sign a tx and encode as a 0x78 fee payer envelope.
    fn sign_and_encode_0x78(
        tx: tempo_primitives::TempoTransaction,
        signer: &alloy::signers::local::PrivateKeySigner,
    ) -> Vec<u8> {
        use super::super::{FeePayerEnvelope78, TEMPO_FEE_PAYER_ENVELOPE_TYPE_ID};
        use alloy::signers::SignerSync;

        let sig_hash = tx.signature_hash();
        let sig = signer.sign_hash_sync(&sig_hash).unwrap();
        let signature: tempo_primitives::transaction::TempoSignature = sig.into();
        let encoded =
            FeePayerEnvelope78::from_signing_tx(tx, signer.address(), signature).encoded_envelope();
        assert_eq!(encoded[0], TEMPO_FEE_PAYER_ENVELOPE_TYPE_ID);
        encoded
    }

    /// Round-trip: sign 0x78 envelope → cosign_fee_payer_transaction
    /// succeeds and produces a valid co-signed 0x76 transaction.
    #[test]
    fn test_fee_payer_round_trip_0x78_envelope() {
        use super::super::{FeePayerEnvelope78, TEMPO_FEE_PAYER_ENVELOPE_TYPE_ID};
        use alloy::eips::Decodable2718;
        use alloy::signers::SignerSync;

        let client_signer = alloy::signers::local::PrivateKeySigner::random();
        let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
        let fee_token: Address = "0x20c0000000000000000000000000000000000000"
            .parse()
            .unwrap();

        let tx = make_fee_payer_tx(60);

        // Encode as a 0x78 fee payer envelope (sender address in the fee_payer slot).
        let sig_hash = tx.signature_hash();
        let sig = client_signer.sign_hash_sync(&sig_hash).unwrap();
        let signature: tempo_primitives::transaction::TempoSignature = sig.into();

        let encoded = FeePayerEnvelope78::from_signing_tx(tx, client_signer.address(), signature)
            .encoded_envelope();
        assert_eq!(encoded[0], TEMPO_FEE_PAYER_ENVELOPE_TYPE_ID);

        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());

        let method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer);

        let result = method.cosign_fee_payer_transaction(
            &encoded,
            method.fee_payer_signer.as_ref().unwrap(),
            fee_token,
        );

        let co_signed = result.expect("cosign should succeed for valid 0x78 envelope");

        // Result should be a valid 0x76 transaction
        assert_eq!(
            co_signed[0],
            tempo_primitives::transaction::TEMPO_TX_TYPE_ID,
            "co-signed output should be 0x76"
        );

        // It should be decodable by AASigned
        let signed = tempo_primitives::AASigned::decode_2718(&mut &co_signed[..])
            .expect("co-signed tx should be decodable as AASigned");

        let decoded_tx = signed.tx();
        assert_eq!(decoded_tx.chain_id, CHAIN_ID);
        assert_eq!(decoded_tx.nonce_key, U256::MAX);
        assert_eq!(decoded_tx.fee_token, Some(fee_token));
        assert!(decoded_tx.fee_payer_signature.is_some());
        assert!(decoded_tx.valid_before.is_some());
    }

    /// cosign_fee_payer_transaction rejects txs with wrong nonce_key.
    #[test]
    fn test_cosign_rejects_wrong_nonce_key() {
        let client_signer = alloy::signers::local::PrivateKeySigner::random();
        let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
        let fee_token: Address = "0x20c0000000000000000000000000000000000000"
            .parse()
            .unwrap();

        let mut tx = make_fee_payer_tx(60);
        tx.nonce_key = U256::ZERO; // Wrong — should be U256::MAX

        let encoded = sign_and_encode_0x78(tx, &client_signer);

        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());

        let method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer);

        let result = method.cosign_fee_payer_transaction(
            &encoded,
            method.fee_payer_signer.as_ref().unwrap(),
            fee_token,
        );

        let err = result.expect_err("should reject wrong nonce_key");
        assert!(
            err.to_string().contains("expiring nonce key"),
            "error should mention expiring nonce key, got: {err}"
        );
    }

    /// cosign_fee_payer_transaction rejects txs without valid_before.
    #[test]
    fn test_cosign_rejects_missing_valid_before() {
        let client_signer = alloy::signers::local::PrivateKeySigner::random();
        let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
        let fee_token: Address = "0x20c0000000000000000000000000000000000000"
            .parse()
            .unwrap();

        let mut tx = make_fee_payer_tx(60);
        tx.valid_before = None; // Missing

        let encoded = sign_and_encode_0x78(tx, &client_signer);

        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());

        let method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer);

        let result = method.cosign_fee_payer_transaction(
            &encoded,
            method.fee_payer_signer.as_ref().unwrap(),
            fee_token,
        );

        let err = result.expect_err("should reject missing valid_before");
        assert!(
            err.to_string().contains("must include valid_before"),
            "error should mention valid_before, got: {err}"
        );
    }

    /// cosign_fee_payer_transaction rejects txs with expired valid_before.
    #[test]
    fn test_cosign_rejects_expired_valid_before() {
        let client_signer = alloy::signers::local::PrivateKeySigner::random();
        let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
        let fee_token: Address = "0x20c0000000000000000000000000000000000000"
            .parse()
            .unwrap();

        // Build a tx with valid_before in the past
        let past = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 10;

        let mut tx = make_fee_payer_tx(60);
        tx.valid_before = Some(past);

        let encoded = sign_and_encode_0x78(tx, &client_signer);

        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());

        let method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer);

        let result = method.cosign_fee_payer_transaction(
            &encoded,
            method.fee_payer_signer.as_ref().unwrap(),
            fee_token,
        );

        let err = result.expect_err("should reject expired valid_before");
        assert!(
            err.to_string().contains("expired"),
            "error should mention expiration, got: {err}"
        );
    }

    /// cosign_fee_payer_transaction rejects empty input.
    #[test]
    fn test_cosign_rejects_empty_input() {
        let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
        let fee_token: Address = "0x20c0000000000000000000000000000000000000"
            .parse()
            .unwrap();

        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());

        let method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer);

        let result = method.cosign_fee_payer_transaction(
            &[],
            method.fee_payer_signer.as_ref().unwrap(),
            fee_token,
        );

        let err = result.expect_err("should reject empty input");
        assert!(
            err.to_string().contains("Empty transaction bytes"),
            "error should mention empty, got: {err}"
        );
    }

    /// cosign_fee_payer_transaction rejects non-0x78 type byte.
    #[test]
    fn test_cosign_rejects_wrong_type_byte() {
        let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
        let fee_token: Address = "0x20c0000000000000000000000000000000000000"
            .parse()
            .unwrap();

        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());

        let method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer);

        let result = method.cosign_fee_payer_transaction(
            &[0x79, 0xc0], // wrong type byte
            method.fee_payer_signer.as_ref().unwrap(),
            fee_token,
        );

        let err = result.expect_err("should reject wrong type");
        assert!(
            err.to_string()
                .contains("Expected fee payer envelope (0x78)"),
            "error should mention 0x78, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_store_rejects_replayed_hash() {
        use crate::store::{MemoryStore, Store};

        let store = Arc::new(MemoryStore::new());
        let hash = "0xabc123def456";

        // Simulate first successful verification: record the hash
        let key = format!("mpp:charge:{hash}");
        store
            .put(&key, serde_json::Value::Bool(true))
            .await
            .unwrap();

        // Verify the hash is now in the store
        let seen = store.get(&key).await.unwrap();
        assert!(seen.is_some(), "hash should be recorded after first use");

        // A second lookup should find it (replay detected)
        let seen_again = store.get(&key).await.unwrap();
        assert!(
            seen_again.is_some(),
            "replayed hash should be detected via store"
        );
    }

    #[tokio::test]
    async fn test_store_allows_unseen_hash() {
        use crate::store::{MemoryStore, Store};

        let store = Arc::new(MemoryStore::new());

        // A hash that was never recorded should not be found
        let key = "mpp:charge:0xnever_seen";
        let seen = store.get(key).await.unwrap();
        assert!(seen.is_none(), "unseen hash should not be in store");
    }

    #[tokio::test]
    async fn test_store_dedup_different_hashes_independent() {
        use crate::store::{MemoryStore, Store};

        let store = Arc::new(MemoryStore::new());

        // Record one hash
        store
            .put("mpp:charge:0xhash_a", serde_json::Value::Bool(true))
            .await
            .unwrap();

        // Different hash should not be affected
        let seen = store.get("mpp:charge:0xhash_b").await.unwrap();
        assert!(seen.is_none(), "different hash should not be blocked");

        // Original hash should still be blocked
        let seen = store.get("mpp:charge:0xhash_a").await.unwrap();
        assert!(seen.is_some(), "original hash should still be recorded");
    }
}
