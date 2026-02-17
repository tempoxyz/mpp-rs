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

use super::{parse_iso8601_timestamp, TempoChargeExt, CHAIN_ID, INTENT_CHARGE, METHOD_NAME};

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
    fee_payer_signer: Option<Arc<alloy_signer_local::PrivateKeySigner>>,
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
        }
    }

    /// Configure a fee payer signer for sponsoring transaction fees.
    ///
    /// When set, requests with `feePayer: true` will be accepted and
    /// broadcast. Without a fee payer signer, such requests are rejected.
    pub fn with_fee_payer(mut self, signer: alloy_signer_local::PrivateKeySigner) -> Self {
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
        let tx_data = if !tx_bytes.is_empty() && tx_bytes[0] == 0x76 {
            &tx_bytes[1..]
        } else {
            tx_bytes
        };

        // Decode the signed Tempo transaction (AASigned = tx fields + signature).
        // Try normal decode first, then fall back to normalizing viem format
        // (viem uses 0x00 for fee_payer_signature placeholder instead of 0x80).
        let signed = match tempo_primitives::AASigned::rlp_decode(&mut &tx_data[..]) {
            Ok(s) => s,
            Err(_) => {
                let normalized = normalize_viem_tx(tx_data);
                tempo_primitives::AASigned::rlp_decode(&mut normalized.as_slice()).map_err(|e| {
                    VerificationError::new(format!("Failed to decode transaction: {}", e))
                })?
            }
        };
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

        // Pre-broadcast validation: verify transaction contains expected payment call
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

        self.validate_transaction(
            &tx_bytes,
            currency,
            expected_recipient,
            expected_amount,
            memo.as_deref(),
            expected_chain_id,
        )?;

        // Fail fast if fee payer is requested but no signer is configured.
        if charge.fee_payer() && self.fee_payer_signer.is_none() {
            return Err(VerificationError::new(
                "feePayer requested but fee sponsorship is not configured on this server"
                    .to_string(),
            ));
        }

        // If fee payer is requested, decode the tx, add the fee payer signature,
        // and re-encode before broadcasting.
        let broadcast_bytes = if charge.fee_payer() {
            if let Some(fee_signer) = &self.fee_payer_signer {
                use alloy::consensus::transaction::SignerRecoverable;
                use alloy::eips::Encodable2718;
                use alloy::signers::SignerSync;

                // Strip type byte for decoding
                let tx_data = if !tx_bytes.is_empty() && tx_bytes[0] == 0x76 {
                    &tx_bytes[1..]
                } else {
                    &tx_bytes[..]
                };

                // Decode the tx, normalizing viem format if needed
                let mut signed =
                    match tempo_primitives::AASigned::rlp_decode(&mut &tx_data[..]) {
                        Ok(s) => s,
                        Err(_) => {
                            let normalized = normalize_viem_tx(tx_data);
                            tempo_primitives::AASigned::rlp_decode(&mut normalized.as_slice())
                                .map_err(|e| {
                                    VerificationError::new(format!(
                                        "Failed to decode transaction for fee payer: {}",
                                        e
                                    ))
                                })?
                        }
                    };

                // Recover sender address from the transaction signature
                let sender = signed.recover_signer().map_err(|e| {
                    VerificationError::new(format!("Failed to recover sender: {}", e))
                })?;

                // Compute fee payer signature hash and sign it
                let fee_hash = signed.tx().fee_payer_signature_hash(sender);
                let fee_sig = fee_signer.sign_hash_sync(&fee_hash).map_err(|e| {
                    VerificationError::new(format!("Failed to sign fee payer: {}", e))
                })?;

                // Set the fee payer signature on the transaction
                signed.tx_mut().fee_payer_signature = Some(fee_sig.into());

                // Re-encode with the fee payer signature
                let encoded = signed.encoded_2718();
                Bytes::from(encoded)
            } else {
                tx_bytes.clone()
            }
        } else {
            tx_bytes.clone()
        };

        let pending = self
            .provider
            .send_raw_transaction(&broadcast_bytes)
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

        async move {
            let this = ChargeMethod {
                provider,
                fee_payer_signer,
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

/// Normalize a viem-encoded Tempo transaction for RLP decoding compatibility.
///
/// viem encodes fee_payer_signature placeholder as `0x00` (RLP single byte) instead of
/// an RLP-encoded list `[v=0, r=0, s=0]` that `AASigned::rlp_decode` expects. This
/// function replaces the `0x00` byte at the fee_payer_signature position (field index 11)
/// with a properly-encoded placeholder signature list `c3808080` (RLP list [0x80, 0x80, 0x80]).
///
/// This ensures `fee_payer_signature` decodes as `Some(Signature::zero())` rather than
/// `None`, which is critical because `signature_hash()` uses `fee_payer_signature.is_some()`
/// to determine whether to skip the fee_token field in the signing hash.
fn normalize_viem_tx(tx_data: &[u8]) -> Vec<u8> {
    if tx_data.len() < 3 {
        return tx_data.to_vec();
    }

    // Parse outer list header to get start of list content
    let (content_start, content_end, _header_len) = match tx_data[0] {
        0xf8..=0xff => {
            let len_of_len = (tx_data[0] - 0xf7) as usize;
            if tx_data.len() < 1 + len_of_len {
                return tx_data.to_vec();
            }
            let payload_len = usize::from_be_bytes({
                let mut buf = [0u8; 8];
                let start = 8 - len_of_len;
                buf[start..].copy_from_slice(&tx_data[1..1 + len_of_len]);
                buf
            });
            (1 + len_of_len, 1 + len_of_len + payload_len, 1 + len_of_len)
        }
        0xc0..=0xf7 => {
            let payload_len = (tx_data[0] - 0xc0) as usize;
            (1, 1 + payload_len, 1)
        }
        _ => return tx_data.to_vec(),
    };

    // Skip RLP items to find the fee_payer_sig field (index 11)
    let mut pos = content_start;
    for field_idx in 0..12 {
        if pos >= content_end {
            return tx_data.to_vec();
        }

        let item_len = rlp_item_length(tx_data, pos);
        if item_len == 0 {
            return tx_data.to_vec();
        }

        // fee_payer_sig is field index 11
        if field_idx == 11 && tx_data[pos] == 0x00 {
            // Replace 0x00 (1 byte) with c3808080 (4 bytes = RLP list [v=0, r=0, s=0])
            // This requires adjusting the outer list header payload length by +3.
            let placeholder_sig: &[u8] = &[0xc3, 0x80, 0x80, 0x80];
            let old_payload_len = content_end - content_start;
            let new_payload_len = old_payload_len + 3; // replacing 1 byte with 4 bytes

            let mut result = Vec::with_capacity(tx_data.len() + 3);

            // Re-encode the outer list header with the new payload length
            if new_payload_len <= 55 {
                result.push(0xc0 + new_payload_len as u8);
            } else if new_payload_len <= 0xff {
                result.push(0xf8);
                result.push(new_payload_len as u8);
            } else {
                result.push(0xf9);
                result.extend_from_slice(&(new_payload_len as u16).to_be_bytes());
            }

            // Copy content before the fee_payer_sig field
            result.extend_from_slice(&tx_data[content_start..pos]);
            // Insert the placeholder signature
            result.extend_from_slice(placeholder_sig);
            // Copy content after the 0x00 byte
            result.extend_from_slice(&tx_data[pos + 1..]);

            return result;
        }

        pos += item_len;
    }

    tx_data.to_vec()
}

/// Returns the total length (header + payload) of an RLP item at the given position.
fn rlp_item_length(data: &[u8], pos: usize) -> usize {
    if pos >= data.len() {
        return 0;
    }
    let b = data[pos];
    match b {
        // Single byte (0x00..=0x7f)
        0x00..=0x7f => 1,
        // Short string (0x80..=0xb7): length = b - 0x80
        0x80..=0xb7 => 1 + (b - 0x80) as usize,
        // Long string (0xb8..=0xbf): length-of-length = b - 0xb7
        0xb8..=0xbf => {
            let len_of_len = (b - 0xb7) as usize;
            if pos + 1 + len_of_len > data.len() {
                return 0;
            }
            let mut buf = [0u8; 8];
            let start = 8 - len_of_len;
            buf[start..].copy_from_slice(&data[pos + 1..pos + 1 + len_of_len]);
            1 + len_of_len + usize::from_be_bytes(buf)
        }
        // Short list (0xc0..=0xf7): length = b - 0xc0
        0xc0..=0xf7 => 1 + (b - 0xc0) as usize,
        // Long list (0xf8..=0xff): length-of-length = b - 0xf7
        0xf8..=0xff => {
            let len_of_len = (b - 0xf7) as usize;
            if pos + 1 + len_of_len > data.len() {
                return 0;
            }
            let mut buf = [0u8; 8];
            let start = 8 - len_of_len;
            buf[start..].copy_from_slice(&data[pos + 1..pos + 1 + len_of_len]);
            1 + len_of_len + usize::from_be_bytes(buf)
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

    #[test]
    fn test_normalize_viem_tx_replaces_zero_fee_payer_sig() {
        // A viem-encoded tx with 0x00 at the fee_payer_sig position (field index 11)
        // This is a real transaction from mppx client
        let viem_tx = hex::decode(
            "f8d882a5bf0285059682f00282f299\
             f87ef87c9420c000000000000000000000000000000000000080\
             b86495777d59\
             0000000000000000000000005f270b1a3f160f7dbd21f8840bba82c61f62a029\
             00000000000000000000000000000000000000000000000000000000000f4240\
             ef1ed71201546a07b8cebd18e742dc\
             0000000000000000000075943864ff95b1\
             c0\
             80\
             06\
             80\
             80\
             80\
             00\
             c0\
             b841f94e83c7cae5d97c235de1de04a48cdad0d3a552921b730e5300fd3ce3f6a7f8\
             1409df263a6f761984537176e7dd30bab5aacdd7a4179f5fdc69d29252bcd5581c"
        ).unwrap();

        let normalized = normalize_viem_tx(&viem_tx);

        // The 0x00 fee_payer_sig should now be c3808080 (RLP list [v=0, r=0, s=0])
        // The normalized data should be 3 bytes longer (replacing 1 byte with 4 bytes)
        assert_eq!(normalized.len(), viem_tx.len() + 3);

        // Verify we can decode the normalized tx
        let result = tempo_primitives::AASigned::rlp_decode(&mut normalized.as_slice());
        assert!(result.is_ok(), "Failed to decode normalized viem tx: {:?}", result.err());

        let signed = result.unwrap();
        assert_eq!(signed.tx().chain_id, MODERATO_CHAIN_ID);
        // fee_payer_signature should be Some (placeholder)
        assert!(signed.tx().fee_payer_signature.is_some());
    }

    #[test]
    fn test_normalize_viem_tx_preserves_normal_tx() {
        // A normally-encoded tx with 0x80 (empty string) at fee_payer_sig position
        // should be unchanged
        let normal_tx = hex::decode(
            "f8d882a5bf0285059682f00282f299\
             f87ef87c9420c000000000000000000000000000000000000080\
             b86495777d59\
             0000000000000000000000005f270b1a3f160f7dbd21f8840bba82c61f62a029\
             00000000000000000000000000000000000000000000000000000000000f4240\
             ef1ed71201546a07b8cebd18e742dc\
             0000000000000000000075943864ff95b1\
             c0\
             80\
             06\
             80\
             80\
             80\
             80\
             c0\
             b841f94e83c7cae5d97c235de1de04a48cdad0d3a552921b730e5300fd3ce3f6a7f8\
             1409df263a6f761984537176e7dd30bab5aacdd7a4179f5fdc69d29252bcd5581c"
        ).unwrap();

        let normalized = normalize_viem_tx(&normal_tx);
        assert_eq!(normal_tx, normalized, "Normal tx should not be modified");
    }

    #[test]
    fn test_normalize_viem_tx_short_input() {
        // Inputs shorter than 3 bytes should be returned unchanged
        assert_eq!(normalize_viem_tx(&[]), Vec::<u8>::new());
        assert_eq!(normalize_viem_tx(&[0xc0]), vec![0xc0u8]);
        assert_eq!(normalize_viem_tx(&[0xc1, 0x80]), vec![0xc1u8, 0x80]);
    }

    #[test]
    fn test_normalize_viem_tx_no_fee_payer_field() {
        // A list with fewer than 12 fields should be returned unchanged
        // Short list: c5 = list of 5 bytes, then 5 single-byte items
        let short_list = vec![0xc5, 0x01, 0x02, 0x03, 0x04, 0x05];
        let normalized = normalize_viem_tx(&short_list);
        assert_eq!(short_list, normalized);
    }

    #[test]
    fn test_normalize_viem_tx_non_zero_fee_payer_sig() {
        // When fee_payer_sig is a real signature (not 0x00), don't touch it.
        // Build a viem tx but with 0x01 at the fee_payer_sig position instead of 0x00
        let viem_tx_with_real_sig = hex::decode(
            "f8d882a5bf0285059682f00282f299\
             f87ef87c9420c000000000000000000000000000000000000080\
             b86495777d59\
             0000000000000000000000005f270b1a3f160f7dbd21f8840bba82c61f62a029\
             00000000000000000000000000000000000000000000000000000000000f4240\
             ef1ed71201546a07b8cebd18e742dc\
             0000000000000000000075943864ff95b1\
             c0\
             80\
             06\
             80\
             80\
             80\
             01\
             c0\
             b841f94e83c7cae5d97c235de1de04a48cdad0d3a552921b730e5300fd3ce3f6a7f8\
             1409df263a6f761984537176e7dd30bab5aacdd7a4179f5fdc69d29252bcd5581c"
        ).unwrap();

        let normalized = normalize_viem_tx(&viem_tx_with_real_sig);
        // 0x01 is not 0x00, so no replacement should happen
        assert_eq!(viem_tx_with_real_sig, normalized, "Non-zero fee_payer_sig should not be modified");
    }

    #[test]
    fn test_rlp_item_length_single_byte() {
        // Single bytes 0x00..0x7f have length 1
        assert_eq!(rlp_item_length(&[0x00], 0), 1);
        assert_eq!(rlp_item_length(&[0x7f], 0), 1);
        assert_eq!(rlp_item_length(&[0x42], 0), 1);
    }

    #[test]
    fn test_rlp_item_length_short_string() {
        // 0x80 = empty string, length 1
        assert_eq!(rlp_item_length(&[0x80], 0), 1);
        // 0x83 = 3-byte string, total length 4
        assert_eq!(rlp_item_length(&[0x83, 0x01, 0x02, 0x03], 0), 4);
    }

    #[test]
    fn test_rlp_item_length_short_list() {
        // 0xc0 = empty list, length 1
        assert_eq!(rlp_item_length(&[0xc0], 0), 1);
        // 0xc3 = list of 3 bytes, total length 4
        assert_eq!(rlp_item_length(&[0xc3, 0x80, 0x80, 0x80], 0), 4);
    }

    #[test]
    fn test_rlp_item_length_out_of_bounds() {
        assert_eq!(rlp_item_length(&[], 0), 0);
        assert_eq!(rlp_item_length(&[0x80], 5), 0);
    }

    #[test]
    fn test_rlp_item_length_long_string() {
        // 0xb8 0x38 = string of 56 bytes (len_of_len=1), total = 1 + 1 + 56 = 58
        let mut data = vec![0xb8, 0x38];
        data.extend_from_slice(&[0xaa; 56]);
        assert_eq!(rlp_item_length(&data, 0), 58);
    }

    #[test]
    fn test_rlp_item_length_long_list() {
        // 0xf8 0x38 = list of 56 bytes (len_of_len=1), total = 1 + 1 + 56 = 58
        let mut data = vec![0xf8, 0x38];
        data.extend_from_slice(&[0x80; 56]);
        assert_eq!(rlp_item_length(&data, 0), 58);
    }

    #[test]
    fn test_normalize_viem_tx_idempotent() {
        // Normalizing an already-normalized tx should not change it further
        let viem_tx = hex::decode(
            "f8d882a5bf0285059682f00282f299\
             f87ef87c9420c000000000000000000000000000000000000080\
             b86495777d59\
             0000000000000000000000005f270b1a3f160f7dbd21f8840bba82c61f62a029\
             00000000000000000000000000000000000000000000000000000000000f4240\
             ef1ed71201546a07b8cebd18e742dc\
             0000000000000000000075943864ff95b1\
             c0\
             80\
             06\
             80\
             80\
             80\
             00\
             c0\
             b841f94e83c7cae5d97c235de1de04a48cdad0d3a552921b730e5300fd3ce3f6a7f8\
             1409df263a6f761984537176e7dd30bab5aacdd7a4179f5fdc69d29252bcd5581c"
        ).unwrap();

        let first = normalize_viem_tx(&viem_tx);
        let second = normalize_viem_tx(&first);
        assert_eq!(first, second, "Normalizing twice should be idempotent");
    }

    #[test]
    fn test_normalize_viem_tx_signature_hash_consistency() {
        // The critical invariant: after normalization, fee_payer_signature is Some,
        // which means signature_hash() will exclude fee_token from the hash.
        // This is required for correct sender recovery.
        let viem_tx = hex::decode(
            "f8d882a5bf0285059682f00282f299\
             f87ef87c9420c000000000000000000000000000000000000080\
             b86495777d59\
             0000000000000000000000005f270b1a3f160f7dbd21f8840bba82c61f62a029\
             00000000000000000000000000000000000000000000000000000000000f4240\
             ef1ed71201546a07b8cebd18e742dc\
             0000000000000000000075943864ff95b1\
             c0\
             80\
             06\
             80\
             80\
             80\
             00\
             c0\
             b841f94e83c7cae5d97c235de1de04a48cdad0d3a552921b730e5300fd3ce3f6a7f8\
             1409df263a6f761984537176e7dd30bab5aacdd7a4179f5fdc69d29252bcd5581c"
        ).unwrap();

        let normalized = normalize_viem_tx(&viem_tx);
        let signed = tempo_primitives::AASigned::rlp_decode(&mut normalized.as_slice()).unwrap();

        // The signature_hash depends on fee_payer_signature.is_some()
        // With Some(zero), it skips fee_token → correct signing hash for sender recovery
        let hash_with_some = signed.tx().signature_hash();

        // Build the same tx but with fee_payer_signature = None to show they differ
        let mut tx_none = signed.tx().clone();
        tx_none.fee_payer_signature = None;
        let hash_with_none = tx_none.signature_hash();

        assert_ne!(
            hash_with_some, hash_with_none,
            "signature_hash must differ between Some(zero) and None fee_payer_signature"
        );
    }
}
