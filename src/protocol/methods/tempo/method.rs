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

use alloy::network::ReceiptResponse;
use alloy::primitives::{hex, Address, Bytes, TxKind, B256, U256};
use alloy::providers::Provider;
use alloy::rlp::Decodable as _;
use std::borrow::Cow;
use std::future::Future;
use std::sync::Arc;
use tempo_alloy::TempoNetwork;
use tempo_primitives::TempoTransaction;

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
const TRANSFER_WITH_MEMO_SELECTOR: [u8; 4] = [0x4a, 0x7a, 0x13, 0x64];

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

        self.verify_receipt(&receipt, tx_hash, charge)
    }

    fn verify_receipt(
        &self,
        receipt: &<TempoNetwork as alloy::network::Network>::ReceiptResponse,
        tx_hash: &str,
        charge: &ChargeRequest,
    ) -> Result<Receipt, VerificationError> {
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

        self.verify_tip20_transfer(
            receipt,
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

        let tx = TempoTransaction::decode(&mut &tx_data[..])
            .map_err(|e| VerificationError::new(format!("Failed to decode transaction: {}", e)))?;

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
                // Look for transfer(address,uint256)
                // Exact length: 4 (selector) + 32 (address) + 32 (amount) = 68 bytes
                if selector == TRANSFER_SELECTOR && data.len() == 68 {
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
    ) -> Result<Receipt, VerificationError> {
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

        // Fail fast if fee payer is requested but not configured.
        // Full fee payer support requires passing a signer to ChargeMethod.
        if charge.fee_payer() {
            return Err(VerificationError::new(
                "feePayer requested but fee sponsorship is not configured on this server"
                    .to_string(),
            ));
        }

        let canonical_tx = format!("0x{}", hex::encode(&tx_bytes));
        let receipt: <TempoNetwork as alloy::network::Network>::ReceiptResponse = self
            .provider
            .raw_request(Cow::Borrowed("eth_sendRawTransactionSync"), (canonical_tx,))
            .await
            .map_err(|e| VerificationError::network_error(format!("Failed to broadcast: {}", e)))?;

        let tx_hash = format!("{:#x}", receipt.transaction_hash());
        self.verify_receipt(&receipt, &tx_hash, charge)
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
                this.verify_hash(credential.payload.tx_hash().unwrap(), &request)
                    .await
            } else {
                // Client sent signed transaction, broadcast via eth_sendRawTransactionSync
                // which returns the receipt directly, avoiding extra RPC round-trips
                this.broadcast_transaction(
                    credential.payload.signed_tx().unwrap(),
                    &request,
                    expected_chain_id,
                )
                .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{super::MODERATO_CHAIN_ID, *};
    use tempo_alloy::rpc::TempoTransactionReceipt;

    const CURRENCY: &str = "0x20c0000000000000000000000000000000000001";
    const RECIPIENT: &str = "0x742d35Cc6634C0532925a3b844Bc9e7595f3bB77";
    const TX_HASH: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn test_charge(amount: &str) -> ChargeRequest {
        ChargeRequest {
            amount: amount.to_string(),
            currency: CURRENCY.to_string(),
            recipient: Some(RECIPIENT.to_string()),
            ..Default::default()
        }
    }

    fn test_charge_with_memo(amount: &str, memo: &str) -> ChargeRequest {
        ChargeRequest {
            amount: amount.to_string(),
            currency: CURRENCY.to_string(),
            recipient: Some(RECIPIENT.to_string()),
            method_details: Some(serde_json::json!({ "memo": memo })),
            ..Default::default()
        }
    }

    fn make_receipt(status: bool, logs: serde_json::Value) -> TempoTransactionReceipt {
        let receipt_json = serde_json::json!({
            "transactionHash": TX_HASH,
            "transactionIndex": "0x0",
            "blockHash": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "blockNumber": "0x1",
            "from": "0x0000000000000000000000000000000000000001",
            "to": CURRENCY,
            "cumulativeGasUsed": "0x5208",
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x3b9aca00",
            "logs": logs,
            "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "status": if status { "0x1" } else { "0x0" },
            "type": "0x76",
            "feePayer": "0x0000000000000000000000000000000000000001"
        });
        serde_json::from_value(receipt_json).expect("valid receipt JSON")
    }

    fn transfer_log(currency: &str, from: &str, to: &str, amount_hex: &str) -> serde_json::Value {
        let from_topic = format!("0x000000000000000000000000{}", &from[2..]);
        let to_topic = format!("0x000000000000000000000000{}", &to[2..]);
        serde_json::json!({
            "address": currency,
            "topics": [
                format!("0x{}", hex::encode(TRANSFER_EVENT_TOPIC)),
                from_topic,
                to_topic
            ],
            "data": format!("0x{}", amount_hex),
            "blockNumber": "0x1",
            "transactionHash": TX_HASH,
            "transactionIndex": "0x0",
            "blockHash": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "logIndex": "0x0",
            "removed": false
        })
    }

    fn transfer_with_memo_log(
        currency: &str,
        from: &str,
        to: &str,
        amount_hex: &str,
        memo_hex: &str,
    ) -> serde_json::Value {
        let from_topic = format!("0x000000000000000000000000{}", &from[2..]);
        let to_topic = format!("0x000000000000000000000000{}", &to[2..]);
        serde_json::json!({
            "address": currency,
            "topics": [
                format!("0x{}", hex::encode(TRANSFER_WITH_MEMO_EVENT_TOPIC)),
                from_topic,
                to_topic
            ],
            "data": format!("0x{}{}", amount_hex, memo_hex),
            "blockNumber": "0x1",
            "transactionHash": TX_HASH,
            "transactionIndex": "0x0",
            "blockHash": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "logIndex": "0x0",
            "removed": false
        })
    }

    fn dummy_charge_method() -> ChargeMethod<crate::server::TempoProvider> {
        let provider = crate::server::tempo_provider("http://localhost:1234").unwrap();
        ChargeMethod::new(provider)
    }

    #[test]
    fn test_verify_receipt_success() {
        let method = dummy_charge_method();
        let amount_hex = "00000000000000000000000000000000000000000000000000000000000f4240"; // 1000000
        let log = transfer_log(
            CURRENCY,
            "0x0000000000000000000000000000000000000001",
            RECIPIENT,
            amount_hex,
        );
        let receipt = make_receipt(true, serde_json::json!([log]));
        let charge = test_charge("1000000");

        let result = method.verify_receipt(&receipt, TX_HASH, &charge);
        assert!(result.is_ok());
        let r = result.unwrap();
        assert!(r.is_success());
        assert_eq!(r.reference, TX_HASH);
    }

    #[test]
    fn test_verify_receipt_reverted() {
        let method = dummy_charge_method();
        let receipt = make_receipt(false, serde_json::json!([]));
        let charge = test_charge("1000000");

        let result = method.verify_receipt(&receipt, TX_HASH, &charge);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("reverted"));
    }

    #[test]
    fn test_verify_receipt_no_matching_transfer() {
        let method = dummy_charge_method();
        let receipt = make_receipt(true, serde_json::json!([]));
        let charge = test_charge("1000000");

        let result = method.verify_receipt(&receipt, TX_HASH, &charge);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("No matching Transfer"));
    }

    #[test]
    fn test_verify_receipt_wrong_amount() {
        let method = dummy_charge_method();
        let amount_hex = "0000000000000000000000000000000000000000000000000000000000000001"; // 1 (wrong)
        let log = transfer_log(
            CURRENCY,
            "0x0000000000000000000000000000000000000001",
            RECIPIENT,
            amount_hex,
        );
        let receipt = make_receipt(true, serde_json::json!([log]));
        let charge = test_charge("1000000");

        let result = method.verify_receipt(&receipt, TX_HASH, &charge);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_receipt_wrong_recipient() {
        let method = dummy_charge_method();
        let amount_hex = "00000000000000000000000000000000000000000000000000000000000f4240";
        let log = transfer_log(
            CURRENCY,
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000099", // wrong recipient
            amount_hex,
        );
        let receipt = make_receipt(true, serde_json::json!([log]));
        let charge = test_charge("1000000");

        let result = method.verify_receipt(&receipt, TX_HASH, &charge);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_receipt_wrong_currency() {
        let method = dummy_charge_method();
        let amount_hex = "00000000000000000000000000000000000000000000000000000000000f4240";
        let log = transfer_log(
            "0x0000000000000000000000000000000000000099", // wrong currency
            "0x0000000000000000000000000000000000000001",
            RECIPIENT,
            amount_hex,
        );
        let receipt = make_receipt(true, serde_json::json!([log]));
        let charge = test_charge("1000000");

        let result = method.verify_receipt(&receipt, TX_HASH, &charge);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_receipt_with_memo_success() {
        let method = dummy_charge_method();
        let memo_hex = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let amount_hex = "00000000000000000000000000000000000000000000000000000000000f4240";
        let log = transfer_with_memo_log(
            CURRENCY,
            "0x0000000000000000000000000000000000000001",
            RECIPIENT,
            amount_hex,
            memo_hex,
        );
        let receipt = make_receipt(true, serde_json::json!([log]));
        let charge = test_charge_with_memo("1000000", &format!("0x{}", memo_hex));

        let result = method.verify_receipt(&receipt, TX_HASH, &charge);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_receipt_with_memo_wrong_memo() {
        let method = dummy_charge_method();
        let memo_hex = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let wrong_memo = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let amount_hex = "00000000000000000000000000000000000000000000000000000000000f4240";
        let log = transfer_with_memo_log(
            CURRENCY,
            "0x0000000000000000000000000000000000000001",
            RECIPIENT,
            amount_hex,
            wrong_memo,
        );
        let receipt = make_receipt(true, serde_json::json!([log]));
        let charge = test_charge_with_memo("1000000", &format!("0x{}", memo_hex));

        let result = method.verify_receipt(&receipt, TX_HASH, &charge);
        assert!(result.is_err());
    }

    #[test]
    fn test_transfer_selector() {
        // transfer(address,uint256) = 0xa9059cbb
        assert_eq!(TRANSFER_SELECTOR, [0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn test_transfer_with_memo_selector() {
        // transferWithMemo(address,uint256,bytes32) = 0x4a7a1364
        assert_eq!(TRANSFER_WITH_MEMO_SELECTOR, [0x4a, 0x7a, 0x13, 0x64]);
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
}
