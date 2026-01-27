//! Tempo charge intent for server-side payment verification.
//!
//! This module provides the `TempoChargeIntent` which verifies Tempo blockchain
//! payments by checking transaction receipts and transfer events via RPC.
//!
//! # Example
//!
//! ```ignore
//! use mpay::protocol::methods::tempo::TempoChargeIntent;
//! use mpay::protocol::intent::Intent;
//!
//! let intent = TempoChargeIntent::new("https://rpc.moderato.tempo.xyz");
//!
//! // In your server handler:
//! let receipt = intent.verify(&credential, &request).await?;
//! assert!(receipt.is_success());
//! ```

use crate::evm::{parse_address, parse_amount, Address, U256};
use crate::protocol::core::{PaymentCredential, PaymentPayload, PaymentReceipt};
use crate::protocol::intent::{Intent, VerificationError};
use crate::protocol::intents::ChargeRequest;
use std::future::Future;

use super::{parse_iso8601_timestamp, ERC20_TRANSFER_TOPIC, TempoChargeExt, CHAIN_ID, METHOD_NAME};

/// Tempo charge intent for one-time payment verification.
///
/// Verifies that a payment transaction matches the requested parameters by:
/// 1. Parsing the credential payload (hash or transaction)
/// 2. Fetching the transaction receipt from Tempo RPC
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
/// use mpay::protocol::methods::tempo::TempoChargeIntent;
/// use mpay::protocol::intent::Intent;
///
/// let intent = TempoChargeIntent::new("https://rpc.moderato.tempo.xyz");
///
/// // Verify a payment
/// let receipt = intent.verify(&credential, &request_json).await?;
/// if receipt.is_success() {
///     println!("Payment verified: {}", receipt.reference);
/// }
/// ```
#[derive(Clone)]
pub struct TempoChargeIntent {
    rpc_url: String,
    timeout_secs: u64,
}

impl TempoChargeIntent {
    /// Create a new Tempo charge intent with the given RPC URL.
    pub fn new(rpc_url: impl Into<String>) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            timeout_secs: 30,
        }
    }

    /// Set the timeout for RPC requests.
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    /// Get the RPC URL.
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    async fn verify_hash(
        &self,
        tx_hash: &str,
        charge: &ChargeRequest,
    ) -> Result<PaymentReceipt, VerificationError> {
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

        let receipt = self
            .fetch_transaction_receipt(tx_hash)
            .await
            .map_err(|e| VerificationError::new(format!("Failed to fetch receipt: {}", e)))?;

        let receipt_json: serde_json::Value = serde_json::from_str(&receipt)
            .map_err(|e| VerificationError::new(format!("Invalid receipt JSON: {}", e)))?;

        let result = receipt_json.get("result").ok_or_else(|| {
            VerificationError::not_found(format!("Transaction {} not found", tx_hash))
        })?;

        if result.is_null() {
            return Err(VerificationError::not_found(format!(
                "Transaction {} not found or not yet mined",
                tx_hash
            )));
        }

        let status = result
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("0x0");

        if status != "0x1" {
            return Err(VerificationError::transaction_failed(format!(
                "Transaction {} reverted",
                tx_hash
            )));
        }

        self.verify_transfer_logs(
            result,
            expected_recipient,
            expected_amount,
            expected_currency,
        )?;

        Ok(PaymentReceipt::success(METHOD_NAME, tx_hash))
    }

    fn verify_transfer_logs(
        &self,
        receipt: &serde_json::Value,
        expected_recipient: Address,
        expected_amount: U256,
        expected_currency: Address,
    ) -> Result<(), VerificationError> {
        let logs = receipt
            .get("logs")
            .and_then(|l| l.as_array())
            .ok_or_else(|| VerificationError::new("No logs in receipt"))?;

        let transfer_topic = format!("0x{}", hex::encode(ERC20_TRANSFER_TOPIC));

        let is_native = expected_currency == Address::ZERO;

        if is_native {
            let to = receipt.get("to").and_then(|t| t.as_str()).unwrap_or("");
            let value_hex = receipt
                .get("value")
                .and_then(|v| v.as_str())
                .unwrap_or("0x0");

            let to_addr = parse_address(to).map_err(|_| {
                VerificationError::invalid_recipient("Invalid 'to' address in transaction")
            })?;

            if to_addr != expected_recipient {
                return Err(VerificationError::invalid_recipient(format!(
                    "Recipient mismatch: expected {}, got {}",
                    expected_recipient, to_addr
                )));
            }

            let value = parse_hex_u256(value_hex)
                .map_err(|_| VerificationError::new("Invalid value in transaction"))?;

            if value < expected_amount {
                return Err(VerificationError::invalid_amount(format!(
                    "Amount mismatch: expected {}, got {}",
                    expected_amount, value
                )));
            }

            return Ok(());
        }

        for log in logs {
            let topics = match log.get("topics").and_then(|t| t.as_array()) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };

            let topic0 = topics[0].as_str().unwrap_or("");
            if topic0 != transfer_topic {
                continue;
            }

            let log_address = log.get("address").and_then(|a| a.as_str()).unwrap_or("");
            let log_currency = match parse_address(log_address) {
                Ok(a) => a,
                Err(_) => continue,
            };

            if log_currency != expected_currency {
                continue;
            }

            if topics.len() < 3 {
                continue;
            }

            let to_topic = topics[2].as_str().unwrap_or("");
            let to_addr = parse_topic_address(to_topic)?;

            if to_addr != expected_recipient {
                continue;
            }

            let data = log.get("data").and_then(|d| d.as_str()).unwrap_or("0x0");
            let amount = parse_hex_u256(data)
                .map_err(|_| VerificationError::new("Invalid amount in transfer log"))?;

            if amount >= expected_amount {
                return Ok(());
            }
        }

        Err(VerificationError::not_found(
            "No matching transfer found in logs",
        ))
    }

    async fn fetch_transaction_receipt(&self, tx_hash: &str) -> Result<String, String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getTransactionReceipt",
            "params": [tx_hash],
            "id": 1
        });

        let client = reqwest::Client::new();
        let resp = client
            .post(&self.rpc_url)
            .json(&body)
            .timeout(std::time::Duration::from_secs(self.timeout_secs))
            .send()
            .await
            .map_err(|e| format!("RPC request failed: {}", e))?;

        resp.text()
            .await
            .map_err(|e| format!("Failed to read RPC response: {}", e))
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

    async fn fetch_chain_id(&self) -> Result<u64, VerificationError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_chainId",
            "params": [],
            "id": 1
        });

        let client = reqwest::Client::new();
        let resp = client
            .post(&self.rpc_url)
            .json(&body)
            .timeout(std::time::Duration::from_secs(self.timeout_secs))
            .send()
            .await
            .map_err(|e| VerificationError::new(format!("Failed to fetch chain ID: {}", e)))?;

        let text = resp.text().await.map_err(|e| {
            VerificationError::new(format!("Failed to read chain ID response: {}", e))
        })?;

        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| VerificationError::new(format!("Invalid chain ID response: {}", e)))?;

        let result = json
            .get("result")
            .and_then(|r| r.as_str())
            .ok_or_else(|| VerificationError::new("Missing chain ID in response"))?;

        let chain_id = u64::from_str_radix(result.strip_prefix("0x").unwrap_or(result), 16)
            .map_err(|e| VerificationError::new(format!("Invalid chain ID format: {}", e)))?;

        Ok(chain_id)
    }

    async fn broadcast_transaction(&self, signed_tx: &str) -> Result<String, VerificationError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [signed_tx],
            "id": 1
        });

        let client = reqwest::Client::new();
        let resp = client
            .post(&self.rpc_url)
            .json(&body)
            .timeout(std::time::Duration::from_secs(self.timeout_secs))
            .send()
            .await
            .map_err(|e| {
                VerificationError::transaction_failed(format!("Failed to broadcast: {}", e))
            })?;

        let text = resp.text().await.map_err(|e| {
            VerificationError::transaction_failed(format!(
                "Failed to read broadcast response: {}",
                e
            ))
        })?;

        let json: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
            VerificationError::transaction_failed(format!("Invalid broadcast response: {}", e))
        })?;

        if let Some(error) = json.get("error") {
            let message = error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("Unknown error");
            return Err(VerificationError::transaction_failed(format!(
                "Broadcast failed: {}",
                message
            )));
        }

        json.get("result")
            .and_then(|r| r.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| VerificationError::transaction_failed("Missing tx hash in response"))
    }
}

fn parse_hex_u256(hex: &str) -> Result<U256, ()> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.is_empty() {
        return Ok(U256::ZERO);
    }
    U256::from_str_radix(hex, 16).map_err(|_| ())
}

fn parse_topic_address(topic: &str) -> Result<Address, VerificationError> {
    let topic = topic.strip_prefix("0x").unwrap_or(topic);
    if topic.len() != 64 {
        return Err(VerificationError::new("Invalid topic length for address"));
    }
    let addr_hex = &topic[24..];
    parse_address(&format!("0x{}", addr_hex))
        .map_err(|e| VerificationError::new(format!("Invalid address in topic: {}", e)))
}

impl Intent for TempoChargeIntent {
    fn name(&self) -> &str {
        "charge"
    }

    fn verify(
        &self,
        credential: &PaymentCredential,
        request: &serde_json::Value,
    ) -> impl Future<Output = Result<PaymentReceipt, VerificationError>> + Send {
        let credential = credential.clone();
        let request = request.clone();
        let this = self.clone();

        async move {
            let charge: ChargeRequest = serde_json::from_value(request.clone())
                .map_err(|e| VerificationError::new(format!("Invalid charge request: {}", e)))?;

            if let Some(ref expires) = charge.expires {
                this.check_expiration(expires)?;
            }

            let expected_chain_id = charge.chain_id().unwrap_or(CHAIN_ID);
            let actual_chain_id = this.fetch_chain_id().await?;

            if actual_chain_id != expected_chain_id {
                return Err(VerificationError::new(format!(
                    "Chain ID mismatch: expected {}, got {}",
                    expected_chain_id, actual_chain_id
                )));
            }

            match &credential.payload {
                PaymentPayload::Hash { hash, .. } => this.verify_hash(hash, &charge).await,
                PaymentPayload::Transaction { signature, .. } => {
                    let tx_hash = this.broadcast_transaction(signature).await?;
                    this.verify_hash(&tx_hash, &charge).await
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_u256() {
        assert_eq!(parse_hex_u256("0x0").unwrap(), U256::ZERO);
        assert_eq!(parse_hex_u256("0x1").unwrap(), U256::from(1u64));
        assert_eq!(parse_hex_u256("0x10").unwrap(), U256::from(16u64));
        assert_eq!(parse_hex_u256("0x").unwrap(), U256::ZERO);
    }

    #[test]
    fn test_parse_iso8601_timestamp() {
        let ts = parse_iso8601_timestamp("2024-01-01T00:00:00Z");
        assert!(ts.is_some());

        let ts = parse_iso8601_timestamp("2024-06-15T12:30:45Z");
        assert!(ts.is_some());
    }

    #[test]
    fn test_tempo_charge_intent_name() {
        let intent = TempoChargeIntent::new("https://rpc.example.com");
        assert_eq!(intent.name(), "charge");
    }

    #[test]
    fn test_tempo_charge_intent_with_timeout() {
        let intent = TempoChargeIntent::new("https://rpc.example.com").with_timeout(60);
        assert_eq!(intent.timeout_secs, 60);
    }
}
