//! Tempo charge method for server-side payment verification.
//!
//! This module provides [`ChargeMethod`] which implements the [`ChargeMethod`]
//! trait for Tempo blockchain payments.
//!
//! # Example
//!
//! ```ignore
//! use mpay::protocol::methods::tempo::ChargeMethod;
//! use mpay::protocol::traits::ChargeMethod;
//!
//! let method = ChargeMethod::new("https://rpc.moderato.tempo.xyz");
//!
//! // In your server handler:
//! let receipt = method.verify(&credential, &request).await?;
//! assert!(receipt.is_success());
//! ```

use crate::evm::{parse_address, parse_amount, Address, U256};
use crate::protocol::core::{PaymentCredential, PaymentPayload, PaymentReceipt};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::traits::{ChargeMethod, VerificationError};
use std::future::Future;

use super::{TempoChargeExt, CHAIN_ID, METHOD_NAME};

/// Tempo charge method for one-time payment verification.
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
/// use mpay::protocol::methods::tempo::ChargeMethod;
/// use mpay::protocol::traits::ChargeMethod;
///
/// let method = ChargeMethod::new("https://rpc.moderato.tempo.xyz");
///
/// // Verify a payment
/// let receipt = method.verify(&credential, &request).await?;
/// if receipt.is_success() {
///     println!("Payment verified: {}", receipt.reference);
/// }
/// ```
#[derive(Clone)]
pub struct ChargeMethod {
    rpc_url: String,
    timeout_secs: u64,
}

impl ChargeMethod {
    /// Create a new Tempo charge method with the given RPC URL.
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

        let transfer_topic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

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

fn parse_iso8601_timestamp(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.len() < 19 {
        return None;
    }

    let year: i32 = s.get(0..4)?.parse().ok()?;
    let month: u32 = s.get(5..7)?.parse().ok()?;
    let day: u32 = s.get(8..10)?.parse().ok()?;
    let hour: u32 = s.get(11..13)?.parse().ok()?;
    let minute: u32 = s.get(14..16)?.parse().ok()?;
    let second: u32 = s.get(17..19)?.parse().ok()?;

    fn is_leap_year(year: i32) -> bool {
        (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
    }

    let days_before_month = |y: i32, m: u32| -> u32 {
        let leap = is_leap_year(y);
        match m {
            1 => 0,
            2 => 31,
            3 => 59 + u32::from(leap),
            4 => 90 + u32::from(leap),
            5 => 120 + u32::from(leap),
            6 => 151 + u32::from(leap),
            7 => 181 + u32::from(leap),
            8 => 212 + u32::from(leap),
            9 => 243 + u32::from(leap),
            10 => 273 + u32::from(leap),
            11 => 304 + u32::from(leap),
            12 => 334 + u32::from(leap),
            _ => 0,
        }
    };

    let mut days: i64 = 0;
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    days += days_before_month(year, month) as i64;
    days += (day - 1) as i64;

    let timestamp = days as u64 * 86400 + hour as u64 * 3600 + minute as u64 * 60 + second as u64;

    Some(timestamp)
}

impl ChargeMethod for ChargeMethod {
    fn method(&self) -> &str {
        METHOD_NAME
    }

    fn verify(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> impl Future<Output = Result<PaymentReceipt, VerificationError>> + Send {
        let credential = credential.clone();
        let request = request.clone();
        let this = self.clone();

        async move {
            if let Some(ref expires) = request.expires {
                this.check_expiration(expires)?;
            }

            let expected_chain_id = request.chain_id().unwrap_or(CHAIN_ID);
            let actual_chain_id = this.fetch_chain_id().await?;

            if actual_chain_id != expected_chain_id {
                return Err(VerificationError::with_code(
                    format!(
                        "Chain ID mismatch: expected {}, got {}",
                        expected_chain_id, actual_chain_id
                    ),
                    "chain_id_mismatch",
                ));
            }

            match &credential.payload {
                PaymentPayload::Hash { hash, .. } => this.verify_hash(hash, &request).await,
                PaymentPayload::Transaction { signature, .. } => {
                    let tx_hash = this.broadcast_transaction(signature).await?;
                    this.verify_hash(&tx_hash, &request).await
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
    fn test_tempo_charge_method_name() {
        let method = ChargeMethod::new("https://rpc.example.com");
        assert_eq!(method.method(), "tempo");
    }

    #[test]
    fn test_tempo_charge_method_with_timeout() {
        let method = ChargeMethod::new("https://rpc.example.com").with_timeout(60);
        assert_eq!(method.timeout_secs, 60);
    }
}
