//! Tempo charge intent for server-side payment verification.
//!
//! This module provides [`TempoChargeIntent`], which verifies Tempo blockchain
//! payments by checking transaction receipts via RPC.
//!
//! # Examples
//!
//! ```ignore
//! use mpay::protocol::methods::tempo::TempoChargeIntent;
//! use mpay::protocol::traits::Intent;
//!
//! let intent = TempoChargeIntent::new("https://rpc.moderato.tempo.xyz")?;
//!
//! // Verify a credential
//! let receipt = intent.verify(&credential, &request).await?;
//! assert!(receipt.is_success());
//! ```

use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use super::{TempoChargeExt, CHAIN_ID, METHOD_NAME};
use crate::evm::{Address, U256};
use crate::protocol::core::{
    MethodName, PaymentCredential, PaymentPayload, PaymentReceipt, ReceiptStatus,
};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::traits::{BoxFuture, Intent, VerificationError};

/// Tempo charge intent for one-time payment verification.
///
/// Verifies that a Tempo blockchain payment matches the requested parameters
/// by checking the transaction receipt via RPC.
///
/// # Verification Process
///
/// For `hash` payloads (client already broadcast):
/// 1. Call `eth_getTransactionReceipt` to get the receipt
/// 2. Verify the transaction was successful (status = 1)
/// 3. Parse transfer logs to verify amount, recipient, and currency
///
/// For `transaction` payloads (server should broadcast):
/// 1. Decode and validate the signed transaction
/// 2. Submit via `eth_sendRawTransaction`
/// 3. Wait for confirmation and verify as above
///
/// # Examples
///
/// ```ignore
/// use mpay::protocol::methods::tempo::TempoChargeIntent;
/// use mpay::protocol::traits::Intent;
///
/// let intent = TempoChargeIntent::new("https://rpc.moderato.tempo.xyz")?;
///
/// // Use with verify_or_challenge
/// let result = server.verify_or_challenge(
///     authorization_header,
///     &intent,
///     &request,
///     "api.example.com",
/// ).await?;
/// ```
#[derive(Clone)]
pub struct TempoChargeIntent {
    rpc_url: reqwest::Url,
    http_client: Client,
    expected_chain_id: u64,
}

impl std::fmt::Debug for TempoChargeIntent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TempoChargeIntent")
            .field("rpc_url", &self.rpc_url)
            .field("expected_chain_id", &self.expected_chain_id)
            .finish()
    }
}

impl TempoChargeIntent {
    /// Create a new Tempo charge intent with the given RPC URL.
    ///
    /// Uses the default Tempo Moderato chain ID (42431).
    pub fn new(rpc_url: impl AsRef<str>) -> Result<Self, crate::MppError> {
        Self::with_chain_id(rpc_url, CHAIN_ID)
    }

    /// Create a new Tempo charge intent with a specific chain ID.
    pub fn with_chain_id(rpc_url: impl AsRef<str>, chain_id: u64) -> Result<Self, crate::MppError> {
        let url = rpc_url
            .as_ref()
            .parse()
            .map_err(|e| crate::MppError::InvalidConfig(format!("invalid RPC URL: {}", e)))?;
        Ok(Self {
            rpc_url: url,
            http_client: Client::new(),
            expected_chain_id: chain_id,
        })
    }

    /// Create with a custom HTTP client.
    pub fn with_client(rpc_url: impl AsRef<str>, client: Client) -> Result<Self, crate::MppError> {
        let url = rpc_url
            .as_ref()
            .parse()
            .map_err(|e| crate::MppError::InvalidConfig(format!("invalid RPC URL: {}", e)))?;
        Ok(Self {
            rpc_url: url,
            http_client: client,
            expected_chain_id: CHAIN_ID,
        })
    }

    /// Verify a hash payload by fetching the transaction receipt.
    async fn verify_hash(
        &self,
        tx_hash: &str,
        request: &ChargeRequest,
    ) -> Result<PaymentReceipt, VerificationError> {
        let receipt = self
            .get_transaction_receipt(tx_hash)
            .await
            .map_err(|e| VerificationError::Failed(format!("RPC error: {}", e)))?;

        let receipt = receipt.ok_or_else(|| {
            VerificationError::NotFound(format!("Transaction {} not found", tx_hash))
        })?;

        if !receipt.status {
            return Err(VerificationError::TransactionFailed(format!(
                "Transaction {} reverted",
                tx_hash
            )));
        }

        self.verify_transfer_logs(&receipt, request)?;

        Ok(PaymentReceipt {
            status: ReceiptStatus::Success,
            method: MethodName::from(METHOD_NAME),
            timestamp: Utc::now().to_rfc3339(),
            reference: tx_hash.to_string(),
        })
    }

    /// Verify a transaction payload by broadcasting and verifying.
    async fn verify_transaction(
        &self,
        signature: &str,
        request: &ChargeRequest,
    ) -> Result<PaymentReceipt, VerificationError> {
        let tx_hash = self
            .send_raw_transaction(signature)
            .await
            .map_err(|e| VerificationError::Failed(format!("Failed to broadcast: {}", e)))?;

        for _ in 0..30 {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            let receipt = self
                .get_transaction_receipt(&tx_hash)
                .await
                .map_err(|e| VerificationError::Failed(format!("RPC error: {}", e)))?;

            if let Some(receipt) = receipt {
                if !receipt.status {
                    return Err(VerificationError::TransactionFailed(format!(
                        "Transaction {} reverted",
                        tx_hash
                    )));
                }

                self.verify_transfer_logs(&receipt, request)?;

                return Ok(PaymentReceipt {
                    status: ReceiptStatus::Success,
                    method: MethodName::from(METHOD_NAME),
                    timestamp: Utc::now().to_rfc3339(),
                    reference: tx_hash,
                });
            }
        }

        Err(VerificationError::Failed(format!(
            "Transaction {} not confirmed after 30 seconds",
            tx_hash
        )))
    }

    /// Verify that transfer logs match the request.
    fn verify_transfer_logs(
        &self,
        receipt: &TransactionReceipt,
        request: &ChargeRequest,
    ) -> Result<(), VerificationError> {
        let expected_recipient = request
            .recipient_address()
            .map_err(|e| VerificationError::Failed(format!("Invalid recipient address: {}", e)))?;

        let expected_amount = request
            .amount_u256()
            .map_err(|e| VerificationError::Failed(format!("Invalid amount: {}", e)))?;

        let expected_currency = request
            .currency_address()
            .map_err(|e| VerificationError::Failed(format!("Invalid currency address: {}", e)))?;

        if expected_currency == Address::ZERO {
            if let Some(ref to) = receipt.to {
                let to_addr: Address = to.parse().map_err(|_| {
                    VerificationError::Failed("Invalid to address in receipt".to_string())
                })?;

                if to_addr != expected_recipient {
                    return Err(VerificationError::RecipientMismatch {
                        expected: format!("{:?}", expected_recipient),
                        got: format!("{:?}", to_addr),
                    });
                }
            }
        } else {
            let transfer_found = receipt.logs.iter().any(|log| {
                self.is_matching_transfer_log(
                    log,
                    &expected_currency,
                    &expected_recipient,
                    &expected_amount,
                )
            });

            if !transfer_found {
                return Err(VerificationError::Failed(
                    "No matching ERC20 Transfer event found".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Check if a log matches an ERC20 Transfer event.
    fn is_matching_transfer_log(
        &self,
        log: &Log,
        expected_token: &Address,
        expected_to: &Address,
        expected_amount: &U256,
    ) -> bool {
        const TRANSFER_TOPIC: &str =
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

        if log.topics.first() != Some(&TRANSFER_TOPIC.to_string()) {
            return false;
        }

        let log_addr: Address = match log.address.parse() {
            Ok(addr) => addr,
            Err(_) => return false,
        };

        if log_addr != *expected_token {
            return false;
        }

        if log.topics.len() < 3 {
            return false;
        }

        let to_topic = &log.topics[2];
        let to_addr = match parse_topic_address(to_topic) {
            Some(addr) => addr,
            None => return false,
        };

        if to_addr != *expected_to {
            return false;
        }

        let amount = match parse_log_data_amount(&log.data) {
            Some(amt) => amt,
            None => return false,
        };

        amount == *expected_amount
    }

    /// Make an RPC call to get a transaction receipt.
    async fn get_transaction_receipt(
        &self,
        tx_hash: &str,
    ) -> Result<Option<TransactionReceipt>, reqwest::Error> {
        let response: JsonRpcResponse<TransactionReceipt> = self
            .http_client
            .post(self.rpc_url.clone())
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_getTransactionReceipt",
                "params": [tx_hash],
                "id": 1
            }))
            .send()
            .await?
            .json()
            .await?;

        Ok(response.result)
    }

    /// Broadcast a raw transaction and return the hash.
    async fn send_raw_transaction(&self, signed_tx: &str) -> Result<String, reqwest::Error> {
        let response: JsonRpcResponse<String> = self
            .http_client
            .post(self.rpc_url.clone())
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_sendRawTransaction",
                "params": [signed_tx],
                "id": 1
            }))
            .send()
            .await?
            .json()
            .await?;

        Ok(response.result.unwrap_or_default())
    }
}

impl Intent for TempoChargeIntent {
    fn name(&self) -> &str {
        "charge"
    }

    fn verify<'a>(
        &'a self,
        credential: &'a PaymentCredential,
        request: &'a serde_json::Value,
    ) -> BoxFuture<'a, Result<PaymentReceipt, VerificationError>> {
        Box::pin(async move {
            let charge_req: ChargeRequest = serde_json::from_value(request.clone())
                .map_err(|e| VerificationError::Failed(format!("Invalid request: {}", e)))?;

            if let Some(ref expires) = charge_req.expires {
                let expires_dt: DateTime<Utc> = expires
                    .parse()
                    .map_err(|_| VerificationError::Failed("Invalid expires format".to_string()))?;

                if expires_dt < Utc::now() {
                    return Err(VerificationError::Expired(expires.clone()));
                }
            }

            let req_chain_id = charge_req.chain_id().unwrap_or(self.expected_chain_id);
            if req_chain_id != self.expected_chain_id {
                return Err(VerificationError::Failed(format!(
                    "Chain ID mismatch: expected {}, request specifies {}",
                    self.expected_chain_id, req_chain_id
                )));
            }

            match &credential.payload {
                PaymentPayload::Hash { hash, .. } => self.verify_hash(hash, &charge_req).await,
                PaymentPayload::Transaction { signature, .. } => {
                    self.verify_transaction(signature, &charge_req).await
                }
            }
        })
    }
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
}

#[derive(Debug, Deserialize, Serialize)]
struct TransactionReceipt {
    #[serde(rename = "transactionHash")]
    transaction_hash: String,
    #[serde(deserialize_with = "deserialize_bool_from_hex")]
    status: bool,
    to: Option<String>,
    #[serde(default)]
    logs: Vec<Log>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Log {
    address: String,
    topics: Vec<String>,
    data: String,
}

fn deserialize_bool_from_hex<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = String::deserialize(deserializer)?;
    Ok(s == "0x1" || s == "1")
}

fn parse_topic_address(topic: &str) -> Option<Address> {
    let topic = topic.strip_prefix("0x").unwrap_or(topic);
    if topic.len() != 64 {
        return None;
    }
    let addr_hex = &topic[24..];
    format!("0x{}", addr_hex).parse().ok()
}

fn parse_log_data_amount(data: &str) -> Option<U256> {
    let data = data.strip_prefix("0x").unwrap_or(data);
    U256::from_str_radix(data, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tempo_charge_intent_creation() {
        let intent = TempoChargeIntent::new("https://rpc.moderato.tempo.xyz").unwrap();
        assert_eq!(intent.name(), "charge");
        assert_eq!(intent.expected_chain_id, CHAIN_ID);
    }

    #[test]
    fn test_tempo_charge_intent_with_chain_id() {
        let intent = TempoChargeIntent::with_chain_id("https://rpc.example.com", 1).unwrap();
        assert_eq!(intent.expected_chain_id, 1);
    }

    #[test]
    fn test_parse_topic_address() {
        let topic = "0x000000000000000000000000742d35cc6634c0532925a3b844bc9e7595f1b0f2";
        let addr = parse_topic_address(topic).unwrap();
        assert_eq!(
            format!("{:?}", addr).to_lowercase(),
            "0x742d35cc6634c0532925a3b844bc9e7595f1b0f2"
        );
    }

    #[test]
    fn test_parse_log_data_amount() {
        let data = "0x00000000000000000000000000000000000000000000000000000000000f4240";
        let amount = parse_log_data_amount(data).unwrap();
        assert_eq!(amount, U256::from(1_000_000u64));
    }

    #[test]
    fn test_deserialize_receipt() {
        let json = r#"{
            "transactionHash": "0x123",
            "status": "0x1",
            "to": "0x456",
            "logs": []
        }"#;
        let receipt: TransactionReceipt = serde_json::from_str(json).unwrap();
        assert!(receipt.status);
        assert_eq!(receipt.to, Some("0x456".to_string()));
    }
}
